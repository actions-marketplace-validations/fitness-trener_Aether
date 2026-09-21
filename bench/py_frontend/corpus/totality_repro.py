# Sink calls the translator could not see (BUGS.md BUG-012).
#
# `py_to_ir` translated four statement kinds (`Assign` to one name,
# `Expr(Call)`, `Return`, `With`) and one expression shape, and dropped
# every other node. A sink call in any other POSITION — behind an
# `await`, in a `for` iterable, in an `if` test, in a tuple-target
# assignment, inside `x or []`, in a keyword argument, in a comprehension,
# under a `def` nested in `try:` — never reached the IR, so it was not
# over-flagged, it was SILENT. On bench/framework_scan that was 603 sink
# calls behind `await` and 89 in other positions.
#
# The other half of the same bug: three resolvers saw only the
# single-Name `Assign` binding form, so a name whose only VISIBLE binding
# was a literal proved literal-only after `sql += uid`, and a parameter
# with `if q is None: q = "SELECT 1"` proved literal-only while the
# caller supplied the query.
#
# Every function below is judged by the unchanged Aether rules; the fix
# is that the translator is now TOTAL over positions and binding forms.

import pickle
import subprocess
import yaml
from sqlalchemy import select, text


# --- positions that hid a sink ----------------------------------------

async def await_wrapped_query(conn, uid):
    return await conn.execute("SELECT * FROM u WHERE id = " + uid)      # CWE-89


def for_iterable_query(cur, uid):
    for row in cur.execute("SELECT * FROM u WHERE id = " + uid):         # CWE-89
        yield row


def tuple_target_unpickle(blob):
    obj, _ = pickle.loads(blob), None                                     # CWE-502
    return obj


def boolop_query(cur, uid):
    return cur.execute("SELECT * FROM u WHERE id = " + uid) or []        # CWE-89


def keyword_argument_query(cur, uid, emit):
    return emit(rows=cur.execute("SELECT * FROM u WHERE id = " + uid))   # CWE-89


# --- binding forms that hid a rebinding --------------------------------

def augassign_rebinds_literal(cur, uid):
    sql = "SELECT * FROM u WHERE id = "
    sql += uid
    return cur.execute(sql)                                               # CWE-89


def parameter_shadowed_by_literal(cur, query):
    if query is None:
        query = "SELECT 1"
    return cur.execute(query)                                             # CWE-89: caller-supplied


def parameter_shadowed_loader(raw, loader=None):
    if loader is None:
        loader = yaml.SafeLoader
    return yaml.load(raw, Loader=loader)                                  # CWE-502: caller-supplied loader


# --- resolution gaps ----------------------------------------------------

def splat_hides_shell(cmd, **opts):
    return subprocess.run(cmd, **opts)                                    # CWE-78: shell= may be in opts


def getattr_dispatch(cur, uid):
    return getattr(cur, "execute")("SELECT * FROM u WHERE id = " + uid)  # CWE-89


def exec_driver_sql_fstring(conn, table):
    return conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN x INT")  # CWE-89


def raw_hint_in_expression(conn, t, hint):
    return conn.execute(select(t).prefix_with("/*+ " + hint + " */"))     # CWE-89: spliced verbatim


def keyword_only_loader(raw):
    return yaml.load(stream=raw)                                          # CWE-502: no positional slot


# --- the documented fixes, and the shapes that stay clean ---------------

async def await_wrapped_query_safe(conn, uid):
    return await conn.execute(text("SELECT * FROM u WHERE id = :id"), {"id": uid})


def for_iterable_query_safe(cur, uid):
    for row in cur.execute("SELECT * FROM u WHERE id = ?", (uid,)):
        yield row


def augassign_rebinds_literal_safe(cur, uid):
    sql = "SELECT * FROM u WHERE id = ?"
    return cur.execute(sql, (uid,))


def parameter_shadowed_loader_safe(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)


def splat_hides_shell_safe(cmd):
    return subprocess.run(cmd, shell=False)


def none_sentinel_then_expression_safe(conn, t, flag):
    stmt = None
    if flag:
        stmt = select(t).where(t.c.x == 1)
    return conn.execute(stmt)


def raw_hint_literal_safe(conn, t):
    return conn.execute(select(t).prefix_with("/*+ NO_INDEX */"))


def keyword_only_loader_safe(raw):
    return yaml.load(stream=raw, Loader=yaml.SafeLoader)
