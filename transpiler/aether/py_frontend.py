"""Python -> Aether-IR translation frontend.

THIS FILE DOES NOT ANALYZE. It TRANSLATES Python source into the exact
dict-AST shape the existing Aether passes (`aether.passes.capability`,
`aether.passes.effects`) and the dashboard projection (`tools.alsp_surface`)
already consume, then lets those untouched passes do the proving.

The mapping from Python constructs to capability/effect signals is the
analysis surface, and it is intentionally explicit and auditable below:

    CAP_BY_MODULE      import name        -> capability        (whole module)
    CAP_BY_QUALIFIED   module.attr        -> capability        (specific call)
    CAP_BY_BUILTIN     builtin name       -> (capability,verb)
    DYNAMIC_BUILTINS   builtin name       -> reason            (UNPROVABLE)
    PURE_MODULES       import name        -> resolvable, no capability
    PURE_BUILTINS      builtin name       -> resolvable, no capability

SOUNDNESS DISCIPLINE (the whole point of the Python experiment):
  A call whose capability surface we CANNOT determine is NEVER assumed
  clean. It is emitted as an UNPROVABLE record. We only treat a call as
  capability-free when it is (a) a local function, (b) a known-pure
  builtin, or (c) a call into a known-pure module. Everything else —
  unmapped imports, methods on unknown objects, dynamic dispatch — is
  UNPROVABLE. This is why real Python may collapse to UNPROVABLE; the
  experiment is to measure exactly how much.

Output of `py_to_ir(source)`:
    (ast_dict, unprovable_map, meta)
  ast_dict       : {"kind":"Program","decls":[ModuleDecl, FunctionDecl...]}
  unprovable_map : { fn_name: [ {fn,line,granularity,callee/construct,
                                 reason,detail,needs}, ... ] }
  meta           : { "lang":"python", "module": name, "n_functions": int,
                     "pymap_version": str }
"""
from __future__ import annotations
import ast as _pyast
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

PYMAP_VERSION = "py-cap-map/0.2"

# ----------------------------------------------------------------------
# THE AUDITABLE CAPABILITY MAPPING TABLE
# ----------------------------------------------------------------------
# Whole-module imports that confer a capability on ANY call through them.
CAP_BY_MODULE: Dict[str, str] = {
    # network
    "socket": "net", "ssl": "net", "http": "net", "httplib": "net",
    "urllib": "net", "urllib2": "net", "requests": "net", "httpx": "net",
    "aiohttp": "net", "websocket": "net", "websockets": "net",
    "smtplib": "net", "ftplib": "net", "telnetlib": "net", "poplib": "net",
    "imaplib": "net", "xmlrpc": "net", "grpc": "net", "paramiko": "net",
    # filesystem
    "pathlib": "fs", "shutil": "fs", "tempfile": "fs", "glob": "fs",
    "fileinput": "fs", "csv": "fs", "configparser": "fs",
    # process / exec
    "subprocess": "process", "multiprocessing": "process", "pty": "process",
    "signal": "process",
    # database
    "sqlite3": "db", "psycopg2": "db", "psycopg": "db", "pymysql": "db",
    "mysql": "db", "sqlalchemy": "db", "pymongo": "db", "redis": "db",
    "asyncpg": "db", "aioredis": "db", "cassandra": "db", "elasticsearch": "db",
    # logging
    "logging": "log",
}

# Specific dotted calls that confer a capability (finer than whole-module).
CAP_BY_QUALIFIED: Dict[str, str] = {
    "os.system": "process", "os.popen": "process", "os.spawnv": "process",
    "os.spawnl": "process", "os.exec": "process", "os.execv": "process",
    "os.execl": "process", "os.fork": "process", "os.kill": "process",
    "os.remove": "fs", "os.unlink": "fs", "os.mkdir": "fs", "os.makedirs": "fs",
    "os.rmdir": "fs", "os.removedirs": "fs", "os.rename": "fs", "os.replace": "fs",
    "os.open": "fs", "os.read": "fs", "os.write": "fs", "os.listdir": "fs",
    "os.scandir": "fs", "os.walk": "fs", "os.chmod": "fs", "os.chown": "fs",
    "os.stat": "fs", "os.truncate": "fs", "os.link": "fs", "os.symlink": "fs",
    "os.getenv": "env", "os.putenv": "env", "os.unsetenv": "env",
    "os.urandom": "random",
    "time.time": "time", "time.sleep": "time", "time.monotonic": "time",
    "time.perf_counter": "time", "time.localtime": "time", "time.gmtime": "time",
    "time.process_time": "time",
    "datetime.now": "time", "datetime.today": "time", "datetime.utcnow": "time",
    "random.random": "random", "random.randint": "random", "random.choice": "random",
    "random.shuffle": "random", "random.uniform": "random", "random.seed": "random",
    "random.randrange": "random", "random.sample": "random", "random.getrandbits": "random",
    "secrets.token_bytes": "random", "secrets.token_hex": "random",
    "secrets.token_urlsafe": "random", "secrets.choice": "random",
    "secrets.randbelow": "random", "secrets.randbits": "random",
    "uuid.uuid1": "random", "uuid.uuid4": "random",
    # I/O-performing functions that previously hid inside PURE_MODULES.
    # Mapped to their real capability so the verdict is sound AND positively
    # identified rather than merely UNPROVABLE. See PURE_MODULES audit note.
    "pprint.pprint": "log", "pprint.pp": "log",   # write to stdout (a stream)
    "warnings.warn": "log",                          # writes to sys.stderr
    "codecs.open": "fs",                             # opens a file on disk
    # env via os.environ mapping object (the .get() method form; subscript form
    # os.environ['X'] is not a call and remains out of call-based analysis)
    "os.environ.get": "env", "os.environ.setdefault": "env",
    "os.environ.pop": "env",
    # pandas file readers (the module-level read_* functions perform fs I/O;
    # DataFrame .to_* writers are methods on an untyped frame -> UNPROVABLE)
    "pandas.read_csv": "fs", "pandas.read_parquet": "fs",
    "pandas.read_excel": "fs", "pandas.read_json": "fs", "pandas.read_table": "fs",
}

# Builtins that themselves confer a capability.
CAP_BY_BUILTIN: Dict[str, Tuple[str, str]] = {
    "open": ("fs", "open"),
    "print": ("log", "print"),
    "input": ("log", "input"),
}

# ----------------------------------------------------------------------
# THE AUDITABLE SINK MAPPING TABLE
# ----------------------------------------------------------------------
# Python call -> the Aether SINK NAME the existing detectors already know.
# Every value here must be a sink string that appears in
# `aether.passes.detector_specs.LITERAL_OR_WRAPPER_SPECS`; an unmapped
# string matches no row and would silently do nothing.
#
# WHY MATCHING BY METHOD NAME IS LEGITIMATE HERE, having been unsound for
# purity (see the PURE_METHODS note further down):
#   Clearing `obj.append()` as pure from the method NAME, with no proof of
#   the receiver's type, certified a capability-using module CLEAN — a
#   silent false negative, the contract-breach class (trap_04).
#   Treating `cursor.execute(...)` as a SQL sink from the method name,
#   with exactly the same absence of proof, can only produce a finding on
#   code that was not a sink — an over-flag.
#   One rule covers both: never assume clean from a name; freely assume
#   dangerous from a name. The asymmetry is not a double standard, it is
#   the direction of the error.

SINK_BY_QUALIFIED: Dict[str, str] = {
    "os.system": "shellExec", "os.popen": "shellExec",
    "pickle.loads": "deserialize", "pickle.load": "deserialize",
    "marshal.loads": "deserialize", "shelve.open": "deserialize",
    # Added after the bandit-oracle recall run (bench/pypi_scan/run_recall.py)
    # confirmed each of these as a MISS on real PyPI code. Only shapes the
    # oracle actually flagged were added - no speculative rows.
    "marshal.load": "deserialize",        # B302: .load, not just .loads
    "pickle.Unpickler": "deserialize",    # B301: the constructor form
    "xml.dom.pulldom.parse": "parseXml",      # B319
    "xml.dom.pulldom.parseString": "parseXml",
    "xml.sax.parse": "parseXml",              # B317
    "xml.sax.parseString": "parseXml",
    "xml.dom.expatbuilder.parse": "parseXml",         # B316
    "xml.dom.expatbuilder.parseString": "parseXml",
    "xml.etree.cElementTree.fromstring": "parseXml",  # B313
    "xml.etree.cElementTree.parse": "parseXml",
    "flask.render_template_string": "renderTemplate",
    "jinja2.Template": "renderTemplate",
    "django.template.Template": "renderTemplate",
    "flask.redirect": "redirect",
    "django.shortcuts.redirect": "redirect",
    "lxml.etree.fromstring": "parseXml", "lxml.etree.parse": "parseXml",
    "lxml.etree.XML": "parseXml",
    "xml.etree.ElementTree.fromstring": "parseXml",
    "xml.etree.ElementTree.parse": "parseXml",
    "xml.dom.minidom.parseString": "parseXml",
}

# ----------------------------------------------------------------------
# SINK GUARDS — when safety lives somewhere other than the judged argument
# ----------------------------------------------------------------------
# q5 settled that a NAME may not clear a call. A VALUE may not either.
# Each guard answers "is this call safe?", and the answer is accepted only
# when the value is positively identified as one of the sanctioned forms.
# Unrecognized, computed, unresolvable, or absent all mean SINK.
#
# The ad-hoc gates this replaces defaulted the unknown case to "safe" and
# produced three false accepts (BUGS.md BUG-004), one of them an RCE
# written literally at the call site: `yaml.load(raw, Loader=yaml.Loader)`
# was silent, because the old rule read "any Loader= means safe".

class Guard:
    """One sink's safety condition.

    sink_name     — the Aether sink this call becomes when the guard says
                    SINK. Lives here because the guarded callables are not
                    in SINK_BY_QUALIFIED — the guard owns them entirely.
    keyword       — the keyword argument that decides, or None for a
                    positional slot (`arg_index`).
    safe_values   — dotted spellings that make the call SAFE. Empty means
                    no value is sanctioned; presence alone never is.
    sink_values   — dotted spellings that make it a SINK. Used where the
                    absent case is safe (`shell=` absent means no shell).
    absent_is_sink— verdict when the keyword is not present at all.
    """
    def __init__(self, sink_name, keyword=None, arg_index=None,
                 safe_values=(), sink_values=(), absent_is_sink=True):
        self.sink_name = sink_name
        self.keyword = keyword
        self.arg_index = arg_index
        self.safe_values = frozenset(safe_values)
        self.sink_values = frozenset(sink_values)
        self.absent_is_sink = absent_is_sink


# Loader safety verified by EXECUTION on PyYAML 6.0.3 with the payload
# `!!python/object/apply:os.system [...]`:
#   yaml.Loader       -> CONSTRUCTED (unsafe)   yaml.UnsafeLoader -> CONSTRUCTED
#   yaml.FullLoader   -> refused                yaml.SafeLoader   -> refused
# FullLoader is deliberately NOT sanctioned: CVE-2020-1747 and
# CVE-2020-14343 are FullLoader bypasses. Over-flag direction.
_YAML_SAFE_LOADERS = ("yaml.SafeLoader", "yaml.CSafeLoader",
                      "yaml.BaseLoader", "yaml.CBaseLoader")

SINK_GUARDS: Dict[str, "Guard"] = {}
for _fn in ("yaml.load", "yaml.full_load", "yaml.unsafe_load"):
    # Absent Loader= is a sink (that is the classic yaml.load(x) RCE);
    # a SANCTIONED loader clears it; anything else does not.
    # `yaml.load(stream, Loader)`: the loader is also the second positional.
    SINK_GUARDS[_fn] = Guard("deserialize", keyword="Loader", arg_index=1,
                             safe_values=_YAML_SAFE_LOADERS,
                             absent_is_sink=True)
for _fn in ("subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen"):
    # No shell= means no shell — the argv form, which IS the documented
    # fix — so absence is SAFE here. But a shell= we cannot resolve to a
    # literal False is treated as a shell. `shell` is the ninth
    # positional of every one of these (they share Popen's signature).
    SINK_GUARDS[_fn] = Guard("shellExec", keyword="shell", arg_index=8,
                             safe_values=("False",), absent_is_sink=False)

# Method name on a receiver of unresolved type -> sink (over-flag direction).
SINK_BY_METHOD: Dict[str, str] = {
    "execute": "sqlQuery", "executemany": "sqlQuery",
    "executescript": "sqlExec", "raw": "sqlQuery",
    # SQLAlchemy's raw DB-API pass-through, and sqlmodel's `Session.exec`
    # (which takes a SQL expression, so a real one clears as `sqlBind`).
    # 22 of 31 `exec_driver_sql` sites in bench/framework_scan were
    # f-strings and every one was silent (BUG-012 survey).
    "exec_driver_sql": "sqlQuery", "exec": "sqlQuery",
}

# Builtins that are sinks.
SINK_BY_BUILTIN: Dict[str, str] = {"open": "readFile"}

# Python's sanctioned exits, mapped onto Aether's wrapper names so a fixed
# call site reads as clean instead of as an unknown call.
SANITIZER_BY_QUALIFIED: Dict[str, str] = {
    "shlex.quote": "shellArg", "pipes.quote": "shellArg",
    "yaml.safe_load": "schemaDecode",
    "json.loads": "schemaDecode", "json.load": "schemaDecode",
    "werkzeug.utils.secure_filename": "safeJoin",
    "flask.render_template": "trusted",
    "urllib.parse.quote": "trusted", "urllib.parse.quote_plus": "trusted",
    "html.escape": "trusted", "markupsafe.escape": "trusted",
}


# ----------------------------------------------------------------------
# SQL EXPRESSION BUILDERS — a query that is not a string (BUG-010)
# ----------------------------------------------------------------------
# `conn.execute(select(t).where(t.c.id == cid))` is the safest SQL in
# Python: SQLAlchemy compiles the expression with bound parameters, and no
# string is assembled anywhere. Two correct rules composed into refusing
# it anyway — `execute` is a sink by method name, and `_SQL_RULE` reads any
# non-literal argument as dynamic — at a rate of 1,029 findings across 15
# agent frameworks, 97% of everything reported (bench/framework_scan).
#
# A call rooted at one of these builders is named as the E0713 wrapper
# (`sqlBind`) so the untouched Aether rule clears it. Rooted means: walk
# `select(t).where(x).order_by(y)` down its receiver chain to `select(t)`.
# The root must resolve, through the file's imports, to one of these
# MODULES — a bare NAME spelled `select` from anywhere else clears
# nothing (q5).
_SQL_EXPR_ROOTS = frozenset({"sqlalchemy", "sqlmodel"})
_SQL_EXPR_BUILDERS = frozenset({"select", "insert", "update", "delete",
                                "text", "union", "union_all", "exists"})
# Where a RAW SQL STRING re-enters the expression language. These are the
# soundness line: `text("... " + uid)` is a real injection, nested inside
# a safe `select(...)` or not. Every such call anywhere in the expression
# must take a str literal as its first argument, or nothing is sanctioned.
# A name bound to a literal is NOT resolved here — over-flag direction.
_SQL_RAW_ENTRY = frozenset({"text", "literal_column", "column", "table"})
# The Table-object form: `table.delete().where(...)`, `t.select()`,
# `t.update().values(...)`. The receiver is a plain NAME, so no import can
# vouch for it — and q5 says a name clears nothing. What makes this form
# safe to accept is narrower than the name: the root call is accepted ONLY
# when it takes no positional argument at all. A homegrown builder that
# returns a raw string (`qb.select("SELECT " + x)`) has to be handed that
# string, so it can never match; `.values(...)` keywords are bound
# parameters. A receiver whose STATE is a raw string is outside any
# argument-shape rule, and is the recorded residual (q5).
_SQL_TABLE_METHODS = frozenset({"select", "insert", "update", "delete"})
# Methods that splice a raw string VERBATIM into the compiled SQL of an
# otherwise-parameterized expression: `select(t).prefix_with("/*+ " + h)`
# emits the string as written. They are `text()`'s siblings and get its
# discipline — every str argument must be a literal (or a literal-bound
# name), or the expression sanctions nothing. `with_hint(selectable,
# text)` carries its string in the SECOND positional slot.
_SQL_RAW_METHODS = frozenset({"prefix_with", "suffix_with", "with_hint",
                              "with_statement_hint", "op"})


class _FnScope:
    """Per-function facts the expression translator consults.

    Callable, so it stands wherever a plain `consts.get` resolver did:
    `_dotted_of` asks only for a name's single dotted binding. The two
    sets are what BUG-010's second measurement needed — names that hold a
    SQL expression (`stmt = select(t); stmt = stmt.where(...)`) and names
    bound only to a string literal (`text(sql_query)`).

    `local_names` is every name the function binds by ANY form
    (`_bindings_of`); a bare name not in it may be resolved through the
    module's imports, one in it may not — a local rebinding wins over
    an import, and an unresolvable local rebinding wins over both.
    `module_lits` maps a module-level name bound exactly once, to a str
    literal, nowhere else in the module, to that literal."""
    def __init__(self, consts: Dict[str, str], sql_names=(), lit_names=(),
                 local_names=(), module_lits: Optional[Dict[str, Tuple[str, int]]] = None):
        self.consts = consts
        self.sql_names = frozenset(sql_names)
        self.lit_names = frozenset(lit_names)
        self.local_names = frozenset(local_names)
        self.module_lits: Dict[str, Tuple[str, int]] = module_lits or {}
        self.depth = 0            # current `_expr` nesting (see _MAX_EXPR_DEPTH)
        self.too_deep = False     # set when the cap was hit in this scope

    def __call__(self, name: str) -> Optional[str]:
        return self.consts.get(name)


# ----------------------------------------------------------------------
# BINDING FORMS — every way a Python name acquires a value
# ----------------------------------------------------------------------
# The three per-function resolvers (`_local_constants`,
# `_safe_xml_parser_names`, `_sql_expression_names`) and the `Let` nodes
# the Aether safe-name pass reads all used to see ONE binding form: a
# single-Name `Assign`. Every other form — a parameter, `sql += uid`, a
# for-target, a tuple unpack, a walrus, an except-as, a `global` — was
# invisible, so a name whose only VISIBLE binding was a literal proved
# "literal-only" after it had been rebound to attacker input, and
# `if q is None: q = "SELECT 1"` made a caller-supplied query a constant
# (BUGS.md BUG-012). One walk, consumed by every resolver, so the
# discipline cannot drift again. A form whose value the translator can
# see yields it; every other form yields None, which every consumer
# reads as UNRESOLVED — the disqualifying case.

_PARAM_FIELDS = ("posonlyargs", "args", "kwonlyargs")
# Statement/expression fields that are binding SITES, not values.
_TARGET_FIELDS = frozenset({"target", "targets", "optional_vars"})
_PATTERN_BASE = getattr(_pyast, "pattern", ())


def _target_names(t: Any) -> List[str]:
    """Names bound by an assignment / for / with / comprehension target."""
    if isinstance(t, _pyast.Name):
        return [t.id]
    if isinstance(t, (_pyast.Tuple, _pyast.List)):
        return [n for e in t.elts for n in _target_names(e)]
    if isinstance(t, _pyast.Starred):
        return _target_names(t.value)
    return []      # Attribute / Subscript targets bind no local name


def _param_names(a: Any) -> List[str]:
    out = [x.arg for f in _PARAM_FIELDS for x in getattr(a, f, None) or []]
    for x in (a.vararg, a.kwarg):
        if x is not None:
            out.append(x.arg)
    return out


def _bindings_of(node: Any) -> List[Tuple[str, Any, int]]:
    """Every (name, value-or-None, line) binding inside `node`: its own
    parameters when it is a function, then every binding form in its
    body — nested functions and lambdas included, because their bodies
    are translated into the enclosing function and their names are its
    names. Over a Module it is every binding in the file, at any depth."""
    out: List[Tuple[str, Any, int]] = []
    if isinstance(node, (_pyast.FunctionDef, _pyast.AsyncFunctionDef, _pyast.Lambda)):
        out += [(n, None, getattr(node, "lineno", 0)) for n in _param_names(node.args)]
    for s in _pyast.walk(node):
        if s is node:
            continue
        ln = getattr(s, "lineno", 0)
        if isinstance(s, _pyast.Assign):
            for t in s.targets:
                if isinstance(t, _pyast.Name):
                    out.append((t.id, s.value, ln))
                else:
                    out += [(n, None, ln) for n in _target_names(t)]
        elif isinstance(s, _pyast.AnnAssign):
            if s.value is not None and isinstance(s.target, _pyast.Name):
                out.append((s.target.id, s.value, ln))
        elif isinstance(s, _pyast.AugAssign):
            out += [(n, None, ln) for n in _target_names(s.target)]
        elif isinstance(s, _pyast.NamedExpr):
            out.append((s.target.id, s.value, ln))
        elif isinstance(s, (_pyast.For, _pyast.AsyncFor, _pyast.comprehension)):
            out += [(n, None, ln) for n in _target_names(s.target)]
        elif isinstance(s, _pyast.withitem):
            if isinstance(s.optional_vars, _pyast.Name):
                out.append((s.optional_vars.id, s.context_expr, ln))
            else:
                out += [(n, None, ln) for n in _target_names(s.optional_vars)]
        elif isinstance(s, _pyast.ExceptHandler) and s.name:
            out.append((s.name, None, ln))
        elif isinstance(s, (_pyast.Global, _pyast.Nonlocal)):
            out += [(n, None, ln) for n in s.names]
        elif isinstance(s, (_pyast.FunctionDef, _pyast.AsyncFunctionDef)):
            out.append((s.name, None, ln))
            out += [(n, None, ln) for n in _param_names(s.args)]
        elif isinstance(s, _pyast.Lambda):
            out += [(n, None, ln) for n in _param_names(s.args)]
        elif isinstance(s, _pyast.ClassDef):
            out.append((s.name, None, ln))
        elif _PATTERN_BASE and isinstance(s, _PATTERN_BASE):
            for attr in ("name", "rest"):
                if getattr(s, attr, None):
                    out.append((getattr(s, attr), None, ln))
    return out


def _exprs_in(x: Any) -> Iterator[Any]:
    """Expression nodes directly held by `x` — descending through the
    helper nodes that are neither statements nor expressions
    (`arguments`, `keyword`, `withitem`, `match_case`, `comprehension`),
    never into a statement or a pattern, and never into a binding
    target field (those are names, not values)."""
    if isinstance(x, _pyast.expr):
        yield x
    elif isinstance(x, list):
        for e in x:
            yield from _exprs_in(e)
    elif isinstance(x, _pyast.AST) and not isinstance(x, _pyast.stmt) \
            and not (_PATTERN_BASE and isinstance(x, _PATTERN_BASE)):
        for field, child in _pyast.iter_fields(x):
            if field in _TARGET_FIELDS:
                continue
            yield from _exprs_in(child)


def _stmt_expr_children(stmt: Any) -> Iterator[Any]:
    """The value expressions a statement evaluates: `for`'s iterable,
    `if`/`while`'s test, `assert`'s operands, `raise`'s exception,
    `match`'s subject and guards, a nested `def`'s decorators and
    defaults, `del`'s operands. Bodies are statements and are visited on
    their own; targets are binding sites."""
    for field, child in _pyast.iter_fields(stmt):
        if field in _TARGET_FIELDS:
            continue
        yield from _exprs_in(child)


def _expr_children(node: Any) -> Iterator[Any]:
    """Expression children of an expression, through helper nodes."""
    for child in _pyast.iter_child_nodes(node):
        if isinstance(child, _pyast.expr):
            yield child
        elif not isinstance(child, _pyast.stmt):
            yield from _expr_children(child)


class _NameScope:
    """The resolver `_local_constants` uses while computing itself: it
    knows which names the function binds (so a Name bound locally is
    never resolved through an import) and resolves nothing else."""
    def __init__(self, local_names):
        self.local_names = frozenset(local_names)

    def __call__(self, name: str) -> Optional[str]:
        return None


def _scope_has_content(stripped: Any) -> bool:
    """A module or class body worth a scope of its own: it makes a call,
    or it binds a string literal that is not a docstring. The second
    half is E0723's: `API_KEY = "AKIA..."` at module level is THE
    hardcoded-credential shape, and before scopes existed it was never
    scanned at all. A docstring alone adds nothing."""
    for s in _pyast.walk(stripped):
        if isinstance(s, _pyast.Call):
            return True
        if isinstance(s, _pyast.Expr) and _const_str(s.value) is not None:
            continue                      # a docstring / bare string statement
        if isinstance(s, (_pyast.Assign, _pyast.AnnAssign)) \
                and any(_const_str(c) is not None for c in _pyast.walk(s.value or s)):
            return True
    return False


class _ScopeStripper(_pyast.NodeTransformer):
    """Remove every `def` / `class` from a (copied) tree, leaving the
    statements that run when the enclosing scope itself executes."""
    def visit_FunctionDef(self, node):
        return None
    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef


def _sql_builder_of(func: Any, imp: "_Imports") -> Optional[str]:
    """The builder's bare name if `func` resolves, via imports, into one of
    `_SQL_EXPR_ROOTS` (`sqlalchemy.select`, `sqlalchemy.sql.text`,
    `sa.delete` through an alias); else None."""
    dotted = _callee_spelling(func, imp)
    if not dotted or "." not in dotted:
        return None
    if _module_root(dotted) not in _SQL_EXPR_ROOTS:
        return None
    return dotted.rpartition(".")[2]


def _is_sql_expression(node: _pyast.Call, imp: "_Imports",
                       scope: Any = None, self_name: Optional[str] = None) -> bool:
    """True if `node` is a SQL expression that carries no raw SQL string
    anywhere inside it.

    Rooted means: walk `select(t).where(x).order_by(y)` down its receiver
    chain to the first call. That root is accepted if it resolves through
    imports to a builder, or is a method on a name already known to hold a
    SQL expression (`self_name` lets a rebinding `stmt = stmt.where(x)`
    refer to itself during the fixpoint), or is the argument-free Table
    form. Then every raw-string entry point inside the whole expression
    must take a str literal, or a name bound only to one."""
    sql_names = getattr(scope, "sql_names", frozenset())
    lit_names = getattr(scope, "lit_names", frozenset())
    root = node
    while isinstance(root.func, _pyast.Attribute) \
            and isinstance(root.func.value, _pyast.Call):
        root = root.func.value
    rf = root.func
    ok = _sql_builder_of(rf, imp) in _SQL_EXPR_BUILDERS
    if not ok and isinstance(rf, _pyast.Attribute) \
            and isinstance(rf.value, _pyast.Name):
        recv = rf.value.id
        if recv in sql_names or recv == self_name:
            ok = True
        elif rf.attr in _SQL_TABLE_METHODS and not root.args:
            ok = True
    if not ok:
        return False

    def _raw_ok(a: Any) -> bool:
        return _const_str(a) is not None \
            or (isinstance(a, _pyast.Name) and a.id in lit_names)

    for sub in _pyast.walk(node):
        if not isinstance(sub, _pyast.Call):
            continue
        if _sql_builder_of(sub.func, imp) in _SQL_RAW_ENTRY:
            if not _raw_ok(sub.args[0] if sub.args else None):
                return False
        elif isinstance(sub.func, _pyast.Attribute) \
                and sub.func.attr in _SQL_RAW_METHODS:
            strs = sub.args[1:] if sub.func.attr == "with_hint" else sub.args
            if not all(_raw_ok(a) for a in strs):
                return False
    return True


def _assign_bindings(fn_node: Any) -> Dict[str, List[Any]]:
    """name -> every value bound to it, by ANY binding form; None stands
    for a form whose value the translator cannot see (a parameter, an
    augmented assignment, a for-target ...) and disqualifies the name in
    every consumer."""
    out: Dict[str, List[Any]] = {}
    for name, value, _ln in _bindings_of(fn_node):
        out.setdefault(name, []).append(value)
    return out


def _is_none_const(v: Any) -> bool:
    return isinstance(v, _pyast.Constant) and v.value is None


def _sql_expression_names(fn_node: Any, imp: "_Imports",
                          module_lits: Optional[Dict[str, Tuple[str, int]]] = None
                          ) -> Tuple[Set[str], Set[str]]:
    """(names holding a SQL expression, names bound only to a str literal).

    The first is a least fixpoint that ALLOWS self-reference but REQUIRES
    an anchor: a name qualifies when at least one binding is a SQL
    expression with no reference to the name, and every binding is one
    when the name may refer to itself. So `stmt = select(t)` followed by
    `stmt = stmt.where(x)` qualifies, and a parameter-only chain
    (`a = b.where(); b = a.where()`) never does — there is no anchor, and
    a name still clears nothing. A binding that fails the raw-string check
    disqualifies the name outright, in every later round.

    A `stmt = None` sentinel before the real binding is ignored: executing
    None is a TypeError, not a query. Every other non-call binding —
    including the unresolved forms `_bindings_of` reports as None —
    still disqualifies. A module-level literal constant the function
    never rebinds counts as a literal-bound name."""
    binds = _assign_bindings(fn_node)
    lit = {n for n, vs in binds.items()
           if vs and all(_const_str(v) is not None for v in vs)}
    lit |= {n for n in (module_lits or {}) if n not in binds}
    binds = {n: [v for v in vs if not _is_none_const(v)]
             for n, vs in binds.items()}
    sql: Set[str] = set()
    changed = True
    while changed:
        changed = False
        scope = _FnScope({}, sql, lit)
        for n, vs in binds.items():
            if n in sql or not vs \
                    or not all(isinstance(v, _pyast.Call) for v in vs):
                continue
            anchored = any(_is_sql_expression(v, imp, scope) for v in vs)
            closed = all(_is_sql_expression(v, imp, scope, self_name=n) for v in vs)
            if anchored and closed:
                sql.add(n)
                changed = True
    return sql, lit


# Builtins that DEFEAT sound static analysis -> always UNPROVABLE.
DYNAMIC_BUILTINS: Dict[str, str] = {
    "eval": "eval", "exec": "exec", "compile": "compile",
    "__import__": "dynamic_import",
    "globals": "reflection", "locals": "reflection", "vars": "reflection",
}
# getattr/setattr/delattr are dynamic ONLY when the attribute name is not a
# constant; handled specially in the visitor.
DYNAMIC_ATTR_BUILTINS = {"getattr", "setattr", "delattr"}

# Imports that are pure (CPU only, no capability) -> resolvable, no effect.
#
# SOUNDNESS AUDIT (P0.1): every entry below must perform NO I/O at module or
# call scope. Three former entries were removed because they CAN do I/O and
# were therefore unsound to trust wholesale:
#   * pprint   -> pprint.pprint/pp write to stdout  (now CAP_BY_QUALIFIED: log)
#   * warnings -> warnings.warn writes to stderr     (now CAP_BY_QUALIFIED: log)
#   * codecs   -> codecs.open opens a file           (now CAP_BY_QUALIFIED: fs)
# A bogus "dataclass" entry (not a real stdlib module; the module is
# "dataclasses") was also removed. Any *other* call into these modules now
# degrades to UNPROVABLE rather than being silently cleared.
#
# PURE_MODULE_CITATIONS gives the per-module justification (machine-readable
# provenance, surfaced via mapping_table()/the /pymap audit endpoint).
PURE_MODULE_CITATIONS: Dict[str, str] = {
    "math": "CPython Lib/math: pure C math, no I/O",
    "cmath": "complex math, no I/O",
    "json": "encode/decode in memory; file I/O happens on a caller-supplied fp (its own open() is gated)",
    "re": "regex compile/match over in-memory strings",
    "collections": "container datatypes, in-memory only",
    "itertools": "iterator algebra, in-memory only",
    "functools": "higher-order helpers (reduce/lru_cache), no I/O",
    "dataclasses": "class codegen at def time, no I/O",
    "typing": "type hints, erased at runtime, no I/O",
    "string": "string constants/templates/Formatter, no I/O",
    "decimal": "fixed-point arithmetic, no I/O",
    "fractions": "rational arithmetic, no I/O",
    "statistics": "numeric reductions over in-memory data",
    "operator": "operator functions, no I/O",
    "copy": "shallow/deep object copy, no I/O",
    "enum": "enumeration types, no I/O",
    "abc": "abstract base class machinery, no I/O",
    "numbers": "numeric tower ABCs, no I/O",
    "heapq": "heap algorithms over in-memory lists",
    "bisect": "binary search over in-memory sequences",
    "array": "typed array container; fromfile/tofile are object METHODS (UNPROVABLE), not module calls",
    "textwrap": "string wrapping/filling, no I/O",
    "base64": "byte<->ascii transforms in memory",
    "binascii": "binary/ascii conversions in memory",
    "hashlib": "cryptographic digests over in-memory bytes",
    "hmac": "keyed-hash MAC over in-memory bytes",
    "struct": "binary packing/unpacking in memory",
    "unicodedata": "Unicode database lookups, no I/O",
    "html": "HTML escaping/parsing of in-memory strings",
    "difflib": "sequence diffing in memory",
    "keyword": "Python keyword predicates, no I/O",
    "token": "tokenizer constants, no I/O",
    "graphlib": "topological sort over in-memory graph",
    "types": "dynamic type construction helpers, no I/O",
    "contextlib": "context-manager utilities; do not themselves perform I/O",
    "weakref": "weak references, no I/O",
}
PURE_MODULES: Set[str] = set(PURE_MODULE_CITATIONS)

# Pure builtins -> resolvable, no capability.
PURE_BUILTINS: Set[str] = {
    "len", "range", "str", "int", "float", "bool", "complex", "list", "dict",
    "set", "frozenset", "tuple", "bytes", "bytearray", "memoryview",
    "enumerate", "zip", "map", "filter", "sorted", "reversed", "sum", "min",
    "max", "abs", "round", "isinstance", "issubclass", "hasattr", "repr",
    "format", "ord", "chr", "hex", "oct", "bin", "divmod", "pow", "all",
    "any", "iter", "next", "type", "id", "hash", "callable", "slice",
    "object", "super", "property", "staticmethod", "classmethod", "ascii",
}

# NOTE (P0.2): the former PURE_METHODS allowlist (pragmatic mode) was DELETED.
# It cleared an unknown object's method call (e.g. `.append()`) as pure based on
# the method NAME alone, with no proof of the receiver's type. That is unsound:
# trap_04's `AuditLog.append()` opens a file and writes to disk, yet was being
# certified PROVEN_CLEAN. A method on an object of unresolved type is now ALWAYS
# UNPROVABLE. Soundness is the product; this allowlist is never coming back.


def _module_root(dotted: str) -> str:
    return dotted.split(".", 1)[0]


class _Imports:
    """Resolves a local name used in a Call back to a dotted module path or
    builtin, using the file's import statements."""
    def __init__(self):
        self.alias_to_path: Dict[str, str] = {}    # local name -> dotted path
        self.fromimport: Dict[str, str] = {}       # local name -> module.attr
        # A local name bound by two imports to DIFFERENT targets
        # (`try: import ujson as json` / `except: import json`) resolves to
        # nothing: a sink reached through it is missed exactly as it was
        # before imports were collected from the whole module, and a
        # builder or sanitizer reached through it clears nothing. Never
        # pick a winner — the direction of that error is a false accept.
        self.ambiguous: Set[str] = set()

    def _bind(self, table: Dict[str, str], local: str, target: str):
        prev = table.get(local)
        other = (self.fromimport if table is self.alias_to_path
                 else self.alias_to_path).get(local)
        if (prev is not None and prev != target) or other is not None:
            self.ambiguous.add(local)
        table[local] = target

    def add_import(self, node: _pyast.Import):
        for a in node.names:
            self._bind(self.alias_to_path, a.asname or _module_root(a.name), a.name)

    def add_importfrom(self, node: _pyast.ImportFrom):
        mod = node.module or ""
        for a in node.names:
            self._bind(self.fromimport, a.asname or a.name,
                       (mod + "." + a.name) if mod else a.name)

    def resolve_attr(self, value_name: str, attr: str) -> Optional[str]:
        """`value_name.attr` -> dotted path using import aliases."""
        if value_name in self.ambiguous:
            return None
        base = self.alias_to_path.get(value_name)
        if base is not None:
            return base + "." + attr
        if value_name in self.fromimport:        # from x import y; y.attr
            return self.fromimport[value_name] + "." + attr
        return None

    def resolve_name(self, name: str) -> Optional[str]:
        """bare `name(...)` -> dotted path if it came from a `from` import."""
        if name in self.ambiguous:
            return None
        return self.fromimport.get(name)


def _const_str(node: Any) -> Optional[str]:
    if isinstance(node, _pyast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# ----------------------------------------------------------------------
# EXPRESSION TRANSLATION
# ----------------------------------------------------------------------
# The detectors in `aether.passes.detector_specs` judge argument SHAPES:
# a fixed StringLit passes, a `+` concatenation is refused, a sanctioned
# wrapper call passes, an unknown expression is refused. Translating
# Python expressions into exactly those shapes is what lets the untouched
# Aether detectors run on Python.
#
# Anything not modeled becomes `PyExpr`, a kind no rule knows. `_arg_reason`
# falls through to `rule.default` for it — REFUSED, not cleared. That is the
# same direction as the UNPROVABLE discipline above: never assume clean.

def _pos(node: Any, fallback: int = 0) -> Dict[str, int]:
    return {"line": getattr(node, "lineno", fallback),
            "column": getattr(node, "col_offset", 0) + 1}


def _concat(parts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Left-nested `+` tree over `parts` (>=1)."""
    out = parts[0]
    for p in parts[1:]:
        out = {"kind": "BinOp", "op": "+", "left": out, "right": p}
    return out


# Deepest expression the translator will nest. The detectors walk the IR
# recursively (two frames per level), so an expression the frontend CAN
# translate can still overflow a detector; capping here makes the limit
# the frontend's, deterministic, and reported — a scope that hits it gets
# an `unprovable` `too_deep` region and keeps every other finding.
_MAX_EXPR_DEPTH = 200


def _expr(node: Any, imp: "_Imports",
          safe_xml: Optional[Set[str]] = None,
          resolver: Optional[Any] = None) -> Dict[str, Any]:
    """One Python expression -> one Aether expression node. Total: always
    returns a dict, never None. Depth-capped through the scope's counter
    (see `_MAX_EXPR_DEPTH`); without a scope there is nothing to count."""
    if resolver is None or not hasattr(resolver, "depth"):
        return _expr_inner(node, imp, safe_xml, resolver)
    resolver.depth += 1
    try:
        if resolver.depth > _MAX_EXPR_DEPTH:
            resolver.too_deep = True
            return {"kind": "PyExpr", "py": "TooDeep"}
        return _expr_inner(node, imp, safe_xml, resolver)
    finally:
        resolver.depth -= 1


def _expr_inner(node: Any, imp: "_Imports",
                safe_xml: Optional[Set[str]] = None,
                resolver: Optional[Any] = None) -> Dict[str, Any]:
    if isinstance(node, _pyast.Constant):
        if isinstance(node.value, str):
            # `pos` is load-bearing: E0723 anchors on the literal itself,
            # and a finding with no line is useless to a fix-loop.
            return {"kind": "StringLit", "value": node.value, "pos": _pos(node)}
        return {"kind": "PyExpr", "py": "Constant"}
    if isinstance(node, _pyast.Name):
        # A module-level constant bound exactly once, to a str literal,
        # and never rebound anywhere in the module IS that literal at
        # every read site (`conn.execute(_CREATE_TABLE)`). Inlined rather
        # than re-bound per function so the safe-name pass needs no
        # extra rule; `synthetic` tells E0723 the literal is not written
        # at this position (it is reported once, at its definition).
        lits = getattr(resolver, "module_lits", None)
        if lits and node.id in lits \
                and node.id not in getattr(resolver, "local_names", ()):
            return {"kind": "StringLit", "value": lits[node.id][0],
                    "pos": _pos(node), "synthetic": True}
        return {"kind": "Ident", "name": node.id}
    if isinstance(node, _pyast.Await):
        # `await conn.execute(q)` IS the call — 603 sink calls in
        # bench/framework_scan sat behind an await and were invisible
        # because Await translated to an opaque leaf (BUG-012).
        return _expr(node.value, imp, safe_xml, resolver)
    if isinstance(node, (_pyast.Yield, _pyast.YieldFrom)):
        if node.value is None:
            return {"kind": "PyExpr", "py": "Yield"}
        return _expr(node.value, imp, safe_xml, resolver)
    if isinstance(node, _pyast.NamedExpr):
        # The binding is emitted as a `Let` by the statement walk
        # (`_FnVisitor._walrus_lets`), which carries the value once.
        return {"kind": "PyExpr", "py": "NamedExpr"}
    if isinstance(node, _pyast.BinOp):
        # `a + b` is concatenation; `"fmt" % x` builds a dynamic string and
        # is the same hazard, so it gets the same shape.
        if isinstance(node.op, _pyast.Add):
            return {"kind": "BinOp", "op": "+",
                    "left": _expr(node.left, imp, safe_xml, resolver), "right": _expr(node.right, imp, safe_xml, resolver)}
        if isinstance(node.op, _pyast.Mod) and _const_str(node.left) is not None:
            return _concat([_expr(node.left, imp, safe_xml, resolver), _expr(node.right, imp, safe_xml, resolver)])
        return {"kind": "PyExpr", "py": "BinOp"}
    if isinstance(node, _pyast.JoinedStr):
        # f-string. With >=1 FormattedValue it is a dynamic string — the
        # dominant modern injection shape — so it reaches the rules as a
        # concatenation. With none it is just a literal.
        parts: List[Dict[str, Any]] = []
        dynamic = False
        for v in node.values:
            if isinstance(v, _pyast.FormattedValue):
                dynamic = True
                parts.append(_expr(v.value, imp, safe_xml, resolver))
            elif isinstance(v, _pyast.Constant) and isinstance(v.value, str):
                parts.append({"kind": "StringLit", "value": v.value})
            else:
                dynamic = True
                parts.append({"kind": "PyExpr", "py": "FormattedValue"})
        if not parts:
            return {"kind": "StringLit", "value": ""}
        if not dynamic:
            return {"kind": "StringLit",
                    "value": "".join(p.get("value", "") for p in parts)}
        return _concat(parts)
    if isinstance(node, _pyast.Call):
        return _call_expr(node, imp, safe_xml, resolver)
    if isinstance(node, _pyast.Attribute):
        # `subprocess.run(...).returncode`, `requests.get(u).text` — an
        # attribute READ of a call result. Not a call itself, so it used
        # to translate to a bare PyExpr and the call inside it vanished:
        # the bench's `run_shell_bound_elsewhere` went silent while the
        # same shape without `.returncode` was flagged. `walk` descends
        # dict values, so carrying the base is enough to find it again.
        return {"kind": "PyExpr", "py": "Attribute",
                "base": _expr(node.value, imp, safe_xml, resolver)}
    # Every other expression is opaque to the rules (`PyExpr` matches no
    # row, so an argument of this shape is REFUSED) — but its CHILDREN are
    # translated and carried, so a sink call inside `x or []`, `a == b`,
    # `not f()`, `c if t else e`, `f()[0]`, a list/dict/tuple display, a
    # lambda body or a comprehension is still found by `walk`. Parking
    # them under `parts` is enough: `_arg_reason` reads only `args[i]`,
    # so a carried call can never be mistaken for a wrapper argument.
    out: Dict[str, Any] = {"kind": "PyExpr", "py": type(node).__name__}
    parts = [_expr(c, imp, safe_xml, resolver) for c in _expr_children(node)]
    if parts:
        out["parts"] = parts
    return out


def _dotted_of(node: Any, imp: "_Imports",
               resolver: Optional[Any] = None) -> Optional[str]:
    """The dotted spelling of a VALUE expression, or None if it cannot be
    positively identified. `resolver` maps a local name to the single
    value bound to it; without one, a bare Name is unresolved — which,
    per the guard contract, means unsafe."""
    if isinstance(node, _pyast.Constant):
        return repr(node.value) if node.value is None else str(node.value)
    if isinstance(node, _pyast.Attribute) and isinstance(node.value, _pyast.Name):
        return imp.resolve_attr(node.value.id, node.attr) or \
            (node.value.id + "." + node.attr)
    if isinstance(node, _pyast.Name):
        if resolver is not None:
            d = resolver(node.id)
            if d is not None:
                return d
            if node.id in getattr(resolver, "local_names", ()):
                return None          # bound locally, not to one known value
        # `from yaml import SafeLoader` then `Loader=SafeLoader`: the same
        # import table the sink resolver trusts; a name two imports bind
        # differently is ambiguous there and resolves to nothing.
        return imp.resolve_name(node.id)
    return None


def _local_constants(fn_node: Any, imp: "_Imports") -> Dict[str, str]:
    """local name -> the single dotted value bound to it in this function.

    A name bound more than once to DIFFERENT values is omitted, and so is
    one whose value could not be identified: ambiguity must over-flag,
    never resolve. This only ever feeds `safe_values`, and a WRONG
    resolution to a safe value IS a false accept — which is the whole of
    BUG-004 — so the bar is a single unique binding, or nothing.

    Straight-line: no control flow is modeled, so a name assigned in one
    branch and read in another counts as one binding. That direction is
    safe here precisely because disagreement, not agreement, is what
    disqualifies a name. Every binding form counts (`_bindings_of`): a
    parameter, a for-target or a `+=` is a binding to an unknown value,
    so `if loader is None: loader = yaml.SafeLoader` no longer proves a
    caller-supplied loader safe (BUG-012)."""
    binds = _bindings_of(fn_node)
    names = _NameScope(n for n, _v, _l in binds)
    seen: Dict[str, Set[str]] = {}
    for name, value, _ln in binds:
        val = _dotted_of(value, imp, names) if value is not None else None
        seen.setdefault(name, set()).add(val if val is not None
                                         else "<unresolved>")
    return {n: next(iter(vs)) for n, vs in seen.items()
            if len(vs) == 1 and "<unresolved>" not in vs}


def _guard_verdict(call: _pyast.Call, guard: "Guard", imp: "_Imports",
                   resolver: Optional[Any] = None) -> bool:
    """True if this call IS a sink under `guard`."""
    node = None
    # A `**kwargs` splat (or a `*args` splat that could reach the
    # positional slot) may carry the deciding keyword and cannot be
    # resolved; the guard contract says unresolvable means SINK, so
    # `subprocess.run(cmd, **opts)` is no longer read as "shell absent".
    splat = any(kw.arg is None for kw in call.keywords or []) or (
        guard.arg_index is not None
        and any(isinstance(a, _pyast.Starred) for a in call.args))
    for kw in call.keywords or []:
        if kw.arg == guard.keyword:
            node = kw.value
            break
    if node is None and guard.arg_index is not None \
            and len(call.args) > guard.arg_index:
        node = call.args[guard.arg_index]
    if node is None:
        return True if splat else guard.absent_is_sink
    dotted = _dotted_of(node, imp, resolver)
    if dotted is None:
        return True                      # unresolved -> sink, never safe
    if dotted in guard.safe_values:
        return False
    if guard.sink_values:
        return dotted in guard.sink_values
    return True                          # not positively sanctioned -> sink


# XML parser constructors whose keyword arguments carry the XXE guard.
_XML_PARSER_CTORS = {"lxml.etree.XMLParser", "xml.sax.make_parser"}


def _safe_xml_parser_names(fn_node: Any, imp: "_Imports") -> Set[str]:
    """Names bound to an XML parser constructed with entity resolution
    OFF. Passing one of these disarms the XXE sink.

    This is the GUARD-BOUND-ELSEWHERE class: in `lxml_repro.py` the
    vulnerable and safe call sites are byte-identical
    (`etree.fromstring(raw, parser)`) and the safety lives in a DIFFERENT
    statement, in a keyword of the parser. E0727 inspects argument 0, so
    no argument-shape rule can ever see it — resolving it is the
    frontend's job, because the frontend is where the Python-specific
    knowledge belongs.

    Conservative: a name is safe only when EVERY binding to it in this
    function is an explicit `resolve_entities=False`. Rebound, computed,
    keyword absent, or constructor unknown — not safe.

    This is the parser-shaped instance of `_local_constants`' discipline:
    resolve a local name only when every binding agrees, and treat
    disagreement as unsafe. Kept separate because the value being
    resolved is a keyword INSIDE the bound call rather than the bound
    value itself; merging them would change what each one accepts, and a
    tidier guard that accepts more is a worse guard."""
    bound: Dict[str, List[bool]] = {}
    for name, value, _ln in _bindings_of(fn_node):
        # EVERY binding of the name is recorded — a rebinding to anything
        # but a hardened constructor is False and disqualifies it. The
        # old loop skipped non-constructor bindings, so `parser = make()`
        # after the safe constructor still disarmed the sink (BUG-012).
        off = False
        if isinstance(value, _pyast.Call) \
                and _callee_spelling(value.func, imp) in _XML_PARSER_CTORS:
            off = any(kw.arg == "resolve_entities"
                      and isinstance(kw.value, _pyast.Constant)
                      and kw.value.value is False
                      for kw in value.keywords or [])
        bound.setdefault(name, []).append(off)
    return {n for n, flags in bound.items() if flags and all(flags)}


def _sink_name(call: _pyast.Call, imp: "_Imports",
               safe_xml: Optional[Set[str]] = None,
               resolver: Optional[Any] = None) -> Optional[str]:
    """The Aether sink name for this Python call, or None."""
    dotted = _callee_spelling(call.func, imp, resolver)
    if dotted is None:
        return None
    guard = SINK_GUARDS.get(dotted)
    if guard is not None:
        return guard.sink_name if _guard_verdict(call, guard, imp, resolver) \
            else None
    sink = SINK_BY_QUALIFIED.get(dotted)
    if sink == "parseXml":
        for a in call.args[1:]:
            if isinstance(a, _pyast.Name) and a.id in (safe_xml or set()):
                return None      # entity resolution explicitly disabled
        return sink
    if sink is not None:
        return sink
    if dotted in SINK_BY_BUILTIN:
        return SINK_BY_BUILTIN[dotted]
    # Method on an unresolved receiver: over-flag by name (see doctrine note).
    #
    # No parameterized-query special case. `cur.execute("... id = ?", params)`
    # is ALREADY clean because argument 0 is a StringLit and `_SQL_RULE` has
    # no literal_bans — the rule clears it without help. The recognizer that
    # used to live here cleared ANY two-argument execute, so
    # `cur.execute("SELECT ... " + name, extra)` went silent: params do not
    # launder a concatenated query. BUGS.md BUG-004.
    attr = _method_name(call.func, resolver)
    if attr is not None:
        return SINK_BY_METHOD.get(attr)
    return None


def _method_name(func: Any, resolver: Optional[Any] = None) -> Optional[str]:
    """The method a call spells, for the by-name sink rule: `x.execute`,
    `getattr(x, "execute")` with a literal attribute, or a bare name the
    function bound once to a bound method (`ex = cur.execute; ex(q)`).
    Lookups can only ADD a finding, so a wrong resolution over-flags."""
    if isinstance(func, _pyast.Attribute):
        return func.attr
    if isinstance(func, _pyast.Call) and isinstance(func.func, _pyast.Name) \
            and func.func.id == "getattr" and len(func.args) >= 2 \
            and _const_str(func.args[1]) is not None:
        return _const_str(func.args[1])
    if isinstance(func, _pyast.Name) and resolver is not None:
        d = resolver(func.id)
        if d and "." in d:
            return d.rpartition(".")[2]
    return None


def _call_expr(node: _pyast.Call, imp: "_Imports",
               safe_xml: Optional[Set[str]] = None,
               resolver: Optional[Any] = None) -> Dict[str, Any]:
    """A Python call as an Aether Call node, named so the existing
    detectors recognize it: the Aether SINK name when it maps to one, the
    Aether WRAPPER name when it is a sanctioned exit, otherwise its Python
    spelling under a `py:` prefix (which matches neither, so an argument
    that is one of these calls is refused — the flag-more direction).

    The prefix is load-bearing. Without it the raw Python spelling shares
    a namespace with Aether's sink names, and any method that happens to
    be spelled like one becomes a sink WITHOUT passing through the
    mapping table: `self.redirect(uri)` fired E0718 and
    `self.renderTemplate(x)` fired E0719 on that collision alone. Found
    by the PyPI scan (`bench/pypi_scan/`), where it accounted for most of
    tornado's and websockets' E0718 hits. It over-flags rather than
    misses, so it is not a soundness bug — but an unmapped, unaudited
    sink is invisible to `mapping_table()`, which is exactly what the
    auditable-surface design exists to prevent."""
    dotted = _callee_spelling(node.func, imp, resolver)
    name = (_sink_name(node, imp, safe_xml, resolver)
            or SANITIZER_BY_QUALIFIED.get(dotted or "")
            # A SQLAlchemy expression is a parameterized query by
            # construction; naming it as E0713's wrapper is the same move
            # SANITIZER_BY_QUALIFIED makes for `shlex.quote` (BUG-010).
            or ("sqlBind" if _is_sql_expression(node, imp, resolver) else None)
            or ("py:" + dotted if dotted else "<expr>"))
    args = list(node.args)
    kws = list(node.keywords or [])
    if not args and kws:
        # A sink fed keyword-only — `yaml.load(stream=raw)`,
        # `cur.execute(query=q)`, `subprocess.run(args=cmd, shell=True)` —
        # has nothing in the positional slot the rules judge, so it was
        # silent. The keyword values take the positional slots, in
        # order. Flag-more: whatever lands in `args[0]` is refused unless
        # it is a literal or a sanctioned wrapper (BUG-012).
        args = [kw.value for kw in kws]
        kws = []
    out: Dict[str, Any] = {"kind": "Call",
                           "func": {"kind": "Ident", "name": name},
                           "args": [_expr(a, imp, safe_xml, resolver) for a in args],
                           "pos": _pos(node)}
    # Keyword values are carried too, so `f(k=cur.execute(q))` is found by
    # `walk`; `_arg_reason` reads only `args[i]`, so nothing here is ever
    # judged as the sink's own argument (BUG-012).
    kw_vals = [_expr(kw.value, imp, safe_xml, resolver) for kw in kws]
    if kw_vals:
        out["kwargs"] = kw_vals
    # A call used as a RECEIVER is still a call: `open(p).read()`,
    # `conn.cursor().execute(sql)`, `requests.get(u).json()`. Chaining is
    # idiomatic Python, and dropping the receiver loses the sink entirely
    # (measured: `return open(base + name).read()` reported nothing).
    # `walk` descends dict values, so parking it under a key is enough for
    # every detector to find it; `_arg_reason` only ever reads `args[i]`,
    # so it cannot mistake a receiver for an argument.
    if isinstance(node.func, _pyast.Attribute) and \
            isinstance(node.func.value, _pyast.Call):
        out["recv"] = _call_expr(node.func.value, imp, safe_xml, resolver)
    return out


def _callee_spelling(func: Any, imp: "_Imports",
                     resolver: Optional[Any] = None) -> Optional[str]:
    """Dotted path for a call target, using the file's imports; falls back
    to the bare attribute/name as written. With a `resolver`, a bare name
    the function bound once to a dotted value (`run = subprocess.run`)
    spells that value; `getattr(obj, "m")(...)` with a literal attribute
    spells `obj.m`."""
    if isinstance(func, _pyast.Name):
        d = imp.resolve_name(func.id)
        if d is None and resolver is not None:
            d = resolver(func.id)
        return d or func.id
    if isinstance(func, _pyast.Call) and isinstance(func.func, _pyast.Name) \
            and func.func.id == "getattr" and len(func.args) >= 2 \
            and _const_str(func.args[1]) is not None:
        return _callee_spelling(
            _pyast.Attribute(value=func.args[0], attr=_const_str(func.args[1]),
                             ctx=_pyast.Load()), imp, resolver)
    if isinstance(func, _pyast.Attribute):
        if isinstance(func.value, _pyast.Name):
            return imp.resolve_attr(func.value.id, func.attr) or func.attr
        if isinstance(func.value, _pyast.Attribute):
            # Chained module path: `import xml.sax` + `xml.sax.parseString(...)`
            # arrives as Attribute(Attribute(Name)). Resolving only one level
            # returned the bare method name, so the dotted entry never
            # matched — `xml.sax.parseString` was a confirmed MISS in the
            # bandit-oracle run while the `from xml.dom import minidom` form
            # of the same sink matched fine. Mirrors _FnVisitor._flatten_attr,
            # which the capability side has always done.
            parts, cur = [], func
            while isinstance(cur, _pyast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, _pyast.Name):
                base = imp.alias_to_path.get(cur.id, cur.id)
                # `import xml.sax` binds the ROOT name: alias_to_path["xml"]
                # is "xml.sax". Substituting there would yield
                # "xml.sax.sax.parseString". Substitute only for a real
                # rename (`import numpy as np`), where the bound name is not
                # the path's own root.
                if _module_root(base) == cur.id:
                    base = cur.id
                parts.append(base)
                return ".".join(reversed(parts))
        return func.attr
    return None


def _classify_dotted(dotted: str) -> Optional[Tuple[str, str]]:
    """Return (capability, verb) for a dotted call path, or None if not a
    known capability. Checks exact qualified entry, then module root, then
    os.exec* prefix."""
    if dotted in CAP_BY_QUALIFIED:
        return (CAP_BY_QUALIFIED[dotted], dotted.split(".")[-1])
    root = _module_root(dotted)
    if root in CAP_BY_MODULE:
        return (CAP_BY_MODULE[root], dotted.split(".")[-1])
    if dotted.startswith("os.exec") or dotted.startswith("os.spawn"):
        return ("process", dotted.split(".")[-1])
    return None


class _FnVisitor:
    """Walk one function body and emit (effects, local_calls, unprovable)."""
    def __init__(self, imports: _Imports, local_fns: Set[str], fn_name: str,
                 fn_line: int, safe_xml: Optional[Set[str]] = None,
                 consts: Optional[Dict[str, str]] = None,
                 sql_names: Optional[Set[str]] = None,
                 lit_names: Optional[Set[str]] = None,
                 local_names: Optional[Set[str]] = None,
                 module_lits: Optional[Dict[str, Tuple[str, int]]] = None):
        self.imp = imports
        # Names bound to an XML parser with entity resolution disabled —
        # the guard lives in a different statement than the parse call.
        self.safe_xml: Set[str] = safe_xml or set()
        # local name -> the single dotted value bound to it (Task 2).
        # Empty here means every bare Name is unresolved, which the guard
        # contract reads as SINK — the sound default.
        self.consts: Dict[str, str] = consts or {}
        # What the expression translator resolves against. Empty sets mean
        # no name holds a SQL expression or a literal — the sound default.
        self.scope = _FnScope(self.consts, sql_names or (), lit_names or (),
                              local_names or (), module_lits)
        self.local_fns = local_fns
        self.fn_name = fn_name
        self.fn_line = fn_line
        self.effects: List[Dict[str, Any]] = []
        self.local_calls: List[str] = []
        self.stmts: List[Dict[str, Any]] = []
        self.unprovable: List[Dict[str, Any]] = []
        self._eff_seen: Set[Tuple[str, str, Optional[str]]] = set()
        self._unp_seen: Set[str] = set()

    def _add_effect(self, cap: str, verb: str, arg: Optional[str]):
        key = (cap, verb, arg)
        if key in self._eff_seen:
            return
        self._eff_seen.add(key)
        eff: Dict[str, Any] = {"path": [cap, verb]}
        if arg is not None:
            eff["arg"] = {"kind": "StringLit", "value": arg}
        self.effects.append(eff)

    def _add_unprovable(self, reason: str, construct: str, detail: str,
                        line: int):
        key = reason + ":" + construct
        if key in self._unp_seen:
            return
        self._unp_seen.add(key)
        self.unprovable.append({
            "fn": self.fn_name, "line": self.fn_line, "granularity": "function",
            "callee": construct, "reason": reason, "detail": detail,
            "construct_line": line, "needs": "human review or a runtime check",
        })

    def _e(self, node: Any) -> Dict[str, Any]:
        return _expr(node, self.imp, self.safe_xml, self.scope)

    def seed_bindings(self, fn_node: Any):
        """One unresolved binding per name bound by a form whose value the
        translator cannot see — a parameter, `x += ...`, a for-target, a
        tuple unpack, an except-as, a `global` — emitted as an `Assign`
        (the kind the safe-name pass reads alongside `Let`) whose value
        is an opaque `PyExpr`. A name with such a binding can never prove
        literal-only, whatever else it is bound to (BUG-012)."""
        seen: Set[str] = set()
        for name, value, line in _bindings_of(fn_node):
            if value is None and name not in seen:
                seen.add(name)
                self.stmts.append({"kind": "Assign", "name": name,
                                   "value": {"kind": "PyExpr", "py": "Binding"},
                                   "pos": {"line": line, "column": 1}})

    def _walrus_lets(self, expr: Any):
        """`(q := build())` binds a name inside an expression; the binding
        is a `Let` carrying the value ONCE — `_expr` translates the
        NamedExpr itself to an opaque leaf."""
        for sub in _pyast.walk(expr):
            if isinstance(sub, _pyast.NamedExpr):
                self.stmts.append({"kind": "Let", "name": sub.target.id,
                                   "value": self._e(sub.value),
                                   "pos": _pos(sub, self.fn_line)})

    def visit_stmt(self, stmt: Any):
        """Translate ONE statement into what the detectors read: `Let`
        nodes for the bindings the safe-name pass consumes, and every
        value expression the statement evaluates, in place.

        Total over statement kinds. The old walk translated four
        (`Assign`, `Expr(Call)`, `Return`, `With`) and dropped the rest,
        so a sink in a `for` iterable, an `if` test, a `yield`, an
        `assert`, a tuple-target assignment, an augmented assignment or
        a decorator was never seen — 89 sink calls on the framework
        corpus, plus 603 behind `await` (BUG-012). Control flow is still
        not modeled, exactly as in the Aether passes themselves; what
        changed is that no POSITION hides a value."""
        if isinstance(stmt, (_pyast.Assign, _pyast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, _pyast.Assign) else [stmt.target]
            if stmt.value is None:          # a bare annotation binds nothing
                return
            if _is_none_const(stmt.value):
                # `stmt = None` before `stmt = select(...)`: a None can
                # never reach a sink as a query, path or command
                # (executing it is a TypeError), so it is not a binding
                # the safe-name pass needs to see. Every other constant
                # kind still binds an opaque value.
                return
            self._walrus_lets(stmt.value)
            val = self._e(stmt.value)
            carried = False
            for t in targets:
                if isinstance(t, _pyast.Name):
                    # `a = b = f()`: the value travels with the first name;
                    # later names get an opaque binding (never a cleared one).
                    self.stmts.append({"kind": "Let", "name": t.id,
                                       "value": val if not carried
                                       else {"kind": "PyExpr", "py": "Assign"},
                                       "pos": _pos(stmt, self.fn_line)})
                    carried = True
                else:
                    # `self.x = ...`, `out[k] = ...`, `a, b = ...`: no local
                    # name proves anything, but the value is still a
                    # statement the rules must see. The index/base of the
                    # target can hold calls too.
                    for sub in _exprs_in(t):
                        for c in _expr_children(sub):
                            self.stmts.append(self._e(c))
            if not carried:
                self.stmts.append(val)
            return
        if isinstance(stmt, _pyast.AugAssign):
            # The name's binding was seeded unresolved; the value is a
            # statement of its own (`out += subprocess.check_output(c)`).
            self._walrus_lets(stmt.value)
            self.stmts.append(self._e(stmt.value))
            return
        if isinstance(stmt, (_pyast.With, _pyast.AsyncWith)):
            # `with open(path) as f:` is THE idiomatic Python file access.
            # Measured: without this, `with open(base + name)` produced no
            # E0711 at all while the bare `open(base + name)` did — the
            # benign-corpus false-positive count looked good only because
            # most file opens were invisible.
            for item in stmt.items:
                self._walrus_lets(item.context_expr)
                val = self._e(item.context_expr)
                tgt = item.optional_vars
                if isinstance(tgt, _pyast.Name):
                    self.stmts.append({"kind": "Let", "name": tgt.id,
                                       "value": val,
                                       "pos": _pos(stmt, self.fn_line)})
                else:
                    self.stmts.append(val)
            return
        if isinstance(stmt, _pyast.Return):
            if stmt.value is not None:
                self._walrus_lets(stmt.value)
                self.stmts.append({"kind": "Return", "value": self._e(stmt.value),
                                   "pos": _pos(stmt, self.fn_line)})
            return
        # Every other statement — `Expr` (any value, not only a call),
        # `for`/`if`/`while` tests and iterables, `assert`, `raise`,
        # `match` subjects and guards, `del`, and the decorators, defaults
        # and annotations of a nested `def` or `class` — evaluates its
        # expression children in place. Bodies are statements and are
        # visited on their own; targets are binding sites, seeded above.
        for child in _stmt_expr_children(stmt):
            self._walrus_lets(child)
            self.stmts.append(self._e(child))

    def visit_call(self, call: _pyast.Call):
        func = call.func
        arg0 = _const_str(call.args[0]) if call.args else None
        line = getattr(call, "lineno", self.fn_line)

        # bare name(...)
        if isinstance(func, _pyast.Name):
            name = func.id
            if name in DYNAMIC_BUILTINS:
                self._add_unprovable("dynamic_construct", name,
                    f"`{name}(...)` executes or imports code chosen at runtime; "
                    f"its capability surface cannot be determined statically", line)
                return
            if name in DYNAMIC_ATTR_BUILTINS:
                # getattr/setattr/delattr — dynamic unless attr name constant
                if len(call.args) >= 2 and _const_str(call.args[1]) is None:
                    self._add_unprovable("dynamic_attr", name,
                        f"`{name}` with a computed attribute name dispatches to "
                        f"a target unknown at analysis time", line)
                return
            if name in CAP_BY_BUILTIN:
                cap, verb = CAP_BY_BUILTIN[name]
                self._add_effect(cap, verb, arg0); return
            if name in self.local_fns:
                self.local_calls.append(name); return
            if name in PURE_BUILTINS:
                return
            dotted = self.imp.resolve_name(name)   # from-import
            if dotted is not None:
                self._handle_dotted(dotted, arg0, line); return
            # Unknown bare callable -> cannot prove capability-free.
            self._add_unprovable("unresolved_call", name,
                f"callee `{name}` is not a local function, a known-pure builtin, "
                f"or a mapped import; its capability surface is unknown", line)
            return

        # value.attr(...)
        if isinstance(func, _pyast.Attribute):
            attr = func.attr
            val = func.value
            if isinstance(val, _pyast.Name):
                dotted = self.imp.resolve_attr(val.id, attr)
                if dotted is not None:
                    self._handle_dotted(dotted, arg0, line); return
                # method on a local variable / unknown object
                self._add_unprovable("unresolved_method", val.id + "." + attr,
                    f"method `{attr}` is called on `{val.id}`, whose type is not "
                    f"resolved here; its capability surface is unknown", line)
                return
            if isinstance(val, _pyast.Attribute):
                # a.b.c(...) — try to flatten to dotted import path
                dotted = self._flatten_attr(func)
                if dotted is not None:
                    cls = _classify_dotted(dotted)
                    if cls is not None:
                        self._add_effect(cls[0], cls[1], arg0); return
                    if _module_root(dotted) in PURE_MODULES:
                        return
                self._add_unprovable("unresolved_method", attr,
                    f"chained attribute call `...{attr}(...)` could not be "
                    f"resolved to a known module path", line)
                return
            # self.method(), obj().method(), subscript().method() ...
            self._add_unprovable("dynamic_dispatch", attr,
                f"call target `{attr}` is dispatched on a runtime value "
                f"(self/expression); its effects cannot be traced statically", line)
            return

        # eval()() , (lambda...)() , etc.
        self._add_unprovable("computed_callee", "<expr>",
            "the call target is an expression, not a named function", line)

    def _flatten_attr(self, node: _pyast.Attribute) -> Optional[str]:
        parts = []
        cur: Any = node
        while isinstance(cur, _pyast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, _pyast.Name):
            base = self.imp.alias_to_path.get(cur.id, cur.id)
            parts.append(base)
            return ".".join(reversed(parts))
        return None

    def _handle_dotted(self, dotted: str, arg0: Optional[str], line: int):
        if dotted == "importlib.import_module" or dotted.endswith(".import_module"):
            self._add_unprovable("dynamic_construct", dotted,
                "dynamic import selects a module at runtime; the imported "
                "capability surface is unknown", line); return
        cls = _classify_dotted(dotted)
        if cls is not None:
            self._add_effect(cls[0], cls[1], arg0); return
        root = _module_root(dotted)
        if root in PURE_MODULES:
            return
        if root == "os":
            # os.* not in the explicit table -> unknown, be honest.
            self._add_unprovable("unresolved_call", dotted,
                f"`{dotted}` is an os call not in the capability table; "
                f"treated as unknown rather than assumed safe", line); return
        # imported but unmapped module -> unknown capability surface.
        self._add_unprovable("unresolved_call", dotted,
            f"`{dotted}` comes from an unmapped import; its capability surface "
            f"is unknown and cannot be assumed empty", line)


def py_to_ir(source: str) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Translate Python source into Aether IR + an UNPROVABLE map.

    Single sound mode only. (The former `strict`/pragmatic split was removed in
    P0.2: pragmatic mode was unsound.)"""
    tree = _pyast.parse(source)

    imports = _Imports()
    func_nodes: List[Tuple[str, Any]] = []   # (qualname, node)

    # Every import anywhere in the module: under `try:` (the optional-
    # dependency guard every framework uses), inside functions, behind
    # `if TYPE_CHECKING:`. `collect` below used to read imports only as
    # direct children of the module and class bodies it walked, so a
    # try-guarded `import yaml` left `yaml.load(x)` unresolved — and an
    # unresolved qualified sink is SILENT, not over-flagged. Found by
    # bench/framework_scan (BUGS.md BUG-011); the same gap kept every
    # try-guarded `select` from resolving to a builder (BUG-010).
    for n in _pyast.walk(tree):
        if isinstance(n, _pyast.Import):
            imports.add_import(n)
        elif isinstance(n, _pyast.ImportFrom):
            imports.add_importfrom(n)

    # Every `def` at any STATEMENT depth outside a function body: under
    # `try:` (the optional-dependency fallback every framework writes),
    # under `if`, inside a `with`/`for`, in a class nested in a class.
    # `collect` used to read only direct children of the module and of
    # its top-level classes, so a `def` anywhere else was never analysed
    # at all — the function-shaped instance of BUG-011 (BUG-012). Nested
    # functions (a `def` inside a `def`) stay part of their enclosing
    # function: `_pyast.walk` already translates their bodies there.
    class_nodes: List[Tuple[str, Any]] = []

    def scope_stmts(stmts):
        """Statements of one scope, through `if`/`try`/`with`/`for`/
        `match` blocks, never into a `def` or `class` body."""
        for child in stmts:
            yield child
            if isinstance(child, (_pyast.FunctionDef, _pyast.AsyncFunctionDef,
                                  _pyast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                yield from scope_stmts(getattr(child, field, None) or [])
            for h in getattr(child, "handlers", None) or []:
                yield from scope_stmts(h.body)
            for c in getattr(child, "cases", None) or []:
                yield from scope_stmts(c.body)

    def collect(stmts, prefix=""):
        for child in scope_stmts(stmts):
            if isinstance(child, (_pyast.FunctionDef, _pyast.AsyncFunctionDef)):
                func_nodes.append((prefix + child.name, child))
            elif isinstance(child, _pyast.ClassDef):
                class_nodes.append((prefix + child.name, child))
                collect(child.body, prefix + child.name + ".")
    collect(tree.body)

    local_fn_names: Set[str] = set(q for q, _ in func_nodes)
    # local-call resolution uses simple names too (module-level helpers)
    simple_names: Set[str] = set(q.split(".")[-1] for q, _ in func_nodes if "." not in q)

    # Module-level literal constants: a name bound exactly ONCE in the
    # whole module, at module level, to a str literal — by any binding
    # form, in any function (a `global` declaration or a parameter of
    # the same name is a second binding and disqualifies it). Such a
    # name IS its literal at every read (`conn.execute(_CREATE_TABLE)`).
    mod_binds: Dict[str, int] = {}
    for n, _v, _l in _bindings_of(tree):
        mod_binds[n] = mod_binds.get(n, 0) + 1
    module_lits: Dict[str, Tuple[str, int]] = {}
    for s in scope_stmts(tree.body):
        if isinstance(s, _pyast.Assign) and len(s.targets) == 1 \
                and isinstance(s.targets[0], _pyast.Name) \
                and _const_str(s.value) is not None \
                and mod_binds.get(s.targets[0].id) == 1:
            module_lits[s.targets[0].id] = (_const_str(s.value),
                                            getattr(s, "lineno", 0))

    decls: List[Dict[str, Any]] = []
    unprovable_map: Dict[str, List[Dict[str, Any]]] = {}
    export_names: List[str] = []

    def translate(qual: str, node: Any, line: int):
        v = _FnVisitor(imports, simple_names, qual, line, module_lits=module_lits)
        try:
            sql_names, lit_names = _sql_expression_names(node, imports, module_lits)
            v = _FnVisitor(imports, simple_names, qual, line,
                           _safe_xml_parser_names(node, imports),
                           _local_constants(node, imports),
                           sql_names, lit_names,
                           {n for n, _v, _l in _bindings_of(node)},
                           module_lits)
            # Two separate walks, deliberately. `visit_call` drives the
            # untouched capability/UNPROVABLE analysis over EVERY call
            # anywhere in the function (including inside comprehensions
            # and nested calls); `visit_stmt` builds the expression shapes
            # the detectors judge. Merging them would change what the
            # capability pass sees.
            for sub in _pyast.walk(node):
                if isinstance(sub, _pyast.Call):
                    v.visit_call(sub)
            v.seed_bindings(node)
            for sub in _pyast.walk(node):
                if isinstance(sub, (_pyast.stmt, _pyast.excepthandler)) \
                        or type(sub).__name__ == "match_case":
                    v.visit_stmt(sub)
            if v.scope.too_deep:
                v._add_unprovable("too_deep", qual,
                                  f"an expression in this scope is nested deeper "
                                  f"than {_MAX_EXPR_DEPTH} levels; the part below "
                                  f"the cap was not translated and its calls were "
                                  f"not judged", line)
        except RecursionError:
            # An expression deeper than the interpreter's stack. The old
            # behaviour let it escape and the CLI counted the WHOLE FILE
            # as unreadable — every other function's findings lost, exit
            # 0. Now this one scope reports an unprovable region and the
            # rest of the file is judged (BUG-012).
            v.stmts = []
            v._add_unprovable("too_deep", qual,
                              "an expression in this scope is nested deeper "
                              "than the analyzer can translate; its calls "
                              "were not judged", line)
        body_calls = [{"kind": "Call",
                       "func": {"kind": "Ident", "name": c},
                       "args": [], "pos": {"line": line, "column": 1}}
                      for c in v.local_calls]
        decls.append({
            "kind": "FunctionDecl",
            "name": qual,
            "effects": v.effects,
            "body": v.stmts + body_calls,
            "pos": {"line": line, "column": 1},
        })
        export_names.append(qual)
        if v.unprovable:
            unprovable_map[qual] = v.unprovable

    for qual, node in func_nodes:
        translate(qual, node, getattr(node, "lineno", 0))

    # Code that runs when the module is imported — `os.system(sys.argv[1])`
    # at the top level, an `if __name__ == "__main__":` block, a class
    # attribute computed at class-creation time — was never analysed:
    # `n_functions: 0, ok: true` for a script whose whole body is a sink
    # (BUG-012). Each such scope becomes one synthetic decl, `<module>` or
    # `Class.<class>`, run through the identical machinery; a scope with
    # no call at all is omitted so a module of plain assignments adds
    # nothing to the output.
    n_scopes = 0
    # Stripped IN PLACE, after every `def` has been translated from its
    # own node: removing a `def` from its parent's list does not touch
    # the node. No copy — a deep copy of a deep expression is itself a
    # RecursionError. `generic_visit`, not `visit`, on a class: strip
    # its CHILDREN and keep the class node (`visit_ClassDef` deletes).
    stripper = _ScopeStripper()
    scopes = [(q + ".<class>", c, getattr(c, "lineno", 0)) for q, c in class_nodes]
    scopes.append(("<module>", tree, 1))
    for qual, node, line in scopes:
        try:
            stripped = stripper.generic_visit(node)
        except RecursionError:
            unprovable_map.setdefault(qual, []).append({
                "fn": qual, "line": line, "granularity": "function",
                "callee": qual, "reason": "too_deep",
                "detail": "an expression in this scope is nested deeper than "
                          "the analyzer can translate; its calls were not judged",
                "construct_line": line, "needs": "human review or a runtime check"})
            continue
        if not _scope_has_content(stripped):
            continue
        n_scopes += 1
        translate(qual, stripped, line)

    module_name = "PythonModule"
    decls.insert(0, {
        "kind": "ModuleDecl",
        "name": module_name,
        "capabilities": [],         # default boundary: nothing allowed (policy overrides)
        "exports": export_names,
        "pos": {"line": 1, "column": 1},
    })

    ast_dict = {"kind": "Program", "decls": decls}
    meta = {"lang": "python", "module": module_name,
            "n_functions": len(func_nodes), "n_scopes": n_scopes,
            "pymap_version": PYMAP_VERSION, "mode": "sound"}
    return ast_dict, unprovable_map, meta


def mapping_table() -> Dict[str, Any]:
    """Expose the capability mapping table for auditing (the /pymap endpoint)."""
    return {
        "pymap_version": PYMAP_VERSION,
        "cap_by_module": CAP_BY_MODULE,
        "cap_by_qualified": CAP_BY_QUALIFIED,
        "cap_by_builtin": {k: list(v) for k, v in CAP_BY_BUILTIN.items()},
        "dynamic_builtins": sorted(DYNAMIC_BUILTINS) + sorted(DYNAMIC_ATTR_BUILTINS),
        "pure_modules": sorted(PURE_MODULES),
        "pure_module_citations": PURE_MODULE_CITATIONS,
        "pure_builtins": sorted(PURE_BUILTINS),
        "sink_by_qualified": SINK_BY_QUALIFIED,
        "sink_by_method": SINK_BY_METHOD,
        "sink_by_builtin": SINK_BY_BUILTIN,
        "sink_guards": {
            name: {"sink": g.sink_name, "keyword": g.keyword,
                   "safe_values": sorted(g.safe_values),
                   "sink_values": sorted(g.sink_values),
                   "absent_is_sink": g.absent_is_sink}
            for name, g in sorted(SINK_GUARDS.items())},
        "sanitizer_by_qualified": SANITIZER_BY_QUALIFIED,
        "sql_expression_builders": {
            "roots": sorted(_SQL_EXPR_ROOTS),
            "builders": sorted(_SQL_EXPR_BUILDERS),
            "table_methods_argument_free_only": sorted(_SQL_TABLE_METHODS),
            "raw_string_entry_points": sorted(_SQL_RAW_ENTRY),
            "raw_string_methods": sorted(_SQL_RAW_METHODS)},
        "mode": "sound",
    }
