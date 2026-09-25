"""Every Python sink/sanitizer table row, exercised — one generated snippet each.

Audit 2026-09-24 F2: 21 of 78 rows appeared in no test, and deleting
`mogrify`, `os.popen`, `executemany`, `pandas.read_pickle` or
`HttpResponseRedirect` survived the whole suite. Here every row is PINNED
to the codes one call through it yields, and the pins must equal the live
tables in both directions:

  * a row deleted, or its sink changed, goes red below;
  * a row added without a pin goes red, so a new spelling ships with its
    test by construction (and `tests/test_ratchet.py` counts the rows).

Snippets are minimal: the argument is a parameter (untrusted by
construction), so the row alone decides the verdict.

Run: python -B tests/test_sink_rows.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether import py_frontend as pf                       # noqa: E402
from aether.passes import analyze_flat                     # noqa: E402
from aether.passes.ast_walk import walk, callee_name       # noqa: E402

# What `check-py --strict` runs (E0711 is a strict-only row, `open`).
_SKIP = pf.PY_SKIP_STAGES + ("capability",)

# codes one call yields -> rows. `executescript` is a sqlExec: E0713 for
# the query text and E0716 for an unauthorized state change (documented).
QUALIFIED = {
    ("E0713",): ("pandas.read_sql", "pandas.read_sql_query",
                 "django.db.models.expressions.RawSQL", "django.db.models.RawSQL"),
    ("E0714",): ("os.system", "os.popen", "subprocess.getoutput",
                 "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
                 "commands.getoutput"),
    ("E0718",): ("flask.redirect", "django.shortcuts.redirect",
                 "starlette.responses.RedirectResponse",
                 "fastapi.responses.RedirectResponse",
                 "django.http.HttpResponseRedirect", "aiohttp.web.HTTPFound"),
    ("E0719",): ("flask.render_template_string", "jinja2.Template",
                 "django.template.Template", "mako.template.Template"),
    ("E0720",): ("pickle.loads", "pickle.load", "marshal.loads", "shelve.open",
                 "marshal.load", "pickle.Unpickler", "joblib.load", "dill.load",
                 "dill.loads", "cloudpickle.load", "cloudpickle.loads",
                 "pandas.read_pickle", "jsonpickle.decode"),
    ("E0727",): ("xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
                 "xml.sax.parse", "xml.sax.parseString",
                 "xml.dom.expatbuilder.parse", "xml.dom.expatbuilder.parseString",
                 "xml.etree.cElementTree.fromstring", "xml.etree.cElementTree.parse",
                 "lxml.etree.fromstring", "lxml.etree.parse", "lxml.etree.XML",
                 "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.parse",
                 "xml.dom.minidom.parseString", "xml.dom.minidom.parse"),
}
METHOD = {
    ("E0713",): ("execute", "executemany", "raw", "exec_driver_sql", "exec",
                 "fetchrow", "fetchval", "fetch_all", "fetch_one", "fetch_val",
                 "mogrify"),
    ("E0713", "E0716"): ("executescript",),
    ("E0714",): ("exec_command",),
    ("E0719",): ("from_string",),
}
BUILTIN = {
    ("E0711",): ("open",),
    ("E0731",): ("exec", "eval", "compile"),
}
GUARDS = {
    ("E0714",): ("subprocess.run", "subprocess.call", "subprocess.check_call",
                 "subprocess.check_output", "subprocess.Popen"),
    ("E0720",): ("yaml.load", "yaml.full_load", "yaml.unsafe_load", "yaml.load_all",
                 "yaml.full_load_all", "yaml.unsafe_load_all", "torch.load",
                 "numpy.load"),
    ("E0727",): ("defusedxml.minidom.parse", "defusedxml.minidom.parseString",
                 "defusedxml.pulldom.parse", "defusedxml.pulldom.parseString",
                 "defusedxml.ElementTree.parse"),
}
# wrapper -> (rows, the documented-fix snippet using `{san}`)
SANITIZERS = {
    "shellArg": (("shlex.quote", "pipes.quote"),
                 "import os\ndef f(x):\n    return os.system('ls ' + {san}(x))\n"),
    "schemaDecode": (("yaml.safe_load", "yaml.safe_load_all", "json.loads", "json.load"),
                     "def f(x):\n    return {san}(x)\n"),
    "safeJoin": (("werkzeug.utils.secure_filename",),
                 "def f(x):\n    return open({san}(x))\n"),
    "htmlEscape": (("html.escape", "markupsafe.escape"),
                   "def f(x):\n    return {san}(x)\n"),
}

# Rows a snippet cannot exercise: none today. An entry needs a reason.
UNEXERCISABLE: dict = {}

# Sanitizer rows whose documented fix is STILL flagged — a known defect,
# not a pass. The assertion is inverted rather than dropped: the day the
# fix goes clean this test goes red, so the entry cannot outlive the bug.
#   shlex.quote / pipes.quote: `"ls " + shlex.quote(x)` fires E0714 at
#   0.95 — the fix the hint names is flagged (audit 2026-09-24 C1,
#   Wave 5). `os.system(shlex.quote(x))` alone fires too, correctly: the
#   input still picks the program (py_whole).
KNOWN_FLAGGED_FIX = {"shlex.quote": ["E0714"], "pipes.quote": ["E0714"]}


def _codes(src: str) -> list:
    ir, _unp, _meta = pf.py_to_ir(src)
    return sorted(d.code for d in analyze_flat(ir, skip=_SKIP))


def _import(path: str) -> str:
    return f"import {path.rsplit('.', 1)[0]}\n"


def _flat(pins: dict) -> dict:
    return {row: list(codes) for codes, rows in pins.items() for row in rows}


def _check_pins(name: str, live, pins: dict) -> list:
    pinned = set(pins)
    live = set(live) - set(UNEXERCISABLE)
    out = []
    if live - pinned:
        out.append(f"{name}: rows with no pin (add each to this test with "
                   f"its expected codes): {sorted(live - pinned)}")
    if pinned - live:
        out.append(f"{name}: pinned rows gone from the table (a deleted sink "
                   f"is a recall regression): {sorted(pinned - live)}")
    return out


def test_every_row_is_pinned():
    bad = (_check_pins("SINK_BY_QUALIFIED", pf.SINK_BY_QUALIFIED, _flat(QUALIFIED))
           + _check_pins("SINK_BY_METHOD", pf.SINK_BY_METHOD, _flat(METHOD))
           + _check_pins("SINK_BY_BUILTIN", pf.SINK_BY_BUILTIN, _flat(BUILTIN))
           + _check_pins("SINK_GUARDS", pf.SINK_GUARDS, _flat(GUARDS))
           + _check_pins("SANITIZER_BY_QUALIFIED", pf.SANITIZER_BY_QUALIFIED,
                         {r: w for w, (rows, _s) in SANITIZERS.items() for r in rows}))
    assert not bad, "\n".join(bad)
    print("rows: every sink/guard/sanitizer row is pinned, and every pin is live")


def test_every_sink_row_fires_its_code():
    cases = [(row, want, _import(row) + f"def f(x):\n    return {row}(x)\n")
             for row, want in _flat(QUALIFIED).items()]
    cases += [(f".{row}", want, f"def f(cur, x):\n    return cur.{row}(x)\n")
              for row, want in _flat(METHOD).items()]
    cases += [(row, want, f"def f(x):\n    return {row}(x)\n")
              for row, want in _flat(BUILTIN).items()]
    bad = [f"{row}: want {want}, got {got}" for row, want, src in cases
           if (got := _codes(src)) != want]
    assert not bad, "sink rows that do not fire their code:\n  " + "\n  ".join(bad)
    print(f"rows: {len(cases)} sink rows each fire exactly their code")


def test_every_guard_flags_and_clears():
    """Both spellings: the one the guard must flag and the one it clears."""
    bad, n = [], 0
    for row, want in _flat(GUARDS).items():
        g = pf.SINK_GUARDS[row]
        values = g.safe_values | g.sink_values
        head = "".join(sorted({_import(row)} | {_import(v) for v in values if "." in v}))

        def call(kw):
            arg = "x" if kw is None else f"x, {g.keyword}={kw}"
            return head + f"def f(x, p):\n    return {row}({arg})\n"
        if g.absent_is_sink:
            flagged, cleared = call(None), call(sorted(g.safe_values)[0])
        else:
            # A literal sink value if the guard names one; else a value the
            # guard cannot resolve (a parameter), which must read as a sink.
            flagged = call(sorted(g.sink_values)[0] if g.sink_values else "p")
            cleared = call(None)
        n += 1
        if (got := _codes(flagged)) != want:
            bad.append(f"{row} flagged spelling: want {want}, got {got}")
        if (got := _codes(cleared)) != []:
            bad.append(f"{row} cleared spelling: want clean, got {got}")
    assert not bad, "guard rows:\n  " + "\n  ".join(bad)
    print(f"rows: {n} guard rows flag the unsafe spelling and clear the safe one")


def test_every_sanitizer_maps_and_its_fix_is_clean():
    bad, n = [], 0
    for wrapper, (rows, template) in SANITIZERS.items():
        for row in rows:
            n += 1
            ir, _u, _m = pf.py_to_ir(_import(row) + f"def f(x):\n    return {row}(x)\n")
            if wrapper not in {callee_name(c) for c in walk(ir, "Call")}:
                bad.append(f"{row}: not translated to {wrapper}")
            got = _codes(_import(row) + template.format(san=row))
            want = KNOWN_FLAGGED_FIX.get(row, [])
            if got != want:
                bad.append(f"{row}: documented fix gives {got}, want {want}"
                           + (" — the known defect is fixed; drop its "
                              "KNOWN_FLAGGED_FIX entry" if row in KNOWN_FLAGGED_FIX else ""))
    # The one sanitizer with a Python sink it clears: prove it clears.
    assert _codes("def f(x):\n    return open(x)\n") == ["E0711"]
    assert not bad, "sanitizer rows:\n  " + "\n  ".join(bad)
    print(f"rows: {n} sanitizer rows map to their wrapper; fixes clean "
          f"({len(KNOWN_FLAGGED_FIX)} known-flagged, audit C1)")


if __name__ == "__main__":
    test_every_row_is_pinned()
    test_every_sink_row_fires_its_code()
    test_every_guard_flags_and_clears()
    test_every_sanitizer_maps_and_its_fix_is_clean()
    print("SINK ROWS: every row is exercised")
