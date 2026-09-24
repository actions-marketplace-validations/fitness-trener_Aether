"""Confidence ratings — the per-finding axis.

`risk` rates the CLASS a code names; `confidence` rates ONE finding's
evidence: how sure the analysis is that this call is the sink it says.
The evidence is the Python frontend's match kind, so the table and the
frontend must agree — a match kind the frontend can emit but the table
does not rate would silently take the floor, and a rated kind the
frontend never emits is an invented fact, which the honesty rules forbid
outright.

The coverage checks below read the frontend's own `SINK_MATCH_KINDS`
vocabulary and the literal strings `_sink_match` returns, the way
`tests/test_risk.py` reads the codes the tree constructs.

Run: python -B tests/test_confidence.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.confidence import (CONFIDENCE, FLOOR, AETHER_SOURCE,   # noqa: E402
                               confidence_of)
from aether.py_frontend import SINK_MATCH_KINDS, py_to_ir          # noqa: E402
from aether.passes import analyze_flat                             # noqa: E402
from aether.parser import parse                                    # noqa: E402

FRONTEND = os.path.join(ROOT, "transpiler", "aether", "py_frontend.py")

# Exactly what `check-py` runs by default: the one Python skip list +
# capability. The literal copy here had drifted (it skipped `smt` and
# `imports`, which are not stages, and ran `semantic`).
from aether.py_frontend import PY_SKIP_STAGES                      # noqa: E402
_PY_SKIP = PY_SKIP_STAGES + ("capability",)


def _emitted_match_kinds() -> set:
    """The match strings `_sink_match` can actually return.

    Read from the source, not from the declared tuple: the point of the
    check is to catch a NEW `return sink, "..."` that nobody added to the
    vocabulary or the table.

    Walked as an AST, not matched as text: the kind is not always the
    last thing on the `return` line (`compile`'s rides a conditional
    expression across two lines), and a regex tuned to the shapes that
    exist today is blind to exactly the new shape this test is for.
    """
    import ast as _ast
    tree = _ast.parse(open(FRONTEND, encoding="utf-8").read())
    fn = next((n for n in _ast.walk(tree)
               if isinstance(n, _ast.FunctionDef) and n.name == "_sink_match"),
              None)
    assert fn is not None, "_sink_match not found in the frontend"

    def strings(node):
        """String constants a node can EVALUATE to. A `Compare` is a test,
        not a value — `"compile" if dotted == "compile" else "builtin"`
        yields two kinds, not three."""
        if isinstance(node, _ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, _ast.IfExp):
            return strings(node.body) | strings(node.orelse)
        if isinstance(node, _ast.Compare):
            return set()
        out = set()
        for child in _ast.iter_child_nodes(node):
            out |= strings(child)
        return out

    kinds = set()
    for r in _ast.walk(fn):
        # Every sink return is `(sink_name, match_kind)`; the kind is the
        # second element, whatever expression produces it.
        if isinstance(r, _ast.Return) and isinstance(r.value, _ast.Tuple) \
                and len(r.value.elts) == 2:
            kinds |= strings(r.value.elts[1])
    return kinds


def test_every_frontend_match_kind_is_rated():
    emitted = _emitted_match_kinds()
    assert emitted, "found no match kinds in _sink_match — parse broke"
    missing = sorted(emitted - set(CONFIDENCE))
    assert not missing, (
        f"frontend match kinds with no confidence rating: {missing}. Add a "
        f"row to transpiler/aether/confidence.py — an unrated kind takes "
        f"the floor silently.")
    declared = sorted(set(SINK_MATCH_KINDS) ^ emitted)
    assert not declared, (
        f"py_frontend.SINK_MATCH_KINDS and what _sink_match returns "
        f"disagree on: {declared}. The tuple is what mapping_table() "
        f"publishes, so it must be the whole truth.")
    print(f"confidence: all {len(emitted)} frontend match kinds rated")


def test_no_phantom_kinds_rated():
    phantom = sorted(set(CONFIDENCE) - _emitted_match_kinds())
    assert not phantom, (
        f"confidence table rates match kinds the frontend never emits: "
        f"{phantom}. Remove them — an invented fact is the one thing the "
        f"honesty rules forbid outright.")
    print("confidence: no phantom match kinds rated")


def test_ratings_are_in_range_and_floor_is_the_floor():
    bad = sorted((k, v) for k, v in CONFIDENCE.items()
                 if not 0.0 <= v <= 1.0)
    assert not bad, f"confidence values outside [0,1]: {bad}"
    assert FLOOR == min(CONFIDENCE.values()), (
        f"FLOOR {FLOOR} is not the least-confident rating in the table "
        f"{sorted(CONFIDENCE.values())}; an unknown kind must degrade to "
        f"the least confident value")
    assert AETHER_SOURCE == 1.0, AETHER_SOURCE
    print("confidence: all ratings in [0,1]; FLOOR is the table minimum")


def test_unknown_kind_is_least_confident_not_most():
    assert confidence_of("some_new_kind_2027") == FLOOR, (
        "an unrecognised match kind must take the FLOOR, never 1.0 — a new "
        "frontend match kind must not be able to claim certainty by being "
        "new; test_every_frontend_match_kind_is_rated catches the lag")
    assert confidence_of("some_new_kind_2027") < confidence_of("qualified")
    print("confidence: unknown match kind degrades to the floor")


def test_absent_match_is_an_aether_source_finding():
    assert confidence_of(None) == 1.0
    assert confidence_of("") == 1.0
    print("confidence: an absent match kind is 1.0 (nothing was guessed)")


def _py_findings(src: str):
    ast, _unp, _meta = py_to_ir(src)
    return analyze_flat(ast, skip=_PY_SKIP)


def test_by_name_sink_ranks_below_a_resolved_one():
    ds = {d.code: d for d in _py_findings(
        "import pickle\n"
        "def f(x, cur, tpl):\n"
        "    pickle.loads(x)\n"
        "    cur.execute('SELECT ' + x)\n"
        "    tpl.from_string(x)\n")}
    assert set(ds) >= {"E0713", "E0719", "E0720"}, sorted(ds)
    assert ds["E0720"].confidence == confidence_of("qualified")
    assert ds["E0713"].confidence == confidence_of("method")
    assert ds["E0719"].confidence == confidence_of("method")
    assert ds["E0713"].confidence < ds["E0720"].confidence, (
        "`cursor.execute` matched by method name must rank below a "
        "`pickle.loads` resolved through the imports — of 24 new "
        "`from_string` hits about 8 were non-jinja methods "
        "(bench/framework_scan/REPORT.md section 8)")
    assert ds["E0719"].confidence < ds["E0720"].confidence
    print("confidence: a by-name sink ranks below a resolved one")


def test_compile_ranks_below_exec():
    ds = _py_findings("def f(x):\n"
                      "    exec(x)\n"
                      "    compile(x, '<s>', 'exec')\n")
    by_line = {d.position.line: d for d in ds if d.code == "E0731"}
    assert set(by_line) == {2, 3}, sorted(by_line)
    assert by_line[2].confidence == confidence_of("builtin")
    assert by_line[3].confidence == confidence_of("builtin_compile")
    assert by_line[3].confidence < by_line[2].confidence, (
        "compile() builds a code object and executes nothing — 4 of the 8 "
        "measured corpus sites never run the result")
    print("confidence: compile() ranks below exec()")


def test_match_kind_reaches_extra_and_argv_and_guard_are_rated():
    ds = {(d.code, d.position.line): d for d in _py_findings(
        "import subprocess\n"
        "def f(x):\n"
        "    subprocess.run(['bash', '-c', x])\n"
        "    subprocess.run(x, shell=True)\n")}
    argv = ds[("E0714", 3)]
    guard = ds[("E0714", 4)]
    assert argv.extra["match"] == "argv", argv.extra
    assert guard.extra["match"] == "guard", guard.extra
    assert argv.confidence == confidence_of("argv")
    assert guard.confidence == confidence_of("guard")
    print("confidence: argv and guard matches are rated and reach `extra`")


def test_aether_source_finding_is_one_point_zero():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    ast = parse(open(p, encoding="utf-8").read(), p)
    ds = [d for d in analyze_flat(ast) if d.code == "E0713"]
    assert ds, "expected E0713 on the SQL-injection demo"
    for d in ds:
        assert d.confidence == 1.0, (
            f"an Aether-source finding guesses nothing — the sink is "
            f"spelled in the source: {d}")
        assert "match" not in d.extra, d.extra
    print("confidence: an Aether-source finding is 1.0 with no match kind")


if __name__ == "__main__":
    test_every_frontend_match_kind_is_rated()
    test_no_phantom_kinds_rated()
    test_ratings_are_in_range_and_floor_is_the_floor()
    test_unknown_kind_is_least_confident_not_most()
    test_absent_match_is_an_aether_source_finding()
    test_by_name_sink_ranks_below_a_resolved_one()
    test_compile_ranks_below_exec()
    test_match_kind_reaches_extra_and_argv_and_guard_are_rated()
    test_aether_source_finding_is_one_point_zero()
    print("\nconfidence: 9/9 pass")
