"""Aether `Call` and `ExprStmt` nodes carry a position, and findings about a
call are reported AT the call (audit 2026-09-24 D10, Wave 7).

E0801 used to point at the function declaration: in a long body an agent
(or a person) had to search for the offending call, and the fix-loop's
patch target picked the caller's FIRST call to the callee by name, so two
violations in one function both patched the same call.

Run: python -B tests/test_call_positions.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.parser import parse                               # noqa: E402
from aether.passes import analyze_flat                        # noqa: E402
from aether.passes.ast_walk import walk                       # noqa: E402
from aether.passes.patch_target import compute_patch_target   # noqa: E402
from aether.pretty import pretty                              # noqa: E402

SRC = """function main() returns Unit
  effects pure
do
  let x = 1
  print("one")
  if x > 0 then
    print("two")
  end
end
"""


def _at(d):
    return (d.position.line, d.position.column)


def test_call_and_exprstmt_are_positioned():
    ast = parse(SRC, "<t>")
    calls = list(walk(ast, "Call"))
    stmts = list(walk(ast, "ExprStmt"))
    assert [(c["pos"]["line"], c["pos"]["column"]) for c in calls] == [(5, 3), (7, 5)], calls
    assert [(s["pos"]["line"], s["pos"]["column"]) for s in stmts] == [(5, 3), (7, 5)], stmts
    # A method-style call chain starts where the chain starts.
    ast2 = parse("function f(s: String) returns Int\n  effects pure\ndo\n"
                 "  return length(trim(s))\nend\n", "<t>")
    assert [c["pos"]["column"] for c in walk(ast2, "Call")] == [10, 17]


def test_e0801_is_reported_at_each_call():
    diags = [d for d in analyze_flat(parse(SRC, "<t>")) if d.code == "E0801"]
    assert [_at(d) for d in diags] == [(5, 3), (7, 5)], [_at(d) for d in diags]


def test_patch_target_picks_the_reported_call():
    ast = parse(SRC, "<t>")
    diags = [d for d in analyze_flat(ast) if d.code == "E0801"]
    paths = [compute_patch_target(ast, d) for d in diags]
    assert len(set(map(str, paths))) == 2, paths   # was: both the first print


def test_dead_exprstmt_is_reported_where_it_is():
    src = ("function f() returns Int\n  effects log\ndo\n  return 1\n"
           "  print(\"dead\")\nend\n")
    diags = [d for d in analyze_flat(parse(src, "<t>")) if d.code == "E0204"]
    assert [_at(d) for d in diags] == [(5, 3)], [_at(d) for d in diags]


def test_comment_above_a_bare_call_survives_fmt():
    # A bare call with no literal in it had no positioned node at all, so
    # the comment above it had nothing to anchor to and was dropped.
    src = ("function f(a: String) returns Unit\n  effects log\ndo\n"
           "  let b = 1\n  // say it\n  print(a)\nend\n")
    assert "// say it" in pretty(parse(src, "<t>"), src)


def main() -> int:
    tests = [test_call_and_exprstmt_are_positioned,
             test_e0801_is_reported_at_each_call,
             test_patch_target_picks_the_reported_call,
             test_dead_exprstmt_is_reported_where_it_is,
             test_comment_above_a_bare_call_survives_fmt]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"  [FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} call-position checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
