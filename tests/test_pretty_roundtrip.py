"""C.1 regression tests for the canonical pretty-printer.

The contract under test is the round-trip property:

    parse(pretty(parse(src))) ≡ parse(src)  (modulo position metadata)

across every program in the reference corpus, the benchmark reference
solutions, and the architectural-integrity demo corpus. If the
round-trip ever drops below the full corpus, the pretty-printer has
lost faithfulness for some AST shape and must be fixed before the
formatter (C.4) or the agent SDK's structural-edit tooling (C.2) is
shipped.

Three tests:
  1. Round-trip every file in the union corpus.
  2. Re-pretty is idempotent (`pretty(parse(pretty(parse(src))))` ==
     `pretty(parse(src))`), so the formatter has a stable fixed point.
  3. `asts_equal_ignoring_pos` actually ignores position metadata.
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.parser import parse  # noqa: E402
from aether.pretty import pretty, asts_equal_ignoring_pos  # noqa: E402


def _collect_corpus():
    """EVERY `.aeth` in the repository that parses — not a sample. The old
    sample (reference/, bench/tasks/, architectural-integrity/) missed
    `playground/examples/32_function_typed_param.aeth`, on which `pretty`
    crashed (`KeyError: 'ret'`, audit 2026-09-24 A9). Files that do not
    parse are the malformed-input fixtures; they have no AST to print."""
    paths = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".") and d != "_work")
        for f in sorted(filenames):
            if not f.endswith(".aeth"):
                continue
            p = os.path.join(dirpath, f)
            try:
                parse(open(p, encoding="utf-8-sig").read(), p)
            except Exception:
                continue
            paths.append(p)
    assert any(p.endswith("32_function_typed_param.aeth") for p in paths)
    return paths


def test_roundtrip_full_corpus():
    corpus = _collect_corpus()
    assert len(corpus) >= 400, f"expected >=400 files, found {len(corpus)}"
    failures = []
    for path in corpus:
        try:
            src = open(path, encoding="utf-8-sig").read()
            ast1 = parse(src, path)
            rendered = pretty(ast1)
            ast2 = parse(rendered, path)
            if not asts_equal_ignoring_pos(ast1, ast2):
                failures.append((path, "AST mismatch after round-trip"))
            # With comments kept (fmt, fix-loop): same AST, and a fixed point.
            kept = pretty(ast1, src)
            if not asts_equal_ignoring_pos(ast1, parse(kept, path)):
                failures.append((path, "AST mismatch with comments kept"))
            elif pretty(parse(kept, path), kept) != kept:
                failures.append((path, "comment-keeping pretty not idempotent"))
        except Exception as e:
            failures.append((path, f"{type(e).__name__}: {e}"))
    assert not failures, failures
    print(f"C.1 roundtrip: {len(corpus)} files parse + pretty + reparse to same AST")


def test_pretty_is_idempotent():
    corpus = _collect_corpus()
    failures = []
    for path in corpus:
        src = open(path, encoding="utf-8-sig").read()
        once = pretty(parse(src, path))
        twice = pretty(parse(once, path))
        if once != twice:
            failures.append(path)
    assert not failures, f"pretty not idempotent on {len(failures)} files: {failures[:3]}"
    print(f"C.1 idempotence: pretty stable as a fixed point across {len(corpus)} files")


def test_function_types_print_as_parsed():
    """A9: FunctionType is `{params, returns}` in the parser and prints
    as `function(<params>) returns <T>`."""
    src = ("function apply(f: function(Int, String) returns Bool, x: Int) returns Bool\n"
           "  effects pure\ndo\n  return f(x, \"a\")\nend\n")
    assert pretty(parse(src, "<ft>")) == src, pretty(parse(src, "<ft>"))
    print("C.1 function types: printed from params/returns")


def test_asts_equal_ignoring_pos_strips_pos_metadata():
    a = {"kind": "Ident", "name": "x", "pos": {"line": 1, "column": 1}}
    b = {"kind": "Ident", "name": "x", "pos": {"line": 99, "column": 5}}
    assert asts_equal_ignoring_pos(a, b)
    # but a real structural difference is still caught
    c = {"kind": "Ident", "name": "y", "pos": {"line": 1, "column": 1}}
    assert not asts_equal_ignoring_pos(a, c)
    # nested 'position' as well
    a2 = {"kind": "Foo", "position": {"line": 1, "column": 1}, "children": [a]}
    b2 = {"kind": "Foo", "position": {"line": 7, "column": 2}, "children": [b]}
    assert asts_equal_ignoring_pos(a2, b2)
    print("C.1 oracle: asts_equal_ignoring_pos strips pos + position metadata")


if __name__ == "__main__":
    test_roundtrip_full_corpus()
    test_pretty_is_idempotent()
    test_function_types_print_as_parsed()
    test_asts_equal_ignoring_pos_strips_pos_metadata()
    print("C.1 ALL PRETTY-ROUNDTRIP TESTS PASS")
