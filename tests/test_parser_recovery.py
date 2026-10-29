"""Regression tests for C.6: multi-error parser recovery.

`parse(...)` keeps its single-error contract (raises AetherError on the
first parse failure). `parse_collect(...)` is the new lenient API: it
recovers at top-level boundaries and returns (partial_ast, [Diagnostic, ...])
so an agent fix-loop can act on every parse problem in one shot rather
than re-running the parser for each.

Tests:
  1. parse_collect on a clean program returns 0 diags + a full AST.
  2. parse_collect on a 2-error program returns 2 diags AND parses
     every clean decl on either side of each broken one.
  3. parse_collect recovers from 3 independent errors and still
     surfaces a 4th-decl clean parse afterwards.
  4. The legacy parse(...) entry point still raises on the first error.
  5. The AetherError class accepts an optional `diagnostics=` list and
     surfaces `(+ N more)` in the summary message.
  6. CLI flag `--collect-errors` reports every recoverable error and
     exits 2.
"""

from __future__ import annotations
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.parser import parse, parse_collect  # noqa: E402
from aether.diagnostics import AetherError, Diagnostic, Position  # noqa: E402


_CLEAN = """
function ok() returns Unit
  effects log
do
  print("hi")
end
"""

# Two top-level decls between three broken ones.
_THREE_BROKEN = """
function badA() returns
  effects log
do
  print("a")
end

function okA() returns Unit
  effects log
do
  print("a-ok")
end

function badB() returns Unit
  effects
do
  print("b")
end

function okB() returns Unit
  effects log
do
  print("b-ok")
end

function badC(x: ) returns Unit
  effects log
do
  print("c")
end

function okC() returns Unit
  effects log
do
  print("c-ok")
end
"""


def test_parse_collect_clean():
    ast, diags = parse_collect(_CLEAN)
    assert diags == [], diags
    assert ast["kind"] == "Program", ast
    assert len(ast["decls"]) == 1
    print("C.6 parse_collect clean: 0 diagnostics, 1 decl")


def test_parse_collect_recovers_three_independent_errors():
    ast, diags = parse_collect(_THREE_BROKEN)
    assert len(diags) >= 3, diags
    # Every diag should be a structured E0201 parse error.
    for d in diags:
        assert d.code == "E0201", d.code
        assert d.category == "parse", d.category
        assert d.position.line > 0, d.position
    # And the clean decls on either side of each broken one must have
    # parsed cleanly — the partial AST should hold at least the three
    # ok* decls.
    decl_names = [d["name"] for d in ast["decls"] if d.get("kind") == "FunctionDecl"]
    for expected in ("okA", "okB", "okC"):
        assert expected in decl_names, decl_names
    print(f"C.6 parse_collect recovery: {len(diags)} diagnostics + "
          f"{len(decl_names)} clean decls preserved")


def test_legacy_parse_still_raises_on_first_error():
    raised = False
    try:
        parse(_THREE_BROKEN)
    except AetherError as e:
        raised = True
        assert e.diag.code == "E0201", e.diag.code
        # Single-error path: e.diagnostics has exactly the one we raised.
        assert len(e.diagnostics) == 1, e.diagnostics
    assert raised
    print("C.6 legacy parse: still raises AetherError on first error")


def test_AetherError_accepts_multi_diagnostics():
    d1 = Diagnostic(code="E0201", category="parse", severity="error",
                    message="first problem", position=Position(1, 1))
    d2 = Diagnostic(code="E0201", category="parse", severity="error",
                    message="second problem", position=Position(2, 1))
    d3 = Diagnostic(code="E0201", category="parse", severity="error",
                    message="third problem", position=Position(3, 1))
    e = AetherError(None, diagnostics=[d1, d2, d3])
    assert e.diag is d1                      # primary stays stable
    assert e.diagnostics == [d1, d2, d3]
    # Message advertises the extras.
    assert "+ 2 more" in str(e), str(e)
    print("C.6 AetherError: multi-diagnostic carrier works")


def test_cli_collect_errors_flag():
    import tempfile
    fd, src_path = tempfile.mkstemp(prefix="aether_c6_", suffix=".aeth", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_THREE_BROKEN)
        # First — strict mode bails on first error.
        strict = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli", "check", src_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert strict.returncode == 4, strict   # 4 = unparsed (Wave 5b D5; was 2)
        strict_count = strict.stderr.count("[E0201]")
        assert strict_count == 1, f"strict mode should bail on first, got {strict_count} E0201s"
        # Then — collect mode surfaces every recoverable error.
        collect = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "check", "--collect-errors", src_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert collect.returncode == 4, collect
        collect_count = collect.stderr.count("[E0201]")
        assert collect_count >= 3, f"collect mode should surface >=3 errors, got {collect_count}"
        print(f"C.6 cli --collect-errors: strict={strict_count}, collect={collect_count}")
    finally:
        try:
            if os.path.exists(src_path):
                os.remove(src_path)
        except OSError:
            pass     # /tmp file on a sandboxed mount may refuse unlink


if __name__ == "__main__":
    test_parse_collect_clean()
    test_parse_collect_recovers_three_independent_errors()
    test_legacy_parse_still_raises_on_first_error()
    test_AetherError_accepts_multi_diagnostics()
    test_cli_collect_errors_flag()
    print("C.6 ALL PARSER-RECOVERY TESTS PASS")
