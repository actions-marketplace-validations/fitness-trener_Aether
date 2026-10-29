"""Regression tests for the three post-audit fixes.

S-001 — ensures clauses fire at runtime.
S-011 — `x!=3` (no spaces) tokenizes correctly.
S-012 — harness enforces timeout_ms.
"""

from __future__ import annotations
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.lexer import tokenize
from aether.parser import parse
from aether.emitter import emit
from aether.runtime import build_namespace
from aether.diagnostics import AetherError
from bench.harness import compile_and_run


def test_S011_lexer_tight_neq():
    """`x!=3` must lex as ident, !=, int — not as ident-with-bang then = then int."""
    toks = tokenize("x!=3")
    kinds_values = [(t.kind, t.value) for t in toks if t.kind != "eof"]
    assert kinds_values == [("ident", "x"), ("sym", "!="), ("int", 3)], kinds_values
    # And predicate idents still work
    toks = tokenize("isVowel? c")
    vals = [t.value for t in toks if t.kind != "eof"]
    assert vals == ["isVowel?", "c"], vals
    # Effectful idents still work
    toks = tokenize("readFile! path")
    vals = [t.value for t in toks if t.kind != "eof"]
    assert vals == ["readFile!", "path"], vals
    # And ident! followed by = still lexes correctly: writeFile != 5
    toks = tokenize("writeFile!=5")
    vals = [(t.kind, t.value) for t in toks if t.kind != "eof"]
    assert vals == [("ident", "writeFile"), ("sym", "!="), ("int", 5)], vals
    print("S-011: lexer handles x!=3 correctly")


def _run(src):
    """Compile + exec a program, return its captured stdout or raise."""
    import io
    from contextlib import redirect_stdout
    ast = parse(src, "<test>")
    py = emit(ast)
    code = compile(py, "<test>", "exec")
    g = build_namespace()
    g["__name__"] = "__main__"
    buf = io.StringIO()
    with redirect_stdout(buf):
        exec(code, g)
    return buf.getvalue()


def test_S001_ensures_violation_raises():
    """D.2 split: `ensures` violations now raise [E0304], not E0301.
    `requires` violations still raise [E0301]. An agent fix-loop can
    read the code alone and decide caller-side vs implementation-side
    fix without parsing the message text.
    """
    bad = """
function double(x: Int) returns Int
  ensures result == x * 2
  effects pure
do
  return x + x + 1
end

function main() returns Unit
  effects log
do
  print(intToString(double(5)))
end
"""
    raised = False
    try:
        _run(bad)
    except AetherError as e:
        raised = True
        assert e.diag.code == "E0304", e.diag.code
        assert "ensures" in e.diag.message, e.diag.message
        assert "double" in e.diag.message, e.diag.message
        # D.2: extra dict carries machine-readable fields.
        assert e.diag.extra["function"] == "double"
        assert e.diag.extra["clause_kind"] == "ensures"
    assert raised, "ensures violation did not raise"
    print("S-001/D.2: ensures violation now raises E0304 (split from E0301)")


def test_S001_ensures_honored_passes():
    """A function that honors its ensures clause must run to completion."""
    good = """
function double(x: Int) returns Int
  ensures result == x * 2
  effects pure
do
  return x + x
end

function main() returns Unit
  effects log
do
  print(intToString(double(5)))
end
"""
    out = _run(good)
    assert out == "10\n", repr(out)
    print("S-001: honored ensures lets program complete")


def test_S012_timeout_fires():
    """compile_and_run must enforce timeout_ms via SIGALRM."""
    if not hasattr(__import__("signal"), "SIGALRM"):
        print("S-012: SKIPPED (no SIGALRM on this platform)")
        return
    looper = """
function main() returns Unit
  effects log
do
  var i: Int = 0
  while i >= 0 do
    i = i + 1
  end
end
"""
    t0 = time.time()
    out = compile_and_run(looper, "<looper>", timeout_ms=300)
    elapsed = (time.time() - t0) * 1000
    assert out["ok"] is False, out
    assert out["stage"] == "exec", out
    assert out["diagnostic"]["category"] == "timeout", out
    assert out["diagnostic"]["code"] == "E0601", out
    # Timeout should fire close to 300ms (allow generous slack)
    assert 250 <= elapsed <= 1500, f"timeout fired at {elapsed:.0f}ms"
    print(f"S-012: timeout fired at {elapsed:.0f}ms with structured diagnostic")


def test_S002_refinement_violation_raises():
    """A value that fails its refinement predicate must raise [E0302]."""
    bad = """
type PositiveInt = Int where self > 0

function show(n: PositiveInt) returns String
  effects pure
do
  return intToString(n)
end

function main() returns Unit
  effects log
do
  print(show(0))
end
"""
    raised = False
    try:
        _run(bad)
    except AetherError as e:
        raised = True
        assert e.diag.code == "E0302", e.diag.code
        assert "PositiveInt" in e.diag.message, e.diag.message
    assert raised, "refinement violation did not raise"
    print("S-002: refinement boundary check fires with E0302")


def test_S002_refinement_passes_on_valid():
    """A value that satisfies the refinement must pass through cleanly."""
    good = """
type PositiveInt = Int where self > 0

function show(n: PositiveInt) returns String
  effects pure
do
  return intToString(n)
end

function main() returns Unit
  effects log
do
  print(show(42))
  print(show(1))
end
"""
    out = _run(good)
    assert out == "42\n1\n", repr(out)
    print("S-002: honored refinement lets program complete")


def test_B4_refinement_diagnostic_includes_predicate_text():
    """B.4 polish: the E0302 diagnostic must mention the predicate
    text and the failing value, so a model fix-loop knows *why* the
    boundary check rejected the call."""
    bad = """
type PositiveInt = Int where self > 0

function show(n: PositiveInt) returns String
  effects pure
do
  return intToString(n)
end

function main() returns Unit
  effects log
do
  print(show(0))
end
"""
    raised = False
    try:
        _run(bad)
    except AetherError as e:
        raised = True
        assert e.diag.code == "E0302", e.diag.code
        # The polished message includes the predicate text.
        assert "self > 0" in e.diag.message, e.diag.message
        # And the failing value's repr.
        assert "= 0" in e.diag.message or "0" in e.diag.extra.get("value_repr", ""), \
            e.diag.message
        # The extra dict carries structured info for an agent loop.
        assert e.diag.extra["type"] == "PositiveInt"
        assert e.diag.extra["binding"] == "n"
        assert "self > 0" in e.diag.extra["predicate"]
    assert raised
    print("B.4 refinement: polished diagnostic includes predicate text + value")


def test_B4_refinement_helper_is_module_level():
    """B.4 polish: refinement predicates compile to one module-level
    `_aert_refn_<TypeName>` helper (audit A4 moved helpers out of the user namespace), not a per-call-site lambda. This both
    avoids lambda allocation per invocation and makes the emitted code
    inspectable."""
    src = """
type PositiveInt = Int where self > 0

function show(n: PositiveInt) returns String
  effects pure
do
  return intToString(n)
end

function main() returns Unit
  effects log
do
  print(show(42))
end
"""
    py = emit(parse(src, "<b4>"))
    # The helper must exist exactly once.
    assert "def _aert_refn_PositiveInt(_ae_self):" in py, py
    # And the boundary check must reference it by name (no lambda).
    assert "_aert_check_refinement(_ae_n, _aert_refn_PositiveInt" in py, py
    # No per-call-site lambda allocation.
    assert "lambda _ae_self" not in py, "boundary check still allocates lambda"
    print("B.4 refinement: hoisted module-level helper, no per-call lambda")


def test_capability_no_module_passes_under_b3():
    """B.3 contract: a program with no module declaration is treated as
    having an implicit all-capability grant. Preserves backward compat
    with the v0.1/v0.2 reference programs that don't declare modules.
    Phase D.3 may tighten this default once modules become real
    composition units."""
    from aether.passes.capability import check_capabilities
    from aether.parser import parse as _parse
    src = """
function main() returns Unit
  effects log
do
  print("hello")
end
"""
    ast = _parse(src, "<cap>")
    diags = check_capabilities(ast)
    assert diags == [], diags
    print("B.3 capability: no-module program passes (implicit all-grant)")


def test_capability_module_missing_capability_blocks():
    """When ANY module is declared, the check is enforced. A function
    whose declared effects need a capability not granted by any module
    triggers E0701."""
    from aether.passes.capability import check_capabilities
    from aether.parser import parse as _parse
    src = """
module App
  requires capability log
  exports main
end

function leak() returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/x", "x")
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    ast = _parse(src, "<cap>")
    diags = check_capabilities(ast)
    assert any(d.code == "E0701" and d.extra.get("required_capability") == "fs"
               for d in diags), diags
    print("B.3 capability: missing 'fs' capability flagged with E0701")


def test_capability_admits_declared():
    from aether.passes.capability import check_capabilities
    from aether.parser import parse as _parse
    src = """
module App
  requires capability log
  exports main
end

function main() returns Unit
  effects log
do
  print("hello")
end
"""
    ast = _parse(src, "<cap>")
    diags = check_capabilities(ast)
    assert diags == [], diags
    print("B.3 capability: declared capability admits the function")


def test_capability_transitive():
    from aether.passes.capability import check_capabilities
    from aether.parser import parse as _parse
    src = """
module App
  requires capability log
  exports main
end

function reader() returns String
  effects fs.read
do
  match readFile("/etc/x") do
    case Ok(s) do
      return s
    end
    case Err(_e) do
      return ""
    end
  end
end

function main() returns Unit
  effects log
do
  print("ok")
end
"""
    ast = _parse(src, "<cap>")
    diags = check_capabilities(ast)
    assert any(d.code == "E0701" and d.extra.get("required_capability") == "fs"
               for d in diags), diags
    print("B.3 capability: transitive fs.read flagged via per-function check")


if __name__ == "__main__":
    test_S011_lexer_tight_neq()
    test_S001_ensures_violation_raises()
    test_S001_ensures_honored_passes()
    test_S012_timeout_fires()
    test_S002_refinement_violation_raises()
    test_S002_refinement_passes_on_valid()
    test_B4_refinement_diagnostic_includes_predicate_text()
    test_B4_refinement_helper_is_module_level()
    test_capability_no_module_passes_under_b3()
    test_capability_module_missing_capability_blocks()
    test_capability_admits_declared()
    test_capability_transitive()
    print("ALL REGRESSION TESTS PASS")
