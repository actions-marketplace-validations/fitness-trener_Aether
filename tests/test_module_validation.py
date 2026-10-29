"""D.3 regression tests for the module-validation pass.

Three contracts (E0702 / E0703 / E0704) plus three negative cases:
the pass must be a no-op on clean source, a no-op on programs without
any `module` declaration, and the CLI must honour `--no-module-check`.
"""
from __future__ import annotations
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.parser import parse  # noqa: E402
from aether.passes.modules import check_modules  # noqa: E402


# ---- Clean / no-op cases ------------------------------------------

def test_no_modules_is_noop():
    src = """
function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert diags == [], diags
    print("D.3 module: no-module program produces 0 diagnostics")


def test_clean_module_is_noop():
    src = """
module App
  requires capability log
  exports main
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert diags == [], diags
    print("D.3 module: clean module declaration produces 0 diagnostics")


# ---- E0702: exports references undeclared name --------------------

def test_E0702_undeclared_export():
    src = """
module App
  requires capability log
  exports notExist
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert any(d.code == "E0702" for d in diags), diags
    d = next(d for d in diags if d.code == "E0702")
    assert d.extra["module"] == "App"
    assert d.extra["exported"] == "notExist"
    assert "main" in d.extra["declared_names"]
    print("D.3 E0702: undeclared export flagged with structured extra")


def test_E0702_does_not_fire_for_exports_that_match_any_decl_kind():
    """Should accept exports referring to types, records, unions, consts,
    not just functions."""
    src = """
type PositiveInt = Int where self > 0

module App
  requires capability log
  exports PositiveInt
  exports main
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert diags == [], diags
    print("D.3 E0702: exports may reference types/records/unions/consts")


# ---- E0703: duplicate module --------------------------------------

def test_E0703_duplicate_module():
    src = """
module App
  requires capability log
  exports main
end

module Other
  requires capability log
  exports main
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert any(d.code == "E0703" for d in diags), diags
    d = next(d for d in diags if d.code == "E0703")
    assert d.extra["first_module"] == "App"
    assert d.extra["duplicate_module"] == "Other"
    print("D.3 E0703: duplicate module flagged with both names in extra")


# ---- E0704: unknown capability ------------------------------------

def test_E0704_unknown_capability():
    src = """
module App
  requires capability quantum
  exports main
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    diags = check_modules(parse(src))
    assert any(d.code == "E0704" for d in diags), diags
    d = next(d for d in diags if d.code == "E0704")
    assert d.extra["capability"] == "quantum"
    assert "log" in d.extra["known"]
    print("D.3 E0704: unknown capability flagged with the known set in extra")


# ---- A11: the effects clause itself is validated -------------------

def test_A11_pure_alongside_other_effects_is_a_parse_error():
    """`effects pure, log` passed `check` (static read it as {log}) and
    failed `--effect-strict` (runtime read it as pure) — audit A11."""
    from aether.diagnostics import AetherError
    src = ("function f() returns Unit\n  effects pure, log\ndo\n"
           "  print(\"x\")\nend\n")
    try:
        parse(src)
    except AetherError as e:
        d = e.diag
        assert d.code == "E0201", d
        assert (d.position.line, d.position.column) == (2, 11), d.position
        assert "pure" in d.message
    else:
        raise AssertionError("effects pure, log was accepted")
    parse(src.replace("pure, log", "log"))
    print("A11: `pure` alongside another effect is E0201")


def test_A11_effect_with_unknown_capability_is_E0704():
    """An effect whose capability (first path segment) is outside the known
    vocabulary can never be granted by a module; it was accepted silently
    in a module-less program — audit A11."""
    src = ("function main() returns Unit\n  effects log, bogus.effect, fs.read\n"
           "do\n  print(\"x\")\nend\n")
    diags = check_modules(parse(src))
    assert [d.code for d in diags] == ["E0704"], diags
    d = diags[0]
    assert d.extra["function"] == "main" and d.extra["effect"] == "bogus.effect"
    assert d.extra["capability"] == "bogus" and "log" in d.extra["known"]
    assert (d.position.line, d.position.column) == (1, 1), d.position
    # Known capability heads with any tail stay declarations (effects.md).
    ok = src.replace("bogus.effect", "fs.delete, random, panic, mutate(x)")
    assert check_modules(parse(ok)) == []
    # Python has no effects clause: the frontend's inferred `env`/`process`
    # paths are not declarations and are not judged.
    from aether.py_frontend import py_to_ir
    ast = py_to_ir("import os\ndef f():\n    return os.getenv('X')\n")[0]
    assert any(e["path"][0] == "env" for d in ast["decls"]
               for e in d.get("effects", [])), "fixture must infer env"
    assert check_modules(ast) == []
    print("A11: unknown effect capability is E0704; Python not judged")


# ---- CLI integration ----------------------------------------------

def test_cli_module_check_default_on():
    src = """
module App
  requires capability log
  exports notExist
end

function main() returns Unit
  effects log
do
  print("hi")
end
"""
    fd, p = tempfile.mkstemp(prefix="aether_d3_", suffix=".aeth", text=True)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(src)
        r = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli", "check", p],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert r.returncode == 1, r   # 1 = findings (Wave 5b D5; was 2)
        assert "E0702" in r.stderr, r.stderr
        # Now with the opt-out flag — exit 0
        r2 = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "check", "--no-module-check", p],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert r2.returncode == 0, r2
        assert "E0702" not in r2.stderr
        print("D.3 CLI: default-on, opts out with --no-module-check")
    finally:
        try: os.remove(p)
        except OSError: pass


if __name__ == "__main__":
    test_no_modules_is_noop()
    test_clean_module_is_noop()
    test_E0702_undeclared_export()
    test_E0702_does_not_fire_for_exports_that_match_any_decl_kind()
    test_E0703_duplicate_module()
    test_E0704_unknown_capability()
    test_A11_pure_alongside_other_effects_is_a_parse_error()
    test_A11_effect_with_unknown_capability_is_E0704()
    test_cli_module_check_default_on()
    print("D.3 ALL MODULE-VALIDATION TESTS PASS")
