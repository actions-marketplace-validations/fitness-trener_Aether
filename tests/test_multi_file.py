"""H.E.3 regression tests for multi-file import resolution.

Three contracts:
1. A two-file program where `prog.aeth` imports `lib.aeth` parses, type-checks,
   and runs producing the expected stdout.
2. A cycle (A imports B, B imports A) surfaces E0706 rather than recursing.
3. An import naming a non-existent file surfaces E0705.

Plus an opt-out check: with `--no-import-resolution`, the same multi-file
program goes back to single-file semantics (and fails because the imported
symbol is unknown to the emitter pass), confirming the flag is actually
gating the resolution pass and not silently no-opping.
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
from aether.passes.imports import resolve_imports  # noqa: E402


# ---- direct-API smoke ---------------------------------------------

def test_resolve_imports_inlines_decls():
    """Calling resolve_imports() directly returns a combined Program AST
    that contains the imported file's decls plus the entry file's decls."""
    with tempfile.TemporaryDirectory(prefix="aether_he3_") as tmp:
        lib_path = os.path.join(tmp, "lib.aeth")
        prog_path = os.path.join(tmp, "prog.aeth")
        with open(lib_path, "w", encoding="utf-8") as f:
            f.write(
                "function greet() returns String\n"
                "  effects pure\n"
                "do\n"
                "  return \"hello from lib\"\n"
                "end\n"
            )
        with open(prog_path, "w", encoding="utf-8") as f:
            f.write(
                "import lib\n"
                "\n"
                "function main() returns Unit\n"
                "  effects log\n"
                "do\n"
                "  print(greet())\n"
                "end\n"
            )
        with open(prog_path, "r", encoding="utf-8") as f:
            ast = parse(f.read(), prog_path)
        combined, diags = resolve_imports(ast, prog_path)
        assert diags == [], diags
        decl_kinds = [d["kind"] for d in combined["decls"]]
        # ImportDecl preserved for entry file; greet + main inlined.
        assert "ImportDecl" in decl_kinds, decl_kinds
        assert any(d.get("name") == "greet" for d in combined["decls"]), decl_kinds
        assert any(d.get("name") == "main" for d in combined["decls"]), decl_kinds
        print("H.E.3 direct-API: resolve_imports inlined imported decls")


# ---- CLI: happy path ----------------------------------------------

def test_cli_check_and_run_two_file_program():
    """End-to-end: `aether check` and `aether run` succeed on a two-file
    program reached through resolve_imports."""
    with tempfile.TemporaryDirectory(prefix="aether_he3_") as tmp:
        lib_path = os.path.join(tmp, "lib.aeth")
        prog_path = os.path.join(tmp, "prog.aeth")
        with open(lib_path, "w", encoding="utf-8") as f:
            f.write(
                "function greet() returns String\n"
                "  effects pure\n"
                "do\n"
                "  return \"hello from lib\"\n"
                "end\n"
            )
        with open(prog_path, "w", encoding="utf-8") as f:
            f.write(
                "import lib\n"
                "\n"
                "function main() returns Unit\n"
                "  effects log\n"
                "do\n"
                "  print(greet())\n"
                "end\n"
            )
        rc = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "check", prog_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert rc.returncode == 0, (rc.stdout, rc.stderr)
        rr = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "run", prog_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert rr.returncode == 0, (rr.stdout, rr.stderr)
        assert "hello from lib" in rr.stdout, rr.stdout
        print("H.E.3 CLI: two-file check + run produce expected stdout")


# ---- CLI: E0705 missing file --------------------------------------

def test_cli_missing_import_emits_E0705():
    """Importing a sibling file that does not exist surfaces E0705."""
    with tempfile.TemporaryDirectory(prefix="aether_he3_") as tmp:
        prog_path = os.path.join(tmp, "prog.aeth")
        with open(prog_path, "w", encoding="utf-8") as f:
            f.write(
                "import nonexistent\n"
                "\n"
                "function main() returns Unit\n"
                "  effects log\n"
                "do\n"
                "  print(\"unreachable\")\n"
                "end\n"
            )
        r = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "check", prog_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert r.returncode == 4, (r.stdout, r.stderr)  # 4 = not loaded (Wave 5b D5; was 2)
        assert "E0705" in r.stderr, r.stderr
        print("H.E.3 CLI: missing import surfaces E0705")


# ---- CLI: E0706 import cycle --------------------------------------

def test_cli_import_cycle_emits_E0706():
    """A imports B, B imports A → E0706 (no infinite recursion)."""
    with tempfile.TemporaryDirectory(prefix="aether_he3_") as tmp:
        a_path = os.path.join(tmp, "a.aeth")
        b_path = os.path.join(tmp, "b.aeth")
        with open(a_path, "w", encoding="utf-8") as f:
            f.write(
                "import b\n"
                "\n"
                "function from_a() returns String\n"
                "  effects pure\n"
                "do\n"
                "  return \"a\"\n"
                "end\n"
                "\n"
                "function main() returns Unit\n"
                "  effects log\n"
                "do\n"
                "  print(from_a())\n"
                "end\n"
            )
        with open(b_path, "w", encoding="utf-8") as f:
            f.write(
                "import a\n"
                "\n"
                "function from_b() returns String\n"
                "  effects pure\n"
                "do\n"
                "  return \"b\"\n"
                "end\n"
            )
        r = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "check", a_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert r.returncode == 4, (r.stdout, r.stderr)  # 4 = not loaded (Wave 5b D5; was 2)
        assert "E0706" in r.stderr, r.stderr
        print("H.E.3 CLI: import cycle surfaces E0706")


# ---- CLI: opt-out flag --------------------------------------------

def test_cli_no_import_resolution_flag_is_honoured():
    """With --no-import-resolution, multi-file resolution is skipped.
    The same prog/lib pair that worked above must now fail because
    `greet` is no longer in scope from the entry file's perspective."""
    with tempfile.TemporaryDirectory(prefix="aether_he3_") as tmp:
        lib_path = os.path.join(tmp, "lib.aeth")
        prog_path = os.path.join(tmp, "prog.aeth")
        with open(lib_path, "w", encoding="utf-8") as f:
            f.write(
                "function greet() returns String\n"
                "  effects pure\n"
                "do\n"
                "  return \"hello from lib\"\n"
                "end\n"
            )
        with open(prog_path, "w", encoding="utf-8") as f:
            f.write(
                "import lib\n"
                "\n"
                "function main() returns Unit\n"
                "  effects log\n"
                "do\n"
                "  print(greet())\n"
                "end\n"
            )
        # Without the flag — succeeds.
        ok = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "run", prog_path],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert ok.returncode == 0, (ok.stdout, ok.stderr)
        # With the flag — must fail at runtime because greet is unresolved.
        nf = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             "run", prog_path, "--no-import-resolution"],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert nf.returncode != 0, (nf.stdout, nf.stderr)
        print("H.E.3 CLI: --no-import-resolution gates the pass")


if __name__ == "__main__":
    test_resolve_imports_inlines_decls()
    test_cli_check_and_run_two_file_program()
    test_cli_missing_import_emits_E0705()
    test_cli_import_cycle_emits_E0706()
    test_cli_no_import_resolution_flag_is_honoured()
    print("ALL OK")
