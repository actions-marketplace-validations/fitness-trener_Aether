"""Tests for the opt-in SMT contract-proving pass (--prove; E0901/E0902).

Runs standalone (`python -B tests/test_smt.py`, exit 0) or under pytest.
Every test body no-ops when z3-solver is not installed: the pass is
opt-in and the core toolchain stays stdlib-only, so a z3-less machine
must stay green.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

try:
    import z3  # noqa: F401
    HAVE_Z3 = True
except ImportError:
    HAVE_Z3 = False

from aether.parser import parse  # noqa: E402

if HAVE_Z3:
    from aether.passes.smt import (  # noqa: E402
        translate_expr, _resolve_param_sort, _mk_var, check_contracts_smt)


# One function whose clauses exercise the whole fragment. `requires`
# and `ensures` clause ASTs are pulled out of the parse result so the
# translator tests track the real parser shapes, not hand-built dicts.
FRAGMENT_SRC = """
function frag(x: Int, b: Bool) returns Int
  requires x >= 0 and x < 100
  requires b or not b
  requires -x <= 0
  requires x + 1 > x - 1
  requires x * 2 >= 0 implies x >= 0
  requires x != 3
  ensures result == old(x)
  effects pure
do
  return x
end
"""

UNTRANSLATABLE_SRC = """
function bad(x: Int, s: String) returns Int
  requires isFine(x)
  requires x / 2 == 0
  requires x % 2 == 0
  requires s == "hi"
  effects pure
do
  return x
end
"""


def _clauses(src, name="frag"):
    ast = parse(src, "<smt-test>")
    fn = next(d for d in ast["decls"] if d.get("kind") == "FunctionDecl"
              and d["name"] == name)
    return fn


def test_translate_full_fragment():
    if not HAVE_Z3:
        return
    fn = _clauses(FRAGMENT_SRC)
    env = {"x": _mk_var("x", "int"), "b": _mk_var("b", "bool")}
    for clause in fn["requires"]:
        z = translate_expr(clause, env)
        assert z is not None, clause
    env["result"] = _mk_var("result", "int")
    z = translate_expr(fn["ensures"][0], env)
    assert z is not None
    # old(x) must translate as x: prove result == old(x) equivalent to
    # result == x under this env.
    s = z3.Solver()
    s.add(z3.Not(z == (env["result"] == env["x"])))
    assert s.check() == z3.unsat


def test_untranslatable_returns_none():
    if not HAVE_Z3:
        return
    fn = _clauses(UNTRANSLATABLE_SRC, "bad")
    env = {"x": _mk_var("x", "int")}
    for clause in fn["requires"]:
        assert translate_expr(clause, env) is None, clause


def test_unknown_ident_returns_none():
    if not HAVE_Z3:
        return
    fn = _clauses(FRAGMENT_SRC)
    # empty env: every clause mentions x or b, so all must be None
    for clause in fn["requires"]:
        assert translate_expr(clause, {}) is None


def test_sort_mismatch_returns_none():
    if not HAVE_Z3:
        return
    src = """
function m(x: Int, b: Bool) returns Bool
  requires x + b > 0
  effects pure
do
  return b
end
"""
    fn = _clauses(src, "m")
    env = {"x": _mk_var("x", "int"), "b": _mk_var("b", "bool")}
    assert translate_expr(fn["requires"][0], env) is None


def test_resolve_param_sort_refinement_chain():
    if not HAVE_Z3:
        return
    src = """
type Percentage = Int where self >= 0 and self <= 100
type Half = Percentage where self <= 50

function f(p: Half) returns Int
  effects pure
do
  return p
end
"""
    ast = parse(src, "<smt-test>")
    type_decls = {d["name"]: d for d in ast["decls"]
                  if d.get("kind") == "TypeDecl"}
    fn = next(d for d in ast["decls"] if d.get("kind") == "FunctionDecl")
    resolved = _resolve_param_sort(fn["params"][0]["type"], type_decls)
    assert resolved is not None
    sort, preds = resolved
    assert sort == "int"
    assert len(preds) == 2  # Percentage's predicate + Half's predicate
    # unsupported types resolve to None
    assert _resolve_param_sort({"kind": "TypeName", "name": "String"},
                               type_decls) is None
    assert _resolve_param_sort({"kind": "GenericType", "name": "List",
                                "args": []}, type_decls) is None


REFUTABLE = """
function myAbs(x: Int) returns Int
  ensures result >= 0
  effects pure
do
  return x
end
"""

PROVABLE = """
function clampLow(x: Int) returns Int
  requires x >= 0
  requires x <= 100
  ensures result >= 0
  ensures result <= 100
  effects pure
do
  return x
end
"""

REFINED = """
type Percentage = Int where self >= 0 and self <= 100

function keep(p: Percentage) returns Int
  ensures result >= 0
  effects pure
do
  return p
end
"""

VIA_CALL = """
function helper(x: Int) returns Int
  effects pure
do
  return x
end

function viaCall(x: Int) returns Int
  ensures result >= 0
  effects pure
do
  return helper(x)
end
"""

UNSOUND_ASSUMPTION = """
function trusted(x: Int) returns Int
  requires isFine(x)
  ensures result >= 0
  effects pure
do
  return x
end
"""


def test_refutable_emits_e0901_with_counterexample():
    if not HAVE_Z3:
        return
    diags, summary = check_contracts_smt(parse(REFUTABLE, "<smt>"))
    assert summary == {"proved": 0, "refuted": 1, "timeout": 0,
                       "skipped": 0}, summary
    d = diags[0]
    assert d.code == "E0901"
    assert d.category == "contract"
    assert d.severity == "error"
    assert d.extra["function"] == "myAbs"
    assert d.extra["clause_kind"] == "ensures"
    cx = d.extra["counterexample"]
    assert int(cx["x"]) < 0, cx        # roadmap 1.3: concrete violating input
    assert int(cx["result"]) < 0, cx


def test_provable_produces_no_diagnostics():
    if not HAVE_Z3:
        return
    diags, summary = check_contracts_smt(parse(PROVABLE, "<smt>"))
    assert diags == []
    assert summary == {"proved": 2, "refuted": 0, "timeout": 0, "skipped": 0}


def test_refinement_predicate_is_assumed():
    if not HAVE_Z3:
        return
    diags, summary = check_contracts_smt(parse(REFINED, "<smt>"))
    assert diags == []
    assert summary["proved"] == 1, summary


def test_call_body_is_skipped_not_guessed():
    if not HAVE_Z3:
        return
    diags, summary = check_contracts_smt(parse(VIA_CALL, "<smt>"))
    assert diags == []
    assert summary == {"proved": 0, "refuted": 0, "timeout": 0, "skipped": 1}


def test_untranslatable_requires_skips_whole_function():
    # Soundness: without the isFine(x) assumption, x = -1 would "refute"
    # the ensures. The pass must skip, not fabricate a counterexample.
    if not HAVE_Z3:
        return
    diags, summary = check_contracts_smt(parse(UNSOUND_ASSUMPTION, "<smt>"))
    assert diags == []
    assert summary == {"proved": 0, "refuted": 0, "timeout": 0, "skipped": 1}


def _run_cli(src: str, *flags: str, as_json: bool = False):
    # --json is a top-level flag and must precede the subcommand;
    # --prove & co. belong to the `check` subparser and follow the file.
    pre = ["--json"] if as_json else []
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "prog.aeth")
        with open(path, "w") as f:
            f.write(src)
        return subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli",
             *pre, "check", path, *flags],
            cwd=ROOT, capture_output=True, text=True)


def test_cli_prove_refuted_exits_1():
    if not HAVE_Z3:
        return
    r = _run_cli(REFUTABLE, "--prove", as_json=True)
    # 1 = findings; --json is one document on stdout (Wave 5b D5/D6; the
    # exit was 2 and the diagnostics JSONL on stderr).
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    doc = json.loads(r.stdout)
    assert doc["ok"] is False and doc["prove"]["refuted"] >= 1, doc
    d = next(d for d in doc["diagnostics"] if d["code"] == "E0901")
    assert d["stage"] == "smt" and "counterexample" in r.stdout, d


def test_cli_prove_proved_exits_0_with_summary():
    if not HAVE_Z3:
        return
    r = _run_cli(PROVABLE, "--prove", as_json=True)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    data = json.loads(r.stdout.strip().splitlines()[-1])
    assert data["ok"] is True
    assert data["prove"]["proved"] == 2
    assert data["prove"]["refuted"] == 0


def test_cli_prove_is_default_on_when_z3_present():
    if not HAVE_Z3:
        return
    r = _run_cli(REFUTABLE)           # no flag: default-on since wave 1
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "E0901" in (r.stdout + r.stderr)


def test_cli_no_prove_disables():
    if not HAVE_Z3:
        return
    r = _run_cli(REFUTABLE, "--no-prove")
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "E0901" not in (r.stdout + r.stderr)


def main() -> int:
    if not HAVE_Z3:
        print("SKIP: z3-solver not installed; SMT pass tests skipped")
        return 0
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok {name}")
    print(f"OK: {len(tests)} SMT tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
