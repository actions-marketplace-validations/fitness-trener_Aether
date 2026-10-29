"""F.2 regression test for the SDK-driven fix-loop demo.

`demos/payment_workflow/broken.aeth` violates B.1 (a `pure` function
prints) and B.3 (the module does not grant `fs`). The only mechanical
repair for either WIDENS a declaration, which is the thing Aether exists
to refuse. So the contract under test (audit 2026-09-24 D1) is:

  1. By default the loop applies NOTHING, ends `not_repaired`, names both
     would-be widenings with a call-site patch target, exits non-zero,
     and writes the input back unchanged.
  2. `--allow-widen` applies both, tags each step
     `weakens_constraint: true`, ends `widened` (never `clean`), still
     exits non-zero, and its output passes `aether check` while keeping
     the file's leading comment block.

This test used to assert the opposite — two applied fixes and `clean` —
i.e. it pinned the widening as the correct outcome.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)


DEMO_DIR = os.path.join(ROOT, "demos", "payment_workflow")
BROKEN = os.path.join(DEMO_DIR, "broken.aeth")
DRIVER = os.path.join(DEMO_DIR, "fix_loop.py")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_fix_loop_refuses_to_widen_broken_candidate():
    # Default output paths: this regenerates the demo's tracked
    # broken.fixed.aeth / broken.transcript.json, deterministically.
    r = subprocess.run(
        [sys.executable, "-B", DRIVER, BROKEN, "--quiet"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert r.returncode == 1, r
    assert "not repaired: fixing this would widen" in r.stderr, r.stderr
    transcript = json.loads(_read(BROKEN.replace(".aeth", ".transcript.json")))
    assert not [t for t in transcript if "diagnostic" in t], transcript
    final = transcript[-1]
    assert final["status"] == "not_repaired", final
    blocked = {b["code"] for b in final["blocked"]}
    assert blocked == {"E0801", "E0701"}, final
    e0801 = next(b for b in final["blocked"] if b["code"] == "E0801")
    # The call to remove, not the declaration to widen.
    assert e0801["patch_target"][0][0] == "decls", e0801
    assert e0801["patch_target"][-1][0] != "effects", e0801
    assert _read(BROKEN.replace(".aeth", ".fixed.aeth")) == _read(BROKEN)
    print("F.2 fix-loop: refuses both widening repairs, not_repaired, exit 1")


def test_allow_widen_applies_flags_and_never_says_clean():
    with tempfile.TemporaryDirectory() as d:
        out_src = os.path.join(d, "fixed.aeth")
        out_tr = os.path.join(d, "t.json")
        r = subprocess.run(
            [sys.executable, "-B", DRIVER, BROKEN, "--allow-widen", "--quiet",
             "--out-source", out_src, "--out-transcript", out_tr],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert r.returncode == 1, r
        assert "WARNING" in r.stderr and "WIDEN" in r.stderr, r.stderr
        transcript = json.loads(_read(out_tr))
        fixes = [t for t in transcript if "diagnostic" in t]
        assert sorted(t["diagnostic"]["code"] for t in fixes) == ["E0701", "E0801"], fixes
        assert all(t["weakens_constraint"] is True and t["widens"] for t in fixes), fixes
        assert transcript[-1]["status"] == "widened", transcript[-1]
        fixed = _read(out_src)
        assert fixed.startswith("// expect: E0701x2, E0801\n"), fixed[:80]
        chk = subprocess.run(
            [sys.executable, "-B", "-m", "transpiler.aether.cli", "check", out_src],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert chk.returncode == 0, chk
    print("F.2 --allow-widen: 2 steps tagged weakens_constraint, final 'widened', exit 1")


def test_payment_workflow_aether_runs_cleanly():
    """F.1 — the architecturally-correct reference must check + run."""
    src = os.path.join(DEMO_DIR, "aether", "main.aeth")
    chk = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "check", src],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert chk.returncode == 0, chk
    run = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "run", src],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert run.returncode == 0, run
    out = run.stdout
    assert "DONE rcpt-8500-USD" in out, out
    print("F.1 payment workflow Aether: check + run both clean")


def test_payment_workflow_python_runs_cleanly():
    src = os.path.join(DEMO_DIR, "python", "main.py")
    r = subprocess.run([sys.executable, "-B", src],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r
    assert "DONE rcpt-8500-USD" in r.stdout, r.stdout
    print("F.1 payment workflow Python: runs cleanly with matching output")


if __name__ == "__main__":
    test_payment_workflow_aether_runs_cleanly()
    test_payment_workflow_python_runs_cleanly()
    test_fix_loop_refuses_to_widen_broken_candidate()
    test_allow_widen_applies_flags_and_never_says_clean()
    print("F ALL DEMO TESTS PASS")
