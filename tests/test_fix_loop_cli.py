"""H.A.2 — regression for `aether fix-loop` CLI dispatch.

Three things this test enforces:

  1. `aether fix-loop --help` prints text that documents both paths
     (deterministic + --live) and uses honest framing. This catches a
     future drift where the help text might overclaim what the
     deterministic path is.

  2. `aether fix-loop <file>` (default = deterministic) does NOT call
     Anthropic. We assert this by checking that the `anthropic`
     module is not present in `sys.modules` after the run. The
     deterministic path must never reach into the LLM SDK.

  3. `aether fix-loop --live` with no API key fails fast with the
     expected explanatory text and a non-zero exit code. This is the
     "never silently fall back to deterministic" property.

  4. (audit 2026-09-24 D1) The loop never repairs by WIDENING a declared
     effects clause or module capability list: over every `.aeth` in the
     repository the default output declares nothing its input did not;
     the attack demos end `not_repaired`; `--allow-widen` tags each
     widening step and still exits non-zero; the `--live` verdict applies
     the same rule to a model's fix.

  5. (D8) Output paths never overwrite the input; outputs are UTF-8/LF.

Script-style test matching `tests/test_regressions.py` (no
TestCase wrapper). Exits 0 on full pass, 1 otherwise.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BROKEN = os.path.join(ROOT, "demos", "payment_workflow", "broken.aeth")


def _py():
    return [sys.executable, "-B"]


def _run(args, env=None):
    """Run `aether <args>` and return (returncode, stdout, stderr)."""
    cmd = _py() + ["-m", "transpiler.aether.cli"] + list(args)
    cp_env = os.environ.copy()
    cp_env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        cp_env.update(env)
    cp_env.pop("ANTHROPIC_API_KEY", None) if env is None else None
    r = subprocess.run(cmd, cwd=ROOT, env=cp_env,
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def test_help_documents_both_paths():
    rc, out, err = _run(["fix-loop", "--help"])
    text = (out or "") + (err or "")
    failures = []
    if rc != 0:
        failures.append(f"  --help exit {rc}, expected 0")
    if "deterministic" not in text.lower():
        failures.append("  --help text missing 'deterministic'")
    if "--live" not in text:
        failures.append("  --help text missing '--live'")
    if "ANTHROPIC_API_KEY" not in text:
        failures.append("  --help text missing 'ANTHROPIC_API_KEY'")
    return failures


def test_default_does_not_call_anthropic():
    """Default (no --live) must complete WITHOUT importing anthropic.

    We probe this by spawning a subprocess that runs the CLI default
    path, then in the same subprocess checks sys.modules. We use a
    one-liner: import the CLI module, monkey-block anthropic, run
    fix-loop, then assert.
    """
    if not os.path.isfile(BROKEN):
        return [f"  fixture missing: {BROKEN}"]
    probe = (
        "import sys\n"
        "# Block any future anthropic import. If the deterministic path\n"
        "# tries to import it, we'll get an ImportError that bubbles up.\n"
        "sys.modules['anthropic'] = None\n"
        "sys.path.insert(0, %r)\n"
        "from transpiler.aether.cli import main\n"
        "rc = main(['fix-loop', %r, '--out-source', '/tmp/_t.aeth',\n"
        "           '--out-transcript', '/tmp/_t.json', '--quiet'])\n"
        "assert 'anthropic' not in [m for m in sys.modules if m and \n"
        "       sys.modules.get(m) is not None and m == 'anthropic'], \\\n"
        "    'anthropic was imported on the deterministic path'\n"
        "print('OK rc=' + str(rc))\n"
    ) % (ROOT, BROKEN)
    cmd = _py() + ["-c", probe]
    cp_env = os.environ.copy()
    cp_env["PYTHONDONTWRITEBYTECODE"] = "1"
    cp_env.pop("ANTHROPIC_API_KEY", None)
    r = subprocess.run(cmd, cwd=ROOT, env=cp_env,
                       capture_output=True, text=True)
    failures = []
    if r.returncode != 0:
        failures.append(f"  default-path probe exit {r.returncode}")
        failures.append(f"  stderr: {r.stderr[:300]!r}")
    # rc=1, not 0: broken.aeth's only repairs widen a declaration, which
    # the loop refuses (D1). This probe is about `anthropic`, not the rc.
    if "OK rc=1" not in (r.stdout or ""):
        failures.append(f"  default-path probe stdout: {r.stdout[:300]!r}")
    return failures


def test_live_without_api_key_fails_clean():
    if not os.path.isfile(BROKEN):
        return [f"  fixture missing: {BROKEN}"]
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cmd = _py() + ["-m", "transpiler.aether.cli", "fix-loop", BROKEN, "--live"]
    r = subprocess.run(cmd, cwd=ROOT, env=env,
                       capture_output=True, text=True)
    text = (r.stdout or "") + (r.stderr or "")
    failures = []
    if r.returncode == 0:
        failures.append(f"  --live without key: exit {r.returncode}, "
                        "expected non-zero")
    if "ANTHROPIC_API_KEY" not in text:
        failures.append("  --live without key: error text missing the env var")
    if "deterministic" in text.lower() and "fall back" in text.lower() \
            and "never" not in text.lower():
        failures.append("  --live without key: text suggests silent fallback")
    return failures


def test_deterministic_path_needs_no_demos_dir():
    """BUG-026: the deterministic engine is part of the package. Copy ONLY
    `aether/` into a temp dir -- the shape of an installed wheel, with no
    demos/ anywhere -- and run `aether fix-loop` from there. It used to
    import its engine from demos/payment_workflow/, which no wheel ships,
    so every installed copy failed with `No module named 'fix_loop'`."""
    import shutil
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(os.path.join(ROOT, "transpiler", "aether"),
                        os.path.join(d, "aether"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        src = os.path.join(d, "broken.aeth")
        shutil.copy(BROKEN, src)
        fixed = os.path.join(d, "fixed.aeth")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = d
        env.pop("ANTHROPIC_API_KEY", None)
        r = subprocess.run(_py() + ["-m", "aether.cli", "fix-loop", src,
                                    "--out-source", fixed,
                                    "--out-transcript", os.path.join(d, "t.json"),
                                    "--quiet"],
                           cwd=d, env=env, capture_output=True, text=True)
        # Exit 1 is the refusal to widen (D1), and a traceback is ALSO
        # exit 1 — so the transcript is what proves the engine ran.
        tr = os.path.join(d, "t.json")
        if r.returncode != 1 or not os.path.isfile(tr):
            fails.append(f"exit {r.returncode}: {r.stderr.strip()[-400:]}")
        elif json.load(open(tr, encoding="utf-8"))[-1].get("status") != "not_repaired":
            fails.append("the installed engine did not report not_repaired")
        elif not os.path.isfile(fixed):
            fails.append("no fixed source was written")
    return fails


# --- D1: the loop never weakens a declared constraint -----------------

# The demos whose POINT is a refused composition. The loop used to
# "repair" each by granting the forbidden authority and report clean.
ATTACK_DEMOS = [
    "demos/capability-firewall/log_formatter.aeth",
    "playground/examples/03_B2_url_discipline.aeth",
    "playground/examples/10_pii_telemetry_violation.aeth",
    "demos/architectural-integrity/demo_02_net_glob_mismatch/aether/main.aeth",
    "demos/case_studies/log4shell/aether/vulnerable.aeth",
    "demos/payment_workflow/broken.aeth",
]


def _aeth_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".") and d != "_work")
        out += [os.path.join(dirpath, f) for f in sorted(filenames)
                if f.endswith(".aeth") and not f.endswith(".fixed.aeth")]
    return out


def _fl():
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether import fix_loop
    return fix_loop


def test_attack_demos_end_not_repaired():
    FL = _fl()
    fails = []
    for rel in ATTACK_DEMOS:
        path = os.path.join(ROOT, rel)
        src = open(path, encoding="utf-8-sig").read()
        fixed, tr = FL.fix_loop(src, filename=path)
        applied = [t for t in tr if "diagnostic" in t]
        if applied or tr[-1].get("status") != "not_repaired":
            fails.append(f"  {rel}: {tr[-1].get('status')} after {len(applied)} step(s)")
        elif fixed != src:
            fails.append(f"  {rel}: output differs from input with nothing applied")
        elif not all(b["would_widen"] and b["reason"].startswith("not repaired")
                     for b in tr[-1]["blocked"]):
            fails.append(f"  {rel}: blocked entry without its widening/reason")
    rc, _out, err = _run(["fix-loop", os.path.join(ROOT, ATTACK_DEMOS[0]),
                          "--out-source", os.path.join(_tmp(), "lf.fixed.aeth"),
                          "--out-transcript", os.path.join(_tmp(), "lf.json"),
                          "--quiet"])
    if rc != 1 or "would widen" not in err:
        fails.append(f"  CLI on log_formatter: rc={rc} stderr={err[-300:]!r}")
    return fails


_TMP = []


def _tmp():
    import tempfile
    if not _TMP:
        _TMP.append(tempfile.mkdtemp(prefix="aether_fl_"))
    return _TMP[0]


def test_fix_loop_never_widens_any_repo_file():
    """The Wave 3 acceptance: over EVERY .aeth in the repository, the
    default loop's output declares no effect/capability its input did not;
    with --allow-widen, every step that widens is tagged, and a run that
    widened never ends `clean`."""
    FL = _fl()
    fails, n, widened_runs = [], 0, 0
    for path in _aeth_files():
        src = open(path, encoding="utf-8-sig").read()
        n += 1
        fixed, tr = FL.fix_loop(src, filename=path)
        w = FL.source_widening(src, fixed, path)
        if w or any(t.get("weakens_constraint") for t in tr):
            fails.append(f"  default widened {os.path.relpath(path, ROOT)}: {w}")
        fixed, tr = FL.fix_loop(src, filename=path, allow_widen=True)
        steps = [t for t in tr if "diagnostic" in t]
        if FL.source_widening(src, fixed, path):
            widened_runs += 1
            if not any(t["weakens_constraint"] for t in steps):
                fails.append(f"  untagged widening {os.path.relpath(path, ROOT)}")
            if tr[-1].get("status") == "clean":
                fails.append(f"  widened yet 'clean': {os.path.relpath(path, ROOT)}")
    if n < 400 or widened_runs < 20:
        fails.append(f"  corpus too small to mean anything: {n} files, "
                     f"{widened_runs} widened under --allow-widen")
    print(f"  (D1) {n} .aeth files: default never widens; "
          f"{widened_runs} widen only under --allow-widen, all tagged")
    return fails


def test_widening_is_structural():
    FL = _fl()
    from aether.parser import parse
    base = ('module M\n  requires capability net\n  exports f\nend\n'
            'function f() returns Unit\n  effects net.fetch("https://a.example/x")\n'
            'do\n  print("x")\nend\n')

    def w(after):
        return FL.widening(parse(base, "a"), parse(after, "b"))
    fails = []
    broader = base.replace('"https://a.example/x"', '"https://a.example/*"')
    narrower = base
    extra_cap = base.replace("requires capability net", "requires capability net\n  requires capability fs")
    new_fn = base + 'function g() returns Unit\n  effects log\ndo\n  print("y")\nend\n'
    old_fn = base + 'function g() returns Unit\n  effects net.fetch("https://a.example/x")\ndo\n  print("y")\nend\n'
    if not w(broader):
        fails.append("  a broader glob is not widening")
    if w(narrower):
        fails.append(f"  identical program counted as widening: {w(narrower)}")
    if not w(extra_cap):
        fails.append("  an added capability is not widening")
    if not w(new_fn):
        fails.append("  a new function with an effect nobody declared is not widening")
    if w(old_fn):
        fails.append("  a new function reusing a declared effect counted as widening")
    return fails


def test_patch_target_E0801_is_the_call_site():
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether import sdk
    from aether.passes.patch_target import compute_patch_target, resolve_path_kind
    src = ('function f(s: String) returns Unit\n  effects pure\ndo\n'
           '  let n = length(s)\n  print(s)\nend\n')
    r = sdk.check(src)
    d = next(x for x in r.diagnostics if x.code == "E0801")
    pt = compute_patch_target(r.ast, d)
    if pt != [["decls", 0], ["body", 1], ["expr", None]] \
            or resolve_path_kind(r.ast, pt) != "Call":
        return [f"  E0801 patch_target {pt!r} is not the print() call"]
    return []


def test_live_verdict_rejects_a_widening_fix():
    """--live used to accept any model fix that `sdk.check` passed, so a
    model could 'fix' E0801 by widening the clause. `_judge_live_fix`
    holds it to the same rule; the shipped replay transcript must not
    widen either."""
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether.cli import _judge_live_fix
    from aether.fix_loop import source_widening
    import argparse
    bad_in = 'function f() returns Unit\n  effects pure\ndo\n  print("x")\nend\n'
    widened = bad_in.replace("effects pure", "effects log")
    fails = []
    for allow in (False, True):
        p = os.path.join(_tmp(), f"live_{allow}.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"input": {"source": bad_in}, "fixed_source": widened}, f)
        rc = _judge_live_fix(p, argparse.Namespace(file="x.aeth", allow_widen=allow))
        tr = json.load(open(p, encoding="utf-8"))
        if rc != 1 or tr.get("weakens_constraint") is not True \
                or ("rejected" in tr) == allow:
            fails.append(f"  allow_widen={allow}: rc={rc} transcript={tr}")
    p = os.path.join(_tmp(), "live_ok.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"input": {"source": bad_in},
                   "fixed_source": bad_in.replace('  print("x")\n', "")}, f)
    if _judge_live_fix(p, argparse.Namespace(file="x.aeth", allow_widen=False)) != 0:
        fails.append("  a non-widening fix was rejected")
    replay = json.load(open(os.path.join(ROOT, "demos", "payment_workflow",
                                         "llm_fix_demo.transcript.json"),
                            encoding="utf-8"))
    w = source_widening(replay["input"]["source"], replay["fixed_source"])
    if w:
        fails.append(f"  the shipped LLM replay fix widens: {w}")
    return fails


# --- D8: output paths --------------------------------------------------

def test_outputs_never_overwrite_the_input():
    import shutil
    fails = []
    d = _tmp()
    src = os.path.join(d, "noext")          # no `.aeth`: str.replace no-op
    shutil.copy(BROKEN, src)
    with open(src, "a", encoding="utf-8") as f:
        f.write("// non-ASCII kept as UTF-8: \u2014 \u00e9\n")
    before = open(src, "rb").read()
    rc, _o, err = _run(["fix-loop", src, "--quiet"])
    if open(src, "rb").read() != before:
        fails.append("  the input was overwritten")
    for out in ("noext.fixed.aeth", "noext.transcript.json"):
        p = os.path.join(d, out)
        if not os.path.isfile(p):
            fails.append(f"  {out} not written (rc={rc}, {err[-200:]!r})")
            continue
        raw = open(p, "rb").read()
        if b"\r\n" in raw:
            fails.append(f"  {out} has CRLF line ends")
        raw.decode("utf-8")
    if "\u2014".encode("utf-8") not in open(os.path.join(d, "noext.fixed.aeth"), "rb").read():
        fails.append("  fixed source is not UTF-8")
    rc, _o, err = _run(["fix-loop", src, "--out-source", src, "--quiet"])
    if rc != 2 or open(src, "rb").read() != before:
        fails.append(f"  --out-source == input: rc={rc}, input intact="
                     f"{open(src, 'rb').read() == before}")
    return fails


def main() -> int:
    cases = [
        ("help documents both paths", test_help_documents_both_paths),
        ("default does not call anthropic", test_default_does_not_call_anthropic),
        ("live without API key fails clean", test_live_without_api_key_fails_clean),
        ("deterministic path needs no demos/ (BUG-026)",
         test_deterministic_path_needs_no_demos_dir),
        ("attack demos end not_repaired (D1)", test_attack_demos_end_not_repaired),
        ("fix-loop never widens any repo file (D1)",
         test_fix_loop_never_widens_any_repo_file),
        ("widening is judged structurally (D1)", test_widening_is_structural),
        ("E0801 patch target is the call site (D1)",
         test_patch_target_E0801_is_the_call_site),
        ("--live verdict rejects a widening fix (D1)",
         test_live_verdict_rejects_a_widening_fix),
        ("outputs never overwrite the input; UTF-8/LF (D8)",
         test_outputs_never_overwrite_the_input),
    ]
    passed = 0
    failures = {}
    for name, fn in cases:
        fs = fn()
        if fs:
            failures[name] = fs
        else:
            passed += 1
    total = len(cases)
    print(f"H.A.2 fix_loop_cli: {passed}/{total}")
    if failures:
        print(f"--- {len(failures)} failure(s) ---")
        for n, fs in failures.items():
            print(f"FAIL {n}")
            for line in fs:
                print(line)
        return 1
    print("H.A.2 fix_loop_cli: ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
