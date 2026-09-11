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

Script-style test matching `tests/test_regressions.py` (no
TestCase wrapper). Exits 0 on full pass, 1 otherwise.
"""
from __future__ import annotations
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
    if "OK rc=0" not in (r.stdout or ""):
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
        if r.returncode != 0:
            fails.append(f"exit {r.returncode}: {r.stderr.strip()[-400:]}")
        elif not os.path.isfile(fixed):
            fails.append("exit 0 but no fixed source was written")
    return fails


def main() -> int:
    cases = [
        ("help documents both paths", test_help_documents_both_paths),
        ("default does not call anthropic", test_default_does_not_call_anthropic),
        ("live without API key fails clean", test_live_without_api_key_fails_clean),
        ("deterministic path needs no demos/ (BUG-026)",
         test_deterministic_path_needs_no_demos_dir),
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
