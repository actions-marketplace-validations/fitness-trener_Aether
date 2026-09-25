"""Run every reference program, every benchmark reference solution, and
the regression test suite.

Exit 0 if everything passes, 1 otherwise.

Test suites are DISCOVERED, not listed: every `tests/test_*.py` runs
unless `EXCLUDE` below names it with a reason. A hand-maintained list let
three suites (`test_cause_b.py`, `test_phase1.py`, `test_mining.py`)
never run, and one of them was red (audit 2026-09-24, F3). A test file
not in the gate does not exist.
"""

from __future__ import annotations
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# tests/test_*.py files the gate does NOT run, each with its reason.
# Empty on purpose: every suite in tests/ is fast, offline and green. Add
# an entry only with a reason a reviewer can check — never to hide red.
EXCLUDE: dict = {}

# The summary lines people read (and grep), keyed by suite file. A suite
# not named here still runs and gets a generic line. Order = print order.
LABELLED = {
    "test_regressions.py":          ("regression_tests", "regression:     ", ""),
    "test_static_effects.py":       ("static_effects", "static_effects: ", " (B.1)"),
    "test_effect_scope.py":         ("effect_scope", "effect_scope:   ", " (E0710: SSRF host-pin)"),
    "test_runtime_enforcement.py":  ("runtime_enforcement", "runtime_enforce:", " (8 defenses defang real payloads)"),
    "test_false_positive_corpus.py": ("false_positive", "false_positive: ", " (every fixed.aeth + clean examples, 0 diagnostics)"),
    "test_corpus.py":               ("corpus", "corpus:         ", " ({n_corpus} programs state + meet their own expectation)"),
    "test_exhaustiveness.py":       ("exhaustiveness", "static_semantic: ", " (E0202-E0207: match/reachability/dead-store/error/impossible-type)"),
    "test_scan.py":                 ("scan_tool", "scan_tool:      ", " (tools/scan.py corpus scanner)"),
    "test_risk.py":                 ("risk", "risk:           ", " (diagnostic risk ratings)"),
    "test_confidence.py":           ("confidence", "confidence:     ", " (per-finding match-kind confidence)"),
    "test_ratchet.py":              ("ratchet", "ratchet:        ", " (monotonic: detectors, recall floor, merge-base)"),
    "test_parser_recovery.py":      ("parser_recovery", "parser_recovery:", " (C.6)"),
    "test_deterministic.py":        ("deterministic", "deterministic:  ", " (C.5)"),
    "test_pretty_roundtrip.py":     ("pretty_roundtrip", "pretty_roundtrip:", " (C.1)"),
    "test_fmt.py":                  ("fmt", "fmt:             ", " (C.4)"),
    "test_sdk.py":                  ("sdk", "sdk:             ", " (C.2)"),
    "test_lsp.py":                  ("lsp", "lsp:             ", " (C.3)"),
    "test_stdlib_d1.py":            ("stdlib_d1", "stdlib_d1:      ", " (D.1)"),
    "test_diagnostic_catalog.py":   ("diagnostic_catalog", "diag_catalog:   ", " (D.2)"),
    "test_module_validation.py":    ("module_validation", "module_valid:   ", " (D.3)"),
    "test_multi_file.py":           ("multi_file", "multi_file:     ", " (H.E.3: imports)"),
    "test_smt.py":                  ("smt", "smt:            ", " (v2 1.1: --prove)"),
    "test_stdlib_bytes.py":         ("stdlib_bytes", "stdlib_bytes:   ", " (wave 1: bitwise + bytes bridge)"),
    "test_pack.py":                 ("pack", "pack:           ", " (wave 1: python interop)"),
    "test_release_emit.py":         ("release_emit", "release_emit:   ", " (wave 1: --release)"),
    "test_fix_loop_demo.py":        ("fix_loop_demo", "fix_loop_demo: ", " (F: payment + fix-loop)"),
    "test_alsp_corpus.py":          ("alsp_corpus", "alsp_corpus:    ", " (H.A.1: 30 programs)"),
    "test_fix_loop_cli.py":         ("fix_loop_cli", "fix_loop_cli:   ", " (H.A.2: split + dispatch)"),
    "test_llm_fix_demo.py":         ("llm_fix_demo", "llm_fix_demo:  ", " (H.A: replay + L2 skip)"),
    "test_packaging.py":            ("packaging", "packaging:     ", " (H.B.1: aether-lang)"),
    "test_playground.py":           ("playground", "playground:    ", " (H.B.2: sandbox)"),
    "test_py_soundness.py":         ("py_soundness", "py_soundness:  ", " (nothing UNPROVABLE becomes clean)"),
    "test_py_frontend_sinks.py":    ("py_frontend_sinks", "py_sinks:      ", " (sinks fire on unmodified Python)"),
    "test_action.py":               ("action", "action:        ", " (action.yml stays wired to the CLI)"),
}


def test_files() -> list:
    """Every suite the gate runs, sorted. `tests/test_ratchet.py` reads
    this too: only an assertion in a suite that RUNS can prove a code."""
    return sorted(p for p in glob.glob(os.path.join(ROOT, "tests", "test_*.py"))
                  if os.path.basename(p) not in EXCLUDE)


def _run(cmd, env) -> dict:
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    out = (r.stdout or "").strip()
    lines = out.splitlines()
    return {
        "ok": r.returncode == 0,
        # A suite that exits 0 and ends on `SKIP:` ran nothing (test_smt.py
        # without z3). That is not a failure, and it is not a PASS either.
        "skipped": r.returncode == 0 and bool(lines) and lines[-1].startswith("SKIP:"),
        "stdout": out,
        "stderr": (r.stderr or "").strip()[:4000],
    }


def _status(res) -> str:
    if not res or not res["ok"]:
        return "FAIL"
    return "SKIP" if res.get("skipped") else "PASS"


def main() -> int:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    results = {"reference_programs": [], "benchmark_tasks": []}

    refdir = os.path.join(ROOT, "reference")
    for d in sorted(os.listdir(refdir)):
        td = os.path.join(refdir, d)
        if not os.path.isdir(td):
            continue
        cmd = [sys.executable, "-B", "-m", "transpiler.aether.cli", "test", td]
        r = subprocess.run(cmd, cwd=ROOT, env=env,
                           capture_output=True, text=True)
        results["reference_programs"].append(
            {"id": d, "ok": r.returncode == 0,
             "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
        )

    cmd = [sys.executable, "-B", "-m", "bench.harness", "run-reference"]
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    try:
        results["benchmark_tasks"] = json.loads(r.stdout)
    except Exception:
        results["benchmark_tasks"] = [
            {"ok": False, "raw": r.stdout, "err": r.stderr}
        ]

    suites = {}          # file name -> result key
    for path in test_files():
        name = os.path.basename(path)
        key = LABELLED.get(name, (name[len("test_"):-len(".py")],))[0]
        suites[name] = key
        results[key] = _run([sys.executable, "-B", path], env)

    arch_bench = os.path.join(ROOT, "bench", "architectural", "run_bench.py")
    if os.path.isfile(arch_bench):
        cmd = [sys.executable, "-B", arch_bench]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["architectural_bench"] = {
            "ok": r.returncode == 0,
            "stdout_tail": (r.stdout or "").strip().splitlines()[-6:],
            "stderr": (r.stderr or "").strip()[:400],
        }

    # H.A.3 - capability firewall demo (Aether check must reject .aeth)
    capfw = os.path.join(ROOT, "demos", "capability-firewall",
                         "log_formatter.aeth")
    if os.path.isfile(capfw):
        cmd = [sys.executable, "-B", "-m", "transpiler.aether.cli",
               "--json", "check", capfw]
        r = subprocess.run(cmd, cwd=ROOT, env=env,
                           capture_output=True, text=True)
        combined = (r.stdout or "") + (r.stderr or "")
        rejected = (r.returncode != 0
                    and ("E0801" in combined or "E0701" in combined))
        results["capability_firewall"] = {
            "ok": rejected,
            "exit_code": r.returncode,
        }

    demos = os.path.join(ROOT, "demos", "architectural-integrity", "run_demos.py")
    if os.path.isfile(demos):
        results["architectural_integrity_demos"] = _run(
            [sys.executable, "-B", demos], env)

    fuzz = os.path.join(ROOT, "scripts", "fuzz_parser.py")
    if os.path.isfile(fuzz):
        cmd = [sys.executable, "-B", fuzz, "--rounds", "200", "--mode", "all"]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["parser_fuzz"] = {
            "ok": r.returncode == 0,
            "stdout_tail": r.stdout.strip().splitlines()[-12:] if r.stdout else [],
            "stderr": r.stderr.strip()[:400],
        }

    print(json.dumps(results, indent=2))

    n_ref_ok = sum(1 for r in results["reference_programs"] if r.get("ok"))
    n_ref = len(results["reference_programs"])
    n_bench_ok = sum(1 for r in results["benchmark_tasks"] if r.get("ok"))
    n_bench = len(results["benchmark_tasks"])
    # Read the count out of the suite's own line rather than restating it:
    # a summary that has to be edited by hand is a summary that goes stale.
    n_corpus = "?"
    _m = re.search(r"corpus: (\d+) programs",
                   (results.get("corpus") or {}).get("stdout", "") or "")
    if _m:
        n_corpus = _m.group(1)

    def line(text):
        print(f"# {text}", file=sys.stderr)

    line(f"reference:      {n_ref_ok}/{n_ref}")
    line(f"bench:          {n_bench_ok}/{n_bench}")
    for name, (key, head, tail) in LABELLED.items():
        if name in suites:
            line(f"{head}{_status(results.get(key))}{tail.format(n_corpus=n_corpus)}")
        elif name not in EXCLUDE:
            # A labelled suite that vanished is a failure, not a quiet
            # shrink of the gate.
            results[key] = None
            line(f"{head}FAIL (tests/{name} is missing)")
    for name in sorted(set(suites) - set(LABELLED)):
        line(f"{suites[name]}: {_status(results[suites[name]])} (tests/{name})")
    other = (("architectural_bench", "arch_bench:     ", " (E: 10 tasks)"),
             ("capability_firewall", "capability_fw:  ", " (H.A.3: firewall demo)"),
             ("architectural_integrity_demos", "demos:          ", " (5 pairs, B.6)"),
             ("parser_fuzz", "fuzz:           ", " (200 rounds x 3 modes)"))
    for key, head, tail in other:
        line(f"{head}{_status(results.get(key))}{tail}")
    skipped = [k for k, v in results.items()
               if isinstance(v, dict) and v.get("skipped")]
    if skipped:
        line(f"SKIPPED (not counted as PASS): {', '.join(skipped)}")

    everything = ((n_ref_ok == n_ref) and (n_bench_ok == n_bench)
                  and all(results.get(k) and results[k]["ok"]
                          for k in [*suites.values(), *(k for k, _h, _t in other)])
                  and all(results.get(k) is not None
                          for n, (k, _h, _t) in LABELLED.items()
                          if n not in EXCLUDE))
    return 0 if everything else 1


if __name__ == "__main__":
    raise SystemExit(main())
