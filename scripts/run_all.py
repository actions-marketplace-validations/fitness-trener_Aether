"""Run every reference program, every benchmark reference solution, and
the regression test suite.

Exit 0 if everything passes, 1 otherwise.
"""

from __future__ import annotations
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    results = {"reference_programs": [], "benchmark_tasks": [], "regression_tests": None}

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

    reg = os.path.join(ROOT, "tests", "test_regressions.py")
    if os.path.isfile(reg):
        cmd = [sys.executable, "-B", reg]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["regression_tests"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    static_eff = os.path.join(ROOT, "tests", "test_static_effects.py")
    if os.path.isfile(static_eff):
        cmd = [sys.executable, "-B", static_eff]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["static_effects"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    scope_t = os.path.join(ROOT, "tests", "test_effect_scope.py")
    if os.path.isfile(scope_t):
        cmd = [sys.executable, "-B", scope_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["effect_scope"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    rte_t = os.path.join(ROOT, "tests", "test_runtime_enforcement.py")
    if os.path.isfile(rte_t):
        cmd = [sys.executable, "-B", rte_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["runtime_enforcement"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    fp_t = os.path.join(ROOT, "tests", "test_false_positive_corpus.py")
    if os.path.isfile(fp_t):
        cmd = [sys.executable, "-B", fp_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["false_positive"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    corpus_t = os.path.join(ROOT, "tests", "test_corpus.py")
    if os.path.isfile(corpus_t):
        cmd = [sys.executable, "-B", corpus_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["corpus"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    ex_t = os.path.join(ROOT, "tests", "test_exhaustiveness.py")
    if os.path.isfile(ex_t):
        cmd = [sys.executable, "-B", ex_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["exhaustiveness"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    scan_t = os.path.join(ROOT, "tests", "test_scan.py")
    if os.path.isfile(scan_t):
        cmd = [sys.executable, "-B", scan_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["scan_tool"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    risk_t = os.path.join(ROOT, "tests", "test_risk.py")
    if os.path.isfile(risk_t):
        cmd = [sys.executable, "-B", risk_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["risk"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    # The Python frontend's two contracts. `test_py_soundness.py` guards
    # the capability tables (nothing UNPROVABLE may become clean) and is
    # cited as "4/4 green" by four result documents, but it was never in
    # the gate — it only ran when someone ran it by hand. A test file not
    # in the gate does not exist.
    for _name, _rel in (("py_soundness", "test_py_soundness.py"),
                        ("py_frontend_sinks", "test_py_frontend_sinks.py"),
                        # The published Action only ever executes in someone
                        # else's workflow, so every way it can drift from the
                        # CLI is invisible here unless it is asserted here.
                        ("action", "test_action.py")):
        _t = os.path.join(ROOT, "tests", _rel)
        if os.path.isfile(_t):
            r = subprocess.run([sys.executable, "-B", _t], cwd=ROOT, env=env,
                               capture_output=True, text=True)
            results[_name] = {
                "ok": r.returncode == 0,
                "stdout": r.stdout.strip(),
                "stderr": r.stderr.strip(),
            }

    ratchet_t = os.path.join(ROOT, "tests", "test_ratchet.py")
    if os.path.isfile(ratchet_t):
        cmd = [sys.executable, "-B", ratchet_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["ratchet"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    pr = os.path.join(ROOT, "tests", "test_parser_recovery.py")
    if os.path.isfile(pr):
        cmd = [sys.executable, "-B", pr]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["parser_recovery"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    det = os.path.join(ROOT, "tests", "test_deterministic.py")
    if os.path.isfile(det):
        cmd = [sys.executable, "-B", det]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["deterministic"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    rt = os.path.join(ROOT, "tests", "test_pretty_roundtrip.py")
    if os.path.isfile(rt):
        cmd = [sys.executable, "-B", rt]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["pretty_roundtrip"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    fmt = os.path.join(ROOT, "tests", "test_fmt.py")
    if os.path.isfile(fmt):
        cmd = [sys.executable, "-B", fmt]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["fmt"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    sdk_t = os.path.join(ROOT, "tests", "test_sdk.py")
    if os.path.isfile(sdk_t):
        cmd = [sys.executable, "-B", sdk_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["sdk"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    lsp_t = os.path.join(ROOT, "tests", "test_lsp.py")
    if os.path.isfile(lsp_t):
        cmd = [sys.executable, "-B", lsp_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["lsp"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    d1_t = os.path.join(ROOT, "tests", "test_stdlib_d1.py")
    if os.path.isfile(d1_t):
        cmd = [sys.executable, "-B", d1_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["stdlib_d1"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    d2_t = os.path.join(ROOT, "tests", "test_diagnostic_catalog.py")
    if os.path.isfile(d2_t):
        cmd = [sys.executable, "-B", d2_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["diagnostic_catalog"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    d3_t = os.path.join(ROOT, "tests", "test_module_validation.py")
    if os.path.isfile(d3_t):
        cmd = [sys.executable, "-B", d3_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["module_validation"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    mf_t = os.path.join(ROOT, "tests", "test_multi_file.py")
    if os.path.isfile(mf_t):
        cmd = [sys.executable, "-B", mf_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["multi_file"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    smt_t = os.path.join(ROOT, "tests", "test_smt.py")
    if os.path.isfile(smt_t):
        cmd = [sys.executable, "-B", smt_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["smt"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    bb_t = os.path.join(ROOT, "tests", "test_stdlib_bytes.py")
    if os.path.isfile(bb_t):
        cmd = [sys.executable, "-B", bb_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["stdlib_bytes"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    pack_t = os.path.join(ROOT, "tests", "test_pack.py")
    if os.path.isfile(pack_t):
        cmd = [sys.executable, "-B", pack_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["pack"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    rel_t = os.path.join(ROOT, "tests", "test_release_emit.py")
    if os.path.isfile(rel_t):
        cmd = [sys.executable, "-B", rel_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["release_emit"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    arch_bench = os.path.join(ROOT, "bench", "architectural", "run_bench.py")
    if os.path.isfile(arch_bench):
        cmd = [sys.executable, "-B", arch_bench]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["architectural_bench"] = {
            "ok": r.returncode == 0,
            "stdout_tail": (r.stdout or "").strip().splitlines()[-6:],
            "stderr": (r.stderr or "").strip()[:400],
        }

    f_t = os.path.join(ROOT, "tests", "test_fix_loop_demo.py")
    if os.path.isfile(f_t):
        cmd = [sys.executable, "-B", f_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["fix_loop_demo"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    # H.A.1 - alsp corpus (patch_target + structured diagnostic regression)
    alsp_t = os.path.join(ROOT, "tests", "test_alsp_corpus.py")
    if os.path.isfile(alsp_t):
        cmd = [sys.executable, "-B", alsp_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["alsp_corpus"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    # H.A.2 - fix-loop CLI (deterministic/live split, never conflated)
    flc_t = os.path.join(ROOT, "tests", "test_fix_loop_cli.py")
    if os.path.isfile(flc_t):
        cmd = [sys.executable, "-B", flc_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["fix_loop_cli"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
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

    llm_t = os.path.join(ROOT, "tests", "test_llm_fix_demo.py")
    if os.path.isfile(llm_t):
        cmd = [sys.executable, "-B", llm_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["llm_fix_demo"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    pkg_t = os.path.join(ROOT, "tests", "test_packaging.py")
    if os.path.isfile(pkg_t):
        cmd = [sys.executable, "-B", pkg_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["packaging"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

    pg_t = os.path.join(ROOT, "tests", "test_playground.py")
    if os.path.isfile(pg_t):
        cmd = [sys.executable, "-B", pg_t]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["playground"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": (r.stderr or "").strip()[:400],
        }

    demos = os.path.join(ROOT, "demos", "architectural-integrity", "run_demos.py")
    if os.path.isfile(demos):
        cmd = [sys.executable, "-B", demos]
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        results["architectural_integrity_demos"] = {
            "ok": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }

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
    reg_ok = bool(results["regression_tests"] and results["regression_tests"]["ok"])
    fuzz_ok = bool(results.get("parser_fuzz") and results["parser_fuzz"]["ok"])
    static_ok = bool(results.get("static_effects") and results["static_effects"]["ok"])
    scope_ok = bool(results.get("effect_scope") and results["effect_scope"]["ok"])
    rte_ok = bool(results.get("runtime_enforcement") and results["runtime_enforcement"]["ok"])
    fp_ok = bool(results.get("false_positive") and results["false_positive"]["ok"])
    corpus_ok = bool(results.get("corpus") and results["corpus"]["ok"])
    # Read the count out of the suite's own line rather than restating it:
    # the literal here said 83 while the corpus had grown to 93, and a
    # summary that has to be edited by hand is a summary that goes stale.
    n_corpus = "?"
    _m = re.search(r"corpus: (\d+) programs",
                   (results.get("corpus") or {}).get("stdout", "") or "")
    if _m:
        n_corpus = _m.group(1)
    ex_ok = bool(results.get("exhaustiveness") and results["exhaustiveness"]["ok"])
    scan_ok = bool(results.get("scan_tool") and results["scan_tool"]["ok"])
    risk_ok = bool(results.get("risk") and results["risk"]["ok"])
    ratchet_ok = bool(results.get("ratchet") and results["ratchet"]["ok"])
    pysound_ok = bool(results.get("py_soundness") and results["py_soundness"]["ok"])
    pysink_ok = bool(results.get("py_frontend_sinks")
                     and results["py_frontend_sinks"]["ok"])
    action_ok = bool(results.get("action") and results["action"]["ok"])
    recovery_ok = bool(results.get("parser_recovery") and results["parser_recovery"]["ok"])
    det_ok = bool(results.get("deterministic") and results["deterministic"]["ok"])
    rt_ok = bool(results.get("pretty_roundtrip") and results["pretty_roundtrip"]["ok"])
    fmt_ok = bool(results.get("fmt") and results["fmt"]["ok"])
    sdk_ok = bool(results.get("sdk") and results["sdk"]["ok"])
    lsp_ok = bool(results.get("lsp") and results["lsp"]["ok"])
    d1_ok = bool(results.get("stdlib_d1") and results["stdlib_d1"]["ok"])
    d2_ok = bool(results.get("diagnostic_catalog") and results["diagnostic_catalog"]["ok"])
    d3_ok = bool(results.get("module_validation") and results["module_validation"]["ok"])
    mf_ok = bool(results.get("multi_file") and results["multi_file"]["ok"])
    smt_ok = bool(results.get("smt") and results["smt"]["ok"])
    bb_ok = bool(results.get("stdlib_bytes") and results["stdlib_bytes"]["ok"])
    pack_ok = bool(results.get("pack") and results["pack"]["ok"])
    rel_ok = bool(results.get("release_emit") and results["release_emit"]["ok"])
    arch_ok = bool(results.get("architectural_bench") and results["architectural_bench"]["ok"])
    f_ok = bool(results.get("fix_loop_demo") and results["fix_loop_demo"]["ok"])
    alsp_ok = bool(results.get("alsp_corpus") and results["alsp_corpus"]["ok"])
    flc_ok = bool(results.get("fix_loop_cli") and results["fix_loop_cli"]["ok"])
    capfw_ok = bool(results.get("capability_firewall")
                    and results["capability_firewall"]["ok"])
    llm_ok = bool(results.get("llm_fix_demo") and results["llm_fix_demo"]["ok"])
    pkg_ok = bool(results.get("packaging") and results["packaging"]["ok"])
    pg_ok = bool(results.get("playground") and results["playground"]["ok"])
    demos_ok = bool(results.get("architectural_integrity_demos")
                    and results["architectural_integrity_demos"]["ok"])
    print(f"# reference:      {n_ref_ok}/{n_ref}", file=sys.stderr)
    print(f"# bench:          {n_bench_ok}/{n_bench}", file=sys.stderr)
    print(f"# regression:     {'PASS' if reg_ok else 'FAIL'}", file=sys.stderr)
    print(f"# static_effects: {'PASS' if static_ok else 'FAIL'} (B.1)", file=sys.stderr)
    print(f"# effect_scope:   {'PASS' if scope_ok else 'FAIL'} (E0710: SSRF host-pin)", file=sys.stderr)
    print(f"# runtime_enforce:{'PASS' if rte_ok else 'FAIL'} (8 defenses defang real payloads)", file=sys.stderr)
    print(f"# false_positive: {'PASS' if fp_ok else 'FAIL'} (every fixed.aeth + clean examples, 0 diagnostics)", file=sys.stderr)
    print(f"# corpus:         {'PASS' if corpus_ok else 'FAIL'} ({n_corpus} programs state + meet their own expectation)", file=sys.stderr)
    print(f"# static_semantic: {'PASS' if ex_ok else 'FAIL'} (E0202-E0207: match/reachability/dead-store/error/impossible-type)", file=sys.stderr)
    print(f"# scan_tool:      {'PASS' if scan_ok else 'FAIL'} (tools/scan.py corpus scanner)", file=sys.stderr)
    print(f"# risk:           {'PASS' if risk_ok else 'FAIL'} (diagnostic risk ratings)", file=sys.stderr)
    print(f"# ratchet:        {'PASS' if ratchet_ok else 'FAIL'} (monotonic: detector count never drops)", file=sys.stderr)
    print(f"# parser_recovery:{'PASS' if recovery_ok else 'FAIL'} (C.6)", file=sys.stderr)
    print(f"# deterministic:  {'PASS' if det_ok else 'FAIL'} (C.5)", file=sys.stderr)
    print(f"# pretty_roundtrip:{'PASS' if rt_ok else 'FAIL'} (C.1)", file=sys.stderr)
    print(f"# fmt:             {'PASS' if fmt_ok else 'FAIL'} (C.4)", file=sys.stderr)
    print(f"# sdk:             {'PASS' if sdk_ok else 'FAIL'} (C.2)", file=sys.stderr)
    print(f"# lsp:             {'PASS' if lsp_ok else 'FAIL'} (C.3)", file=sys.stderr)
    print(f"# stdlib_d1:      {'PASS' if d1_ok else 'FAIL'} (D.1)", file=sys.stderr)
    print(f"# diag_catalog:   {'PASS' if d2_ok else 'FAIL'} (D.2)", file=sys.stderr)
    print(f"# module_valid:   {'PASS' if d3_ok else 'FAIL'} (D.3)", file=sys.stderr)
    print(f"# multi_file:     {'PASS' if mf_ok else 'FAIL'} (H.E.3: imports)", file=sys.stderr)
    print(f"# smt:            {'PASS' if smt_ok else 'FAIL'} (v2 1.1: --prove)", file=sys.stderr)
    print(f"# stdlib_bytes:   {'PASS' if bb_ok else 'FAIL'} (wave 1: bitwise + bytes bridge)", file=sys.stderr)
    print(f"# pack:           {'PASS' if pack_ok else 'FAIL'} (wave 1: python interop)", file=sys.stderr)
    print(f"# release_emit:   {'PASS' if rel_ok else 'FAIL'} (wave 1: --release)", file=sys.stderr)
    print(f"# arch_bench:     {'PASS' if arch_ok else 'FAIL'} (E: 10 tasks)", file=sys.stderr)
    print(f"# fix_loop_demo: {'PASS' if f_ok else 'FAIL'} (F: payment + fix-loop)", file=sys.stderr)
    print(f"# alsp_corpus:    {'PASS' if alsp_ok else 'FAIL'} (H.A.1: 30 programs)", file=sys.stderr)
    print(f"# fix_loop_cli:   {'PASS' if flc_ok else 'FAIL'} (H.A.2: split + dispatch)", file=sys.stderr)
    print(f"# capability_fw:  {'PASS' if capfw_ok else 'FAIL'} (H.A.3: firewall demo)", file=sys.stderr)
    print(f"# llm_fix_demo:  {'PASS' if llm_ok else 'FAIL'} (H.A: replay + L2 skip)", file=sys.stderr)
    print(f"# packaging:     {'PASS' if pkg_ok else 'FAIL'} (H.B.1: aether-lang)", file=sys.stderr)
    print(f"# playground:    {'PASS' if pg_ok else 'FAIL'} (H.B.2: sandbox)", file=sys.stderr)
    print(f"# demos:          {'PASS' if demos_ok else 'FAIL'} (5 pairs, B.6)", file=sys.stderr)
    print(f"# fuzz:           {'PASS' if fuzz_ok else 'FAIL'} (200 rounds x 3 modes)", file=sys.stderr)
    print(f"# py_soundness:  {'PASS' if pysound_ok else 'FAIL'} (nothing UNPROVABLE becomes clean)", file=sys.stderr)
    print(f"# py_sinks:      {'PASS' if pysink_ok else 'FAIL'} (sinks fire on unmodified Python)", file=sys.stderr)
    print(f"# action:        {'PASS' if action_ok else 'FAIL'} (action.yml stays wired to the CLI)", file=sys.stderr)
    everything = ((n_ref_ok == n_ref) and (n_bench_ok == n_bench) and reg_ok
                  and static_ok and recovery_ok and det_ok and rt_ok and fmt_ok
                  and sdk_ok and lsp_ok and d1_ok and d2_ok and d3_ok and mf_ok
                  and smt_ok and bb_ok and pack_ok and rel_ok
                  and arch_ok and f_ok and llm_ok and pkg_ok and pg_ok
                  and demos_ok and fuzz_ok and scope_ok and rte_ok and fp_ok
                  and ex_ok and scan_ok and risk_ok and ratchet_ok and corpus_ok
                  and alsp_ok and flc_ok and capfw_ok
                  and pysound_ok and pysink_ok and action_ok)
    return 0 if everything else 1


if __name__ == "__main__":
    raise SystemExit(main())
