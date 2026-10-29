"""E.2 architectural-integrity benchmark harness.

For every task in `bench/architectural/T*` the harness drives four
variants through the toolchain and the Python interpreter, then
classifies the outcome against the task's `grader.json` contract.

For each task we measure four cells:

    +---------------+-------------------------------+
    | variant       | expected behaviour            |
    +---------------+-------------------------------+
    | naive Aether  | rejected (exit 1 + diag code) |
    | naive Python  | runs cleanly, wrong output    |
    | correct Aether| runs cleanly, expected stdout |
    | correct Python| runs cleanly, expected stdout |
    +---------------+-------------------------------+

The headline rates produced from a green run:

  - **Aether catch rate** = (naive Aether rejected) / (total tasks)
  - **Python silent-failure rate** = (naive Python ran to exit 0
    without warning) / (total tasks)
  - **False-alarm rate** = (correct Aether rejected) / (total tasks)
  - **Aether viability** = (correct Aether runs cleanly) / (total tasks)

A task is fully PASS only if all four cells match the grader; otherwise
the task is FAIL and the report records which cells diverged.

Exit 0 only if every task is fully PASS.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PY = sys.executable


def _run(cmd: List[str]) -> Dict[str, Any]:
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}


def _expect(actual: Dict[str, Any], spec: Dict[str, Any]) -> Optional[str]:
    """Return None if everything matches `spec`, else a brief reason."""
    exp_rc = spec.get("expected_exit_code")
    if exp_rc is not None and actual["rc"] != exp_rc:
        return f"exit {actual['rc']} != {exp_rc}"
    exp_stdout = spec.get("expected_stdout")
    if exp_stdout is not None and actual["stdout"] != exp_stdout:
        return f"stdout {actual['stdout']!r} != {exp_stdout!r}"
    pat = spec.get("expected_stdout_pattern")
    if pat is not None and not re.search(pat, actual["stdout"]):
        return f"stdout pattern miss: {pat!r}"
    diag = spec.get("expected_diagnostic_code")
    if diag is not None and diag not in actual["stderr"]:
        return f"diagnostic {diag} not in stderr"
    diag_pat = spec.get("expected_stderr_pattern")
    if diag_pat is not None:
        combined = (actual["stdout"] or "") + "\n" + (actual["stderr"] or "")
        if not re.search(diag_pat, combined):
            return f"stderr pattern miss: {diag_pat!r}"
    return None


def _run_variant(task_dir: str, variant: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    stage = spec.get("stage", "run")
    if variant.endswith("_aether"):
        sub_dir = "naive" if variant.startswith("naive") else "correct"
        src_path = os.path.join(task_dir, sub_dir, "main.aeth")
        sub_cmd = "check" if stage == "check" else "run"
        cmd = [PY, "-B", "-m", "transpiler.aether.cli", sub_cmd, src_path]
    else:
        sub_dir = "naive" if variant.startswith("naive") else "correct"
        src_path = os.path.join(task_dir, sub_dir, "main.py")
        cmd = [PY, "-B", src_path]
    actual = _run(cmd)
    reason = _expect(actual, spec)
    return {
        "variant": variant, "src": src_path,
        "actual": {"rc": actual["rc"],
                   "stdout_tail": (actual["stdout"] or "").strip().splitlines()[-3:],
                   "stderr_tail": (actual["stderr"] or "").strip().splitlines()[-3:]},
        "spec": spec,
        "passed": reason is None,
        "fail_reason": reason,
    }


def _grade_task(task_dir: str) -> Dict[str, Any]:
    grader_path = os.path.join(task_dir, "grader.json")
    with open(grader_path) as f:
        grader = json.load(f)
    variants = ["naive_aether", "naive_python", "correct_aether", "correct_python"]
    results = []
    for v in variants:
        spec = grader.get(v)
        if not spec:
            continue
        results.append(_run_variant(task_dir, v, spec))
    return {
        "id": grader["id"],
        "axis": grader.get("axis", "unknown"),
        "summary": grader.get("summary", ""),
        "variants": results,
        "passed": all(r["passed"] for r in results),
    }


def _summary(tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(tasks)
    aether_caught = sum(
        1 for t in tasks
        for v in t["variants"]
        if v["variant"] == "naive_aether" and v["passed"]
    )
    python_silent = sum(
        1 for t in tasks
        for v in t["variants"]
        if v["variant"] == "naive_python" and v["passed"]
    )
    correct_aether_ok = sum(
        1 for t in tasks
        for v in t["variants"]
        if v["variant"] == "correct_aether" and v["passed"]
    )
    correct_python_ok = sum(
        1 for t in tasks
        for v in t["variants"]
        if v["variant"] == "correct_python" and v["passed"]
    )
    return {
        "tasks_total": n,
        "tasks_passed": sum(1 for t in tasks if t["passed"]),
        "aether_catch_rate": f"{aether_caught}/{n}",
        "python_silent_failure_rate": f"{python_silent}/{n}",
        "aether_correct_passes": f"{correct_aether_ok}/{n}",
        "python_correct_passes": f"{correct_python_ok}/{n}",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON to stdout")
    args = p.parse_args(argv)

    tasks = []
    for name in sorted(os.listdir(HERE)):
        d = os.path.join(HERE, name)
        if os.path.isdir(d) and name.startswith("T"):
            tasks.append(_grade_task(d))
    summary = _summary(tasks)
    output = {"summary": summary, "tasks": tasks}

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(f"Architectural-integrity benchmark: {summary['tasks_total']} tasks")
        for t in tasks:
            mark = "PASS" if t["passed"] else "FAIL"
            print(f"  [{mark}] {t['id']:38s} axis={t['axis']:8s} {t['summary']}")
            if not t["passed"]:
                for v in t["variants"]:
                    if not v["passed"]:
                        print(f"     - {v['variant']:16s} {v['fail_reason']}")
        print()
        print(f"  Aether catch rate          : {summary['aether_catch_rate']}")
        print(f"  Python silent-failure rate : {summary['python_silent_failure_rate']}")
        print(f"  Correct Aether passes      : {summary['aether_correct_passes']}")
        print(f"  Correct Python passes      : {summary['python_correct_passes']}")
    return 0 if all(t["passed"] for t in tasks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
