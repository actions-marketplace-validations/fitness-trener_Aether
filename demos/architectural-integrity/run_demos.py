#!/usr/bin/env python3
"""Grades each demo pair in the architectural-integrity corpus.

For each demo directory:
  - run `python3 -m transpiler.aether.cli check` (or `run` for B.4) on
    aether/main.aeth and confirm the exit code + stderr pattern match
    aether/grader.json.
  - run python/main.py and confirm exit 0 — that's the wedge: Python's
    version of the same architectural error is invisible.

Prints a per-demo PASS/FAIL line and a final summary. Exit 1 on any
failure so this runner can be wired into scripts/run_all.py.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


# Some refinement-boundary errors only surface at run time (B.4) — for
# those we use the `run` subcommand, otherwise `check`.
RUN_INSTEAD_OF_CHECK = {"demo_04_refinement_boundary"}


def _run(cmd, **kw):
    return subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, **kw
    )


def grade(demo_dir):
    name = os.path.basename(demo_dir)
    grader_path = os.path.join(demo_dir, "aether", "grader.json")
    aether_src = os.path.join(demo_dir, "aether", "main.aeth")
    python_src = os.path.join(demo_dir, "python", "main.py")
    with open(grader_path) as f:
        grader = json.load(f)
    sub = "run" if name in RUN_INSTEAD_OF_CHECK else "check"
    a = _run([sys.executable, "-B", "-m", "transpiler.aether.cli", sub, aether_src])
    expected_exit = grader.get("expected_exit_code", 1)
    pattern = grader.get("expected_stderr_pattern", "")
    a_ok = (a.returncode == expected_exit)
    if pattern:
        combined = (a.stdout or "") + "\n" + (a.stderr or "")
        a_ok = a_ok and bool(re.search(pattern, combined))
    p = _run([sys.executable, "-B", python_src])
    p_ok = (p.returncode == 0)
    return name, a_ok, p_ok, a, p


def main():
    demos = sorted(
        os.path.join(HERE, d) for d in os.listdir(HERE)
        if os.path.isdir(os.path.join(HERE, d)) and d.startswith("demo_")
    )
    all_ok = True
    print(f"Architectural-integrity demo corpus: {len(demos)} pairs\n")
    for d in demos:
        name, a_ok, p_ok, a, p = grade(d)
        status = "PASS" if (a_ok and p_ok) else "FAIL"
        if not (a_ok and p_ok):
            all_ok = False
        print(f"  [{status}] {name}")
        if not a_ok:
            print(f"     aether: exit={a.returncode} stderr_tail={a.stderr.strip().splitlines()[-3:] if a.stderr else []!r}")
        if not p_ok:
            print(f"     python: exit={p.returncode} stderr_tail={p.stderr.strip().splitlines()[-3:] if p.stderr else []!r}")
    print()
    print("ALL DEMOS PASS" if all_ok else "DEMO CORPUS FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
