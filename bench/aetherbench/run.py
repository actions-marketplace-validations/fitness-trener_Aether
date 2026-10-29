"""AetherBench runner — drive a model over the task set and grade it.

    python -B bench/aetherbench/run.py --model-cmd "claude -p" \
        [--mode full|nl|both] [--arms structured,prose] [--max-fix 4] \
        [--tasks t1_01_clamp,...] [--out bench/aetherbench/results/results.jsonl]

    python -B bench/aetherbench/run.py --replay-reference   # smoke test:
        # "model" replies with the reference solution; validates the
        # whole pipeline without an API.

Model contract: the command receives the full prompt on stdin and must
write the Aether source (optionally in a ``` fence) to stdout.

Grading stages per attempt:
    check  — `aether --json check` (parse + contracts + effects +
             capabilities + E0710-19), exit 0 required
    run    — transpile + execute (bench.harness), stdout must equal
             grader.json expected_stdout

Fix-loop ablation: when the first attempt fails, the repair loop is run
once per arm from the SAME failed attempt:
    structured — feedback is the full diagnostic JSON (code, position,
                 suggestion, extra) or a WRONG_OUTPUT record
    prose      — feedback is the bare human message + line number only

One JSONL row per attempt.
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from bench.harness import compile_and_run  # noqa: E402

TASKS_DIR = os.path.join(HERE, "tasks")
CARD = os.path.join(HERE, "language_card.md")


# ----------------------------------------------------------------------
# Model invocation
# ----------------------------------------------------------------------

def call_model(model_cmd: str, prompt: str, timeout_s: int = 600) -> str:
    p = subprocess.run(model_cmd, shell=True, input=prompt,
                       capture_output=True, text=True, timeout=timeout_s,
                       encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError("model command failed (%d): %s"
                           % (p.returncode, (p.stderr or "")[:500]))
    return p.stdout


def extract_code(reply: str) -> str:
    """Take the largest ``` fenced block, else the whole reply."""
    blocks, cur, in_block = [], [], False
    for line in reply.splitlines():
        if line.strip().startswith("```"):
            if in_block:
                blocks.append("\n".join(cur))
                cur = []
            in_block = not in_block
            continue
        if in_block:
            cur.append(line)
    if not blocks:
        return reply.strip() + "\n"
    return max(blocks, key=len).strip() + "\n"


# ----------------------------------------------------------------------
# Grading
# ----------------------------------------------------------------------

def aether_check_json(path: str):
    """Return (ok, diagnostic dict | None)."""
    p = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli",
         "--json", "check", path],
        capture_output=True, text=True, cwd=ROOT, timeout=120)
    if p.returncode == 0:
        return True, None
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    # One JSON document on stdout (0.5.0; it was JSONL on stderr).
    try:
        diags = json.loads(p.stdout).get("diagnostics") or []
    except (json.JSONDecodeError, AttributeError):
        diags = []
    if diags:
        return False, diags[0]
    # fallback: parse the classic "[Exxxx] ..." text form
    for line in out.splitlines():
        if line.startswith("[E"):
            code = line[1:line.index("]")]
            return False, {"code": code, "message": line.strip()[:500]}
    # Non-E sentinel (like WRONG_OUTPUT below): the CLI produced no
    # parseable diagnostic. NOT a compiler diagnostic code — kept out of
    # the E-space so the D.2 catalog invariant (every emitted Exxxx is
    # documented) is not tripped by a harness fallback.
    return False, {"code": "NO_DIAGNOSTIC", "message": out.strip()[:500]}


def grade(src: str, task_dir: str, attempt_path: str):
    """Full grade of one candidate. Returns a result dict."""
    os.makedirs(os.path.dirname(attempt_path), exist_ok=True)
    with open(attempt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    with open(os.path.join(task_dir, "grader.json"), encoding="utf-8") as f:
        grader = json.load(f)

    ok, diag = aether_check_json(attempt_path)
    if not ok:
        return {"stage": "check", "ok": False, "diag": diag,
                "stdout_match": False}

    res = compile_and_run(src, attempt_path,
                          stdin_text=grader.get("stdin", "") or "",
                          timeout_ms=grader.get("timeout_ms", 5000))
    if not res["ok"]:
        return {"stage": "run", "ok": False, "diag": res.get("diagnostic"),
                "stdout_match": False}
    if res["actual"] != grader["expected_stdout"]:
        return {"stage": "run", "ok": False,
                "diag": {"code": "WRONG_OUTPUT",
                         "expected": grader["expected_stdout"],
                         "actual": res["actual"]},
                "stdout_match": False}
    return {"stage": "run", "ok": True, "diag": None, "stdout_match": True}


def render_feedback(diag, arm: str) -> str:
    if diag is None:
        return ""
    if arm == "structured":
        return json.dumps(diag, indent=2)
    # prose arm: bare message + line, mimicking a plain compiler
    if diag.get("code") == "WRONG_OUTPUT":
        return "The program ran but printed the wrong output."
    pos = diag.get("position") or {}
    line = pos.get("line", "?") if isinstance(pos, dict) else "?"
    return "error at line %s: %s" % (line, diag.get("message", "unknown"))


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------

def build_prompt(card: str, task_prompt: str) -> str:
    return card + "\n\n---\n\n" + task_prompt


def fix_prompt(base_prompt: str, prev_src: str, feedback: str) -> str:
    return (base_prompt
            + "\n\n---\n\nYour previous program:\n\n```\n" + prev_src
            + "```\n\nIt failed with:\n\n```\n" + feedback
            + "\n```\n\nReply with ONLY the corrected Aether source code.")


def run_task(task_id, mode, model_cmd, replay, card, arms, max_fix,
             out_rows):
    task_dir = os.path.join(TASKS_DIR, task_id)
    tier = int(task_id[1])
    prompt_file = "prompt_full.md" if mode == "full" else "prompt_nl.md"
    with open(os.path.join(task_dir, prompt_file), encoding="utf-8") as f:
        base_prompt = build_prompt(card, f.read())

    attempts_dir = os.path.join(HERE, "results", "attempts")

    def attempt_file(arm, n):
        return os.path.join(attempts_dir,
                            "%s__%s__%s__a%d.aeth" % (task_id, mode, arm, n))

    def emit(arm, attempt, result, elapsed_ms, src_file):
        diag = result.get("diag") or {}
        out_rows.append({
            "task": task_id, "tier": tier, "mode": mode, "arm": arm,
            "attempt": attempt, "stage": result["stage"],
            "ok": result["ok"],
            "diag_code": diag.get("code"),
            "elapsed_ms": elapsed_ms, "src_file": src_file,
        })

    # --- initial generation (shared by all arms) ---
    t0 = time.time()
    if replay:
        with open(os.path.join(task_dir, "reference.aeth"),
                  encoding="utf-8") as f:
            src = f.read()
    else:
        src = extract_code(call_model(model_cmd, base_prompt))
    f0 = attempt_file("init", 0)
    result = grade(src, task_dir, f0)
    emit("init", 0, result, int((time.time() - t0) * 1000), f0)
    if result["ok"] or replay:
        return

    # --- fix loop per arm, from the same failed attempt ---
    for arm in arms:
        cur_src, cur_result = src, result
        for n in range(1, max_fix + 1):
            t0 = time.time()
            feedback = render_feedback(cur_result["diag"], arm)
            try:
                reply = call_model(model_cmd,
                                   fix_prompt(base_prompt, cur_src, feedback))
            except RuntimeError as e:
                out_rows.append({"task": task_id, "tier": tier, "mode": mode,
                                 "arm": arm, "attempt": n,
                                 "stage": "model-error", "ok": False,
                                 "diag_code": None,
                                 "elapsed_ms": int((time.time() - t0) * 1000),
                                 "src_file": None, "error": str(e)[:300]})
                break
            cur_src = extract_code(reply)
            fn = attempt_file(arm, n)
            cur_result = grade(cur_src, task_dir, fn)
            emit(arm, n, cur_result, int((time.time() - t0) * 1000), fn)
            if cur_result["ok"]:
                break


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-cmd", default=None,
                    help="shell command; prompt on stdin, code on stdout")
    ap.add_argument("--replay-reference", action="store_true",
                    help="smoke test: use reference solutions as the model")
    ap.add_argument("--mode", default="full", choices=["full", "nl", "both"])
    ap.add_argument("--arms", default="structured,prose")
    ap.add_argument("--max-fix", type=int, default=4)
    ap.add_argument("--tasks", default=None,
                    help="comma-separated task ids (default: all)")
    ap.add_argument("--out",
                    default=os.path.join(HERE, "results", "results.jsonl"))
    args = ap.parse_args()

    if not args.model_cmd and not args.replay_reference:
        ap.error("--model-cmd or --replay-reference required")

    with open(CARD, encoding="utf-8") as f:
        card = f.read()

    all_tasks = sorted(os.listdir(TASKS_DIR))
    task_ids = (args.tasks.split(",") if args.tasks else all_tasks)
    modes = ["full", "nl"] if args.mode == "both" else [args.mode]
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    for task_id in task_ids:
        for mode in modes:
            print("[aetherbench] %s (%s)" % (task_id, mode), flush=True)
            try:
                run_task(task_id, mode, args.model_cmd,
                         args.replay_reference, card, arms, args.max_fix,
                         rows)
            except Exception as e:  # one bad task must not kill the run
                rows.append({"task": task_id, "tier": int(task_id[1]),
                             "mode": mode, "arm": "init", "attempt": 0,
                             "stage": "harness-error", "ok": False,
                             "diag_code": None, "elapsed_ms": 0,
                             "src_file": None, "error": str(e)[:300]})
    with open(args.out, "a", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    n_ok = sum(1 for r in rows if r["attempt"] == 0 and r["ok"])
    n_init = sum(1 for r in rows if r["attempt"] == 0)
    print("[aetherbench] done: %d/%d first-attempt pass, %d rows -> %s"
          % (n_ok, n_init, len(rows), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
