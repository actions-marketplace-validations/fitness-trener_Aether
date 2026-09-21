"""Python sink-detector bench — three measurements, weakest first.

  1. DETECTION vs ground truth (bench/py_frontend/LABELS.json), per
     labelled function: true positives, false negatives, false positives.
  2. FALSE POSITIVES on 77 benign modules (tools/py_corpus/ +
     tools/py_corpus2/). Those were written for the capability
     experiment, not as vulnerabilities; a sink-family finding there is a
     false-positive candidate. This measurement decides which rows are
     default-on — a row that drowns real findings in noise is not shipped
     default-on and is not quietly deleted either.
  3. DIFFERENTIAL vs bandit over the same labelled corpus, including the
     bandit-only column. A differential that shows only the wins is
     marketing. bandit is a BENCH-ONLY optional: if it is not installed
     this measurement prints SKIP and the other two still run. The exit
     code never depends on bandit's presence (Aether has zero runtime
     dependencies and this must not change that).

Run: python -B bench/py_frontend/run_bench.py
     python -B bench/py_frontend/run_bench.py --json
"""
from __future__ import annotations
import ast as pyast
import collections
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.py_frontend import py_to_ir, PY_SKIP_STAGES      # noqa: E402
from aether.passes import analyze_flat                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS_PATH = os.path.join(HERE, "LABELS.json")

# The sink family this frontend claims. Everything else a pass may emit
# (E0701 capability, E0202-E0207 semantic) is out of scope here.
SINK_CODES = ("E0711", "E0713", "E0714", "E0718", "E0719", "E0720",
              "E0723", "E0727", "E0731")


def _codes_for_source(src: str):
    ast_dict, _unp, _meta = py_to_ir(src)
    return [d.code for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES)
            if d.code in SINK_CODES]


def _function_slice(src: str, fn_name: str):
    """One function plus the file's import header — the unit a label
    describes. Analysing the whole file would attribute a sibling
    function's finding to this one."""
    # Every top-level statement that CONTAINS an import, kept whole — so a
    # `try: import yaml / except ImportError:` guard survives with its
    # structure. The old header took only lines starting at column 0 with
    # `import`/`from`, which dropped every guarded import and had the
    # harness re-create BUG-011 on the very repro written to pin it.
    tree = pyast.parse(src)
    header = "\n".join(
        pyast.get_source_segment(src, node) or ""
        for node in tree.body
        if not isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef,
                                 pyast.ClassDef))
        and any(isinstance(n, (pyast.Import, pyast.ImportFrom))
                for n in pyast.walk(node)))
    for node in tree.body:
        if isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)) \
                and node.name == fn_name:
            return header + "\n\n" + (pyast.get_source_segment(src, node) or "")
    return None


# --- 1. detection vs ground truth --------------------------------------

def measure_detection(labels):
    rows, tp, fn_, fp = [], 0, 0, 0
    for key, expected in labels.items():
        if key.startswith("_"):
            continue
        rel, fn_name = key.split("::")
        path = os.path.join(ROOT, rel)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        sliced = _function_slice(src, fn_name)
        if sliced is None:
            rows.append({"key": key, "expected": expected, "got": None,
                         "verdict": "MISSING-FUNCTION"})
            continue
        got = _codes_for_source(sliced)
        if expected == "clean":
            verdict = "ok" if not got else "FALSE-POSITIVE"
            fp += 0 if not got else len(got)
        else:
            if expected in got:
                verdict = "ok"
                tp += 1
                extra = [c for c in got if c != expected]
                if extra:
                    verdict = "ok(+extra)"
                    fp += len(extra)
            else:
                verdict = "FALSE-NEGATIVE"
                fn_ += 1
        rows.append({"key": key, "expected": expected,
                     "got": sorted(set(got)), "verdict": verdict})
    return {"rows": rows, "true_positives": tp,
            "false_negatives": fn_, "false_positives": fp}


# --- 2. false positives on benign code ---------------------------------

def measure_benign():
    files = []
    for sub in ("py_corpus", "py_corpus2"):
        files += sorted(glob.glob(os.path.join(ROOT, "tools", sub, "*.py")))
    per_code = collections.Counter()
    per_file = {}
    errors = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                codes = _codes_for_source(f.read())
        except SyntaxError as e:                 # corpus file not parseable
            errors.append({"file": os.path.relpath(path, ROOT), "error": str(e)})
            continue
        if codes:
            per_file[os.path.relpath(path, ROOT)] = sorted(collections.Counter(codes).items())
        per_code.update(codes)
    return {"n_modules": len(files), "n_modules_with_findings": len(per_file),
            "per_code": dict(sorted(per_code.items())), "per_file": per_file,
            "unparseable": errors}


# --- 3. differential vs bandit -----------------------------------------

def measure_bandit(labels):
    try:
        import bandit                                        # noqa: F401
    except ImportError:
        return {"skipped": True,
                "reason": "bandit not installed (pip install bandit); "
                          "differential column unavailable"}
    files = sorted({k.split("::")[0] for k in labels if not k.startswith("_")})
    out = {}
    for rel in files:
        r = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q",
             os.path.join(ROOT, rel)],
            cwd=ROOT, capture_output=True, text=True)
        try:
            data = json.loads(r.stdout)
        except Exception:
            out[rel] = {"error": (r.stderr or r.stdout)[:200]}
            continue
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            aether = sorted(set(_codes_for_source(f.read())))
        out[rel] = {
            "bandit": sorted({i["test_id"] + " " + i["issue_text"][:60]
                              for i in data.get("results", [])}),
            "aether": aether,
        }
    return {"skipped": False, "per_file": out}


def main() -> int:
    with open(LABELS_PATH, encoding="utf-8") as f:
        labels = json.load(f)

    det = measure_detection(labels)
    benign = measure_benign()
    band = measure_bandit(labels)

    if "--json" in sys.argv:
        json.dump({"detection": det, "benign": benign, "bandit": band},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print("=" * 72)
    print("1. DETECTION vs ground truth (weakest metric first)")
    print("=" * 72)
    print(f"  false negatives : {det['false_negatives']}")
    print(f"  false positives : {det['false_positives']}")
    print(f"  true positives  : {det['true_positives']}")
    for r in det["rows"]:
        if r["verdict"] != "ok":
            print(f"    [{r['verdict']}] {r['key']}: "
                  f"expected {r['expected']}, got {r['got']}")

    print()
    print("=" * 72)
    print("2. FALSE POSITIVES on benign code "
          f"({benign['n_modules']} modules, tools/py_corpus{{,2}})")
    print("=" * 72)
    print(f"  modules with >=1 sink finding: "
          f"{benign['n_modules_with_findings']}/{benign['n_modules']}")
    for code, n in benign["per_code"].items():
        print(f"    {code}: {n} finding(s)")
    if benign["unparseable"]:
        print(f"  ({len(benign['unparseable'])} module(s) not parseable, skipped)")

    print()
    print("=" * 72)
    print("3. DIFFERENTIAL vs bandit")
    print("=" * 72)
    if band["skipped"]:
        print(f"  SKIP: {band['reason']}")
    else:
        for rel, d in sorted(band["per_file"].items()):
            print(f"  {rel}")
            print(f"    aether: {d.get('aether')}")
            print(f"    bandit: {d.get('bandit')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
