"""Scan real installed PyPI packages with the Python sink detectors.

The bench in `bench/py_frontend/` measures against AUTHOR-ESTABLISHED
ground truth — the same repo wrote the repros and the detectors, and its
REPORT.md says so. This scan answers the question that caveat leaves
open: what does `aether check-py` do on a large body of third-party code
nobody wrote for it?

Corpus: every `.py` file under the active interpreter's site-packages.
Real published PyPI distributions, already on disk — nothing is
downloaded and nothing is imported or executed. Files are read as text
and parsed with `ast`.

Row set: exactly `aether check-py`'s DEFAULT output (E0713, E0714, E0718,
E0719, E0720, E0723, E0727 — the `effects`, `semantic` and `capability`
stages skipped, E0711 held back). `--strict` counts are collected
separately so the cost of that decision is visible rather than assumed.

Run: python -B bench/pypi_scan/run_scan.py            (summary)
     python -B bench/pypi_scan/run_scan.py --json     (full findings)
     python -B bench/pypi_scan/run_scan.py --limit 200
"""
from __future__ import annotations
import ast as pyast
import collections
import json
import os
import sys
import sysconfig

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.py_frontend import (py_to_ir, PY_SKIP_STAGES,   # noqa: E402
                                PY_STRICT_ONLY_CODES)
from aether.passes import analyze_flat                      # noqa: E402

# The CLI's row set, from the one definition the CLI itself imports —
# not a copy. test_pypi_scan_row_set_matches_cli pins the identity.
SKIP_DEFAULT = PY_SKIP_STAGES + ("capability",)
SKIP_STRICT = PY_SKIP_STAGES
STRICT_ONLY = PY_STRICT_ONLY_CODES
SINK_CODES = ("E0711", "E0713", "E0714", "E0718", "E0719", "E0720",
              "E0723", "E0727", "E0731")


def _iter_files(root: str, limit: int = 0):
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # test fixtures and vendored copies are still real published code,
        # but bundled test suites deliberately contain unsafe shapes; they
        # are counted separately rather than dropped.
        dirnames.sort()
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            yield os.path.join(dirpath, fn)
            seen += 1
            if limit and seen >= limit:
                return


def _dist_of(path: str, sp: str) -> str:
    rel = os.path.relpath(path, sp)
    return rel.split(os.sep)[0].replace(".py", "")


def _is_test_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    return "/test" in p or "/_test" in p or p.endswith("_test.py") \
        or "/conftest.py" in p


def scan(root: str, limit: int = 0):
    stats = {
        "files_seen": 0, "files_parsed": 0, "sloc": 0,
        "unparseable": 0, "errored": 0,
    }
    findings = []
    err_kinds = collections.Counter()
    for path in _iter_files(root, limit):
        stats["files_seen"] += 1
        try:
            with open(path, encoding="utf-8", errors="strict") as f:
                src = f.read()
        except (UnicodeDecodeError, OSError):
            stats["unparseable"] += 1
            continue
        try:
            pyast.parse(src)
        except (SyntaxError, ValueError, RecursionError):
            stats["unparseable"] += 1          # py2 files, templates, fixtures
            continue
        stats["files_parsed"] += 1
        stats["sloc"] += sum(1 for l in src.splitlines()
                             if l.strip() and not l.lstrip().startswith("#"))
        try:
            ir, _unp, _meta = py_to_ir(src)
            diags = analyze_flat(ir, skip=SKIP_STRICT)
        except RecursionError:
            stats["errored"] += 1
            err_kinds["RecursionError"] += 1
            continue
        except Exception as e:                 # a crash is data, not a skip
            stats["errored"] += 1
            err_kinds[type(e).__name__] += 1
            continue
        for d in diags:
            if d.code not in SINK_CODES:
                continue
            findings.append({
                "code": d.code,
                "file": os.path.relpath(path, root).replace("\\", "/"),
                "dist": _dist_of(path, root),
                "line": d.position.line,
                "is_test": _is_test_path(path),
                "default_row": d.code not in STRICT_ONLY,
                "message": d.message[:160],
            })
    return stats, findings, dict(err_kinds)


def main() -> int:
    sp = sysconfig.get_paths()["purelib"]
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    stats, findings, errs = scan(sp, limit)

    default = [f for f in findings if f["default_row"]]
    strict_only = [f for f in findings if not f["default_row"]]
    nontest = [f for f in default if not f["is_test"]]

    if "--json" in sys.argv:
        json.dump({"root": sp, "stats": stats, "errors": errs,
                   "findings": findings}, sys.stdout, indent=1)
        sys.stdout.write("\n")
        return 0

    kloc = stats["sloc"] / 1000.0
    print("=" * 70)
    print("CORPUS")
    print("=" * 70)
    print(f"  root            {sp}")
    print(f"  .py files seen  {stats['files_seen']}")
    print(f"  parsed          {stats['files_parsed']}")
    print(f"  not parseable   {stats['unparseable']}  (py2 / fixtures / non-utf8)")
    print(f"  SLOC            {stats['sloc']}")
    print(f"  analyzer errors {stats['errored']}  {errs if errs else ''}")

    print()
    print("=" * 70)
    print("DEFAULT ROW SET  (what `aether check-py` prints)")
    print("=" * 70)
    print(f"  findings              {len(default)}")
    print(f"  per KLOC              {len(default) / kloc:.3f}" if kloc else "")
    print(f"  excluding test files  {len(nontest)}")
    by_code = collections.Counter(f["code"] for f in default)
    for code, n in sorted(by_code.items()):
        nt = sum(1 for f in nontest if f["code"] == code)
        print(f"    {code}  {n:5d}   ({nt} outside test dirs)")
    dists = collections.Counter(f["dist"] for f in nontest)
    print(f"  distributions touched {len(set(f['dist'] for f in default))}")
    print("  top distributions (non-test findings):")
    for d, n in dists.most_common(10):
        print(f"    {n:5d}  {d}")

    print()
    print("=" * 70)
    print("HELD BACK BY DEFAULT  (--strict adds these)")
    print("=" * 70)
    print(f"  E0711 findings  {len(strict_only)}")
    print(f"  per KLOC        {len(strict_only) / kloc:.3f}" if kloc else "")
    print("  This is the row demoted in bench/py_frontend/REPORT.md. The")
    print("  ratio below is why it is not in the default output.")
    if default:
        print(f"  E0711 : default-set  =  {len(strict_only) / max(1, len(default)):.1f} : 1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
