#!/usr/bin/env python3
"""Aether scanner — point it at a directory of `.aeth` files (e.g. a corpus
of AI-generated code) and get a findings report across the full detector
suite. Membership is `aether.passes.STAGES`, the same registry the CLI,
the SDK and the LSP cross — this scanner does not keep its own list (it
used to, and drifted three detectors behind).

This is the product shape of Aether's phase-2 story: not "model a known
CVE", but "scan real code and surface real issues".

Usage:
    python -m tools.scan <dir-or-file>... [--json|--sarif] [--expect]
                         [--min-risk RATING] [--min-confidence FLOAT]

Exit code: 0 if no findings, 1 if any file has findings, 2 on usage error.
Parse errors (E0201) are reported separately as generation failures, not
architectural findings.

`--expect` judges each file against the `// expect:` header it declares
(see `tools/expectations.py`) and gates on the DIFFERENCE — an unexpected
finding, or a declared one that stopped firing. A file with no header is
held to `clean`, so in a repo that uses no headers the flag changes
nothing. It exists because a repo can legitimately CONTAIN violations: a
detector's demo pair is a vulnerable file and its fix, and "any finding
fails" makes such a repo unscannable. This is what `.github/workflows/
aether-scan.yml` runs over Aether's own corpus.
"""
from __future__ import annotations
import glob
import json
import os
import sys
from collections import Counter

# Windows consoles with legacy code pages (cp1251 etc.) can't encode '×'/'·';
# degrade to '?' instead of crashing after findings already printed.
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.parser import parse                        # noqa: E402
from aether.diagnostics import AetherError             # noqa: E402
from aether.passes import analyze_flat                 # noqa: E402
from tools.expectations import parse_header            # noqa: E402
from aether.risk import (risk_of, rank, at_or_above, ORDER,   # noqa: E402
                         SECURITY_SEVERITY)
from aether.sarif import (sarif_level,                        # noqa: E402
                          to_sarif as render_sarif)


def _rel(path: str) -> str:
    """Repo-relative, forward-slashed. Falls back to the absolute path for
    a target outside the repo — a `../../..` URI is not a valid SARIF
    artifactLocation, and Code Scanning drops the result silently."""
    r = os.path.relpath(path, ROOT).replace(os.sep, "/")
    return r if not r.startswith("../") else path.replace(os.sep, "/")


def _files(target: str):
    if os.path.isfile(target):
        return [target]
    return sorted(glob.glob(os.path.join(target, "**", "*.aeth"), recursive=True))


def scan_file(path: str) -> dict:
    """Return {path, parse_error?, findings:[{code,message,line}], declared?}."""
    with open(path, encoding="utf-8") as f:
        src = f.read()
    try:
        ast = parse(src, path)
    except AetherError as e:
        # Generation failure — invalid syntax. Reported separately.
        return {"path": path, "parse_error": str(e), "findings": []}
    findings = [{"code": d.code, "message": d.message,
                 "line": d.position.line, "column": d.position.column,
                 "risk": risk_of(d.code), "confidence": d.confidence,
                 "suggestion": d.suggestion,
                 "extra": d.extra}
                for d in analyze_flat(ast)]
    # Worst-first, then most-certain-first: a reviewer reading only the
    # top of a 4,000-finding scan must be reading the critical ones, and
    # of two equally-risky findings the one the analysis is surest about
    # reads first. Line/code break ties so output stays deterministic
    # (tests/test_deterministic.py).
    findings.sort(key=lambda x: (-rank(x["code"]), -x["confidence"],
                                 x["line"], x["code"]))
    declared, _run = parse_header(src, path)
    return {"path": path, "findings": findings, "declared": declared}


def diff_expected(result: dict) -> dict:
    """Compare one file's findings against the codes it declares.

    Returns {unexpected: [finding], missing: [(code, n)]}. No header means
    the file claims `clean`, so every finding is unexpected. `missing` is
    a declared code that stopped firing — a detector regression, which is
    the direction a "fail on any finding" gate can never see.
    """
    declared = result.get("declared") or Counter()
    actual = Counter(f["code"] for f in result["findings"])
    surplus = actual - declared
    unexpected, budget = [], Counter(surplus)
    for f in result["findings"]:
        if budget[f["code"]]:
            budget[f["code"]] -= 1
            unexpected.append(f)
    return {"unexpected": unexpected,
            "missing": sorted((declared - actual).items())}


# The SARIF renderer lives in the package (`aether/sarif.py`) so that this
# scanner and `aether check-py --sarif` cannot drift into two documents.
# These two names are kept because `tests/test_scan.py` addresses them.
_sarif_level = sarif_level


def to_sarif(results: list) -> dict:
    """Render this scanner's findings as SARIF v2.1.0 — the format GitHub
    Code Scanning, VS Code, and most CI security dashboards ingest. This is
    how Aether plugs into a real pipeline as a gate on AI-generated code.

    Paths are reported relative to the Aether checkout, which is the right
    base here: this scanner runs over a corpus inside the repository it was
    invoked from. `check-py` passes its own base (the workspace)."""
    return render_sarif(results, base=ROOT)


def main(argv) -> int:
    as_json = "--json" in argv
    as_sarif = "--sarif" in argv
    expect = "--expect" in argv

    # `--min-risk <rating>` and `--min-confidence <float>` take values, so
    # their arguments must not be mistaken for scan targets.
    min_risk = "info"
    min_conf_raw = None
    args, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a == "--min-risk":
            if i + 1 >= len(argv):
                sys.stderr.write("--min-risk needs a rating\n")
                return 2
            min_risk, skip = argv[i + 1], True
        elif a.startswith("--min-risk="):
            min_risk = a.split("=", 1)[1]
        elif a == "--min-confidence":
            if i + 1 >= len(argv):
                sys.stderr.write("--min-confidence needs a number\n")
                return 2
            min_conf_raw, skip = argv[i + 1], True
        elif a.startswith("--min-confidence="):
            min_conf_raw = a.split("=", 1)[1]
        elif not a.startswith("--"):
            args.append(a)
    if min_risk not in ORDER:
        sys.stderr.write(f"unknown --min-risk {min_risk!r}; "
                         f"expected one of {', '.join(sorted(ORDER))}\n")
        return 2
    min_conf = 0.0
    if min_conf_raw is not None:
        try:
            min_conf = float(min_conf_raw)
        except ValueError:
            sys.stderr.write(f"--min-confidence wants a number in [0,1], "
                             f"got {min_conf_raw!r}\n")
            return 2
        if not 0.0 <= min_conf <= 1.0:
            sys.stderr.write(f"--min-confidence must be in [0,1], "
                             f"got {min_conf}\n")
            return 2
    if not args:
        sys.stderr.write("usage: python -m tools.scan <dir-or-file>... "
                         "[--json|--sarif] [--expect] [--min-risk RATING] "
                         "[--min-confidence FLOAT]\n")
        return 2
    if expect and min_risk != "info":
        sys.stderr.write(
            "--min-risk cannot be combined with --expect: expectation mode "
            "gates on the diff from each file's `// expect:` header, and a "
            "filtered-out declared code reads as a regressed detector, not "
            "as a filtered one\n")
        return 2
    if expect and min_conf > 0.0:
        # Same reason as --min-risk: a declared code filtered out by
        # confidence is indistinguishable from a detector that regressed.
        sys.stderr.write(
            "--min-confidence cannot be combined with --expect: expectation "
            "mode gates on the diff from each file's `// expect:` header, and "
            "a filtered-out declared code reads as a regressed detector, not "
            "as a filtered one\n")
        return 2
    files = sorted({p for a in args for p in _files(a)})
    results = [scan_file(p) for p in files]
    if min_risk != "info":
        results = [dict(r, findings=[f for f in r["findings"]
                                     if at_or_above(f["code"], min_risk)])
                   for r in results]
    if min_conf > 0.0:
        results = [dict(r, findings=[f for f in r["findings"]
                                     if f["confidence"] >= min_conf])
                   for r in results]

    parse_errs = [r for r in results if r.get("parse_error")]
    if not expect:
        with_find = [r for r in results if r["findings"]]
        reported = results
        failed = bool(with_find)
    else:
        # Gate on the DIFFERENCE from what each file declares. `reported`
        # carries only the surplus, so SARIF/Code Scanning shows the
        # unexpected findings and not the demos' declared ones.
        diffs = {r["path"]: diff_expected(r) for r in results}
        reported = [dict(r, findings=diffs[r["path"]]["unexpected"])
                    for r in results]
        with_find = [r for r in reported if r["findings"]]
        missing = [(p, d["missing"]) for p, d in diffs.items() if d["missing"]]
        failed = bool(with_find or missing)

    if as_sarif:
        print(json.dumps(to_sarif(reported), indent=2))
    elif as_json:
        payload = {"scanned": len(files),
                   "files_with_findings": len(with_find),
                   "parse_errors": len(parse_errs),
                   "results": [r for r in reported
                               if r["findings"] or r.get("parse_error")]}
        if expect:
            payload["mode"] = "expect"
            payload["missing"] = [{"path": _rel(p), "codes": dict(m)}
                                  for p, m in missing]
        print(json.dumps(payload, indent=2, default=str))
    else:
        by_code: dict = {}
        for r in with_find:
            print(f"\n{_rel(r['path'])}")
            for f in r["findings"]:
                print(f"  L{f['line']:>4}  {f['risk']:<8} {f['code']}  "
                      f"{f['message'][:80]}")
                by_code[f["code"]] = by_code.get(f["code"], 0) + 1
        if expect:
            for p, m in missing:
                print(f"\n{_rel(p)}")
                for code, n in m:
                    print(f"  DECLARED BUT NOT REPORTED  {code}x{n} "
                          f"— detector regressed, or the header is stale")
        print(f"\n{'='*60}")
        label = "unexpected findings" if expect else "with findings"
        print(f"scanned {len(files)} files · "
              f"{len(with_find)} {label} · "
              f"{len(parse_errs)} parse errors (generation failures)")
        if expect:
            declared = sum(sum((r.get("declared") or Counter()).values())
                           for r in results)
            gone = sum(n for _p, m in missing for _c, n in m)
            print(f"expectation mode: {declared} findings declared by "
                  f"`// expect:` headers, {declared - gone} matched, "
                  f"{gone} declared but not reported")
        if by_code:
            print(("unexpected " if expect else "findings ") + "by code: "
                  + ", ".join(f"{c}×{n}" for c, n in sorted(by_code.items())))
            by_risk: dict = {}
            for r in with_find:
                for f in r["findings"]:
                    by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1
            print("by risk: " + ", ".join(
                f"{lvl}×{by_risk[lvl]}"
                for lvl in sorted(by_risk, key=lambda l: -ORDER[l])))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
