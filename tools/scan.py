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
                         [--allow-parse-errors]

Exit code — the one table in `aether/diagnostics.py`, shared with `aether
check`, `check-py` and `fix-loop`: 0 clean, 1 findings (with `--expect`: a
difference from the headers), 2 usage error, 3 analyzer crash (a bug in
Aether), 4 incomplete — some file did not parse or could not be read, and
nothing was found. A file that does not parse (E01xx lex / E02xx parse)
was not analysed, so it is not a clean file — it used to be counted and
the run still exited 0, so a tree where EVERY file failed to parse passed
(audit 2026-09-24 D3). `--allow-parse-errors` is the explicit opt-out for
a corpus of generated code where some candidates are known not to parse.
A parse error is reported as its diagnostic (`parse_error`:
`Diagnostic.to_dict()`), separately from findings; every finding is
`Diagnostic.to_dict()` plus `risk`. Files are read as `utf-8-sig`, like
`aether check`, and loaded (parse + `import` resolution) by the same
`load_program` every other surface uses.

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

from aether.passes import analyze                      # noqa: E402
from aether.diagnostics import (EXIT_USAGE, error_doc,  # noqa: E402
                                exit_code)
from aether.passes.imports import load_program         # noqa: E402
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


def _finding(d, ast=None) -> dict:
    """`Diagnostic.to_dict()` — the row every surface prints — plus the
    scanner's triage `risk`."""
    return dict(d.to_dict(ast), risk=risk_of(d.code))


def _line(f) -> int:
    return f["position"]["line"]


def scan_file(path: str) -> dict:
    """Return {path, findings: [_finding], declared?} plus, when the file
    was not analysed, `parse_error` (its diagnostic) or `unreadable` (why
    it could not be read) or `error` (the analyzer crashed on it).
    `path` is forward-slashed, whatever the platform."""
    shown = path.replace(os.sep, "/")
    # utf-8-sig: a BOM is not a lex error (it was E0101 here while `check`
    # read the same file fine).
    try:
        with open(path, encoding="utf-8-sig") as f:
            src = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return {"path": shown, "findings": [],
                "unreadable": f"{type(e).__name__}: {e}"}
    try:
        ast, parse_diags, import_diags = load_program(src, path, collect=False)
        if parse_diags:
            # Generation failure — invalid syntax. Reported separately,
            # and the run is incomplete unless --allow-parse-errors.
            return {"path": shown, "findings": [],
                    "parse_error": parse_diags[0].to_dict()}
        # An unresolved import stops before analysis on every surface.
        diags = import_diags
        if not diags:
            for stage, found in analyze(ast):
                for d in found:
                    d.stage = stage
                diags = diags + found
    except Exception as e:
        # A bug in Aether, not in the file: exit 3, never "clean".
        return {"path": shown, "findings": [],
                "error": f"{type(e).__name__}: {e}"}
    findings = [_finding(d, ast) for d in diags]
    # Worst-first, then most-certain-first: a reviewer reading only the
    # top of a 4,000-finding scan must be reading the critical ones, and
    # of two equally-risky findings the one the analysis is surest about
    # reads first. Line/code break ties so output stays deterministic
    # (tests/test_deterministic.py).
    findings.sort(key=lambda x: (-rank(x["code"]), -x["confidence"],
                                 _line(x), x["code"]))
    declared, _run = parse_header(src, path)
    return {"path": shown, "findings": findings, "declared": declared}


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
    invoked from. `check-py` passes its own base (the workspace). A file
    that did not parse becomes a tool-execution notification, so an
    unreadable tree does not look green in Code Scanning."""
    unreadable = [(r["path"], "[{code}] {message} at line {p[line]}, col "
                   "{p[column]}".format(p=r["parse_error"]["position"],
                                        **r["parse_error"]))
                  for r in results if r.get("parse_error")]
    unreadable += [(r["path"], r["unreadable"])
                   for r in results if r.get("unreadable")]
    return render_sarif(results, base=ROOT, unreadable=unreadable,
                        crashed=[(r["path"], r["error"])
                                 for r in results if r.get("error")])


def main(argv) -> int:
    as_json = "--json" in argv
    try:
        return _main(argv, as_json)
    except Exception as e:
        # A crash outside the per-file wall (a renderer, the walk): still
        # exit 3, and `--json` still prints its one document.
        import traceback
        traceback.print_exc()
        if as_json:
            print(json.dumps(error_doc("crash", f"{type(e).__name__}: {e}")))
        return exit_code(0, crashed=True)


def _usage(as_json: bool, message: str) -> int:
    sys.stderr.write(message.rstrip() + "\n")
    if as_json:
        print(json.dumps(error_doc("usage", message.strip())))
    return EXIT_USAGE


def _main(argv, as_json) -> int:
    as_sarif = "--sarif" in argv
    expect = "--expect" in argv
    allow_parse_errors = "--allow-parse-errors" in argv

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
                return _usage(as_json, "--min-risk needs a rating\n")
            min_risk, skip = argv[i + 1], True
        elif a.startswith("--min-risk="):
            min_risk = a.split("=", 1)[1]
        elif a == "--min-confidence":
            if i + 1 >= len(argv):
                return _usage(as_json, "--min-confidence needs a number\n")
            min_conf_raw, skip = argv[i + 1], True
        elif a.startswith("--min-confidence="):
            min_conf_raw = a.split("=", 1)[1]
        elif not a.startswith("--"):
            args.append(a)
    if min_risk not in ORDER:
        return _usage(as_json, f"unknown --min-risk {min_risk!r}; "
                               f"expected one of {', '.join(sorted(ORDER))}")
    min_conf = 0.0
    if min_conf_raw is not None:
        try:
            min_conf = float(min_conf_raw)
        except ValueError:
            return _usage(as_json, f"--min-confidence wants a number in "
                                   f"[0,1], got {min_conf_raw!r}")
        if not 0.0 <= min_conf <= 1.0:
            return _usage(as_json, f"--min-confidence must be in [0,1], "
                                   f"got {min_conf}")
    if not args:
        return _usage(as_json, "usage: python -m tools.scan <dir-or-file>... "
                      "[--json|--sarif] [--expect] [--min-risk RATING] "
                      "[--min-confidence FLOAT] [--allow-parse-errors]")
    missing_paths = [a for a in args if not os.path.exists(a)]
    if missing_paths:
        return _usage(as_json, "; ".join(f"no such file or directory: {a}"
                                         for a in missing_paths))
    if expect and min_risk != "info":
        return _usage(as_json,
            "--min-risk cannot be combined with --expect: expectation mode "
            "gates on the diff from each file's `// expect:` header, and a "
            "filtered-out declared code reads as a regressed detector, not "
            "as a filtered one")
    if expect and min_conf > 0.0:
        # Same reason as --min-risk: a declared code filtered out by
        # confidence is indistinguishable from a detector that regressed.
        return _usage(as_json,
            "--min-confidence cannot be combined with --expect: expectation "
            "mode gates on the diff from each file's `// expect:` header, and "
            "a filtered-out declared code reads as a regressed detector, not "
            "as a filtered one")
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

    parse_errs = [r for r in results
                  if r.get("parse_error") or r.get("unreadable")]
    crashes = [r for r in results if r.get("error")]
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
    rc = exit_code(failed, crashed=bool(crashes),
                   incomplete=bool(parse_errs and not allow_parse_errors))

    if as_sarif:
        print(json.dumps(to_sarif(reported), indent=2))
    elif as_json:
        payload = {"ok": rc == 0,
                   "complete": not (parse_errs or crashes),
                   "scanned": len(files),
                   "files_with_findings": len(with_find),
                   "parse_errors": len(parse_errs),
                   "results": [r for r in reported
                               if r["findings"] or r.get("parse_error")
                               or r.get("unreadable")],
                   "errors": [{"path": r["path"], "error": r["error"]}
                              for r in crashes]}
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
                print(f"  L{_line(f):>4}  {f['risk']:<8} {f['code']}  "
                      f"{f['message'][:80]}")
                by_code[f["code"]] = by_code.get(f["code"], 0) + 1
        if expect:
            for p, m in missing:
                print(f"\n{_rel(p)}")
                for code, n in m:
                    print(f"  DECLARED BUT NOT REPORTED  {code}x{n} "
                          f"— detector regressed, or the header is stale")
        for r in parse_errs:
            e = r.get("parse_error")
            print(f"\n{_rel(r['path'])}\n" + (
                f"  L{_line(e):>4}  NOT PARSED {e['code']}  {e['message'][:80]}"
                if e else f"  NOT READ  {r['unreadable'][:80]}"))
        for r in crashes:
            print(f"\n{_rel(r['path'])}\n  ANALYZER ERROR  {r['error']}"
                  "\n  this is a bug in Aether, not in the file — please "
                  "report it (see BUGS.md)")
        print(f"\n{'='*60}")
        label = "unexpected findings" if expect else "with findings"
        print(f"scanned {len(files)} files · "
              f"{len(with_find)} {label} · "
              f"{len(parse_errs)} parse errors (generation failures"
              + (", allowed by --allow-parse-errors)" if allow_parse_errors
                 else "; any makes the run incomplete: exit 4, or 1 with findings)")
              + (f" · {len(crashes)} analyzer error(s)" if crashes else ""))
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
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
