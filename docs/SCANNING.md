# Scanning AI-generated code with Aether

Aether is a compile-time firewall for AI-generated code. Point the scanner
at a directory of `.aeth` source and it runs the full default-on suite —
the base effect/capability/refinement passes, the security family
(E0710–E0731), and the static-semantic checks (E0202–E0207) — and reports
every finding. Aether is stdlib-only (Python 3.10+); there is nothing to
install.

## Local scan

    python -m tools.scan path/to/dir          # human-readable report
    python -m tools.scan path/to/dir --json    # machine-readable
    python -m tools.scan path/to/dir --sarif    # SARIF v2.1.0

Exit code: `0` = no findings, `1` = at least one finding, `2` = usage
error. Parse errors (invalid syntax — a generation failure) are counted
and reported separately from architectural/security findings.

Example:

    $ python -m tools.scan src/
    src/handler.aeth
      L  12  E0713  function 'lookup' builds a SQL query for 'sqlQuery' unsafely ...
      L  27  E0206  function 'save' discards the Result of 'writeFile' ...
    ============================================================
    scanned 34 files · 2 with findings · 0 parse errors
    findings by code: E0206×1, E0713×1

## CI gate (GitHub Code Scanning)

Copy `.github/workflows/aether-scan.yml` into your repo. On every push and
PR it runs the scanner, uploads findings to the **Security → Code Scanning**
tab as SARIF, and fails the build if anything is found. Set `SCAN_PATH` in
the workflow env if your `.aeth` files live under one directory.

The SARIF integration means Aether findings appear inline on the PR diff,
just like CodeQL — each with its rule id (`E07xx`/`E02xx`), file, and line.

## What it catches

See `SECURITY_POSTURE.md` for the full table. In short: the injection
family (SQL/command/template/XSS/header/CSV/XXE), SSRF and its metadata
variant, cleartext transmission, secret/PII exfiltration, missing and
resource-scoped authorization, open redirect, insecure deserialization,
hardcoded credentials — plus the architectural cluster (non-exhaustive
match, unreachable/dead code, dead stores, unchecked `Result`, impossible
refinement types).

## Scanning Python — `aether check-py`

`tools/scan.py` walks `.aeth` source. **Unmodified Python does not need a
port**: `tools/py_frontend.py` translates it into the same IR, so the
sink+literal and literal-content families run with no rewrite and no
annotations.

    aether check-py path/to/file.py            # one file
    aether check-py src/ scripts/              # any mix of files and directories
    aether check-py src/ --strict              # + E0711 and the E0701 inventory
    python -B -m transpiler.aether.cli check-py src/   # without installing

A directory is walked recursively for `.py`, skipping `.git`, `.venv`,
`venv`, `node_modules`, `__pycache__`, `build`, `dist`, `site-packages`
and the other vendored trees — a repo scan that turns into a dependency
scan buries the findings the user can act on. Findings sort worst-first by
the per-code risk rating (`transpiler/aether/risk.py`).

Exit code: `0` = clean, `2` = findings **or an analyzer crash**. A file
that cannot be parsed (py2 sources, templates, fixtures) is counted on its
own summary line and does not fail the run; a crash inside a detector is a
bug in Aether and does, per `passes/__init__.py`'s rule that a crashing
detector must go red rather than silent.

    scanned 128 file(s) · 3 with findings · 1 unparseable · 0 analyzer error(s)
    findings by code: E0713x2, E0723x1

Default-on rows on Python: **E0713** SQL injection, **E0714** command
injection, **E0718** open redirect, **E0719** SSTI, **E0720** insecure
deserialization, **E0723** hardcoded credential, **E0727** XXE.

**What does not run on Python**, printed by the CLI on every invocation
rather than left to assumption: `E0801` effect composition and the
taint-marker family (`E0712`/`E0715`/`E0716`/`E0717`/`E0724`) need a
declared `effects` clause or a marker type, and Python has neither.
`E0711` and the `E0701` capability inventory are held back from the
default set by measurement — see `bench/py_frontend/REPORT.md` §2.

## Honest scope

The analysis is **intraprocedural and syntactic**: over-flag, never miss
*within the modeled surface*, which is not a soundness proof. Sinks are
matched by method name on receivers of unresolved type. Single file, no
cross-module resolution, no control flow. Full limit list in
`bench/py_frontend/REPORT.md` §4.

Measured results, both reproducible: `bench/py_frontend/REPORT.md`
(ground truth this repo wrote, and it says so), `bench/pypi_scan/REPORT.md`
(1.19M lines of third-party PyPI code — 0 crashes, 0 parse failures,
0.033 findings/KLOC, triaged line by line) and `bench/pypi_scan/RECALL.md`
(86.8% agreement with bandit as an independent oracle). On `.aeth`
corpora, the aetherbench candidate scan found 13 real bugs
(`bench/SCAN_FINDINGS.md`); faithful ports of real-world shapes are in
`bench/REALWORLD_VALIDATION.md`.
