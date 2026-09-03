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
    python -m tools.scan path/to/dir --min-risk high        # triage floor
    python -m tools.scan path/to/dir --min-confidence 0.9   # certainty floor

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
    aether check-py src/ --min-confidence 0.9  # hide the by-name matches
    aether check-py src/ --jobs 4              # 4 worker processes
    python -B -m transpiler.aether.cli check-py src/   # without installing

A directory is walked recursively for `.py`, skipping `.git`, `.venv`,
`venv`, `node_modules`, `__pycache__`, `build`, `dist`, `site-packages`
and the other vendored trees — a repo scan that turns into a dependency
scan buries the findings the user can act on. Findings sort worst-first by
the per-code risk rating (`transpiler/aether/risk.py`), then
most-certain-first by the per-finding confidence below.

### `--jobs`: parallel file analysis

Each file is analyzed independently, so `check-py` can spread them over
worker processes. Measured on 8 logical cores over the whole `agno`
package in `bench/framework_scan/_work/src` (1,024 files, 430 findings):
**241.0 s / 248.3 s serially, 69.5 s / 68.7 s pooled — 3.5x**, with all
four `--json` outputs byte-identical.

A pool is used **only when it can pay for itself**: more than 32 files on
a multi-core machine. Below that, interpreter start-up per worker costs
more than the parallelism buys, so a single-file or small-tree run takes
the serial loop and is byte-identical to what it was before this flag
existed. `--jobs 1` forces serial; `--jobs N` forces N workers. Order
never depends on the choice — the pool maps over the already-sorted paths
— and a detector crash still surfaces as that file's `ANALYZER ERROR`
line, because the per-file `except` wall lives inside the worker.

### `--min-confidence`: how sure the analysis is

Risk rates the CLASS ("if this is real, how bad?"). Confidence rates ONE
finding's evidence: how sure the analysis is that this call is the sink
it says (`transpiler/aether/confidence.py`). It is neither severity nor a
probability of exploitability.

| what matched | confidence |
|---|---|
| a dotted path resolved through the file's imports (`pickle.loads`), or a sink guard | 0.95 |
| a bare builtin (`exec`, `eval`, `open`), or a literal `["bash", "-c", cmd]` argv | 0.9 |
| `compile()` — it builds a code object and executes nothing | 0.6 |
| a METHOD NAME on a receiver whose type was never resolved (`cur.execute`, `env.from_string`) | 0.6 |
| an Aether-source finding — the sink is spelled in the source, nothing was guessed | 1.0 |

`--min-confidence FLOAT` hides everything below the floor. It is a filter
on the output; it changes nothing about what the detectors found. On the
15-framework corpus (`bench/framework_scan/`), 676 findings split
0.95 x44, 0.9 x3, 0.6 x629 — so `--min-confidence 0.9` hides 629 of 676
(93%), almost all of them `cursor.execute`-shaped SQL matched by name.
That is a reading order, not a verdict: those findings are correct by
Aether's rule and stay in the default output.

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
