# Scanning code with Aether

Aether is a security checker for Python, built on the typed intermediate
representation of the Aether language. `aether check-py` translates an
unmodified Python file into that IR and runs the security rules on it;
Aether source (`.aeth`) is checked by the same rules plus the language's
effect, capability and marker-type checks, which Python code has no
declarations for.

Install: `pip install aether-lang` (Python 3.10+; the core has no
third-party dependencies), then `aether check-py <path>` — see *Scanning
Python* below. The `.aeth` corpus scanner `tools/scan.py` ships with the
source checkout, not with the package.

## Scanning `.aeth` source — `tools/scan.py`

From a checkout, `tools/scan.py` runs the full default-on suite over a
directory of `.aeth` source — the effect and capability passes, the
security family (`E0710`–`E0731`), and the static-semantic checks
(`E0202`–`E0207`) — and reports every finding.

    python -m tools.scan path/to/dir          # human-readable report
    python -m tools.scan path/to/dir --json    # machine-readable
    python -m tools.scan path/to/dir --sarif    # SARIF v2.1.0
    python -m tools.scan path/to/dir --min-risk high        # triage floor
    python -m tools.scan path/to/dir --min-confidence 0.9   # certainty floor
    python -m tools.scan path/to/dir --expect  # gate on the diff from `// expect:` headers

Exit code (the table in *Exit codes and the JSON contract* below): `0` =
no findings (with `--expect`: no difference from the declared headers),
`1` = at least one finding (with `--expect`: an undeclared finding or a
declared one that stopped firing), `2` = usage error (a missing path
included), `3` = analyzer crash, `4` = a file did not parse or could not
be read and nothing was found. Parse errors (invalid syntax — a
generation failure) are reported separately from architectural/security
findings; `--allow-parse-errors` keeps them out of the exit code.

Example:

    $ python -m tools.scan src/
    src/handler.aeth
      L  12  E0713  function 'lookup' builds a SQL query for 'sqlQuery' unsafely ...
      L  27  E0206  function 'save' discards the Result of 'writeFile' ...
    ============================================================
    scanned 34 files · 2 with findings · 0 parse errors (generation failures; any makes the run incomplete: exit 4, or 1 with findings)
    findings by code: E0206×1, E0713×1

## CI gate for `.aeth` corpora (GitHub Code Scanning)

For Python, use the GitHub Action in the README (*CI and GitHub Code
Scanning*). For `.aeth` source, `.github/workflows/aether-scan.yml` is the
working reference. On every push and PR it runs
`python -m tools.scan $SCAN_PATH --expect`, uploads the **undeclared**
findings to the **Security → Code Scanning** tab as SARIF, and fails the
build when the findings differ from what the files declare: each `.aeth`
states the codes it produces in a `// expect:` header, and the gate fails
on an undeclared finding or on a declared finding that stopped firing. A
file with no header is held to `clean`, so in a repo that uses no headers
`--expect` fails on any finding. This repository sets `SCAN_PATH` to its
corpus roots (`demos playground/examples`) because its demos are flagged
on purpose; a consumer repo sets `SCAN_PATH: .`. It needs a checkout of
this repository for `tools/scan.py`.

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
port**: `transpiler/aether/py_frontend.py` translates it into the same IR,
so the sink+literal and literal-content families run with no rewrite and
no annotations.

    aether check-py path/to/file.py            # one file
    aether check-py src/ scripts/              # any mix of files and directories
    aether check-py src/ --strict              # + E0711 and the E0701 inventory
    aether check-py src/ --min-confidence 0.9  # hide the by-name matches
    aether check-py src/ --jobs 4              # 4 worker processes
    aether --json check-py src/ --no-unprovable  # JSON without the unprovable rows
    python -B -m transpiler.aether.cli check-py src/   # without installing

A directory is walked recursively for `.py`, skipping `.git`, `.venv`,
`venv`, `node_modules`, `__pycache__`, `build`, `dist`, `site-packages`
and the other vendored trees — a repo scan that turns into a dependency
scan buries the findings the user can act on. Findings sort worst-first by
the per-code risk rating (`transpiler/aether/risk.py`), then
most-certain-first by the per-finding confidence below.

### `--jobs`: parallel file analysis

Each file is analyzed independently, so `check-py` can spread them over
worker processes. Measured 2026-09-03 (`demos/case_studies/LOOP_LOG.md`,
iteration 52) on 8 logical cores over the whole `agno` package in
`bench/framework_scan/_work/src` (1,024 files, 430 findings):
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
| a bare builtin (`exec`, `eval`, `open`), a literal `["bash", "-c", cmd]` argv, or `exec(compile(src))` | 0.9 |
| `compile()` on its own — it builds a code object and runs nothing (`exec(compile(...))` rates as `exec`) | 0.6 |
| a METHOD NAME on a receiver whose type was never resolved (`cur.execute`, `env.from_string`) | 0.6 |
| an Aether-source finding — the sink is spelled in the source, nothing was guessed | 1.0 |

`--min-confidence FLOAT` hides everything below the floor. It changes
nothing about what the detectors found, but it filters the exit code as
well as the output: a run whose only findings are below the floor exits
0. On the 15-framework corpus (`bench/framework_scan/`, re-scanned
2026-09-11 at 0.4.0; framework versions pinned in
`bench/framework_scan/frameworks.lock.txt`), 676 findings split 0.95 x44,
0.9 x4, 0.6 x628 — so `--min-confidence 0.9` hides 628 of
676 (93%): 624 method-name matches, almost all `cursor.execute`-shaped
SQL, and 4 `compile()` calls whose result is never run. Those findings
are what the rules are designed to flag, measured over-flags included,
and they stay in the default output.

Exit code: `0` = clean, `1` = findings, `2` = usage error, `3` = an
analyzer crash, `4` = incomplete. A file that cannot be parsed (py2
sources, templates, fixtures — or valid 3.12+ syntax such as a PEP 701
f-string or a PEP 695 type parameter on a 3.10/3.11 interpreter) was not
checked: it is reported on stderr in every mode and counted on its own
summary line, and a run with no findings exits `4`, never `0`. On 3.10/
3.11 a SyntaxError that looks like 3.12 syntax adds "valid on a newer
Python? scan with 3.12+" (a heuristic on the error text). A crash inside a
detector is a bug in Aether and exits `3` whatever else was found, per
`passes/__init__.py`'s rule that a crashing detector must go red rather
than silent.

    scanned 128 file(s) · 3 with findings · 1 unparseable · 0 analyzer error(s)
    findings by code: E0713x2, E0723x1

Default-on rows on Python: **E0713** SQL injection, **E0714** command
injection, **E0718** open redirect, **E0719** SSTI, **E0720** insecure
deserialization, **E0723** hardcoded credential, **E0727** XXE, **E0731**
code injection (`exec`/`eval`/`compile` of dynamic source).

**What does not run on Python**, printed by the CLI on every invocation
rather than left to assumption: `E0801` effect composition; the
`net.fetch` scope rows (`E0710`/`E0721`/`E0722`), which read a declared
scope and on Python fire only on a mapped network call named `fetch`; the
marker rows (`E0712`/`E0715`/`E0717`/`E0724`/`E0725`/`E0726`/`E0728`/
`E0729`/`E0730`); and the static-semantic family `E0202`–`E0207`.
Python has no declared `effects` clause and no marker types. The
exception is `E0716`: it fires on every `.executescript(...)` method call, literal
scripts included, because the frontend maps it to Aether's `sqlExec`,
which requires an authorization proof; no Python spelling tried clears
it, an `authorize(...)` second argument or an `Authorized` annotation
included (measured).
`E0711` and the `E0701` capability inventory are held back from the
default set by measurement — see `bench/py_frontend/REPORT.md` §2.

## Exit codes and the JSON contract

Since 0.5.0 one table, defined once (`transpiler/aether/diagnostics.py`),
holds for `aether check`, `aether check-py`, `aether fix-loop` and
`tools/scan.py`, in text, `--json` and `--sarif` mode:

| exit | meaning |
|---|---|
| `0` | clean: everything was analysed and nothing was found |
| `1` | findings (`fix-loop`: not repaired — `not_repaired`, `stuck`, `widened`, `max_iters_reached`) |
| `2` | usage error: an unknown flag, a bad value, a missing path; nothing was analysed |
| `3` | analyzer crash: Aether itself failed — a bug in Aether, not in your code |
| `4` | incomplete: some input could not be read or parsed, and nothing was found |

When several apply: `3` over `1` over `4` over `0`. A run with findings
AND an unparsed file exits `1`, and its JSON says `"complete": false`.
`check-py --min-confidence` filters the exit code as well as the output.
On `.aeth`: a lex/parse error, or an `import` that does not resolve
(E0705/E0706), is `4` — the program was not analysed; an SMT refutation
(E0901) is `1`; `--prove` without z3 is `2`. `aether run` exits `0` when
the program ran clean, and `1` on a static finding, a runtime contract or
refinement violation (E03xx) and an exception the program itself raised
(under `--json`, an `E9003` diagnostic with the traceback in `stderr`). `aether test` keeps its fixture table (0 match, 1 mismatch, 2
error). Before 0.5.0, `check` exited `2` on findings, parse errors,
import errors and usage errors alike; `check-py` exited `2` on findings
and on a per-file analyzer crash and `0` on a tree it could not parse;
`tools/scan.py` exited `1` on findings and parse errors; and any other
crash was a raw traceback with exit `1`, even under `--json`.

**One JSON document.** Every `--json` run prints exactly one JSON document
on stdout — including a usage error and a crash; stderr carries only human
text (a crash's traceback goes to stderr in text mode, or with `--debug`).
`ok` is true exactly when the exit code is `0`; `complete` is false when
some input was not analysed.

**One diagnostic shape.** Every diagnostic on every surface — `check
--json`, `check-py --json`, `tools/scan.py --json` (findings and
`parse_error`), `sdk.CheckResult.to_dict()`, the LSP's `aether/check`
reply and `publishDiagnostics` `data`, and the SARIF result properties —
is `Diagnostic.to_dict()`, with every key always present:

    {"code": "E0713", "category": "security", "severity": "error",
     "message": "...", "position": {"line": 2, "column": 5},
     "suggestion": "..." | null, "confidence": 0.6, "extra": {...},
     "stage": "security" | null, "patch_target": [["decls", 0], ...] | null}

`stage` is the analysis stage that produced it (`effects`, `security`,
`semantic`, `capability`, `modules`, or `smt`); null for lex, parse,
import and runtime diagnostics. `patch_target` is the splice site in the
Aether AST (`transpiler/aether/passes/patch_target.py`) for the codes that
have one; always null on a Python finding, whose IR is not your source.
`category` is one of `lex`, `parse`, `type`, `effect`, `capability`
(which includes the E07xx security rows on Aether source), `security`
(the same rows on a Python finding from `check-py`), `module`, `contract`,
`refinement`, `runtime`, `timeout`, `emit`, `internal`.

The documents:

| command | stdout document |
|---|---|
| `aether --json check FILE` | `{ok, complete, diagnostics, decls?, prove?}` |
| `aether --json check-py PATH...` | `{ok, complete, lang: "python", files: [{path, diagnostics, unprovable, meta}], unreadable: [{path, reason, detail}], skipped_dirs, errors: [{path, error}]}` |
| `aether --json fix-loop FILE` | `{ok, complete, diagnostics: [], status, final, fixed_source, transcript}` |
| `aether --json run FILE` | `{ok, complete, diagnostics, stdout, stderr}` — the program's own output, captured (`""` if it never started); the keys `sdk.RunResult.to_dict()` returns |
| `python -m tools.scan --json` | `{ok, complete, scanned, files_with_findings, parse_errors, results: [{path, findings: [to_dict + risk], declared?, parse_error?, unreadable?}], errors}` (+ `mode`, `missing` with `--expect`) |
| any of them, when nothing was analysed (exit 2, 3, or unreadable input) | `{ok: false, complete: false, diagnostics: [], error: {kind: "usage" \| "crash" \| "input", message}}` |

`check-py --no-unprovable` empties each file's `unprovable` rows (most
of the document on a real tree); findings and the exit code do not
change. The LSP `aether/check` reply also carries the pre-0.5 aliases
`position.col` and `data: {suggestion, extra, patch_target}` for the
0.5.x series; they go in 0.6.

**SARIF** carries the same rows: each result has its line and column,
and `properties` holds `confidence`, `suggestion`, `stage` and the
`extra` dict (as `aether`); each rule has `fullDescription` and `help`
(the message and suggestion of its first finding) and a `helpUri` into
`grammar/diagnostics.md`. An unparsed file is a warning
`toolExecutionNotification`; an analyzer crash is an error notification
and sets `executionSuccessful: false`.

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
(86.8% agreement with bandit as an independent oracle **on comparable
categories**, 125 agreed / 19 candidate misses; 34.2% raw agreement over
all of bandit's categories — RECALL.md explains the difference). On `.aeth`
corpora, the aetherbench candidate scan found 13 real bugs
(`bench/SCAN_FINDINGS.md`); faithful ports of real-world shapes are in
`bench/REALWORLD_VALIDATION.md`.
