# Wave 5b record — one exit-code table, one JSON contract (iteration 61)

Plan: `audits/audit_2026-09-24_plan.md`, Wave 5 items D5, D6, D10-partial
(SARIF, category enum, `--no-unprovable`, single Action run) and B6.
Forked from `v0.5-audit-waves` @ `a60b16e`. Ids: BUG-077..079.
**Breaking change: ships as 0.5.0** (`CHANGELOG.md`, new). The version in
`pyproject.toml`/`__init__` is not bumped here — the release does that.

Commits:
- `50ed1f1` one exit-code table and one JSON contract on every surface (D5, D6, B6, D10-partial)
- this record

Every item was reproduced red on `a60b16e` first, and every new/changed
test was run against the `a60b16e` sources (a `git archive a60b16e` tree
with the new tests copied in) and failed — see Measurements, "red before".

## BUGS entries

### BUG-077  exit codes conflated findings, parse errors, usage errors and crashes; a crash under `--json` was a raw traceback  [OPEN]
test: tests/test_exit_codes.py (`::test_check_exit_table`,
`::test_check_crash_is_3_and_json_survives`, `::test_check_py_exit_table`,
`::test_check_py_crash_is_3`, `::test_scan_exit_table_and_json`,
`::test_fix_loop_exit_table`, `::test_real_process_exit_codes`);
tests/test_action.py (`::test_scan_step_obeys_the_exit_code_table`)

Found 2026-09-24 by the audit (D5, P1). Repro on `a60b16e`: `aether check
demos/payment_workflow/broken.aeth` → exit 2; `aether check` on a file with
a parse error → exit 2; `aether check nope.aeth` → exit 2; `aether check
--bogus` → exit 2 (argparse); a detector exception → raw traceback, exit 1,
even under `--json`; `aether check-py` → 2 on findings and 2 on a per-file
analyzer crash; `tools/scan.py` → 1 on findings and 1 on parse errors, and
**0 on a path that does not exist** (it globbed nothing). `action.yml`'s
"an analyzer crash always fails the job" was false: the step detected a
crash only as `rc == 2 && findings == 0`, so a crash in one file of a tree
with findings elsewhere passed with `fail-on-findings: false` (reproduced
by running the step's own script against a stand-in `aether` exiting 3 with
two findings: step exit 0).

Root cause: no shared table. Each command returned literal integers; `main`
caught only `AetherError`/`FileNotFoundError`; argparse exited on its own.

Fix (`50ed1f1`): `diagnostics.py` defines the table once —
`EXIT_CLEAN 0 · EXIT_FINDINGS 1 · EXIT_USAGE 2 · EXIT_CRASH 3 ·
EXIT_INCOMPLETE 4` and `exit_code(findings, incomplete, crashed)` (precedence
3 > 1 > 4 > 0) — imported by `cli.py`, `fix_loop.py` and `tools/scan.py`.
`cli.main` wraps everything: argparse errors (a `_Parser` subclass raising
instead of exiting) and in-command usage errors → 2; an escaped
`AetherError` → 4 for lex/parse, 3 for emit/internal, else 1; unreadable
input → 4; any other exception → 3 with a JSON error document under
`--json` (traceback on stderr in text mode or with the new `--debug`).
`check`: a load failure (parse error, E0705/E0706) → 4; findings and E0901
→ 1; `--prove` without z3 → 2. `run`: a runtime contract violation or an
exception raised by the program itself → 1. `fix_loop.main`: a crash in the
loop → 3, unreadable input → 2. `tools/scan.py`: per-file crash wall →
3, unreadable/unparsed → 4 (unless `--allow-parse-errors`), a missing
path → 2. `action.yml` reads the table: 3 always fails, 2 fails, an
incomplete scan (counted from the SARIF's warning notifications, so it is
seen even when findings make the exit 1) fails unless the new
`allow-incomplete: true`; findings stay with the fail-on-findings step.
`aether test` keeps its fixture table (0/1/2) on purpose — `run_all.py` and
`bench/harness.py` grade on it.

### BUG-078  five JSON shapes: `--json check` wrote JSONL to stderr, `check-py --json` said `ok: true` with nothing analysed, `patch_target` existed only in the LSP  [OPEN]
test: tests/test_exit_codes.py (`::test_check_json_is_one_document_on_stdout`,
`::test_check_py_json_complete_and_ok`, `::test_check_py_no_unprovable`,
`::test_sdk_and_lsp_speak_to_dict`, `::test_sarif_rules_carry_descriptions`)

Found by the audit (D6, P1; D10 partial; survey TC-08). Repro on `a60b16e`:
`aether --json check broken.aeth` → nothing on stdout, three
`{"ok": false, "diagnostic": {...}}` lines on **stderr**; `--collect-errors`
→ the same diagnostics on stdout AND stderr; `check-py --json` on a file
that does not parse → `{"ok": true, ...}`, exit 0; LSP `aether/check` →
`position.col`, no severity/category/confidence; `tools/scan.py` findings
→ their own dict (`line`, `column` top-level), `parse_error` a third shape;
`patch_target` only in the LSP; SARIF rules → `shortDescription` = the bare
code, no description, no help.

Fix (`50ed1f1`): `Diagnostic` gains `stage` (set by every surface
that runs `analyze()`: CLI, `sdk.check`, `check-py`'s `_scan_one`,
`tools/scan.py`; `smt` for E0901/E0902) and `to_dict(ast=None)` always
emits `stage` and `patch_target` (computed by `passes/patch_target.py`,
called, not edited, when an AST is given). Every surface serializes with
it: `check --json`, `--collect-errors`, `check-py --json`,
`sdk.CheckResult.to_dict()` (new, with `complete`), LSP `aether/check` and
`publishDiagnostics` `data`, SARIF, `tools/scan.py` (`to_dict()` + `risk`;
`parse_error` = the parse diagnostic's `to_dict()`). Every `--json` run
prints exactly one document on stdout — usage errors and crashes included
(`{"ok": false, "complete": false, "diagnostics": [], "error": {kind,
message}}`); stderr carries only human text; `aether --json fix-loop`
prints `{ok, complete, status, final, fixed_source, transcript}`.
`check-py --json`: `ok` is exactly "exit 0", new `complete`; new
`--no-unprovable` empties the `unprovable` rows (default unchanged). SARIF:
rules gain `fullDescription`/`help` (the first finding's message and
suggestion) and `helpUri` (`grammar/diagnostics.md`); results gain
`properties.stage`; an analyzer crash is an error notification and
`executionSuccessful: false`. LSP severity now maps warning → 2 (E0902
published as Error before). The Action runs `check-py` once (it ran twice)
and prints the human report from the SARIF. `diagnostics.py` documents the
category enum actually emitted (lex, parse, type, effect, capability,
module, contract, refinement, runtime, timeout, emit, internal); nothing
renamed.

**LSP choice (recorded as asked):** `aether/check` returns the unified
`to_dict()` rows and, for the 0.5.x series only, keeps the old
`position.col` and `data: {suggestion, extra, patch_target}` as aliases;
remove both in 0.6. `tools/alsp_surface.py` and `tools/py_surface.py` build
their own dicts (with `col`) and were not changed (not owned, not
`aether/check`).

### BUG-079  `check-py` exited 0 with `ok: true` when the files could not be parsed — valid 3.12 source scanned on 3.10/3.11 included  [OPEN]
test: tests/test_exit_codes.py (`::test_newer_python_syntax_is_incomplete_with_hint`,
`::test_check_py_exit_table`); tests/test_py_frontend_sinks.py
(`::test_unreadable_and_skipped_are_visible_in_every_mode`)

Found by the audit (B6, P1). Repro on `a60b16e` under Python 3.11:
`import os\ndef f(d):\n    os.system(f"echo {d["k"]}")` (PEP 701) →
stderr note `could not parse ... f-string: unmatched '['`, stdout
`{"ok": true, "files": [], ...}`, exit 0 — an E0714 missed with a green
result. Same for a PEP 695 `type X = ...` line.

Root cause: the documented policy "unparseable input never fails the run".

Fix (`50ed1f1`): an unreadable/unparsed file makes the run incomplete:
exit 4 when nothing was found, 1 when something was (`complete: false`
either way), in text, `--json` and `--sarif`. On 3.10/3.11 a SyntaxError
whose message starts `f-string` or whose line has a PEP 695 shape
(`type X =`, `def f[T]`, `class C[T]`) gets "— valid on a newer Python?
scan with 3.12+ (this is Python 3.x)" appended to its detail (stderr,
JSON, SARIF). A heuristic on the error text, hence the question mark: a
genuinely malformed f-string on 3.11 gets the hint too; py2 `print 'x'`
does not. Verified on 3.13: the PEP 701 repro parses and exits 1 (E0714).

## LOOP_LOG block

## Iteration 61 — Wave 5b of the 2026-09-24 audit: one exit-code table, one JSON contract (no new detector)

- **Target:** not a backlog row. Plan items D5, D6, B6 and D10-partial:
  an agent or CI job could not tell "found something" from "could not
  run" from "crashed", and every surface spoke its own JSON.
- **Probe-confirmed first (on `a60b16e`):** `check` exit 2 for findings,
  parse errors, import errors and usage alike; a crash under `--json` a raw
  traceback, exit 1; `tools/scan.py` exit 0 on a missing path; the Action
  passed a crash that had findings elsewhere; `--json check` JSONL on
  stderr; `check-py --json` `ok: true`, exit 0 on a PEP 701 file under
  3.11. BUG-077..079.
- **Fix (once, where every caller routes through):** the table and
  `exit_code()` in `diagnostics.py`; `Diagnostic.to_dict(ast)` with
  `stage` + `patch_target`; `cli.main` wraps every command; one stdout
  document per `--json` run; SARIF rule descriptions; Action reads the
  table and runs once.
- **Measured non-breaking for findings:** framework corpus 707 findings
  before and after (0 unreadable, 0 errors on 3.11), exit 2 → 1; worktree
  `bench tests tools playground demos` 115 findings, identical rows, exit
  2 → 1. Corpus expect-headers unchanged.
- **Breaking for callers (0.5.0, CHANGELOG):** exit codes and JSON shapes;
  15 grader files and 11 test files that pinned exit 2 / the old shapes
  updated (listed in the record).
- **Residuals (pushed to q1):** see q1 rows.
- **TYPE gap surfaced for next iter:** `aether run --json` still interleaves
  the program's own stdout with the JSON document (the program's output is
  the product); a `run` JSON contract needs the program's stdout captured
  into the document — decide whether `run` is an agent surface at all.
- **Suite:** exit 0 (`smt` SKIP locally — z3 absent under 3.11; `test_smt`
  run green separately under Python 3.13 + z3 4.16).

## q1 rows

| NEW residual: the "valid on a newer Python?" hint is a heuristic on the SyntaxError | iter-61 (Wave 5b, audit B6): on 3.10/3.11 `check-py` cannot parse 3.12 syntax, so it cannot know the file is valid; it appends the hint when the error message starts `f-string` (PEP 701) or the offending line has a PEP 695 shape. A malformed f-string also gets it; 3.13/3.14-only syntax scanned on 3.12 gets none. The exit code does not depend on the hint: any unparsed file is exit 4 (or 1 with findings) `[source: diagnostics, section: exit codes, key: incomplete]` | low |
| NEW residual: a SARIF rule's description is its first finding's text | iter-61 (TC-08): there is no per-code title table in the package (grammar/diagnostics.md is not in the wheel), so `fullDescription`/`help` are the message/suggestion of the first result of that rule, which may name a function; `helpUri` points at grammar/diagnostics.md for the class description `[source: diagnostics, section: SARIF, key: helpUri]` | low |
| NEW residual: `patch_target` is null on every Python finding | iter-61 (D6): the path indexes the Aether IR, not the user's Python source, so `check-py` never fills it; an agent fixing Python has `position` and `suggestion` only `[source: diagnostics, section: E0713, key: patch_target]` | medium |

## Skipped / not reproduced / deferred

- **D10 other parts** (E0801 call-site position in `extra`, `·`/`×`
  mojibake ASCII fallback) — not in this wave's list. JSON output is now
  ASCII-escaped (`json.dump` default), so `--json` never raises on a legacy
  console codepage; text mode is unchanged.
- **`aether run --json`**: the program's own stdout precedes the JSON
  document on stdout. Not fixed (see the LOOP_LOG gap).
- **`aether test`** keeps 0/1/2 (fixture runner; graded by `run_all.py` and
  `bench/harness.py`). Its `--json` output is now one stdout document too.
- **`bench/harness.py` / `aether/runner.py`** `exit_code` (0 / 2
  AetherError / 1 other / 124 timeout) is the in-process runner's own
  field, not a CLI exit; untouched, and `bench/tasks/*/grader.json`
  `expected_exit_code: 2` refer to it.
- **Category `security`**: not added here (Wave 5a owns hint/category
  text); if 5a adds it, extend the enum comment in `diagnostics.py` and the
  sentence in docs/SCANNING.md.
- **Docs that describe pre-0.5 "exit 2" as current** (not owned; for Wave 6
  / the coordinator): `bench/EVIDENCE.md:28-35,83`,
  `bench/REALWORLD_VALIDATION.md:94-99`,
  `demos/capability-firewall/README.md:55`,
  `demos/case_studies/{code_injection,command_injection,crawl4ai_ssrf,idor_cross_tenant,insecure_deserialization,log4shell}/REPORT.md`
  (their "exit 2" lines for `aether check` are now exit 1). Historical
  records (LOOP_LOG, BUGS.md, docs/history) are correct as history and were
  left alone. `bench/CONTRACT_TASKS.md` describes the runner's table — still
  true.
- **Files outside the listed ownership that had to change** (they would
  otherwise go red, or they parse the old output): the 15 `grader.json`
  files (`bench/architectural/T01..T10`, `demos/architectural-integrity/
  demo_01..05`: `expected_exit_code` 2 → 1), `demos/architectural-integrity/
  run_demos.py` (default 2 → 1) and the six READMEs under
  `demos/architectural-integrity/` ("exit 2" → "exit 1"),
  `bench/architectural/run_bench.py` (docstring table), and the JSON readers
  `bench/evidence_run.py`, `bench/realworld_cve/run_corpus.py`,
  `bench/aetherbench/run.py` (JSONL-on-stderr → one stdout document; the
  first two re-run: all 8 / 4 CVE rows OK). `.github/workflows/gate.yml`:
  the installed-wheel step asserted `check-py` exit 2 → now 1 (CI-only,
  not run locally). Coordinator: review.

## README sentences to change (coordinator applies)

- `README.md:39-40` — replace "Exit `0` clean, `2` on findings or on an
  error (a missing path, an analyzer crash)." with: "Exit `0` clean, `1`
  findings, `2` usage error (a missing path), `3` analyzer crash, `4`
  incomplete (a file could not be parsed and nothing was found) — the same
  table for `check`, `check-py`, `fix-loop` and `tools/scan.py`
  ([docs/SCANNING.md](docs/SCANNING.md#exit-codes-and-the-json-contract))."
- `README.md:307-309` — Inputs list: add `allow-incomplete` after
  `fail-on-findings`; Outputs list: add `unparsed` after `exit-code`.
- `README.md:356-357` — after "emits structured output for an agent to
  consume" add: "— exactly one JSON document on stdout, every diagnostic as
  `Diagnostic.to_dict()` (`stage`, `patch_target`, `confidence` included)".
- `README.md:387` — "42 PASS suites" → "43 PASS suites" (new
  `tests/test_exit_codes.py`).
- `README.md:276-277` ("it filters the exit code too: a run whose only
  findings are below the floor exits 0") stays true.

## Measurements

- **Framework corpus** (`bench/framework_scan/_work/src`, 4,946 files,
  `--json check-py --no-unprovable`, Python 3.11): after — 707 findings,
  all `stage: "security"`, 0 unreadable, 0 errors, `complete: true`, exit
  1. At `a60b16e`: 707 findings (Wave 4's number), exit 2. No row can move:
  no detector, frontend table or stage changed; `_scan_one` walks
  `analyze()` instead of `analyze_flat()`, which is the same iteration.
- **Worktree `bench tests tools playground demos`** (`check-py --json`,
  same paths, `a60b16e` sources vs this branch): 213 files, 115 findings
  both (E0713 29, E0714 11, E0718 3, E0719 3, E0720 20, E0723 19, E0727 2,
  E0731 28), 0 added / 0 removed rows, 0 unreadable; exit 2 → 1.
- **Red before** (a60b16e sources, new tests copied in):
  `test_exit_codes` 0/13; `test_action::test_scan_step_obeys_the_exit_code_table`
  red on the crash case (rc 3 + 2 findings → old step exit 0; run with the
  new SARIF renderer, since the old one cannot read `to_dict` rows);
  `test_surfaces_agree`, `test_module_validation`, `test_multi_file`,
  `test_parser_recovery`, `test_static_effects`, `test_playground`,
  `test_scan`, `test_py_frontend_sinks` red on their updated pins;
  `test_smt` (3.13 + z3) red (`rc 2`). All green on this branch.
- **Gate:** `python -B scripts/run_all.py` exit 0 (45 PASS lines, was 44;
  `smt` SKIP, z3 absent under 3.11).

## Changed tests that pinned old behaviour

Each pinned the exit code or JSON shape this wave replaces:

- `tests/test_surfaces_agree.py` — `_cli_json_codes` read JSONL from
  stderr → the stdout document; cross-file E0801 rc 2 → 1; unresolved
  import rc 2 → 4; `--json`/text stage test rc 2 → 1; scan `parse_error`
  `line` → `position.line`; scan exits `[lex]` 1 → 4, `[lex, --expect]`
  1 → 4.
- `tests/test_module_validation.py::test_cli_module_check_default_on` —
  E0702 rc 2 → 1.
- `tests/test_multi_file.py` — missing import E0705 and cycle E0706 rc 2 → 4.
- `tests/test_parser_recovery.py::test_cli_collect_errors_flag` — rc 2 → 4
  (strict and `--collect-errors`).
- `tests/test_static_effects.py::test_default_on_through_cli` — rc 2 → 1.
- `tests/test_playground.py::test_E0801_violation_surfaces` — rc 2 → 1.
- `tests/test_scan.py::test_sarif_carries_risk_metadata` — the synthetic
  finding is now `to_dict`-shaped (`position`).
- `tests/test_py_frontend_sinks.py` — `test_e0711_appears_under_strict`,
  `test_check_py_cli_reports_and_exits_2` (renamed `..._exits_1`),
  `test_directory_walk_scans_every_file`,
  `test_unparseable_file_does_not_abort_the_walk`,
  `test_utf8_bom_file_is_scanned_not_silently_skipped`,
  `test_pep263_cookie_file_is_scanned`: rc 2 → 1;
  `test_unreadable_and_skipped_are_visible_in_every_mode`: rc 2 → 1, plus
  `complete`/`ok` asserted, and "an unparseable file alone never fails the
  run" (rc 0) → rc 4 in text, `--json` and `--sarif` (the B6 defect as the
  expected outcome); `test_file_too_deep_for_python_is_unparseable_not_a_crash`
  rc 0 → 4; `test_detector_value_error_is_a_crash_not_unreadable` patches
  `passes.analyze` instead of `passes.analyze_flat` (the function
  `_scan_one` now walks; same property).
- `tests/test_smt.py` — `test_cli_prove_refuted_exits_2` → `..._exits_1`
  (rc 1; E0901 read from the stdout document, `stage: "smt"`);
  `test_cli_prove_is_default_on_when_z3_present` rc 2 → 1.
- `tests/test_action.py` — new behaviour test (runs the scan step's own
  script under Git bash / bash with a stand-in `aether`); `_bash()` never
  picks System32's WSL launcher; SKIPs without a POSIX bash.
