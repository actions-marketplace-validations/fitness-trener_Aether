# Changelog

## 0.5.0 (unreleased)

### Breaking: one exit-code table, one JSON contract

`aether check`, `aether check-py`, `aether fix-loop` and `tools/scan.py`
now share one exit-code table, in text, `--json` and `--sarif` mode
(audit 2026-09-24 D5/D6/B6; full contract in `docs/SCANNING.md`,
"Exit codes and the JSON contract"):

| exit | meaning |
|---|---|
| `0` | clean |
| `1` | findings (`fix-loop`: not repaired) |
| `2` | usage error (bad flag or value, missing path) |
| `3` | analyzer crash — a bug in Aether |
| `4` | incomplete — some input could not be read or parsed, and nothing was found |

What changes for a caller:

- **Findings exit `1`, not `2`** (`check`, `check-py`, `run`'s static
  stages and runtime violations). A script testing `rc == 2` for
  "found something" must test `rc == 1`.
- **A file that does not parse is exit `4`, not `2` (`check`) or `0`
  (`check-py`) or `1` (`tools/scan.py`).** `check-py` over a tree it could
  not parse used to exit `0` with `"ok": true` — including valid 3.12+
  source scanned on Python 3.10/3.11, which now also says "valid on a
  newer Python? scan with 3.12+". An unresolved `import` (E0705/E0706) is
  `4` too. With findings as well, the exit is `1` and the JSON says
  `"complete": false`.
- **An analyzer crash is exit `3`** everywhere, whatever else was found;
  under `--json` it still prints a JSON document (`error.kind: "crash"`)
  instead of a raw traceback (`--debug` adds the traceback).
- **`--json` prints exactly one JSON document on stdout.** `aether --json
  check` used to print one `{"ok": false, "diagnostic": {...}}` line per
  diagnostic on **stderr**; it now prints `{"ok", "complete",
  "diagnostics": [...], "decls"?, "prove"?}` on stdout. `--collect-errors`
  no longer duplicates its diagnostics on stderr. Usage errors print
  `{"ok": false, "complete": false, "diagnostics": [], "error": {...}}`.
- **Every diagnostic is `Diagnostic.to_dict()`** with every key present:
  `stage` and `patch_target` are new, on every surface (`check`,
  `check-py`, `tools/scan.py`, `sdk.CheckResult.to_dict()` (new), LSP).
  `tools/scan.py` findings are that dict plus `risk` — the top-level
  `line`/`column` keys are gone (read `position.line`/`position.column`),
  and `parse_error` is the parse diagnostic's `to_dict()`.
- **`check-py --json`**: `ok` is false when a file could not be parsed;
  new `complete` key; new `--no-unprovable` flag drops the `unprovable`
  rows.
- **LSP**: `aether/check` returns the `to_dict()` rows; the old
  `position.col` and `data` keys stay as aliases through 0.5.x and go in
  0.6. `publishDiagnostics` maps warnings to LSP severity 2 (was always
  1) and its `data` is the full `to_dict()`.
- **SARIF**: rules gain `fullDescription`, `help` and `helpUri`; results
  gain `properties.stage`; a crash sets `executionSuccessful: false`.
- **GitHub Action**: runs `check-py` once (was twice); an analyzer crash
  always fails the job (it was detected only as "exit 2 with no
  findings"); an incomplete scan fails the job unless the new
  `allow-incomplete: true` input is set; new `unparsed` output.
- `tools/scan.py` given a path that does not exist is a usage error (2);
  it used to scan nothing and exit 0.
- **`aether --json run`** prints one document, `{"ok", "complete",
  "diagnostics", "stdout", "stderr"}`, with the program's own output
  captured into `stdout`/`stderr` (the keys `sdk.RunResult.to_dict()`,
  new, also returns). It used to print the program's output on stdout
  ahead of the document, and a clean run printed no document at all.
  Exit codes unchanged: `0` ran clean; `1` a static finding, a runtime
  contract/refinement violation (E03xx) or an exception the program
  raised (now reported as `E9003` in `diagnostics`, traceback in
  `stderr`). Text mode is unchanged.

### Fixed

- `grammar/stdlib.md` is now checked against the runtime's signatures
  (`tests/test_spec_docs.py`): arity for every documented function,
  parameter order for every function documented once, and a run of every
  overload documented for several types (`length`, `get`, `size`,
  `remove`, `contains?`). Six runtime helpers named their parameters
  differently from the spec (`startsWith?`, `endsWith?`, `reveal`,
  `csvEscape`, `redirect`, `pow`); renamed to the spec's names. Aether
  has no named arguments, so no program's behaviour changes.
