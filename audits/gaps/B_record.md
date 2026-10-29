# Known-gaps round, Agent B (toolchain) record

Base `gaps-2026-09-29` @ `a2f13db`. Ids BUG-090..094 (used: 090, 091),
iteration 64. Commits: see the end of this file.

Scope: G1 (`aether run --json` interleaved the program's stdout with the
document; wave5b_record.md "TYPE gap surfaced") and G4 (the spec test
compared stdlib names, not signatures; wave6_record.md "TYPE gap
surfaced", BUG-050 the example). No detector, no frontend, no pass
changed.

## BUGS entries

### BUG-090  `aether --json run` breaks the one-document contract: the program's stdout precedes (or replaces) the JSON  [OPEN]
test: tests/test_exit_codes.py::test_run_json_captures_the_program_output

Repro on `a2f13db` (the program prints a line that looks like JSON):

    function main() returns Unit
      effects log
    do
      print("{\"ok\": true, \"fake\": 1}")
      print("hello")
    end

`aether --json run p.aeth` → stdout is the program's two lines and
**nothing else**, exit 0: a clean run printed no document at all, and the
first line parses as `{"ok": true}`. With a `requires` violation after a
`print`, stdout was the program's line followed by the diagnostic document
(two JSON-looking lines; `json.loads` → "Extra data"). With an exception
the program raised (`10 / 0`), stdout was the program's output, the
traceback went to stderr, exit 1, and no document was printed.

Root cause: `cli.cmd_run` executed the program with stdout attached to
the process, reported only through `main`'s `AetherError` handler, and
returned `0`/`1` on the other paths without calling `_report`.

Fix (`transpiler/aether/cli.py`): under `--json`, `cmd_run` redirects the
program's stdout and stderr into buffers and every `run` document gets
`stdout` and `stderr` fields. `_report` merges `args.run_output`, which
`cmd_run` sets, so the parse/import-failure document, the static-finding
document and the runtime-violation document raised through `main` all
carry the two keys (`""` when the program never started). A clean run now
prints `{ok: true, complete: true, diagnostics: [], stdout, stderr}`. An
exception the program raised is reported as the documented `E9003`
(category `runtime`, the code the in-process runner already used), with
the traceback in `stderr`. `sdk.RunResult.to_dict()` (new) returns the
same keys; the test asserts the CLI document equals it for a clean
program. Exit codes are unchanged: 0 ran clean, 1 static finding /
E03xx / program exception. Text mode is unchanged (asserted).

Red before the fix: the new test fails with `JSONDecodeError: Extra data:
line 2 column 1` (cli.py and sdk.py reverted, test kept: 13/14).

Measurement: no detector or frontend change; framework corpus `--json
check-py` output byte-identical (below).

### BUG-091  stdlib.md parameter lists drifted from the runtime in six functions; no test compared signatures  [OPEN]
test: tests/test_spec_docs.py::test_stdlib_doc_signatures_match_runtime

`tests/test_spec_docs.py` checked that every documented stdlib name
exists in the runtime, but not its signature, so a documented parameter
list could drift and a documented overload could crash (BUG-050: `remove`
on a Set). The new test reads every `function` signature in
`grammar/stdlib.md` (120 signatures, 115 names) and checks
`inspect.signature(build_namespace()[mangle(name)])`:

- **arity**, for every signature, overloads included: **0 drifts**.
- **parameter names in order**, for each of the 110 names documented
  once. Aether has no named arguments, so ORDER is the contract and equal
  names are how a test can see a swap. One documented name Python cannot
  spell (`replace`'s `from` → runtime `frm`) is allow-listed. **6
  drifts found**:

  | function | stdlib.md | runtime before |
  |---|---|---|
  | `startsWith?` | `(s, prefix)` | `(s, p)` |
  | `endsWith?` | `(s, suffix)` | `(s, p)` |
  | `reveal` | `(s)` | `(x)` |
  | `csvEscape` | `(x)` | `(v)` |
  | `redirect` | `(target)` | `(url)` |
  | `pow` | `(base, exp)` | `(a, b)` |

  None is a positional-order drift: the runtime used different names in
  the same positions. Fixed in the runtime (the spec is the reference):
  parameters renamed, bodies unchanged. No behaviour change is possible:
  Aether calls are positional, the emitter emits positional calls, and a
  grep finds no caller of these helpers outside the emitted code.
- **every overload documented for several types runs**: the test
  derives the overload set from the doc (`length` on List/String, `get` on
  List/Map, `size` on Map/Set, `remove` on Map/Set, `contains?` on
  Set/String: 10) and requires a probe program for each; each is run
  through `sdk.run` and its stdout compared. **0 failures** on `a2f13db`:
  BUG-050's fix (8722ce6) holds. A new overload without a probe fails the
  test.

Red before the fix: on `a2f13db`'s runtime the test fails listing the six
drifts above. The probe half on a deliberately broken copy (the
pre-BUG-050 Map-only `_ae_remove` monkeypatched in) fails with
`remove on Set: ... runtime error: TypeError: cannot convert dictionary
update sequence element #0 to a sequence`.

Measurement: runtime-only rename; framework corpus output byte-identical.

## LOOP_LOG block

## Iteration 64 — known-gaps round, Agent B: `run --json` is one document; stdlib signatures tested (no new detector)

- **Target:** not a backlog row. Two TYPE gaps surfaced by earlier
  iterations: iter-61 (`run --json` interleaves the program's stdout with
  the document) and iter-57 (the spec test covers names, not signatures).
- **Probe-confirmed first (on `a2f13db`):** `--json run` of a clean
  program prints no document; with a contract violation, the program's
  output and the document are two JSON-looking lines on stdout; with a
  program exception, no document. Six stdlib helpers name their
  parameters differently from `grammar/stdlib.md`. BUG-090, BUG-091.
- **Fix:** `cmd_run` captures the program's stdout/stderr under `--json`
  into `{ok, complete, diagnostics, stdout, stderr}` (a program exception
  is `E9003`); `sdk.RunResult.to_dict()` has the same keys. The spec test
  checks arity for all 120 documented signatures, name order for the 110
  names documented once, and runs each of the 10 documented overloads.
  Six runtime parameters renamed to the spec's names.
- **Measured non-breaking:** framework corpus (4,946 files) `--json
  check-py` at `a2f13db` and after: byte-identical, sha256 `87EA1A28...`,
  683 findings, 0 unreadable, 0 errors.
- **TYPE gap surfaced for next iter:** the spec test checks arity and
  order, not TYPES: a documented parameter type the runtime rejects is
  caught only where the doc documents an overload (probed). A
  single-signature function documented for `List<T>` that crashes on a
  `List<String>` (e.g. `sort` on mixed values) is not probed; and return
  types are not compared at all.
- **Suite:** exit 0, 49 PASS suites (`exit_codes` 14 cases, `spec_docs`
  7 tests); `smt` SKIP (z3 absent locally).

## q1 rows

| NEW residual: stdlib signatures are tested for arity and order, not types | iter-64 (known-gaps B, BUG-091): `tests/test_spec_docs.py` compares every documented signature's arity with the runtime and, for a name documented once, its parameter names in order; every overload documented for several types is run once. Parameter TYPES and return types are not compared (there is no type checker to compare against), so a single-signature function that crashes on a documented element type is not caught `[source: stdlib, section: Map<K,V>, key: remove]` | medium |
| NEW scope fact: `run --json` captures only what the program wrote through Python's `sys.stdout`/`sys.stderr` | iter-64 (BUG-090): capture is `contextlib.redirect_stdout/stderr`, which every stdlib output (`print`) goes through; output written to the OS file descriptors directly would bypass it — no stdlib function does. A crash of Aether itself mid-run prints the `error` document (kind `crash`) without the partial output `[source: diagnostics, section: exit codes, key: run]` | low |

## Skipped / not reproduced / deferred

- `sdk.RunResult.exit_code` keeps the runner's own table (0 / 2
  AetherError / 1 other / 124 timeout); it is not in `to_dict()`, so the
  CLI document and the SDK dict never disagree on a key's meaning. The
  runner's `stderr` is the formatted diagnostic text, the CLI's `stderr`
  is the program's own stderr (traceback): both are human text; noted,
  not unified.
- `grammar/diagnostics.md` E9xxx intro says those codes are emitted by
  `bench/harness.py`; `aether --json run` now also emits `E9003`. Not my
  file (Agent A owns diagnostics.md) — coordinator: add "and by `aether
  --json run` for an exception the program raised" to the E9003 row.
- No `.aeth` added; no ratchet change (no detector).

## Measurements

- Framework corpus, `python -B -m transpiler.aether.cli --json check-py
  <_work/src>`: `a2f13db` (pristine `git archive` of `transpiler/` +
  `tools/`) vs this branch — 47,351,778 bytes each, identical sha256
  `87EA1A28017270D214DE2F58A6C2EF50C96971D5B134813E73B217A1CAC9C747`;
  4,946 files, 683 findings, 0 unreadable, 0 errors; exit 1 both.
- `tests/test_exit_codes.py`: 14/14 (was 13 cases).
- `tests/test_spec_docs.py`: 7 tests pass (was 6).
- Gate (`python -B scripts/run_all.py` at `5809adb`'s tree): exit 0, 49
  PASS suites, `smt` SKIP (z3 not installed locally).

## Changed tests that pinned old behaviour

None.

## README sentences to change (coordinator applies)

None required: README does not describe `run --json`. Optional, if the
README lists the `--json` documents: add "`aether --json run` prints
`{ok, complete, diagnostics, stdout, stderr}` with the program's own
output captured".

## Commits

- `6ece638` fix(cli): aether --json run prints one document with the program's output (BUG-090)
- `5809adb` test(spec): check stdlib.md signatures against the runtime (BUG-091; carries the CHANGELOG entries for both)
- this record
