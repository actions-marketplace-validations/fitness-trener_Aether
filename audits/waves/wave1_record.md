# Wave 1 record — make the gate see what matters (iteration 55)

Plan: `audits/audit_2026-09-24_plan.md`, Wave 1 (F1, F2, F3, F4, F6, and
the E8 gate half). Branch forked from `v0.5-audit-waves` @ `99f09cc`.
Ids: BUG-036..039.

Commits:
- `d7732f9` gate: discover tests/test_*.py; the three orphan suites run (F3, E8, F6)
- `032a639` passes: one Python skip list; analyze() refuses unknown stages (F4)
- `e355774` ratchet: merge-base compare, recall floor, assert-only legitimacy; every sink row pinned (F1, F2, E8)
- `9991e52` ratchet: also compare against HEAD~1 (main itself; a key the branch introduced)
- `8fb3d3c` ratchet: a negative assertion (not in, !=) does not prove a code fires

## BUGS entries

### BUG-036  the ratchet compared the baseline against the commit under test, counted detector existence only, and accepted any mention of a code as its proof  [OPEN]
test: tests/test_ratchet.py
(`::test_baseline_never_lowered`, `::test_recall_floor`,
`::test_legitimacy_counts_assertions_only`, `::test_detectors_legitimately_checked`)

Found 2026-09-24 by the whole-repo audit (F1). Three holes in
`tests/test_ratchet.py`, each probe-confirmed on `99f09cc`:
- `test_baseline_never_lowered` diffed the working tree against `HEAD`. In
  CI the checkout IS the commit under test, so a commit that lowers
  `min_emitted_codes` and deletes a detector compares the lowered file
  with itself and passes.
- The floor counted detectors that exist. A detector reduced to
  `return []` still counts; nothing measured what the detectors find.
- Legitimacy (`test_detectors_legitimately_checked`) looked for the code
  as a substring of the concatenated text of every file under `tests/`,
  so a comment, a docstring or an assert message legitimised a code.

Fix (`e355774`, `9991e52`, `8fb3d3c`):
- The baseline must meet or exceed its value at `HEAD`, `HEAD~1` and the
  merge-base with `origin/main` (warning printed when the ref is missing).
  `gate.yml` checks out with `fetch-depth: 0`. Every integer key is
  compared, not two named ones.
- Recall floor added to `tests/ratchet_baseline.json`:
  `min_corpus_claimed_findings` = 117 (the sum of every `// expect:`
  header over the 93 corpus files `test_corpus.py` scans) and
  `min_py_table_rows` = 93 (`SINK_BY_QUALIFIED` 48, `SINK_BY_METHOD` 14,
  `SINK_BY_BUILTIN` 4, `SINK_GUARDS` 18, `SANITIZER_BY_QUALIFIED` 9).
- A code is proven only when it appears in a string constant inside the
  test expression of an `assert`, in a suite `scripts/run_all.py` runs,
  and not under a negative comparison (`not in`, `!=`, `is not`, `not`).
  All 34 protected codes still qualify.

Proof it bites (scratch commits, dropped afterwards): a commit lowering
`min_emitted_codes` 55 → 54 is red ("LOWERED against 11efc72ec6"); a
commit lowering the new key `min_py_table_rows` 93 → 92 is red ("LOWERED
against 9991e5217c", the parent). Deleting any of the five audit rows
turns `test_ratchet.py` red through `min_py_table_rows`.

### BUG-037  the runtime syscall oracle certified "sound" when it had observed nothing, and its test never ran  [OPEN]
test: tests/test_mining.py (`::test_runtime_oracle_catches_fn`)

Found 2026-09-24 by the whole-repo audit (F3). `scripts/run_all.py` listed
its suites by name; `test_cause_b.py`, `test_phase1.py` and
`test_mining.py` never ran, and `test_mining.py` was red (6/7). Repro on
`99f09cc`: `python -B tests/test_mining.py` → exit 1,
`[FAIL] test_runtime_oracle_catches_fn`.

Root cause: `tools/runtime_oracle.py` shells out to `strace` and parses
Linux strace output. On Windows, Git for Windows puts a Cygwin `strace`
(3.6.5) on PATH; it runs, none of the patterns match, the oracle observes
no capability and returns `soundness_ok: True` for a change that writes a
file — a vacuous "sound". The test caught it; nothing ran the test.

Fix (`d7732f9`): `runtime_oracle.available()` (Linux and `strace` on
PATH); `_trace` raises `OracleUnavailable` otherwise. The test asserts the
refusal where the oracle is unavailable and runs the original check where
it is. `tools/mining/swebench_harness.py` already records a raised error
as `oracle_error` instead of an empty observation. `run_all.py` now globs
`tests/test_*.py` with an explicit, commented `EXCLUDE` (empty); the
three orphans run and pass (cause_b 3/3, phase1 5/5, mining 7/7 with the
oracle case as a refusal check on Windows). `gate.yml` installs strace so
CI runs the real oracle path.

Not verified here: the Linux strace path (no Linux machine in this
session). The first CI run of the suite job is its first execution.

### BUG-038  `analyze(skip=...)` ignored unknown stage names; a test's copy of the Python skip list had drifted  [OPEN]
test: tests/test_ratchet.py (`::test_skip_names_are_stages`)

Found 2026-09-24 by the whole-repo audit (F4). The Python stage-skip list
existed as literals in `cli.py`, `tests/test_py_frontend_sinks.py` (twice)
and `tests/test_confidence.py` (plus the one in `py_frontend.py` the
benches import). The `test_confidence.py` copy was
`("effects", "smt", "modules", "imports", "capability")`: `smt` and
`imports` are not stages, and `semantic`, which check-py never runs, ran.
`analyze()` accepted it silently. Repro on `99f09cc`:
`analyze(ast, skip=("smt",))` returns every stage, no error.

Fix (`032a639`): `PY_SKIP_STAGES` / `PY_STRICT_ONLY_CODES` are defined only
in `py_frontend.py` and imported by `cli.py` (as `_PY_SKIP_STAGES` /
`_PY_STRICT_ONLY_CODES`, so existing references hold) and both tests;
`test_confidence.py` uses `PY_SKIP_STAGES + ("capability",)`, exactly
check-py's default. `analyze()` raises `ValueError` on a name that is not
a stage. `capability._STDLIB_EFFECT_PATHS` is derived from
`effects._STDLIB_EFFECTS` in one expression (verified equal first:
10 entries, identical path sets).

### BUG-039  E0711 (`--strict`) flags `os.path.join(base, secure_filename(name))`, the documented Werkzeug fix  [OPEN]
test: none yet (deferred)

Found 2026-09-24 while writing `tests/test_sink_rows.py` (F2 sanitizer
half). `werkzeug.utils.secure_filename` maps to `safeJoin`, and
`open(secure_filename(x))` is clean, but the idiom Werkzeug documents,
`open(os.path.join(upload_dir, secure_filename(name)))`, fires E0711
("path is a computed call") — with a parameter base and with a literal
base alike. Repro: `check-py --strict` on the two-function file in the
wave scratchpad `w1/sf.py` → 2 × E0711 (plus the expected `--strict`
E0701 inventory).

Root cause: E0711's Python mapping clears only when the whole path is the
wrapper call; `os.path.join` is an unknown computed call. Not a table-only
fix — mapping `os.path.join` to `safeJoin` would be wrong (`join(base,
"../x")` escapes). Needs a frontend rule: `os.path.join(<any>, <sanitizer
call>)` as the last argument ≡ `safeJoin`. Precision, strict-only row
(E0711 is held back by default), so deferred to the precision wave
(Wave 5, next to C1).

## LOOP_LOG block

## Iteration 55 — Wave 1 of the 2026-09-24 audit: the gate can see what matters (no new detector)

- **Target:** not a backlog row. Plan Wave 1 (F1–F4, F6, E8's gate half):
  every later wave is only trustworthy if the gate goes red on its
  reversal.
- **Probe-confirmed first (on `99f09cc`, gate exit 0):**
  - A committed baseline lowering passed `test_baseline_never_lowered`
    (it compared against HEAD). BUG-036.
  - Deleting `mogrify`, `os.popen`, `executemany`, `pandas.read_pickle`
    or `HttpResponseRedirect` left the suite green (the rows had no test).
  - `test_cause_b.py`, `test_phase1.py`, `test_mining.py` never ran;
    `test_mining.py` was red on a vacuous oracle verdict. BUG-037.
  - `analyze(skip=("smt",))` silently ran every stage; one test ran a
    different stage set than check-py. BUG-038.
  - `smt: PASS` printed with z3 absent.
- **Fixes (each once, where every caller routes through):**
  - `run_all.py` discovers `tests/test_*.py` (explicit `EXCLUDE`, empty);
    `test_ratchet.py` reads the same discovery for legitimacy.
  - Ratchet: baseline vs HEAD, HEAD~1 and the merge-base with
    `origin/main`; recall floor (117 claimed corpus findings, 93 table
    rows); legitimacy = a positive `assert`, not a substring.
  - `tests/test_sink_rows.py`: every sink/guard/sanitizer row pinned to its
    codes and generated as a snippet; pins equal the live tables both ways.
  - One Python skip list; `analyze()` rejects unknown stages;
    `_STDLIB_EFFECT_PATHS` derived.
  - `smt` reported SKIP (not PASS) without z3; `gate.yml` gains an `smt`
    job with `z3-solver` that fails on a skip.
- **Mutations, each red:** the five audit row deletions (red in
  `test_sink_rows.py` and `test_ratchet.py`; `test_py_frontend_sinks.py`
  stays green on all five, confirming the audit), a value change
  (`mogrify` → `renderTemplate`, red in `test_sink_rows.py`), a committed
  lowering of an old key and of a new key.
- **Measured non-breaking:** no detector or frontend table changed. See
  Measurements for the check-py comparison.
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** BUG-039 (E0711 flags the Werkzeug
  `os.path.join(base, secure_filename(x))` idiom) joins C1 as a
  "flags the fix" row for Wave 5; the table pins now make every Python row
  change visible, so Wave 4/5 row edits must update `test_sink_rows.py`.
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally).

## q1 rows

| NEW residual: the recall floor counts claims and rows, not argument-shape judgement | iter-55 (Wave 1, audit F1/F2): `min_corpus_claimed_findings` (117) and `min_py_table_rows` (93) catch a deleted row, a row whose sink changed (`tests/test_sink_rows.py` pins each), and a corpus header edited down. They do not catch a detector that keeps firing on the one snippet shape each row is exercised with (`sink(param)`) but stops judging another shape (concatenation, f-string, a bound name) — that remains the job of the shape tests in `tests/test_py_frontend_sinks.py`. Legitimacy now requires a positive `assert` in a gate-run suite; one such assert per code is enough, so a code proven only on the Aether side is "legitimate" for Python too `[source: diagnostics, section: E0713, key: sqlQuery]` | high |
| NEW precision residual (open, BUG-039): E0711's Python sanitizer clears only a whole-path wrapper call | iter-55 (probe-confirmed on `99f09cc`): `open(secure_filename(x))` is clean, `open(os.path.join(base, secure_filename(x)))` — the Werkzeug-documented form — fires E0711 under `--strict`, literal or parameter base. Over-flag direction (no miss); strict-only row. Not a table fix: `os.path.join` itself is not a sanitizer. Joins audit C1 (the `shlex.quote` concatenation) as a flagged fix, both pinned in `tests/test_sink_rows.py` (C1 as an inverted, self-expiring assertion) `[source: diagnostics, section: E0711, key: safeJoin]` | high |

## Skipped / not reproduced / deferred

- **Plan Wave 1 item 4, D3 and B7:** not in this wave's file ownership
  (`tools/scan.py`, `cli.py` beyond constants). B7 was already fixed as
  BUG-035 (`3ccf848`) and its test passes; D3 (scan.py BOM/exit) is left
  for the wave that owns `tools/scan.py`.
- **F2 "rows that do not fire":** none. All 66 sink rows fire exactly
  their pinned codes, all 18 guard rows flag the unsafe spelling and clear
  the safe one, all 9 sanitizer rows translate to their wrapper. No table
  fix needed. `UNEXERCISABLE` is empty.
- **F2 sanitizer "safe snippet is clean":** `shlex.quote` / `pipes.quote`
  have no clean Python spelling today (`"ls " + shlex.quote(x)` → E0714,
  audit C1, Wave 5). Pinned in `KNOWN_FLAGGED_FIX` as an inverted
  assertion: the test goes red when the fix goes clean, so the entry must
  be removed then. Not filed as a new BUG (C1 is the plan's own item).
- **E8, local z3:** not installed. Installing it is a download from PyPI,
  which this session may not do without the owner's explicit consent, and
  it would flip `--prove` default-on for the whole local gate. The CI
  `smt` job is unverified until its first run.
- **Linux strace path of the runtime oracle:** unverified here (Windows
  only); first CI run executes it.
- **Docs:** `CLAUDE.md` step 5 still says to register new stdlib effects in
  both `effects._STDLIB_EFFECTS` and `capability._STDLIB_EFFECT_PATHS`;
  the second is now derived. README/claims that say "38 suites" are now
  low (42 discovered suites + 4 non-test checks). Not edited — docs belong
  to the docs wave.

## Measurements

- Gate at `99f09cc`: exit 0, 38 labelled suites + reference 10/10 + bench
  8/8, `smt: PASS` with z3 absent; 69 s.
- Gate at `8fb3d3c`: exit 0; the 34 labelled test suites plus 4 newly
  discovered (`cause_b`, `mining`, `phase1`, `sink_rows`), reference
  10/10, bench 8/8, arch_bench, capability_fw, demos, fuzz;
  `smt: SKIP`, listed as "SKIPPED (not counted as PASS)".
- check-py re-measure (99f09cc toolchain vs HEAD toolchain, same inputs):
  `check-py --json` over the main checkout's `bench tests tools playground
  demos` (5,154 files, the framework corpus included), with the `99f09cc`
  toolchain and with the Wave 1 toolchain: 786 → 786 findings (676 → 676
  on the framework corpus), identical by (file, line, code, confidence,
  severity); 0 unreadable, 0 errors both sides. Measured 2026-09-25 by the
  coordinator after the resume.

## Changed tests that pinned old behaviour

- `tests/test_mining.py::test_runtime_oracle_catches_fn` — where the
  oracle is unavailable it now asserts the oracle REFUSES; it used to
  assert a verdict the oracle could not produce there. The Linux
  assertion is unchanged.
- `tests/test_confidence.py` — its skip tuple (a drifted copy) replaced by
  check-py's actual default; 9/9 still pass.
- `tests/test_ratchet.py::test_detectors_legitimately_checked` — tightened
  (substring → positive assert). No test was loosened.
