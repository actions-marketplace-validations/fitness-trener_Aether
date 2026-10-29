# Wave 6 record — tell the truth everywhere (docs half)

Base `52f04aa` (rebased from `99f09cc`). Commits:

- `36dc323` docs(history): move 13 superseded root reports under docs/history/
- `a48e0c9` docs(spec): say what is checked, and test the spec against the code
- `de779a5` bench(framework_scan): pin the 15-framework corpus by version and hash
- `acc0623` docs: one positioning paragraph; SECURITY_POSTURE and SCANNING rewritten

Scope done: audit E3, E4, E5, E6, E7, E9, E10, E11. No transpiler, runtime
or detector change.

## BUGS entries

### BUG-050  `remove` on a `Set` raises a Python `TypeError`; stdlib.md documents it for `Set<T>`  [OPEN]
test: none yet (runtime fix is outside Wave 6's file ownership; the doc now states the defect)

Found 2026-09-24 while writing `tests/test_spec_docs.py` (E4, reading every
documented stdlib signature against `runtime.py`). `grammar/stdlib.md`
documents `remove<T>(s: Set<T>, x: T) returns Set<T>` beside
`remove<K, V>(m: Map<K, V>, k: K)`. The runtime has one `_ae_remove(m, k)`
that does `new = dict(m)` — written for a Map. Repro on `99f09cc` and
`52f04aa`:

    function main() returns Int effects pure do
      let s: Set<Int> = setUnion([1], [2])
      let t = remove(s, 1)
      return size(t)
    end

`check` exit 0; `run` → `TypeError: cannot convert dictionary update
sequence element #0 to a sequence`. (A Set can only be obtained from
`setUnion`/`setIntersection`/`setDifference`/`add`; there is no Set
literal — `{1, 2}` is `E0201`.)

Root cause: `_ae_remove` in `transpiler/aether/runtime.py` handles only
`dict`. Proposed fix (for the wave that owns runtime.py): branch on
`isinstance(m, (set, frozenset))` → `frozenset(m) - {k}`; regression test
in `tests/test_stdlib_d1.py` asserting `remove(setUnion([1],[2]), 1)` has
size 1. Measurement: none needed (no detector touches `remove`).
`grammar/stdlib.md` "Set<T>" now carries a "Known defect" note — delete it
with the fix.

## LOOP_LOG block

## Iteration 57 — Wave 6 of the 2026-09-24 audit: the spec says what is checked (no new detector)

- **Target:** not a backlog row. Plan Wave 6 docs half (E3–E7, E9–E11):
  the spec and the top-level docs claimed things the code does not do,
  and nothing tested the spec against the code.
- **Probe-confirmed first (on `99f09cc`, again on `52f04aa`):**
  - No type checker, no name resolution: `returns Int` / `return "x"`,
    `let x: Int = "s"`, `f("str")` for `f(a: Int)` pass `check` and `run`;
    `f(1, 2, 3)` and `frobnicate(1)` pass `check` and die at `run` with a
    Python `TypeError` / `NameError`. `types.md` said "everything else is
    checked statically".
  - `stdlib.md` documented `plus(Instant, Duration)` / `minus(Instant,
    Instant)`; `run` → `NameError: _ae_plus`. Every other documented name
    exists (115), and every public runtime name is documented.
  - `effects.md` listed `db.read`/`db.write` (the code uses `db.query`/
    `db.exec`), omitted `exec.run`/`net.redirect` and the `exec`
    capability, and said glob subsumption and static capability checks
    were "parked for v0.2" (both are static today: E0801, E0701).
  - `keywords.md`: "47 reserved words, locked"; the lexer has 56 (missing
    `capability`, `band`, `bor`, `bxor`, `shl`, `shr`; listed `_`, which is
    an identifier). `trait` was both "reserved" and "not reserved"
    (`let trait = 1` is `E0201`). `empty?` returning `Int`, a `pure` `go!`
    and a function named `Main` all pass `check`: the `?`/`!`/case rules
    are conventions, not checks.
  - `is` on a refinement type is always false (`5 is Pos` → false); `is`
    narrows nothing. A List as a Map key raises `unhashable` at runtime
    (types.md said List is hashable). `1 + 2.5` and `xs.length()` pass
    `check` (types.md listed both as "disallowed").
  - SECURITY_POSTURE said "14 classes", stopped at E0723, pointed at
    `tools/py_frontend.py`, and counted 31 FP programs / 8 defenses (now
    37 / 9). SCANNING.md said "nothing to install", ".aeth firewall", that
    aether-scan.yml "fails if anything is found" (it is the `--expect` diff
    gate), and gave 86.8% without "comparable categories" (raw 34.2%).
  - The framework figures were undated and `run_scan.py` downloaded
    unpinned latest; `_work/wheels` holds two versions of six dists, and
    the old `extract()` would pick browser_use 0.13.10 on a fresh tree,
    not the 0.13.8 that was scanned.
- **Fixes:** types.md opens with a static / runtime-only / not-checked
  split; effects.md's stdlib-effect table and capability list are the
  code's; keywords.md is lexer.KEYWORDS; Instant arithmetic removed from
  stdlib.md; `tests/test_spec_docs.py` fails on any difference in either
  direction (names via `runtime.mangle`, so an injective mangling change
  in Wave 2 does not break it) and on the return of any retracted phrase —
  red on the old docs in 5 of 6 tests. SECURITY_POSTURE / SCANNING
  rewritten against the README; one positioning paragraph in README,
  CLAUDE.md, SCANNING.md; figures dated (676 and 628-of-676: 2026-09-11
  re-scan at 0.4.0; 241 s → 69 s: 2026-09-03, iteration 52);
  `bench/framework_scan/frameworks.lock.txt` pins version + sha256, pip
  `--require-hashes`; 13 root reports moved to `docs/history/` with a
  dated index; SPEC_ISSUES header, S-002/S-008 out of Open, S-020/S-021.
- **Found on the way:** BUG-050 (`remove` on a Set raises `TypeError`).
- **TYPE gap surfaced for next iter:** the spec test checks names, effects
  and keyword sets, not signatures — a documented parameter list or return
  type can still drift from the runtime (`_ae_remove` shows the class).
  And A8 stands: with no name resolution, a misspelt stdlib call passes
  `check`; the spec now says so, the language decision is open.
- **Suite:** exit 0, 42 PASS suites (the new `spec_docs` is one); `smt`
  SKIP (z3 not installed locally).

## q1 rows

| NEW residual: the spec-vs-code test covers names, effects and keyword sets, not signatures | iter-57 (Wave 6, audit E4–E6): `tests/test_spec_docs.py` proves every `function` in `grammar/stdlib.md` exists in the runtime and vice versa, every documented `effects` clause equals `_STDLIB_EFFECTS`, the effects.md table equals the checker's registry, and keywords.md equals `lexer.KEYWORDS`. It does not compare parameter lists, arity or return types — BUG-050 (`remove` documented for `Set<T>`, runtime handles only a Map) is that class, and there is no type checker to catch it at `check` either `[source: stdlib, section: Set<T>, key: remove]` | high |
| NEW scope fact (not a taint residual, recorded so no page re-derives it): there is no name resolution | iter-57 (probe-confirmed on `52f04aa`): a call to an undeclared name passes `check` and contributes no effects (so no E0801/E0701), then fails at `run` with a Python `NameError`. A taint pass never sees a sink it cannot name — a misspelt sink (`sqlQeury("SELECT " + u)`) passes `check` with no E0713 (measured, exit 0) and fails at `run` with `NameError` rather than reaching the database. Now stated in `grammar/types.md`; audit A8 (an unresolved-name pass) is a language-scope decision `[source: types, section: What is checked, key: frobnicate]` | high |

## Vault changes wanted (Wave 6 does not edit vault/)

- `vault/wiki/questions/q7-frontend-totality-over-syntax.md` line 61 cites
  `scratchpad/probes/pyfe/census.py`. **The script cannot be found**: not
  in the repo or its history (`git log --all -- '*census*'` finds only
  `bench/framework_scan/e0713_census_2026-09-03.txt`, a different census),
  not at `C:\Users\Alyhan\Claude\Projects\Aether\scratchpad\` (the
  directory does not exist), and a search of the session scratchpads under
  `%TEMP%\claude` found only an unrelated `s_pyfe.py` edit script. The
  citation cannot be reproduced. Suggested wording: "the corpus census
  (method: match every `_sink_name`-recognised `ast.Call` against IR
  `Call` positions; the script was a scratch file and was not kept —
  BUG-012's numbers are the record)". Nothing was copied into `tools/`.
- `vault/wiki/index.md` line 14 and `vault/wiki/sources/keywords.md`
  line 12 say "47 reserved words"; `vault/raw/sources/keywords.md` (a
  read-only stub — add a new stub rather than edit) says "v0.1, 47
  reserved words, locked". Current: 56, `grammar/keywords.md`.
- `vault/wiki/clusters/type-system.md` should cite the new
  "What is checked, and when" section of `grammar/types.md` (no type
  checker; refinements at parameters only, at runtime).
- CLAUDE.md now lists q1–q7; the vault index should agree.

## Skipped / not reproduced / deferred

- **Not assigned to this wave:** E8 (z3 CI job — done in Wave 1), E2's
  implementation (Wave 2), A6–A11. Where the docs had to state current
  behaviour of those rows, they cite the audit id so the owning wave knows
  which sentence to update when it lands:
  - `grammar/effects.md` "Capability gating": "At this version there is no
    runtime capability check" — **Wave 2 (A3) must update this** when it
    implements runtime capability enforcement. The README principle
    sentence ("the runtime grants only what is declared") was left alone
    as instructed; it is false at `52f04aa` until Wave 2 lands.
  - `grammar/types.md` "At runtime only": refinements checked only at
    parameters (A6); `grammar/effects.md`: `pure` alongside other effects
    and unknown effect names not rejected (A11).
  - SPEC_ISSUES S-016 (mangling collision) stays Open; Wave 2's injective
    mangling should close it.
- **Mentions of the moved reports outside my ownership** (bare filenames,
  not links; the `docs/history/README.md` index resolves them):
  `bench/py_frontend/REPORT.md` (lines 14, 333), `tools/scoped_infer.py`,
  `tools/rw_metrics.py`, `tools/delta_eval.py` docstrings,
  `bench/SCAN_FINDINGS.md:86` (already a wrong path, `bench/RW_MINING.md`),
  `validation/tasks/v0{1,4}_*/prompt.md` (`PHASE_A_AUDIT.md`),
  `docs/superpowers/plans/*`. `docs/opus_4_7_architecture.md:208` still
  says "The 47 keywords are locked".
- **A small discrepancy left as found:** LOOP_LOG iteration 52 gives the
  2026-09-03 confidence split as 0.9 ×3 / 0.6 ×629; REPORT.md's
  2026-09-11 re-scan gives ×4 / ×628. The docs cite the dated 2026-09-11
  figure; the iteration-52 text is a record of its day.
- **q7 census script:** not found (above); `tools/` gets no census script.
- **README gate count** is now 42 (this wave's new suite). Other waves'
  new test files will move it again; the coordinator should set it once
  at merge.

## Measurements

- No detector, frontend or runtime change: the framework corpus and the
  repo scan are unaffected by construction (docs, one new test, and
  `run_scan.py`'s download/extract only). Not re-scanned.
- `run_scan.py` pin check: the new `extract()` accepts all 15 existing
  `_work/src/<dist>` dirs of the main checkout (each has exactly the
  pinned `<dist>-<ver>.dist-info`; 4,946 `.py` files); a
  `pip download --no-deps --only-binary :all: --require-hashes -r` of two
  pinned lines (mcp, smolagents) into a scratch dir exit 0.
- `tests/test_spec_docs.py` on the pre-wave docs: 5 of 6 tests red
  (stdlib ↔ runtime: `minus`, `plus`; missing effects table; missing
  capability list; 47 ≠ 56; retracted phrases present). The sixth
  (stdlib `effects` clauses = `_STDLIB_EFFECTS`) already held and guards
  it.
- Gate at `acc0623`: `python -B scripts/run_all.py` exit 0, 42 PASS,
  `smt` SKIP.
- Credibility-triangle counts re-measured at `52f04aa`: false-positive
  corpus 37 programs / 0 diagnostics; runtime enforcement 9 defenses.

## Changed tests that pinned old behaviour

None. One test added: `tests/test_spec_docs.py`.
