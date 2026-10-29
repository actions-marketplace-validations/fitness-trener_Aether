# Known-gaps round, Agent A record — language side (G2, G3, G9) (iteration 63)

Branch forked from `gaps-2026-09-29` @ `a2f13db`; every "before" below is
`a2f13db` (the worktree before the first commit). Ids: BUG-085..089
(085 and 086 used), iteration 63.

Commits:
- `abb964c` fix(lang): one effects clause per function; E0208 name resolution (gaps G2, G3)
- `710e79c` fix(names): a const initializer sees only declarations above it (E0208)
- this record

Files changed: `transpiler/aether/parser.py`,
`transpiler/aether/passes/{__init__,imports}.py`, new
`transpiler/aether/passes/names.py`, `grammar/{diagnostics,types}.md`,
`grammar/grammar.ebnf`, `tests/test_static_effects.py` (one test added),
new `tests/test_name_resolution.py`, `tests/ratchet_baseline.json`
(raised), new `playground/examples/34_misspelt_sink.aeth`.
**Outside the ownership list:** `transpiler/aether/risk.py`, one row
(`"E0208": "medium"`). `tests/test_risk.py::test_every_emitted_code_rated`
fails for any emitted code without a rating, so a new code cannot pass the
gate without it; no other agent owns the file.

Red first:
- G2: `tests/test_static_effects.py::test_repeated_effects_clause_is_a_parse_error`
  failed on `a2f13db` ("a repeated effects clause parsed").
- G3: `tests/test_name_resolution.py::test_misspelt_sink_is_E0208` failed
  with the pass unregistered: `analyze_flat` returned `[]` for
  `sqlQeury("SELECT ... " + u + "'")` (exit 0, no E0713).

## BUGS entries

### BUG-085  A second `effects` clause silently replaced the first  [OPEN]
test: tests/test_static_effects.py (`::test_repeated_effects_clause_is_a_parse_error`)

Found 2026-09-24 while probing audit A11 (Wave 7 record, q1 row
"effect names are validated by capability head only"); fixed in the
2026-09-29 known-gaps round (G2). Repro: `function f(x: Int) returns Int
effects log ... effects pure do ... end`. `check` read it as `pure`: the
declared `log` was gone, with no diagnostic.

Root cause: `Parser.parse_function_decl` loops over interleaved
`requires` / `ensures` / `effects` clauses and assigned
`effects = self.parse_effect_list()` on every `effects`, so the last one
won. `grammar.ebnf` has exactly one `effects_clause`.

Fix (`abb964c`): a second `effects` keyword in one declaration is E0201 at
that keyword ("function 'f' has more than one 'effects' clause", hint:
merge them into one list). Repeated `requires` / `ensures` stay legal —
`{ contract_clause }` in the grammar, each checked at runtime. The EBNF
now spells out that contract clauses may follow the effects clause (the
parser always accepted that): `{ contract_clause } effects_clause
{ contract_clause }`. E0201 row text extended; no new code.
Measurement: 0 of 418 tracked `.aeth` files repeat the clause; the
`check --json` output of all 418 is unchanged.

### BUG-086  A reference to an undeclared name passed `check`; a misspelt sink hid the injection  [OPEN]
test: tests/test_name_resolution.py (`::test_misspelt_sink_is_E0208`, `::test_undeclared_call_and_value`, `::test_block_scoping_and_shadowing`, `::test_const_sees_only_earlier_decls`)

Found 2026-09-24 by the language auditor (A8); recorded in Wave 6 as a
scope fact (q1, iter-57). Known-gaps round G3. Repro:
`sqlQeury("SELECT * FROM users WHERE name = '" + u + "'")` → `check`
exit 0, no E0713; `run` → Python `NameError`. `frobnicate(1)`, never
declared: `check` exit 0. Also found while building the fix:
`const A: Int = B` above `const B: Int = 1` → `check` exit 0, `run`
`NameError: name '_ae_B' is not defined` at module load.

Root cause: no pass resolved names. The emitter mangles every
identifier and runs the program against the runtime's `_ae_*` exports
plus the program's own definitions, so an unbound name only surfaced
when Python reached it; the taint passes match sinks by name, so a sink
they cannot name is invisible to them.

Fix (`abb964c`, `710e79c`): new static-semantic code **E0208** "reference
to an undeclared name", `transpiler/aether/passes/names.py`
(`check_name_resolution`), registered in the `semantic` stage. A name
resolves if it is a parameter (`self` in a refinement predicate, `result`
in `ensures`), a local bound earlier in the same or an enclosing block
(`let` / `var` / assignment / `for` variable / `match` pattern
bindings — the binder kinds of `ast_walk.binders()`), a top-level
function / `const` / record / union case (imports fused in by
`load_program`; inside a `const` initializer, only one declared above
it), or a runtime export (`runtime.unmangle` over `vars(runtime)`: 119
names, derived, not listed). Not resolved because not evaluated: the
right side of `is`, the qualifier of `Union.Case(...)`, patterns, type
annotations, `effects` arguments. `extra` = `function`, `name`, `kind`
(`call` | `value`), `suggestion` (closest known name by
`difflib.get_close_matches`, or null). Positioned at the nearest
positioned ancestor (the call, or the statement) — `Ident` nodes carry no
position and the AST shape was not changed. Silent on a program it
cannot see whole: `parse_collect` marks a partial AST `partial`, and
`resolve_imports` marks its combined program `imports_resolved`; a
program with an `ImportDecl` but no mark (`--no-import-resolution`, or a
caller that parsed without `load_program`) gets no E0208.
This is name resolution, not type checking (`grammar/types.md` says so).

Measurement: see Measurements — 0 new diagnostics on the in-repo `.aeth`
corpus, `check-py` byte-identical.

## LOOP_LOG block

## Iteration 63 — known-gaps round, language side: name resolution (E0208) and one effects clause

- **Target:** not a backlog row. The two language gaps the audit and
  Wave 6/7 left open: A8 (no name resolution; q1 iter-57 scope fact) and
  the repeated-effects residual (q1 iter-62).
- **Probe-confirmed first (on `a2f13db`):** `sqlQeury("SELECT " + u)` →
  `check` exit 0, no E0713; `frobnicate(1)` → exit 0, `run` NameError;
  `effects log` then `effects pure` → checks as `pure`.
- **Fixes:** a second `effects` clause is E0201 (parser). New E0208 pass
  `passes/names.py` in the `semantic` stage: block-scoped locals,
  parameters, top-level decls, imports, runtime exports derived from
  `runtime.unmangle`; const initializers see only earlier decls.
- **Measured:** 418 tracked `.aeth` through `--json check --no-prove`,
  before/after: 0 files change (407 load and are resolved: 5,602
  identifiers, 2,878 calls, 0 E0208; 11 do not parse, by design). Python
  `check-py` byte-identical: framework corpus 4,946 files / 683 findings,
  and `bench tests tools playground demos`.
- **Ratchet:** 55 → 56 codes, 31 → 32 detectors, corpus claims 117 → 118
  (`playground/examples/34_misspelt_sink.aeth`, `// expect: E0208`).
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** E0208 proves a name reaches SOME
  binding; calling a `const Int` (`N(1)`) or a function with the wrong
  number of arguments still passes `check` and is a Python `TypeError` at
  `run`. Arity of direct calls to top-level functions / records / union
  cases needs no type information and reuses this resolver — see the q8
  draft below (option B).
- **Suite:** exit 0, 50 PASS (`smt` SKIP, z3 not installed locally); one
  new suite (`name_resolution`).

## q1 rows

| CLOSED scope fact (was iter-57): there is no name resolution | iter-63 (G3, BUG-086): E0208 resolves every identifier and callee against parameters, block-scoped locals, top-level decls (imports included) and the runtime's exports. A misspelt sink (`sqlQeury("SELECT " + u)`) is now E0208 with `sqlQuery` suggested, instead of exit 0 with no E0713. Still silent on a partial AST and on unresolved imports (the missing declaration may bind the name) `[source: types, section: What is checked, key: E0208]` | high |
| NEW residual: E0208 resolves names, not kinds, types or arity | iter-63 (G3): a name that reaches ANY binding passes — calling a `const N: Int` (`N(1)`) is `check` exit 0 and a Python `TypeError` at `run`; so is `f(1, 2, 3)` for a one-parameter `f` (measured). An assignment `x = 1` with no earlier `let`/`var` binds `x` (the runtime's Python function scope does the same), so it is not E0208 `[source: types, section: What is checked, key: arity]` | high |
| NEW residual: E0208 inherits the import fusion of H.E.3 | iter-63 (G3): `load_program` fuses every top-level decl of an imported file into the caller's namespace regardless of the imported module's `exports`, and ignores `import x as y`; E0208 therefore accepts a name an `exports` clause does not list, and a qualified `lib.helper(...)` is resolved on `lib` (which is unbound: E0208) rather than as a module path `[source: types, section: What is checked, key: import]` | medium |
| NEW residual: const initializers are checked by declaration order, not transitively | iter-63 (G3): `const A = B` above `const B` is E0208; `const A = f()` where `f` (declared anywhere) reads a later const is not — the read happens inside `f`'s body, where every top-level name is visible `[source: types, section: What is checked, key: const]` | low |

## Skipped / not reproduced / deferred

- **G9 type checking** — not built, by instruction. Design draft below
  (`## q8 design page draft`).
- **Block scoping is stricter than the runtime.** The emitted Python has
  function scope, so `if c then let y = 1 end; print(y)` runs when `c` is
  true; E0208 refuses it. Deliberate (the spec never promises
  function-scoped `let`, and the branch-not-taken path is a NameError);
  measured 0 occurrences in the corpus. If the coordinator prefers
  function-flat visibility, it is a one-line change in `_Resolver.block`
  (do not copy `scope`).
- **Suggestion quality.** `difflib` with its default cutoff 0.6 suggests
  `mapValues` for `plus` (measured); a null suggestion is emitted when
  nothing is close. Not tuned.

## Measurements

- `.aeth` corpus (every tracked file, 418): `python -B -m
  transpiler.aether.cli --json check --no-prove <file>`, before
  (`a2f13db`) and after (`710e79c`): **0 files differ** in exit code or in
  the (code, line, column, name) multiset of diagnostics. Exit 0 in 287
  both times. In-process: 407 files load; E0208 resolved 5,602
  identifiers and 2,878 calls in them with **0** E0208; 11 files do not
  load (parse errors on purpose), 0 files have an `import`. Every added
  diagnostic: none. The new `playground/examples/34_misspelt_sink.aeth`
  claims and gets `E0208` ×1 (line 17, column 3).
- Python, framework corpus (`C:\Users\Alyhan\Claude\Projects\Aether\bench\framework_scan\_work\src`,
  4,946 files): `--json check-py` output **byte-identical** before/after
  (`cmp`), 683 findings, exit 1 both.
- Python, in-repo trees `bench tests tools playground demos`: `--json
  check-py` output **byte-identical** with and without the E0208 pass
  registered (exit 1,1,1,0,1 both). By construction too: `check-py` skips
  the `semantic` stage (`py_frontend.PY_SKIP_STAGES`), asserted by
  `tests/test_name_resolution.py::test_python_never_gets_E0208`.
- Probes on `710e79c` for the `grammar/types.md` table: `return "not an
  int"` from `returns Int` → check 0 / run 0; `let x: Int = "s"` → 0 / 0;
  `f("str")` for `f(a: Int)` → 0 / 0; `frobnicate(1)` → **check 1
  (E0208)**, not run; `N(1)` on `const N: Int` → check 0, run Python
  `TypeError` (exit 1).
- Gate: `python -B scripts/run_all.py` exit 0, 50 PASS, `smt` SKIP.

## Changed tests that pinned old behaviour

None. One DOC row changed meaning: `grammar/types.md`'s measured table,
row `frobnicate(1)`: was `exit 0 | Python NameError, exit 1`, now
`E0208, exit 1 | not run (check refuses it)` (re-measured, above).

## Coordinator decisions / follow-ups outside this agent's files

1. **Now-false statements** (not in my files):
   - `CLAUDE.md` line 14 and `SECURITY_POSTURE.md` line 151: "no type
     checker and no name resolution" → "no type checker; names are
     resolved statically (E0208)".
   - `grammar/stdlib.md` lines 476–479 (Agent B's file): "a call passes
     `check` (there is no name resolution, see `types.md`) and `run` fails
     with a Python `NameError`" — now `plus(t, 5)` is E0208 at `check`
     (measured). Proposed: "a call is refused by `check` with E0208 (an
     undeclared name)".
   - `transpiler/aether/cli.py` lines 215, 273, 603 and
     `py_frontend.py` line 49 comments / help say the semantic family is
     `E0202-E0207`; it is now `E0202-E0208`. `SECURITY_POSTURE.md` lines
     11 and 96 say `E0202`–`E0207`.
   - README's suite count (brief says "41 PASS suites"; the gate prints
     50 PASS now) and any "55 codes / 31 detectors" → 56 / 32 (CLAUDE.md
     line 21 too).
   - `playground/examples/31_code_injection.aeth` line 10 says "Each
     function type-checks" — there is no type checker.
2. **vault:** q1 rows above; the q8 draft below as
   `vault/wiki/questions/q8-static-type-checking-scope.md`; index + log.
3. **Code choice to confirm:** E0208 uses `category="type"`, as the other
   semantic codes do (no new category invented); risk `medium`, by
   analogy with E0202 (a live crash on the path that reaches it) — change
   if the triage table should read it as `low`.

## q8 design page draft

---
type: question_page
question_id: q8
status: answered
confidence: medium
last_updated: 2026-09-29
tags: [type-system, name-resolution, design-rationale, backlog]
---

# What should Aether's static type checking be, now that name resolution exists?

## Short Answer

Not a type checker yet, and never an inference engine by default. The
next step worth its cost is a **local arity-and-literal check** that
reuses the E0208 resolver: argument count of a direct call to a
top-level function / record / union case, and a primitive literal
(`"x"`, `1`, `true`) meeting a primitive annotation that disagrees with
it at a `return`, an annotated `let`/`var`, or an argument
`[source: types, section: What is checked, key: E0208]`. It needs no
inference — the resolver already knows which declaration a callee name
reaches, shadowing included (`transpiler/aether/passes/names.py`). Its
measured prevalence in the hand-written corpus is **zero** (934 literal-
meets-primitive sites, 0 mismatches, 0 arity mismatches), so its value
is in agent-generated code and the fix-loop, not in the corpus; by the
q3 heuristic it ranks below any security row with non-zero prevalence
`[source: diagnostics, section: E0208, key: name resolution]`. A full
checker (HM-style or bidirectional, with generics, unions, `Result`,
function types) is out of scope until a measured bug class needs it.
Whatever ships must be described by what it checks — "literal/annotation
mismatch at three sites, and arity" — never as "type-checked" or
"type-safe" `[source: types, section: What is checked, key: Not checked]`.

## Evidence

| Finding | Evidence | Confidence |
|---|---|---|
| Today `check` accepts every type error; only an unbound name is refused | Probes on `710e79c`: `returns Int` + `return "not an int"` → check 0 / run 0; `let x: Int = "s"` → 0 / 0; `f("str")` for `f(a: Int)` → 0 / 0; `frobnicate(1)` → E0208; `N(1)` on `const N: Int` → check 0, run `TypeError`; table in `grammar/types.md` | high |
| E0208 gives the machinery option B needs | `passes/names.py` resolves every callee to a parameter, block-scoped local, top-level decl or runtime export; `tests/test_name_resolution.py` pins shadowing, block scope, imports | high |
| Option B would fire 0× on the corpus | 407 loadable tracked `.aeth`: 165 `return <literal>` / 65 annotated `let <literal>` / 704 literal arguments meet a primitive annotation, 0 disagree; 0 direct calls to user functions with a wrong argument count (probe script, audits/gaps/A_record.md) | high |
| The corpus is not where the bugs are | The corpus runs (`tests/test_corpus.py`, `// expect-run:`); type errors in it would already have crashed. The target is fix-loop candidates (`bench/`, `tools/`) | medium |
| A full checker would make the stdlib signatures load-bearing | 119 runtime exports (`runtime.unmangle`); their documented types in `grammar/stdlib.md` are not checked against `runtime.py` today, and generic parameters are not checked for consistency (SPEC_ISSUES S-007) | medium |
| Marker types complicate a real checker | `Secret<T>`, `PII<T>`, `Untrusted<T>` are read off signatures by the security family E0710–E0731; a checker must treat them as wrappers the passes already reason about, or it will contradict them | medium |
| Runtime refinements are not static types and must not be relabelled | E0302/E0303 are runtime checks (q2); option B does not change that | high |

Options and cost:

| Option | Catches | Cost | Must never claim |
|---|---|---|---|
| A. None (status quo) | nothing beyond E0208 | 0 | — |
| B. Arity + literal/annotation mismatch (recommended) | `f(1, 2, 3)`; `N(1)`-style calls of a non-function top-level decl; `return "x"` from `returns Int`; `let x: Int = "s"`; `f("str")` for `f(a: Int)` | one pass over the E0208 walk, one new E02xx code (needs its `diagnostics.md` row first), decisions: `Int` literal into `Float` (Python accepts it), calls through function-typed params (skip) | "type checking", "type-safe", any soundness claim: a non-literal expression of the wrong type still passes |
| C. Full HM-style / bidirectional | expression types everywhere, generic consistency (S-007), `Result`/`Option` misuse | a checker for every expression form, typed signatures for 119 stdlib functions kept in sync with `runtime.py`, marker-type integration; high false-positive risk on a corpus that runs today | "sound" unless proven; it would still leave refinements runtime-only |

## Recommended Actions

- Ship B in two slices, arity first (no type information at all), each
  gated by 0× on the in-repo `.aeth` corpus like E0208; red-before test
  from the probes above.
- Keep `grammar/types.md`'s measured table as the contract: each row
  moves from `exit 0` to a code only when a probe proves it.
- Re-open C only with a measured class (e.g. fix-loop candidates whose
  runtime failure is a `TypeError` the E02xx family cannot see).

## Related
- [[q1-taint-marker-soundness-boundary]]
- [[q2-runtime-refinement-vs-smt]]
- [[q3-what-makes-a-good-backlog-target]]
- [[q7-frontend-totality-over-syntax]]
