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
