---
type: cluster_page
cluster_id: type-system
status: active
confidence: high
last_updated: 2026-07-03
tags: [type-system]
---

# Cluster: Type System

## Summary
Gradually typed inside bodies, statically typed at boundaries. A checker, not a solver. A small
fixed set of built-in families, records/unions, no subtyping, no implicit coercion, and a
deliberately short v0.1 feature set. Several ergonomic forms are parked.

## Evidence
| Source | Section | Quote / Rule | Signal |
|---|---|---|---|
| types | (intro) | "gradually typed at function bodies, statically typed at function/module boundaries. v0.1 ships a working type checker — not a solver." | Scope of static guarantee |
| types | What is checked, and when (2026-09-24) | There is no type checker and no name resolution; the v0.1 intro and the exhaustiveness line above are RETRACTED. Refinements are checked at runtime at function parameters only | CORRECTION: the static guarantee is the effect/capability/security passes, not types (audit E3) |
| types | Parameterised types | "These are the only built-in collection and sum-type families. There is no `Array`, `Tuple`, `Either`, or `Maybe`." | Closed family set; records cover tuples |
| types | Tagged unions | "Pattern matching is exhaustive — the type checker emits an error if any `case` is missing." | Exhaustiveness statically enforced |
| types | Subtyping | "There is no subtyping. Refinement types are not subtypes of their base." | Conversions are explicit/asserted, never implicit widening |
| types | Disallowed in v0.1 | No HKT, traits, subtyping, implicit numeric coercion, variadics, default args, method-call syntax (`x.foo(y)`) | Deliberate minimalism; `.` only for field access |
| types | Records / Type ascription | Positional `Point(0.0,0.0)` works; brace-init parked (S-006); value-level `as` parked (S-013) | Ergonomic forms deferred |

## Implications
- Method-call syntax is banned: generated code must use `foo(x, y)`, not `x.foo(y)`. This is a frequent LLM-generation footgun to guard for. (assumption about impact)
- No implicit numeric coercion means `Int`→`Float` must be explicit — relevant to contract/refinement boundaries. `[source: types, section: Type ascription]`
- Open source dependency: SPEC_ISSUES S-006/S-013 are cited but not yet ingested. Flagged in log as an open ingest.

## Related
- [[../clusters/refinement-contracts|Cluster: refinement contracts]]
- [[../clusters/design-rationale|Cluster: design rationale]]
- [[../sources/types|Source: types]]
