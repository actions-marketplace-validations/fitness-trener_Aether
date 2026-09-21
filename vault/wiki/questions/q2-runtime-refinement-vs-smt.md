---
type: question_page
question_id: q2
status: answered
confidence: high
last_updated: 2026-07-07
tags: [refinement-contracts, type-system, design-rationale]
---

# Why does Aether check refinements at the runtime boundary instead of proving them with SMT?

## Short Answer

The choice is about the **audience and the fix-loop surface**, not
expressiveness `[source: README, section: fix-loop split]`. An SMT-backed
refinement (Dafny/Liquid Haskell) fails by handing back a proof
obligation the solver could not discharge — debugging it means reading
Z3 quantifier-instantiation traces, which is the wrong API for an AI
agent's repair loop. Aether instead checks each refinement `T where P` at
the **call boundary** and, on violation, emits a structured diagnostic
(E0302/E0305) naming the binding, the value, and the predicate — a
concrete, machine-readable failure an agent can fix in one edit
`[source: diagnostics, section: E03xx]`. The cost is honest and stated:
this is a **runtime** guarantee, not a static proof, so a path never
exercised is never checked (the vault manifest's central Never-Do:
never present the runtime check as static soundness). An SMT pass is
parked for v0.4+, layered *on top of* the boundary check, not replacing
it.

## Evidence

| Finding | Evidence | Confidence |
|---|---|---|
| Refinements checked at the boundary at runtime | `types` source, Refinement types section; E0302/E0305 on the live path | high |
| Rationale is fix-loop UX, not weaker types | `docs/competitive.md` (kept outside the public repo) Dafny/Liquid-Haskell paragraphs (audience/surface argument) | high |
| Runtime-not-static is an explicit honesty rule | vault `CLAUDE.md` Never Do line 2 | high |
| SMT is parked, additive | v2_ROADMAP references SMT default-on as B.5 substrate | medium |

## Recommended Actions

- In any YC-facing or partner-facing text, state the refinement
  guarantee as "runtime boundary check with structured diagnostics",
  never "statically proven" — the distinction survives cross-examination
  and the overstatement does not.
- If SMT lands, the diagnostic surface (code + position + predicate) must
  be preserved so the agent fix-loop API does not regress into
  proof-trace reading — that regression is the exact failure Aether was
  built to avoid.

## Related
- [[../clusters/refinement-contracts|Refinement Types & Contracts]]
- [[../clusters/design-rationale|Design Rationale]]
- [[../clusters/diagnostics-and-fix-loop|Diagnostics & Fix-Loop]]
