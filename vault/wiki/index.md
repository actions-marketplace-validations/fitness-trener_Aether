# Aether Wiki — Index

Analysis vault for **Aether**, a language whose compiler refuses to compose components that violate
declared architectural constraints and emits agent-actionable diagnostics. Entry point for every
query — start here, follow links.

## System artifacts
- [[log|log.md]] — append-only operation journal
- [[lint-report|lint-report.md]] — latest lint run
- [[../CLAUDE|CLAUDE.md (manifest)]] — rules, data model, taxonomy, Never Do

## Sources (`wiki/sources/`)
- [[sources/README|README]] — project front door, install, fix-loop split, design principles (v0.3)
- [[sources/keywords|keywords]] — 47 reserved words, naming laws, LL(1) anchors (v0.1)
- [[sources/effects|effects]] — effect lattice, composition, capability gating (v0.1)
- [[sources/types|types]] — primitives, records/unions, refinements, disallow list (v0.1)
- [[sources/diagnostics|diagnostics]] — code ranges, `extra` dicts, caller/implementer split (v0.3)

## Clusters (`wiki/clusters/`)
- [[clusters/effect-system|Effect System]] — declared effects, subset composition, E0801
- [[clusters/capability-model|Capability Model]] — effect→capability, least-authority, E0701–E0704
- [[clusters/type-system|Type System]] — checker-not-solver, closed families, no subtyping
- [[clusters/refinement-contracts|Refinement Types & Contracts]] — runtime-checked boundaries, E0301/E0304 split
- [[clusters/diagnostics-and-fix-loop|Diagnostics & Fix-Loop]] — deterministic vs live repair paths
- [[clusters/toolchain|Toolchain & CLI]] — stdlib-only, canonical AST, JSON/SDK
- [[clusters/design-rationale|Design Rationale]] — checkable claim → diagnostic → repair
- [[clusters/violation-taxonomy|Violation Taxonomy]] — failure classes caught vs open backlog; E0710/E0711; detection ideas

## Questions (`wiki/questions/`)
- [[questions/q1-taint-marker-soundness-boundary|Q1]] — soundness boundary of the taint passes (E0712/15/16/17): syntactic, intraprocedural, over-flag-never-miss
- [[questions/q2-runtime-refinement-vs-smt|Q2]] — why runtime refinement checks over SMT (fix-loop surface, not weaker types)
- [[questions/q3-what-makes-a-good-backlog-target|Q3]] — the loop's target-selection heuristic (reuse × prevalence ÷ new machinery)
- [[questions/q4-formal-methods-adoption-filter|Q4]] — which formal-methods/PLT concepts to adopt vs park (3 shipped, 1 next upgrade, 2 candidates, 5 traps)
- [[questions/q5-sink-matching-vs-purity-matching|Q5]] — why matching SINKS by method name is legitimate where matching PURITY by name was unsound (the direction of the error), and the measured cost
- [[questions/q6-risk-vs-severity-two-axes|Q6]] — why Aether carries two severity-like axes (gate vs triage) instead of one, and the unused per-finding confidence residual
- [[questions/q7-frontend-totality-over-syntax|Q7]] — why the Python frontend must be TOTAL over statement positions and binding forms: a position it does not emit is a silent miss, not an over-flag (BUG-012, 411 → 628 on the framework corpus)

## Concepts (`wiki/concepts/`)
- _none yet — decisions beyond sources go here_

## Content ideas (`wiki/content-ideas/`)
- _none yet_
