# Aether — Project Guide for Claude

Aether is a language whose compiler **refuses to compose components that
violate declared architectural constraints** (effect locality, capability
scope, refinement-typed boundaries) and emits structured, machine-readable
diagnostics an agent fix-loop can act on. It transpiles to plain Python.

## Two things run here. Know which loop you are in.

### 1. The security-detector improvement loop (the main work)
Aether grows by eliminating one *violation TYPE* per iteration. Ten
detectors shipped: **E0710–E0719** (SSRF, path traversal, secret-log,
SQLi, command-injection, PII egress, missing-auth, IDOR, open-redirect,
SSTI). State of record: `demos/case_studies/LOOP_LOG.md`. Backlog +
coverage: `vault/wiki/clusters/violation-taxonomy.md`.

**Method — follow exactly, every iteration:**
1. **Pick the target** using the heuristic in
   `vault/wiki/questions/q3-what-makes-a-good-backlog-target.md`
   (reuse × prevalence ÷ new machinery). Prefer surfaced residuals from
   the last LOOP_LOG block.
2. **Confirm the gap empirically FIRST.** Write the bad shape, run
   `python -B -m transpiler.aether.cli check <file>`, prove current Aether
   *accepts* it (exit 0). No no-op iterations.
3. **grep-survey before wiring.** Pick names that don't collide; the new
   rule must fire **0×** on the existing corpus (non-breaking).
4. **Eliminate the TYPE, not one instance.** Over-flag rather than miss;
   provide a sanctioned exit/sanitizer where one exists (none for SSTI).
5. **Ship the full slice:** detector in `transpiler/aether/passes/effects.py`
   registered in the `security` stage of `STAGES` in
   `transpiler/aether/passes/__init__.py` — the ONE place detector
   membership is spelled out; every caller (CLI, SDK, LSP, `tools/scan.py`,
   the tests) crosses `analyze()` and picks it up automatically; any new stdlib
   sink/guard in `runtime.py` (+ register effects in `passes/effects.py`
   `_STDLIB_EFFECTS` — `passes/capability.py` derives its path table from it;
   a new Python sink/guard/sanitizer row in `py_frontend.py` needs its pin in
   `tests/test_sink_rows.py` and a raised `min_py_table_rows`,
   + `_KNOWN_CAPABILITIES` in `passes/modules.py` if a new capability);
   **doc row in `grammar/diagnostics.md`** (REQUIRED — the D.2 catalog test
   greps every `code="Exxxx"`); stdlib doc; tests in
   `tests/test_effect_scope.py`; `demos/case_studies/<class>/` +
   `playground/examples/NN_*.aeth` — **each new `.aeth` opens with a
   `// expect:` header** stating the codes it claims (sorted multiset,
   `E0713x2` for multiplicity, `clean` for none). `tests/test_corpus.py`
   fails on any in-scope file without one.
6. **Verify:** `python -B scripts/run_all.py` must exit 0. Red = it did
   not happen; fix or revert. The gate includes a **monotonic ratchet**
   (`tests/test_ratchet.py`): Aether may only improve — you may never
   remove/weaken a detector or lower `tests/ratchet_baseline.json`. When
   you add a detector, RAISE the baseline in the same commit (the test
   prints the target) to lock the gain; when you close a `BUGS.md` entry,
   mark it `[FIXED <commit>]` with a `test:` line. See §4 of
   `tools/self_teaching_agent.md`.
7. **Record & compound (see loop 2):** update `violation-taxonomy.md`,
   append a LOOP_LOG block with the next "TYPE gap surfaced", and **append
   the new residual limit to `vault/wiki/questions/q1-taint-marker-soundness-boundary.md`**.

### 2. The knowledge vault — karpathy LLM-wiki method (makes loop 1 compound)
`vault/` is the long-term analysis memory. It follows Andrej Karpathy's
LLM-wiki method: **the human curates sources and asks questions; the LLM
writes and maintains the analysis.** The vault's own manifest —
`vault/CLAUDE.md` — governs schema, page types, citations, and Never-Do.
**Read it before editing anything under `vault/`.**

The method only compounds if you run its loops. Do:

- **Query loop (the compounding engine).** When you answer a non-trivial
  design/architecture question about Aether — *save the answer* as a
  `question_page` under `vault/wiki/questions/qN-<slug>.md` (contract in
  `vault/templates/page-contracts.md`). Answers become sources the next
  question builds on. Do NOT re-derive an answer that already has a
  question_page — read it, cite it, and extend it. Current: q1 (taint
  soundness), q2 (runtime-vs-SMT), q3 (backlog heuristic).
- **Curate loop.** `raw/sources/` are **read-only pointer stubs** to the
  canonical in-repo spec (`grammar/*.md`, `README.md`). Never edit them;
  add NEW source stubs only. Clusters cite source markers
  `[source: <name>, section: <name>, key: <kw>]`.
- **Lint loop.** Before finishing vault work: every page reachable from
  `vault/wiki/index.md`, ≥2 wikilinks per page (no orphans), every claim
  carries a source marker, no invented codes/effects/keywords.
- **Log.** Prepend an entry to `vault/wiki/log.md` (newest on top) for any
  structural vault change.

**The tie between the loops:** loop-1 iterations *produce* knowledge
(residual limits, design trade-offs); loop-2 *captures* it as
question_pages so future iterations pick better targets (q3) and never
re-litigate a settled soundness/design point (q1, q2). An iteration that
ships a detector but leaves its residual only in LOOP_LOG has half-worked
— push the residual into q1.

## Hard honesty rules (non-negotiable, from the sprint + vault manifest)
- Refinement/capability/effect-scope checks that fire at **runtime** are
  runtime guarantees — never present them as static proof/soundness.
- Taint passes are **syntactic + intraprocedural**; describe them as
  "over-flag, never miss within the modeled surface", not "sound".
- Never invent diagnostic codes, effect names, keywords, or capabilities
  absent from the spec.
- Never describe Aether as "better than X" without the qualifier + metric.
- Cite every quantitative claim to a repo path or public source.

## Environment
- Windows. Use `python` (not `python3`). Bash tool for grep/sed; PowerShell
  for running python. Ignore PowerShell `NativeCommandError` wrapper lines
  on native-exe stderr — check the real exit code.
- Full gate: `python -B scripts/run_all.py` (exit 0 = green).
- Reach-scope tests: `python -B tests/test_effect_scope.py`.
- Playground: `python -m playground.backend.app --port 8080`.
