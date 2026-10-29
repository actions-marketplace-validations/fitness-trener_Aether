# v0.2 Close-out — what shipped, what's next

**Date:** 2026-05-03
**Scope:** the three items you approved before Phase B opens — refinement-type runtime checks (S-002), capability gating, and the property-based fuzzer (S-008).

## End-to-end gate

`PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/run_all.py` from the project root reports:

    # reference:    10/10
    # bench:        3/3
    # regression:   PASS    (8 tests: lexer, ensures×2, timeout, refinement×2, capability×2)
    # fuzz:         PASS    (200 rounds × 3 modes = 600 invariant checks)
    exit 0

Validation runner: 10/10 active.

## What v0.2 adds

### S-002 · Refinement-type runtime check
- New runtime helper `_ae_check_refinement(value, predicate_fn, type_name, binding_name)` at `transpiler/aether/runtime.py`.
- Emitter (`transpiler/aether/emitter.py`) now collects every `TypeDecl` with a `where` clause into `EmitContext.refinements` during the first decl pass, and inserts a `_ae_check_refinement(...)` call at function entry for any parameter whose declared type matches a refinement.
- The predicate is compiled into an inline `lambda _ae_self: bool(<predicate>)` — the `self` keyword inside a refinement clause refers to the value being checked, and Aether's `mangle("self") = "_ae_self"`, so the lambda parameter and the emitted predicate naturally agree.
- New error codes: `E0302` (predicate returned false), `E0303` (predicate raised). Both structured, JSON-friendly.

### Capability gating
- New static pass at `transpiler/aether/passes/capability.py`. Walks every `FunctionDecl`'s effects clause, computes the required capability per effect, and ensures it's covered by some `module ... requires capability X end` block in the program.
- Effect-to-capability rule: first segment of the dotted path. `pure`, `panic`, `mutate(_)` are free.
- Wired into the CLI as `--capability-strict` on both `aether check` and `aether run`. Default mode is unchanged from v0.1 so existing programs still work.
- New error code: `E0701`, category `capability`.

### S-008 · Parser fuzzer
- New script `scripts/fuzz_parser.py` with three modes:
  - `random` — pure-random byte sequences over a restricted ASCII alphabet
  - `mutate` — small mutations (drop / dup / swap / insert) of valid corpus programs
  - `tokens` — tokenize-then-perturb a valid seed, reconstruct source
- Each parse runs under a 1-second `SIGALRM` budget. Invariant: parser must return an AST OR raise `AetherError` OR time out — never any other exception, never silent acceptance that crashes the emitter.
- Wired into `scripts/run_all.py` at 200 rounds × 3 modes (fast — about 0.4s).
- Manual run at 2,000 rounds × 3 modes also clean (0 violations, 0 emit-violations, 0 timeouts).

### Test coverage added
- 4 new entries in `tests/test_regressions.py`: refinement violation raises, refinement honored passes, capability gating blocks undeclared, capability gating admits declared.

## What v0.2 does NOT add (still parked for later)

- `S-004` effect-prefix subset matching (e.g., `net.fetch("https://api.x/*")` ⊆ `net.fetch`). Still a string-equality check.
- `S-006` brace record-update literal `Foo { x = 1.0 }`. Use positional `Foo(1.0)`.
- `S-007` generic-function type-checking.
- `S-009` deterministic-mode (seedable `time.now`/`random`).
- `S-013` value-level `as` cast.
- `S-014` non-zero contract diagnostic positions.
- `S-015` contextual reservation of `result` (still globally reserved).
- `S-016` mangling-collision avoidance.
- `contract_violation_demo` validation task — still deferred. Adding it requires extending the harness to grade exit code + stderr presence in addition to stdout. Half a day of work; happy to do it next if you want it before Phase B.

## Implications for the experiment

The Aether vs Python comparison can now actually test Aether's distinguishing claims, not just verbose-vs-Python ergonomics:

1. **Contract enforcement (`requires` + `ensures`)**: live, structured diagnostics, regression-tested.
2. **Refinement-type boundary checking**: live, regression-tested. A model that types a parameter `Email` cannot pass an arbitrary `String` and have it sneak through.
3. **Capability gating (opt-in via `--capability-strict`)**: live, regression-tested. A function declaring `effects net.fetch` requires the caller's module to declare `requires capability net`. Programs without proper module declarations are rejected before exec.
4. **Parser-soundness backstop**: 6,000 rounds clean. The harness can no longer silently accept malformed model output.

The Python baseline's prompt should teach `assert` for contracts, `dataclass` validation for refinement-style types, and a docstring/explicit-parameter convention for capability declarations — to keep the comparison fair. That's Phase D work.

## Ready for Phase B

Open questions still on the table from prior turns:

1. **Phase B model targets**: confirm Opus 4.6 + Sonnet 4.6 (you picked "Claude×2 as 2-model proxy"). I have access to my own model only; you'll need to drive the second model externally or scope Phase B to one model.
2. **`contract_violation_demo`**: do it now (half-day harness extension) or proceed without it?
3. **LLM-judge problem-signature harness**: I have your prompt at `audits/llm_judge_prompt.md`. For 23-program v0.1 corpus, hand-judgement was sufficient. At Phase C scale (40 programs, ~600 pairs) we'll need to wire it to a model API. Same access constraint as item 1.
