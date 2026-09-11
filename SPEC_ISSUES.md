# SPEC_ISSUES — v0.2+ backlog

Anything discovered while building v0.1 that should be fixed in v0.2 lands here.
Do not edit the v0.1 grammar/spec to address these — work around them in v0.1
and resolve them in a single revision pass.

This log was audited against the actual implementation on 2026-05-03 after an
independent review. Resolved entries reflect the post-audit state.

**See also**: the v2 roadmap (kept outside the public repo) — the strategic, feature-level scope ledger
for v0.4+. The roadmap document explains the *categories* of deferred work
(SMT, native compilation, async, package manager, LSP polish, multi-file
resolution for SDK + LSP, dotted/aliased imports, symbol-level export
filtering) and the reasoning behind each deferral. This file is the
granular bug log; the roadmap is the strategy.

## Open

### S-002 · Refinement types are not runtime-checked at boundary crossings
`type Email = String where matches?(self, ...)` parses, but no runtime check
runs when a `String` is passed to a parameter typed `Email`. Fix: emit a
`_ae_check_refinement(value, predicate, name)` call at the start of the
callee, parameterised by the refinement predicate.

### S-004 · No effect-prefix subset checking
A function declaring `effects net.fetch` cannot, in the strict-effect runtime,
satisfy a check for `net.fetch("https://api.x/*")`. v0.1 compares whole tuples
of strings. Fix: implement glob-aware prefix matching in
`runtime.EffectTracker._prefix_match`.

### S-005 · Pattern-match expressions allocate a helper function per use site
`match ... do ... end` in expression position lowers to a generated
`def _ae_matchexprN(_ae_scrut)` defined at module top. This is correct but
verbose for nested cases. Consider lowering to an inline closure expression
instead, perhaps using Python's pattern-matching at emit time (3.10+).

### S-006 · No support for record-update literal `Foo { x = ... }`
The grammar / `types.md` describe a brace-init form. v0.1 does **not**
accept `Point { x = 1.0, y = 2.0 }` — it parses `{...}` only as a map
literal, and the diagnostic from the parser is misleading ("insert ':' here"
suggests the wrong fix). Workaround in v0.1: use positional construction —
`Point(1.0, 2.0)` — which works because record decls emit a positional
constructor function. Fix in v0.2: implement `RecordLit` AST kind plus
`{**existing, "x": ...}` emission, and either accept the brace form or
delete it from `types.md`.

### S-007 · Generic functions are accepted but not type-checked
`function map<T, U>(...)` parses; `T`, `U` flow through emission unmangled
because they appear only in type positions. v0.2 should add a type-check pass
that at least confirms the generic parameters are used consistently.

### S-008 · No fuzzer or negative reference set
The plan called for property-based fuzzing of the parser plus a
"deliberately wrong" set for negative tests. v0.2 should add `bench/fuzz/`
using Hypothesis to confirm the parser never crashes and never silently
accepts malformed input.

### S-009 · `time.now`, `random` not yet seedable for deterministic mode
The runtime calls Python's wall clock directly. v0.2 should add a
deterministic-mode flag that intercepts these.

### S-010 · CLI compile-cache friction with mounted filesystems
`__pycache__` files on the user's mounted drive may be marked immutable from
the sandbox, causing stale bytecode to be picked up after edits. Workaround:
`PYTHONDONTWRITEBYTECODE=1` and `python3 -B`. v0.2: bake these into the
CLI launcher so users never see the issue.

### S-013 · `as` is parsed only as a pattern alias, not a value-level cast
`types.md` describes `let y = (3.14 as Float)` as a legal value-cast form, but
the parser only accepts `as` inside `pattern as IDENT` (alias binding) and as
the alias clause on `import ... as IDENT`. There is no expression-level cast in v0.1. Fix in v0.2: either implement an `As` expression node and runtime
check, or delete the example from `types.md`. v0.1 doc has been updated to
mark this form as v0.2-only.

### S-014 · Contract diagnostic positions are zero
`requires` / `ensures` failures point at line 0, col 0 instead of the call
site or the failing return. The function name and the failing clause text
are present in the message, which is enough for a model loop, but a human
reading the diagnostic gets no jump-to-source. Fix: thread the call-site
position into `_ae_assert_contract`.

### S-015 · `result` is reserved as a keyword everywhere, not contextually
The lexer reserves `result` so it can be used inside `ensures` clauses to
refer to the return value. Side effect: `let result = computeAnswer()`
fails with a parse error. The collision rate matters because `result` is an
extremely common identifier. Fix in v0.2: contextually reserve `result`
only inside an `ensures` expression (the parser knows the context). v0.1
workaround: documented in `prompt/system_prompt.md` under common mistakes.

### S-016 · Mangling collision between `foo?` / `foo_q` (and `foo!` / `foo_e`)
`empty?` mangles to `_ae_empty_q`, and a user-defined `empty_q` would also
mangle to `_ae_empty_q`. Latent — the v0.1 stdlib doesn't trigger it, and a
user identifier ending in `_q` or `_e` is unusual but not impossible. Fix:
use a non-identifier separator like `__pred__` / `__bang__`, or reject any
user identifier that already ends in `_q` / `_e`.

## Resolved

### S-019 · Int spec/runtime divergence resolved: arbitrary precision  *(resolved 2026-07-06)*
`grammar/types.md` said "64-bit signed integer" while the transpiled
runtime used Python arbitrary-precision int. Three real-world ports
(humanize 10**100, bech32 accumulators) silently relied on > 2**63
values, so the runtime behaviour is the useful one. Decision: the spec
now says arbitrary-precision; overflow/wrapping never occurs; fixed-width
code masks explicitly with `band`. Enforcing 64-bit was rejected: it
would require overflow diagnostics on every arithmetic op and would have
broken all three validated ports.

### S-001 · `ensures` clauses now fire at runtime  *(resolved 2026-05-03)*
Previously a postcondition violation was silently ignored. The emitter now
threads each function's `ensures` clauses through a new `ensures_stack` on
`EmitContext`, and `emit_return` plus the implicit fall-through path emit
`_ae_assert_contract(..., 'ensures', ...)` calls before returning. `old(x)`
snapshots already collected at function entry are visible in scope.
Verified: a function returning `x + x + 1` declared `ensures result == x * 2`
now fails with `[E0301] ensures clause failed in double: (result == (x * 2))`,
exit 2.

### S-003 · Higher-order functions actually work  *(resolved — was never broken)*
The original log entry claimed "function-typed parameters cannot be invoked."
Audit on 2026-05-03 confirmed both `map(xs, double)` (with stdlib `map`) and
a user-defined HOF — `function apply(f: function(Int) returns Int, x: Int) ...`
called as `apply(square, 7)` — emit and execute correctly. The Pratt-style
postfix loop already handles `f(x)` for any expression `f`, including a
parameter-bound function value. The original analysis was wrong.

### S-011 · Lexer mis-tokenized `x!=3` (no spaces)  *(resolved 2026-05-03)*
Previously the lexer greedily ate `!` as the trailing-effectful identifier
marker, leaving `=3` and producing a misleading "expected then" error. The
fix in `lexer._read_ident_or_keyword` peeks one more character before
consuming `!`: if the next char is `=`, leave `!` for the symbol scanner so
`!=` can lex as a single two-character symbol.

### S-012 · Harness now enforces `timeout_ms`  *(resolved 2026-05-03)*
Previously `compile_and_run` ignored `timeout_ms` and a candidate with an
infinite loop hung the harness. The fix uses POSIX `signal.SIGALRM` plus
`setitimer(ITIMER_REAL, …)` to raise a private `_CandidateTimeout`
exception inside `exec()`, which the harness catches and converts into a
structured diagnostic with code `E0601`. Verified: an infinite-loop
candidate against a 500ms task budget returns `ok=false` after ~506ms
with `category: "timeout"` in the diagnostic. On Windows (no `SIGALRM`)
the timeout silently degrades to a no-op; the harness header documents the
recommended workaround (run on POSIX or wrap with an external `timeout`).

### S-017 · Structural AST similarity is unreliable at v0.1's grammar size
The Phase A audit found that with ~30 node kinds in the v0.1 grammar, any two
non-trivial programs share 60–70% of their structural shape by virtue of
boilerplate (`Program → FunctionDecl`, `function with body of statements`,
etc.). A 0.70 threshold on weighted-Jaccard over node-kind and edge multisets
sits *inside* this floor at corpus size ≥ 20, producing many false positives.
The structural metric is fine as a Layer-1 *filter* but should not be used as
a verdict; pair it with a Layer-2 problem-signature check (LLM-judged or
hand-written one-line task descriptions) to actually answer "are these
informational duplicates?". See `PHASE_A_AUDIT.md` for the resolved-flags
table. v0.2 work that grows the grammar (records-as-keys, refinements, more
control constructs) will widen the structural floor's gap to true
near-clones, making the metric more useful — but Layer 2 should remain the
authoritative check.

### S-002 · Refinement-type runtime checks now fire at boundaries  *(resolved 2026-05-03)*
The emitter now collects every `TypeDecl` with a `where` clause into
`EmitContext.refinements`, then for every function parameter whose declared
type matches a refinement, emits a `_ae_check_refinement(value, lambda
_ae_self: <predicate>, type_name, binding_name)` call at function entry.
The runtime helper raises `[E0302]` if the predicate returns false and
`[E0303]` if the predicate itself crashes. Verified: `function show(n:
PositiveInt)` declared `type PositiveInt = Int where self > 0` rejects
`show(0)` with structured diagnostic, accepts `show(42)`. Regression test
in `tests/test_regressions.py::test_S002_*`.

### S-018 · Capability gating implemented as a static pass *(resolved 2026-05-03; new entry)*
Previously module `requires capability X` declarations parsed but were
never enforced. v0.2 adds a static analysis pass at
`transpiler/aether/passes/capability.py` plus a CLI flag
`--capability-strict` available on `aether check` and `aether run`. The
pass collects every capability declared by every `ModuleDecl`, then walks
each `FunctionDecl`'s effects clause and rejects any effect whose required
capability isn't declared. Effect-to-capability mapping: first segment of
the dotted path (so `fs.read` → `fs`, `net.fetch` → `net`); `pure`,
`panic`, and `mutate(_)` need no capability. Diagnostic code `E0701`,
category `capability`. Default mode (without `--capability-strict`) is
unchanged from v0.1 so existing programs still run. Regression tests in
`tests/test_regressions.py::test_capability_*`.

### S-008 · Parser fuzzer added  *(resolved 2026-05-03)*
`scripts/fuzz_parser.py` generates random / mutated / token-perturbed
input streams and asserts the parser invariants: either return a valid
AST, raise `AetherError`, or hit the per-parse `SIGALRM` timeout — never
any other exception, never silent acceptance of malformed input that
breaks emit. Three modes (`random`, `mutate`, `tokens`); 6,000 rounds
total at 0 invariant violations, 0 emit violations, 0 timeouts. Wired
into `scripts/run_all.py` at 200 rounds × 3 modes for fast CI.
