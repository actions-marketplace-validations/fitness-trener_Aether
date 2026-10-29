# Wave 2 record — the compiler refuses again (iteration 58)

Plan: `audits/audit_2026-09-24_plan.md` §A, Wave 2. Base `52f04aa`.
Ids: BUG-055..062 (063, 064 unused). Every repro below was run red on
`52f04aa` first (`check` exit 0, or the wrong runtime outcome); every
regression test in `tests/test_compiler_refuses.py` was run against a
clean `git archive 52f04aa` copy: 35 of its 42 tests are red there; the 7
green ones are the controls (sanctioned shapes stay clean / valid values
run / a 190-term chain still analyzes).

Commits:

| commit | items |
|---|---|
| `c193b21` | A5 binders, A1 contexts, A2 unknown-callee bound |
| `8722ce6` | A4 mangling + helper namespace, A3 runtime grant, BUG-050, A2 Python guard in capability.py |
| `065ee74` | A7 net.fetch glob on the parsed URL |
| `b02eafe` | A6 refinement checks at every binding site |
| `eaa5d91` | A10 iterative walk, parser depth bound, E9001 from emit |
| `af11754` | A3 follow-up: declared effects checked against the grant on invocation |

Gate: `python -B scripts/run_all.py` exit 0 at `af11754` (run after the
last source change; also green after each earlier commit).

## BUGS entries

### BUG-055  `for` / `match` binders (and parameters) re-bound a name the safe / stable / authorized proofs had proven  [OPEN]
test: tests/test_compiler_refuses.py
(`::test_a5_for_shadow_path`, `::test_a5_match_shadow_path`,
`::test_a5_for_shadow_sql`, `::test_a5_for_shadow_idor`,
`::test_a5_for_shadow_authorized`, `::test_a5_raw_param_later_assigned_a_proof`,
`::test_a5_as_pattern_carries_taint`, `::test_a5_sanctioned_shapes_stay_clean`)

Found 2026-09-24 by the whole-repo audit (A5), probe-confirmed on
`52f04aa`: `let s = "SELECT 1"; for s in xs do sqlQuery(s) end`, the same
shape for E0711 (`readFile`), `match o do case Some(p) do readFile(p)`,
and the E0717 IDOR (`let id = "doc-1"; proof = authorizeResource(u, "e",
id); for id in ids do sqlByOwner(stmt, id, proof)`) were all `check`
exit 0. Found while fixing: a raw parameter later assigned a proof
(`sqlExec(s, tok); tok = authorize(u, a)`) was authorized, because
parameters were not bindings; and `case Some(x) as y` never tainted `y`
(`AsPat` names were invisible to the taint pass).

Root cause: six binding fixpoints, each with its own walker. Only
`_marked_taint` knew `For` / `BindPat`; `_safe_names`, `_mutable_names`,
`_record_names`, `_authorized_names`, `_stable_names` saw only
Let/Var/Assign. The BUG-013/014 class, fixed there one walker at a time.

Fix (`c193b21`): one `binders(fn)` iterator in `passes/ast_walk.py`
yields `(name, value, kind, node, source)` for parameters, let / var /
assign, `for` variables and every `BindPat` / `AsPat` of match
statements and match expressions, over body AND contracts. All six
fixpoints read it. A value-less binder (loop variable, pattern name,
plain parameter) disqualifies a name from safe / stable / authorized;
the exceptions are the ones that ARE proofs (an `Authorized<...>`
parameter; an `Ok`/`Some` payload of a proven scrutinee; a record-typed
parameter for `_record_names`). Taint propagates through `source`.

Measurement: in-repo `.aeth` corpus 200 findings before and after,
identical (file, code, line); Python corpora unchanged (see Measurements).

### BUG-056  effects and injections in `requires` / `ensures`, refinement predicates and `const` initializers were never checked  [OPEN]
test: tests/test_compiler_refuses.py
(`::test_a1_requires_effect`, `::test_a1_ensures_effect`,
`::test_a1_refinement_predicate_effect`, `::test_a1_const_initializer_effect`,
`::test_a1_requires_shell_injection`, `::test_a1_pure_contracts_stay_clean`)

Audit A1, probe-confirmed on `52f04aa` (`lang/e01..e04`): a `pure`
function with `requires isOk?(writeFile(...))`, a refinement `where
isOk?(writeFile(...))`, a `const X = isOk?(writeFile(...))` under a
module granting only `log`, and `requires shellExec("rm -rf " + name)
!= ""` were all exit 0 (and `run` wrote the files).

Root cause: `check_effects`, `check_capabilities` and every security
detector walked `d["body"]` only, and only `FunctionDecl`s.

Fix (`c193b21`): `fn_exprs(decl)` = body + requires + ensures, and
`contexts(ast)` = every FunctionDecl plus one synthetic PURE context per
refinement predicate (`<type T where>`, `self` as its parameter) and per
const initializer (`<const X>`). Every per-body scan (E0801, E0701, the
marker-flow and literal-or-wrapper rows, E0716, E0717, E0729) iterates
`contexts()` / `fn_exprs()`; signature tables still read real
FunctionDecls. Effects in a predicate or const are E0801 (pure context)
and, under a module, E0701.

### BUG-057  function values laundered effects and capabilities unless they were a bare Ident argument  [OPEN]
test: tests/test_compiler_refuses.py
(`::test_a2_indexed_list_under_module`, `::test_a2_returned_function`,
`::test_a2_const_alias`, `::test_a2_list_element_to_hof`,
`::test_a2_if_expr_function`, `::test_a2_pattern_bound_function`,
`::test_a2_record_field_function`, `::test_a2_sanctioned_shapes_stay_clean`)

Audit A2, probe-confirmed on `52f04aa` (`lang/c01, p02..p05, p07, p08`):
`let ws = [writeFile]; ws[0](path, s)` in a `pure` function under a
module granting only `log`; a returned function; `const g = print`; a
list element handed to `map`; an if-expression of functions; a
map-valued function unwrapped by `match`; a record-field call — all
exit 0.

Root cause: `callee_name()` returns None for index / call / if / match
callees and the call was skipped; a local or const callee with no alias
binding contributed nothing; `capability.py` treated those callees as
pure.

Fix (`c193b21`, `8722ce6`): one resolver, `resolve_call()` in
`passes/effects.py`, shared by E0801 and E0701. Aether has no lambdas,
so every function value is a named function; a callee the checker
cannot name (index, call result, if / match expression, record field,
an opaque local — one bound by a loop, a pattern, a non-function
parameter or a non-Ident value — or an unresolved const) is bounded by
the declared effects of every function the program uses as a value
(an Ident outside callee position, not shadowed locally). The same holds
for a function value at a position a stdlib HOF or a user
function-typed parameter calls. E0801 names the bound
(`extra.via = "unknown_callee"`, `candidates`, `shape`); `capability.py`
adds an edge to every escaping function. An empty bound (only pure
functions escape) proves the call pure. Function-typed parameters keep
BUG-022/024/025 semantics (charged where the function is passed). No
effects syntax for function types was added (closed design point).
Translated Python keeps the pre-A2 capability edges (`call["py"]`): the
closed-world argument does not hold there, and without the guard
`check-py --strict` gained 39 E0701 on the framework corpus.

Measurement: in-repo `.aeth` corpus 200 = 200 (no corpus program calls
an unnameable callee with an effectful escaping function); framework
corpus 676 = 676 default, 10,808 = 10,808 `--strict`.

### BUG-058  name mangling was not injective and shared the namespace of the runtime's own helpers  [OPEN]
test: tests/test_compiler_refuses.py
(`::test_a4_user_function_cannot_replace_contract_checker`,
`::test_a4_user_function_cannot_replace_refinement_checker`,
`::test_a4_question_suffix_does_not_collide`, `::test_a4_temporaries_do_not_collide`,
`::test_a4_mangle_is_injective`, `::test_a4_runtime_helpers_unreachable_from_user_names`)

Audit A4 (`lang/n01, n02, n04`), probe-confirmed on `52f04aa`: a user
`function assert_contract(...)` disabled every `requires`
(`withdraw(10, -1000)` printed 1010); a user `check_refinement`
disabled refinements; `valid?` and `valid_q` both mangled to
`_ae_valid_q`, so the checker judged one function and the runtime ran
the other. Found while fixing: emitter temporaries `_ae_scrut1`,
`_ae_tmp1`, ... were the mangled spellings of user names `scrut1`, `tmp1`.
Closes SPEC_ISSUES S-016.

Fix (`8722ce6`): `mangle()`: `foo?` -> `_ae_foo__q`, `foo!` ->
`_ae_foo__e`, a plain name ending in `__q`/`__e` -> `_aex_<name>`, else
`_ae_<name>` (injective; proof in the docstring; `unmangle()` is the
inverse). Runtime `?` functions renamed (`_ae_isOk__q`, ...). Helpers
and temporaries live under `_aert_`, which no mangled name can start
with. `_ae_result` / `_ae_self` stay: they are the user's own `result`
and `self`. Test: every `build_namespace()` entry is either reachable
exactly as its stdlib name or unreachable from every identifier.

### BUG-059  the runtime enforced no capabilities  [OPEN]
test: tests/test_compiler_refuses.py
(`::test_a3_effect_outside_grant_fails_at_runtime`,
`::test_a3_release_mode_enforces_too`, `::test_a3_const_initializer_under_module`,
`::test_a3_capability_firewall_demo_fails_at_runtime`,
`::test_a3_granted_and_moduleless_programs_run`)

Audit A3 (`lang/c04`), probe-confirmed on `52f04aa`: module `requires
capability log`, a function calling `writeFile`; `run
--no-static-effects --no-capability-check` wrote the file. The same run
of `demos/capability-firewall/log_formatter.aeth` finished exit 0.

Fix (`8722ce6`, `af11754`): a program with a module emits
`_aert_grant = frozenset([...])` + `set_capability_grant(_aert_grant)`
at the top and passes the grant on every effect frame. The runtime
raises a structured E0701 (`extra.runtime = True`) when (a) a stdlib
function performs an effect outside the grant, or (b) a function whose
DECLARED effects exceed the grant is invoked (before its body runs).
Programs without a module keep the implicit all-grant (unchanged
emitted code). This is a RUNTIME guarantee about the stdlib effects and
declared effects of the running program, not a static proof. Ceiling:
`--release` pushes no frames, so there only performed effects are
checked, against one process-wide grant (two packed modules imported
into one process share the last one set).

### BUG-060  a net.fetch glob `*` crossed `/ @ :` in the authority  [OPEN]
test: tests/test_compiler_refuses.py (`::test_a7_glob_does_not_span_the_path`,
`::test_a7_glob_does_not_span_userinfo`, `::test_a7_subdomain_and_path_globs_still_cover`)

Audit A7 (`lang/g01`): `https://*.corp.example/*` covered
`https://evil.com/.corp.example/x` (E0801 silent). Fix (`065ee74`): for
URL globs the cover is decided per part of the parsed URL; `*` in the
scheme or authority is `[^/@:?#]*`, in the path `.*`. `.aeth` corpus
200 = 200.

### BUG-061  refinements were checked only on direct `TypeName` parameters  [OPEN]
test: tests/test_compiler_refuses.py (`::test_a6_every_binding_site_is_checked`,
`::test_a6_valid_values_pass`)

Audit A6 (`lang/r01..r06`): a refined return, typed `let`, record field,
`List<PositiveInt>` element, `const`, and the base predicate of a refined
alias (`type Small = PositiveInt where self < 10` accepted -50) all
passed at runtime. Fix (`b02eafe`): one `refine_check()` in the emitter
applied at parameters, returns, annotated let/var and assignments to
them, consts, record constructor fields and `List<Refined>` elements;
the hoisted predicate of a refined alias calls its base's predicate.
Runtime guarantees (E0302 when the value is bound).

### BUG-062  deep input crashed the parser / passes / emitter with a Python traceback  [OPEN]
test: tests/test_compiler_refuses.py (`::test_a10_deep_parens_and_long_chains_are_e0201`,
`::test_a10_bounded_depth_still_analyzes_and_runs`, `::test_a10_unemittable_construct_is_e9001`)

Audit A10 (`lang/m01, m02, m07`): ~40+ nested parens → parser
RecursionError; a 500-term `1 + 1 + ...` chain → RecursionError in
`ast_walk.walk`; `const X = old(1)` → NotImplementedError. Fix
(`eaa5d91`): `walk()` iterative; the parser bounds each top-level
declaration (RecursionError, or AST depth > `MAX_AST_DEPTH` = 200, is
E0201 with a split-into-lets hint; deepest in-repo program: 13); `emit()`
turns NotImplementedError into E9001. Done without touching cli.py:
both are raised as `AetherError` below it.

### BUG-050 (coordinator's entry — no new entry)
Fixed in `8722ce6`: `_ae_remove` branches on set/frozenset →
`frozenset(m) - {k}`. test: `tests/test_compiler_refuses.py::test_bug050_remove_on_set`
(red at `52f04aa`: Python TypeError). At merge, delete the "Known
defect" note under `Set<T>` in `grammar/stdlib.md`.

## LOOP_LOG block

## Iteration 58 — Wave 2 of the 2026-09-24 audit: the compiler refuses again (no new detector)

- **Target:** not a backlog row. Plan Wave 2 (A5, A1, A2, A4, A3) plus
  A6, A7, A10 from Wave 6's language list: each is a place the compiler
  accepted, or the runtime ran, what the language promises to refuse.
- **Probe-confirmed first (on `52f04aa`, `check` exit 0 or wrong run):**
  the four arch for/match-shadow probes (E0711, E0713, match E0711, E0717
  IDOR); `lang/e01..e04` (effects in contracts, predicates, consts);
  `lang/c01, p02..p05, p07, p08` (function values); `lang/n01, n02, n04`
  (mangling); `lang/c04` and the capability-firewall demo under
  `--no-static-effects --no-capability-check`; `lang/g01`; `lang/r01..r06`;
  `lang/m01, m02, m07`.
- **Fixes (one mechanism per root cause):**
  - `binders(fn)` — one binding iterator (params, let/var/assign, for,
    BindPat/AsPat in match statements and expressions) read by all six
    fixpoints; value-less binders disqualify proofs.
  - `fn_exprs()` + `contexts()` — contracts, refinement predicates and
    const initializers are code, scanned by every pass.
  - `resolve_call()` — an unnameable callee is bounded by the effects of
    every function the program uses as a value (closed world: no
    lambdas); shared by E0801 and E0701.
  - Injective `mangle()`, helpers under `_aert_`.
  - Runtime capability grant: performed and declared effects outside a
    module's grant raise E0701 at run time.
  - URL-part glob cover; `refine_check()` at every binding site;
    iterative walk + parser depth bound + E9001 from emit.
- **Measured non-breaking:** in-repo `.aeth` corpus 200 findings before
  and after, identical; framework corpus 676 = 676 (default) and
  10,808 = 10,808 (`--strict`); in-repo Python trees unchanged except the
  new test file itself.
- **TYPE gap surfaced:** effect names are still unchecked (A11) — the
  spec lattice (`db.read`/`db.write`) and the stdlib (`db.query`/`db.exec`,
  `exec.run`, `net.redirect`) disagree, so "only spec'd names" cannot be
  enforced until the list is regenerated from code (Wave 6 E5).
- **Residuals (pushed to q1):** see q1 rows below.

## q1 rows

Rows this wave CLOSES:
- Row 70, "NEW probe-confirmed MISS (open): `for` / `match` binders
  re-bind a name the safe/stable/authorized passes proved" (added
  2026-09-24) → CLOSED by `c193b21` (BUG-055). Suggested replacement
  text: "CLOSED (iter-58, BUG-055): one `binders()` iterator feeds all six
  fixpoints; a value-less binder (loop variable, pattern name, plain
  parameter) disqualifies a proof. Found while fixing: parameters were
  not binders (a raw param later assigned a proof was authorized) and
  `AsPat` names were never tainted — both closed by the same iterator."
- The "effect-polymorphic function types" open item (in the
  closed-items paragraph) is narrowed, not closed: calls through values
  the checker cannot name are now bounded (BUG-057) without adding
  effects syntax to function types.

New residual rows:

| Residual | Evidence | Confidence |
|---|---|---|
| NEW residual (A2 bound is program-wide): an unnameable callee is charged the effects of EVERY function used as a value anywhere in the program, not the ones that can reach that call | iter-58 (BUG-057): the bound is sound because Aether has no lambdas and a program is one closed file after import resolution; it is coarse — one `let hs = [logIt]` anywhere makes every `xs[i](...)` in a `pure` function E0801 with `log`. Precision upgrade: a per-value flow of function names (list/map literals, returns). The same bound is NOT applied to translated Python (lambdas, imported callables); there the frontend's `unprovable` report stands `[source: diagnostics, section: E0801, key: unknown_callee]` | high |
| NEW residual: a stable id bound by a `for` loop is never stable | iter-58 (BUG-055): `for id in ids do let p = authorizeResource(u, a, id); sqlByOwner(s, id, p) end` is E0717 (it was before this wave too — the for-variable was never counted). Accepting it needs "one value per iteration" reasoning, the RELAX direction; left as over-flag `[source: diagnostics, section: E0717, key: sqlByOwner]` | high |
| NEW residual: runtime capability grant covers stdlib-performed and declared effects only | iter-58 (BUG-059): the runtime E0701 fires for a stdlib effect outside the grant and for invoking a function whose declared effects exceed it; `--release` code checks performed effects only, against one process-wide grant. It is a runtime guarantee, never a static proof `[source: effects, section: capabilities, key: E0701]` | high |
| NEW residual: A6 refinement sites | iter-58 (BUG-061): checked at params, returns, annotated let/var and assignments to them, consts, record fields, `List<Refined>` elements. Not checked: `Map`/`Option`/`Result`/`Set` payloads, record fields updated after construction, and assignments to a name annotated in a DIFFERENT function. Runtime only `[source: types, section: refinement, key: E0302]` | high |
| NEW residual: declarations deeper than 200 AST levels are refused (E0201) | iter-58 (BUG-062): the recursive passes need a bound; the deepest in-repo program is 13 levels. A generated 500-term flat sum is refused, not analyzed `[source: diagnostics, section: E0201, key: nesting]` | high |

## Skipped / not reproduced / deferred

- **A11 (pure with siblings; unknown effect names): deferred.** Reproduced
  (`lang/e06`: `effects pure, log` passes `check`; `bogus.effect`
  accepted). Not fixed: rejecting `pure, log` belongs in the parser
  (E0201), and parser.py is in my ownership only for A10; rejecting
  unknown effect names needs the canonical list, and the spec lattice in
  `grammar/effects.md` (`db.read`/`db.write`) disagrees with what the
  stdlib performs (`db.query`, `db.exec`, `exec.run`, `net.redirect`) —
  "only spec'd names" would reject the stdlib's own effects. Needs Wave
  6's E5 (effects.md generated from code) first. No corpus file uses
  `pure` with a sibling (grep: 0), so the parser rule is cheap once owned.
- **A2 argument positions:** a function value is charged at a stdlib HOF
  position only for the ten runtime HOFs (`_STDLIB_HOF_ARGS`, from the
  runtime signatures) and at user function-typed parameters; any bare
  Ident argument naming a function is still charged at every position
  (BUG-022, unchanged).
- **`smt.py` `_ae_smt_result`** is a z3 variable name in the `_ae_`
  space; not emitted Python, and smt.py is not in this wave's files.
  Harmless today; worth moving to `_aert_` when smt.py is next touched.
- **`aether pack` public aliases (cli.py, Wave 3):** still computed as
  `mangle(n)[len("_ae_"):]`. Works; the public name of `valid?` is now
  `valid__q` (was `valid_q`, which collided with a user `valid_q`); a
  plain name ending in `__q` gets `_valid__q`-style `_aex_` leftovers
  (`mangle` → `_aex_...`, sliced at 4). Suggest cli.py use
  `runtime.unmangle`-aware naming.
- **LSP / tools/alsp_surface.py** derive stdlib names by stripping
  `_ae_`: `isOk?` now shows as `isOk__q` (was `isOk_q`, equally wrong);
  the helpers `assert_contract` / `check_refinement` no longer appear as
  fake stdlib names (they are under `_aert_`). Both files are Wave 3's;
  `runtime.unmangle()` is the fix.

## Measurements

Commands (brief §Method 4), `--json check-py` from a `git archive` of
each commit:

| corpus | 52f04aa | after (framework: `eaa5d91` snapshot; trees: `af11754` worktree) |
|---|---|---|
| framework `_work/src` (4,946 files), default | 676 | 676 (identical rows) |
| framework, `--strict` | 10,808 | 10,808 (identical rows) |
| `bench tests tools playground demos`, default | 110 | 114 |
| same, `--strict` | 1,816 | 1,828 |
| in-repo `.aeth` corpus (418 files, `analyze_flat` per file, imports resolved) | 200 | 200 (identical (file, code, line) rows) |

Every added in-tree Python finding is in the NEW file
`tests/test_compiler_refuses.py` (4× E0731 on its `exec(code, g)` harness
lines — true by rule, the same shape as the existing runtime suites;
under `--strict` also 7 E0701 inventory rows and 1 E0711 on its
`open(path)`); no existing file changed. The
intermediate measurement at `c193b21` (before the Python guard) showed
+39 E0701 under `--strict` on the framework corpus from A2's new edges;
the guard in `8722ce6` restored identity. `af11754` changes only
runtime.py (no pass or frontend change), so the `eaa5d91` framework
numbers stand for it; the trees were re-scanned at `af11754`.

## Changed tests that pinned old behaviour

- `tests/test_regressions.py::test_B4_refinement_helper_is_module_level`
  asserted the helper spellings `def _ae_refn_PositiveInt(_ae_self):` and
  `_ae_check_refinement(_ae_n, _ae_refn_PositiveInt` — the user-reachable
  namespace A4 moves helpers out of. Now `_aert_refn_...` /
  `_aert_check_refinement(...)`; the property tested (one hoisted helper,
  no per-call lambda) is unchanged.
- `tests/test_release_emit.py::test_release_keeps_boundary_checks` (the
  `"_ae_check_refinement" in py` line) — same rename.

## Doc sentences to update at merge (Wave 6 / coordinator owns the files)

- `grammar/effects.md`: "At this version there is no runtime capability
  check" (coordinator's text on main) and, at `52f04aa`, line 60 "In v0.1
  the capability check is a runtime assertion at module load time and at
  the first effect invocation." → the runtime check now exists: a program
  with a module raises E0701 at run time when a stdlib function performs
  an effect outside the grant, or a function whose declared effects
  exceed it is invoked; programs without a module have the implicit
  all-grant; `--release` checks performed effects only. Runtime
  guarantee, not static.
- `README.md:353` "the runtime grants only what is declared" — now true
  for programs with a module, as a runtime check; say so with that
  qualifier.
- `grammar/diagnostics.md`: E0701 row — add the runtime variant
  (`extra.runtime = true`, fields `effect`, `required_capability`,
  `declared_capabilities`); E0801 row — add `via = "unknown_callee"` with
  `candidates` and `shape` (an unnameable callee is bounded by every
  function used as a value); E0201 row — nesting bound (200 AST levels /
  parser recursion); E9001 row — also raised when the emitter cannot
  translate a construct (`old()` outside a function).
- `SPEC_ISSUES.md` S-016 → FIXED by `8722ce6` (injective mangling, the
  scheme in `runtime.mangle`'s docstring).
- `grammar/stdlib.md`: delete the BUG-050 "Known defect" note under
  `Set<T>`.
- `grammar/types.md` / refinement docs: refinements are checked (at run
  time) at parameters, returns, annotated let/var and their
  assignments, consts, record fields and `List<Refined>` elements, and a
  refined alias checks its base predicate.
