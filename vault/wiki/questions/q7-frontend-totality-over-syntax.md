---
type: question_page
question_id: q7
status: answered
confidence: high
last_updated: 2026-09-11
tags: [toolchain, diagnostics, design-rationale]
---

# Why must the Python frontend be TOTAL over syntax, and why is a position it does not model a soundness hole rather than an over-flag?

## Short Answer

Every Aether detector judges a **shape** — a literal, a sanctioned
wrapper call, a name bound only to safe values — and refuses everything
else `[source: diagnostics, section: E0713, key: sqlQuery]`. That makes
the detectors over-flag by construction. The frontend is the one place
where the direction inverts: it decides **which shapes exist at all**.
A statement position or binding form the translator does not model
produces no node, and a node that does not exist is never refused — it
is silent. Iteration 47's rule for imports (BUG-011) was the first
instance; BUG-012 is the general one: `await conn.execute(q)` was an
opaque leaf, `for row in cur.execute(q)` was a statement kind the walk
skipped, `sql += uid` was a binding form three resolvers could not see,
so a name proved "literal-only" after it had been rebound to input. The
obligation is therefore **totality**: translate every value expression a
statement evaluates, in place; treat every form that binds a name as a
binding, with an opaque value when the value cannot be seen; and let an
unmodeled expression stay opaque *but carry its children*, so a call
inside `x or []` is still found by `walk`. Precision rules (a name
clears something) stay positive-identification-only; totality rules
(a position is seen) must be unconditional.

## Evidence

| Finding | Evidence | Confidence |
|---|---|---|
| The detectors refuse unknown shapes; the frontend decides what is unknown | `_arg_reason` falls through to `rule.default` (REFUSED) for `PyExpr`; a call that never becomes a `Call` node is never judged (`transpiler/aether/py_frontend.py`, `_expr`/`visit_stmt`) | high |
| Four statement kinds and one expression shape were the whole modeled surface | pre-fix `py_to_ir` walked `Assign`/`AnnAssign`/`Expr`/`Return`/`With` and `_expr` returned a leaf for every unmodeled node | high |
| Silence, measured on the population the scanner is for | census over bench/framework_scan (4,946 files): 603 sink calls behind `await`, 89 in other unmodeled positions, 26 of those firing under existing rows once visible; BUGS.md BUG-012 | high |
| Rebinding forms are the same bug in the other direction | `sql += uid` / `for sql in qs` / a parameter with a literal fallback all proved a name literal-only; probe files `scratchpad/probes/pyfe/p/a01..a17`, all `exit 0` before, all firing after | high |
| The fix is structural, not a list of cases | `_bindings_of` (one walk, every binding form, every resolver), `_stmt_expr_children` (every expression a statement evaluates), `_expr_children` (children of every opaque node); `visit_stmt` has no per-kind default that drops | high |
| CORRECTION (2026-09-11): this page first claimed totality over positions, and the frontend was not total | the 0.4.0 pre-release audit probed the claim instead of reading it: a sink in `del d[f(x)]`, `d[f(x)] += 1`, `for d[f(x)] in xs` or `with cm as d[f(x)]` was still exit 0 (BUGS.md BUG-027), because a binding target field was skipped whole as "names, not values". Only a bare name is purely a binding; a subscript or attribute target evaluates its base and index first. The same audit found a case guard or an `except` type reported twice (BUG-028). `_target_loads` now feeds every target consumer, and the walk visits statements only. The lesson is q1's, repeated on a new page: a claim of completeness is a claim about every shape, and it is checked by writing the shapes `[source: README, section: Python, key: check-py]` | high |
| Cost on the target corpus | 411 → 628 findings on the same 4,946 files, 0 analyzer errors, 0 unreadable; +217 E0713 (await-wrapped `text(f"…")` and `exec_driver_sql`), +5 E0720 (tuple-target `pickle.load` in langchain-community vector stores), +1 E0714; 8 over-flags gone (module constants, `None` sentinels); ground truth 41 TP / 0 FN / 0 FP; benign corpus unchanged (`bench/py_frontend/run_bench.py`) | high |
| Depth is the frontend's limit, deterministically | `_MAX_EXPR_DEPTH = 200`: a deeper expression yields an `unprovable` `too_deep` region for its scope and every other finding survives; before, a `RecursionError` lost the whole file as "unreadable", exit 0 | high |

## Recommended Actions

- **New Python syntax goes through the generic paths.** A new statement
  kind is handled by `_stmt_expr_children`; a new expression kind by
  `_expr_children`. Adding a per-kind branch that returns a childless
  leaf re-opens this class. `tests/test_py_frontend_sinks.py`'s
  `test_sink_in_every_statement_position_is_seen` pins 32 positions,
  each seen exactly once — six of them (targets, case guards, handler
  types) added after this page first claimed totality; see the
  correction row.
- **New binding forms go into `_bindings_of`.** It is the only binding
  walk; `_local_constants`, `_safe_xml_parser_names`,
  `_sql_expression_names` and `seed_bindings` all consume it.
- **Measure with the census, not the probe.** A probe proves one shape;
  the corpus census (`scratchpad/probes/pyfe/census.py`'s method:
  match every `_sink_name`-recognised `ast.Call` against IR `Call`
  positions) proves the class is closed.
- Residuals, all over-flag direction, recorded in
  [[q5-sink-matching-vs-purity-matching]]: keyword-only sink arguments
  take positional slots *in keyword order* (a guard keyword before the
  data keyword is judged as the data — refused, never cleared); a
  statement assembled in a helper stays a computed query; `self.table
  .delete()` (attribute receiver) is not the Table-method form.

## Related
- [[q5-sink-matching-vs-purity-matching]] — the direction-of-error rule this page extends from names to positions
- [[q1-taint-marker-soundness-boundary]] — the over-flag-never-miss contract the frontend must preserve
- [[q3-what-makes-a-good-backlog-target]] — why a false-accept class outranks every precision item
- [[../clusters/violation-taxonomy|Violation Taxonomy]] — the sink rows this totality serves
