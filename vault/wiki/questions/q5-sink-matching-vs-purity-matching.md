---
type: question_page
question_id: q5
status: answered
confidence: high
last_updated: 2026-09-03
tags: [diagnostics, design-rationale, toolchain, effect-system]
---

# Why may the Python frontend match SINKS by method name, when matching PURITY by method name was unsound?

## Short Answer

**Because the direction of the error inverts.** The two operations are
identical — read a method name off a receiver whose type was never
resolved, and draw a conclusion — but one conclusion is "this is safe"
and the other is "this is dangerous", and only the first can hide a
real bug.

One rule covers both: **never assume clean from a name; freely assume
dangerous from a name.** The asymmetry is not a double standard, it is
the direction in which each mistake fails.

## The Two Cases

`tools/py_frontend.py` deleted a `PURE_METHODS` allowlist as unsound. It
cleared `obj.append()` as pure from the method NAME alone, and
`trap_04`'s `AuditLog.append()` opens a file and writes to disk — so a
capability-using module was certified `PROVEN_CLEAN`. That is a silent
false negative: the contract-breach class, the one thing a proof tool
must never do. The note left in its place says it is never coming back.

Sink matching does the same thing with the same absence of proof:
`cursor.execute(...)` is treated as a SQL sink whatever `cursor` turns
out to be. The worst case is a finding on code that was not a sink — an
over-flag, the same direction every other Aether taint pass already
accepts `[source: diagnostics, section: E0713, key: sqlQuery]`.

|  | conclusion drawn from the name | worst case | verdict |
|---|---|---|---|
| `PURE_METHODS` | "no capability here" | a real capability certified clean | **unsound — deleted** |
| `SINK_BY_METHOD` | "this may be a sink" | a finding on a non-sink | **over-flag — kept** |

## Why It Matters Beyond Python

This is the general shape of the UNPROVABLE discipline the Python
experiment was built to test. The frontend's rule was always "a call
whose capability surface cannot be determined is NEVER assumed clean" —
stated as a constraint on *clearing*. Sink matching shows the other half
was always implied: nothing stops the analysis from *suspecting* on
weak evidence, because suspicion costs precision and never costs
soundness.

The same reasoning licenses `_expr`'s fallback: a Python expression the
translator does not model becomes `PyExpr`, a node kind no rule knows,
so `_arg_reason` falls through to its default — **refused**, never
cleared.

## Measured Cost

The over-flag is not free, and the price was measured rather than
assumed (`bench/py_frontend/REPORT.md`, 76 benign modules from
`tools/py_corpus{,2}`):

- E0713 fired once, E0720 once — both on genuinely suspicious code, one
  of them (`trap_05_pickle`) a planted trap. Those rows ship default-on.
- E0711 fired 11 times: one real upload write-traversal
  (`fa_04_upload.py`), and eight of the form `open(path_param)` where
  nothing constrains the path. Correct by Aether's rule, too noisy to
  lead with on a language that has no `safeJoin` convention — so it is
  **opt-in behind `--strict`**, published with its number, neither
  deleted nor silently downgraded.

The rule that follows: an over-flag is sound but not automatically
shippable. Measure it on benign code, and let the ratio decide whether
the row leads or waits — the same discipline
[[q3-what-makes-a-good-backlog-target]] applies to choosing targets.

## The rule extends from NAMES to VALUES — and the cost of getting it backwards

The guard-bound-elsewhere item was filed here as a precision residual.
Probing it (iter-45) found something else: **three false accepts**, which
is the contract-breach class, not a precision gap. Silent before the fix:

| Shape | Expected |
|---|---|
| `yaml.load(raw, Loader=yaml.Loader)` | E0720 |
| `loader = yaml.Loader` … `yaml.load(raw, Loader=loader)` | E0720 |
| `sh = True` … `subprocess.run('x ' + cmd, shell=sh)` | E0714 |
| `cur.execute('SELECT ... ' + name, extra)` | E0713 |

The first is the instructive one. It is **not "bound elsewhere" at all** —
the unsafe value is written at the call site, and the gate read *any*
`Loader=` as safe. Adding `Loader=` is the commonest wrong fix for
PyYAML's deprecation warning, and `yaml.Loader` constructs
`!!python/object/apply` (verified by execution, PyYAML 6.0.3). So the
answer this page gives about names was **only half the rule**:

> A NAME may not clear a call. **A VALUE may not either.** A guard clears
> a call only when its value is positively identified as one of the
> sanctioned forms. Unrecognized, computed, unresolvable, or absent all
> mean SINK.

All three bugs were one mistake — the unknown case defaulted to *safe* —
made in three places because each gate was written ad hoc. They are now
one declarative table (BUGS.md BUG-004).

The corollary is about scope, not about Python: **the direction argument
in the Short Answer above is not self-executing.** It says which way to
err; it does not make you err that way. Every place the analysis draws a
conclusion needs the default written down explicitly, because "I could
not tell" is the case that will actually occur and the tempting default
is silence.

**Measured cost of the fix** (`bench/py_frontend/REPORT.md`, same 76
benign modules): E0711 11, E0713 1, E0720 1 — **identical to before**.
Making every unresolvable guard a sink cost zero measured precision on
real code. That is a measurement, not a prediction; it could have gone
the other way, and the decision rule would then have been the one applied
to E0711 — publish the number and put the row behind `--strict`.

Precision was recovered where it is decidable: `_local_constants`
resolves a local name only when **every** binding in the function agrees,
so `loader = yaml.SafeLoader` clears the sink while a name rebound from
`SafeLoader` to `Loader` does not.

## Residual

**Object state and import-time configuration.** What is handled now is a
guard in a *keyword* and a guard in a *local binding*. What is not: state
**mutated after construction** — `s = requests.Session()` then
`s.verify = False` — and configuration set at module scope. Both need a
different traversal (attribute assignment, module-level flow) and their
own probe.

Note `session.verify` was probed and is silent for a *different* reason:
Aether has **no detector that models TLS verification at all**, so there
is nothing to gate. That is a missing-detector item for
[[q3-what-makes-a-good-backlog-target]]'s normal selection, not a guard
bug — the distinction matters, because probing one and reporting the
other would manufacture a gap that does not exist.

**The name rule's cost, measured on the population it was written for
(2026-09-01, iter 47).** `execute` matched by name is sanctioned because
the error direction is safe. `bench/framework_scan/` put a number on that
direction for the first time on code Aether is aimed at: **1,029 of 1,055
findings across 15 AI-agent frameworks** were E0713 on SQLAlchemy Core
expressions — `conn.execute(select(t).where(...))`, a parameterized query
by construction. The name rule did not change; it was never wrong about
`execute` being a sink. What was wrong was one level down: the
*argument* rule read a `select(...)` call as a dynamic query because it
is not a literal. The fix is the same shape as `SANITIZER_BY_QUALIFIED`:
a call rooted, through imports, at a `sqlalchemy`/`sqlmodel` builder is
named `sqlBind`. Rooted through imports, not by name — a `select` from
any other module still clears nothing, which is this page's rule applied
to the fix of its own side effect.

The soundness line inside a recognised expression is the raw-string
entry points (`text`, `literal_column`, `column`, `table`): a non-literal
first argument to any of them, anywhere in the tree, sanctions nothing.
`bench/py_frontend/corpus/sqlalchemy_repro.py` pins 8 safe and 6
vulnerable shapes; the benign corpus did not move.

The rule reached one more place while this was measured: **an import is a
name too.** Frameworks import SQLAlchemy under `try:`, and the frontend
had never registered a guarded import, so `select` was rootless — and,
worse, a guarded `import yaml` left `yaml.load(x)` silent (BUG-011, the
false-accept class). Imports are now read from the whole module, and a
local name bound by two imports to different targets resolves to
nothing: it clears no query and sanctions no builder. Picking a winner is
a false accept in one direction or the other.

*Residual:* recognition is by module root, so other query builders
(`peewee`, `pypika`, `sqlglot`) still read as computed queries until each
is measured and added — over-flag, not miss. A statement assembled in a
helper (`stmt = self._base_query()`) crosses a function boundary and stays
a computed query. `text(name)` resolves only when every binding of `name`
is a literal; a parameter never is. `[source: README, section: Python, key: sqlBind]`

**A position is a name too (2026-09-03, iter 48).** The rule this page
states for names — never clear from one, freely suspect from one —
turned out to have a third clause the frontend had been violating
silently: *a call the translator never emits is neither cleared nor
suspected.* Four statement kinds were translated; a sink behind
`await`, in a `for` iterable, in a tuple-target assignment, inside
`x or []`, or in a `def` under `try:` produced no node at all — 603
await-wrapped sink calls on the framework corpus, plus 89 in other
positions (BUGS.md BUG-012). The same walk-by-kind shape let `sql +=
uid` leave `sql` "literal-only", because three resolvers saw a single
binding form. The obligation that closes both is totality, recorded on
its own page: [[q7-frontend-totality-over-syntax]]. Measured: 411 → 628
findings on the same 4,946 files, 0 errors; ground truth 41 TP / 0 FN /
0 FP; benign corpus unchanged. `[source: README, section: Python, key: check-py]`

*Residuals after iter 48 (all over-flag direction):* the helper-assembled
statement is now **34 of the pre-fix 381** (14 same-module, 20
cross-module) by a source-level census, not the "~100" iteration 47
estimated — the per-module summary stays parked at that price; `self.
table.delete()` (an attribute receiver) is not accepted as the
Table-method form, only a bare name is; a keyword-only sink argument
takes the positional slot *in keyword order*, so a guard keyword written
before the data keyword is what gets judged (refused, never cleared);
`fetch` as a method name is deliberately NOT a SQL sink (too many
non-SQL `fetch`es), so asyncpg's `conn.fetch(q)` is silent until a
qualified row exists; the E0723 PEM pattern matches the header alone,
which module-level strings now expose (two docstring/message hits on
the corpus) — closed in iter 49 (a body is required after the header).

*Iter 50 (E0731 + the sink rows the agent corpus needs):* the builtin
sinks `exec`/`eval`/`compile` match BARE names only — `_callee_spelling`
falls back to the attribute name for an unresolved receiver, and
`session.exec(stmt)` is the by-name SQL row, not the builtin; a local
`def exec` shadow is not the builtin. `torch.load` without
`weights_only=True` is a sink although torch ≥ 2.6 defaults it on — the
same version-dependence lxml has, judged by the older default, over-flag
direction. Bare `fetch` is deliberately NOT a SQL sink by name (vector
stores and HTTP clients spell it); `fetchrow`/`fetchval`/`fetch_all`/
`fetch_one`/`fetch_val` are. The argv form `["bash", "-c", cmd]` is a
shell (BUG-021). `[source: README, section: Python, key: check-py]`

## Related
- [[q1-taint-marker-soundness-boundary]] — the over-flag-never-miss contract every taint pass inherits
- [[q3-what-makes-a-good-backlog-target]] — the selection heuristic this measurement discipline extends
- [[../clusters/violation-taxonomy]] — the sink rows this reasoning licenses on Python
- [[q7-frontend-totality-over-syntax]] — the third clause: a position the translator does not emit is neither cleared nor suspected
