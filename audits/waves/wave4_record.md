# Wave 4 record — the Python scanner stops missing (iteration 59)

Plan: `audits/audit_2026-09-24_plan.md` §B, Wave 4 — B4, B5 (+PM-5, PM-7),
B8, B9, B10. B1/B2/B3/B7 were already fixed (BUG-032..035) and were not
touched; B6 (exit codes) is Wave 5's. Branch forked from
`v0.5-audit-waves` @ `47139a1` (Waves 0, 1, 3, 6 merged); every "before"
below is `47139a1`. Ids: BUG-065..069 (070..072 unused).

Commits:
- `a45ad9d` py_frontend: the scanner stops missing (audit B4/B5/B8/B9/B10)
- this record

Files changed: `transpiler/aether/py_frontend.py`,
`tests/test_py_frontend_sinks.py` (5 new tests), `tests/test_sink_rows.py`
(28 new pins), `tests/ratchet_baseline.json` (`min_py_table_rows` 93 → 121).
Nothing outside the wave's ownership list was edited.

Every item was reproduced silent (or mis-coded) on `47139a1` first, with
the audit's own repro files (`scratchpad\pymiss\p_*.py`, 222 readable) plus
35 extra shapes (`scratchpad\w4\px\`). The five new tests were run against
the `47139a1` `py_frontend.py` with the new tests in place: all five FAIL,
and `test_sink_rows::test_every_row_is_pinned` FAILS (28 pinned rows
absent). All pass at `a45ad9d`.

## BUGS entries

### BUG-065  a non-literal raw SQL string was judged only inside an executor's argument; bound to a name, passed to `Query.filter`/`scalars`/`from_statement`, or built in `.where(...)`, it was silent (false accept)  [OPEN]
test: tests/test_py_frontend_sinks.py
(`::test_raw_sql_string_is_a_finding_wherever_it_enters`)

Found 2026-09-24 by the whole-repo audit (B4, B5, PM-5, PM-7), confirmed on
`47139a1`. Silent: `order = text(col); session.execute(select(t).order_by(order))`
(README: "still an injection … built in one statement or across several");
`cond = text("n = '" + name + "'")` then `.where(cond)`;
`session.query(User).filter(text(f"..."))`; `session.scalars(text(f"..."))`,
`session.scalar(...)`; `.from_statement(text(f"..."))`;
`c = literal_column(col)`; module-level `COND = text(sys.argv[1])`;
`conds = [text(a), text(b)]`; Flask-SQLAlchemy `User.query.filter(db.text("n='" + name + "'"))`
and `select(User).where(db.text(f"..."))` (sanctioned as `sqlBind` —
`db.text` resolves through no import); `select(t).where("n = '" + name + "'")`
and `users.select().where(...)` (sanctioned: the str argument was never
inspected); `session.query(User).filter("name = '%s'" % name)`.

Root cause: `text()`/`literal_column()` were only a *disqualifier* inside
`_is_sql_expression`; the finding came from the executor that judged the
expression, so a raw entry that never sat inside an executor's argument
had no finding at all. `db.text` matched no row. A str argument to
`.where()` was not a raw entry.

Fix (`a45ad9d`): `_raw_sql_entry(call)` — a non-literal raw SQL string
entering the expression language IS the E0713 sink (`sqlQuery`, the string
in the judged slot), wherever it appears: `text`/`literal_column` resolved
into sqlalchemy/sqlmodel (`qualified`, 0.95); `.text(x)` on ANY receiver
with SQLAlchemy's one-argument signature (`method`, 0.6 — over-flag by name,
see Measurements for its cost); a str-shaped argument (f-string, concat with
a str literal, `"..." % x`, `"...".format`/`.join`) to `.where`/`.filter`/
`.having` (`method`). Inside a recognised builder chain, a str-shaped
argument to `.where/.filter/.having/.order_by/.group_by/.select` or
`select(...)`, and any non-literal `.text(...)` whatever its signature,
sanctions nothing (the executor judges it). A literal, a literal-bound
name, a module literal constant, a tuple/list/number argument
(`draw.text((x, y), s)`) are not entries. One finding per flow: an entry
inside an executor's judged argument, or bound to a name an executor then
judges (`q = text(f"..."); session.execute(q)`), is un-named
(`_demote_raw_entries`), because the executor fires on exactly that value —
so `session.execute(text(f"..."))` still reports once, at its line, with
its old match kind (0 confidence changes on the corpus).

Measurement: framework corpus +29 E0713 (below); in-repo trees 0.

### BUG-066  a sink reached through a literal dynamic import, a module-level alias, a local builtin alias, `functools.partial` or a dispatch table was silent (false accept)  [OPEN]
test: tests/test_py_frontend_sinks.py
(`::test_aliases_and_dynamic_callees_reach_the_sink`)

Found 2026-09-24 by the audit (B8, PM-8), confirmed on `47139a1`, all
silent: `importlib.import_module("os").system(cmd)`, `__import__("os").system(cmd)`,
module-level `system = os.system` then `system(cmd)`, `evaluate = eval`,
function-local `e = eval; e(x)`, `run = functools.partial(os.system, cmd); run()`,
module-level `sh = functools.partial(subprocess.run, shell=True); sh(cmd)`,
`HANDLERS = {"sh": os.system}; HANDLERS["sh"](cmd)`, `p = pickle; p.loads(b)`.

Root cause: `_callee_spelling` resolved a bare name only through imports
and function-local single dotted bindings; a receiver only through an
import alias; a call target that is a call or a subscript not at all.

Fix (`a45ad9d`): `_ModuleFacts` — module-level names bound once in the
whole module (the `module_lits` bar) with their value expression and
dotted spelling; `_FnScope.value_of` (local single binding, else module).
`_alias_target` follows Name→Name/Attribute single bindings (≤5 hops) so an
aliased builtin is the builtin unless the builtin's own name is shadowed;
`_attr_spelling` names a receiver that is a literal `import_module`/
`__import__` call (or a name bound to one), `__builtins__`, or a
constructor whose `Ctor.method` is a table row; `_unwrap_indirect`
rewrites `partial(f, *a, **k)(*b, **j)` (direct or through a single-binding
name) to `f(*a, *b, **k, **j)`, and a call through a subscript of a
dict/list/tuple display (inline or single-binding) to the entry a literal
key selects, else to ANY entry that is a sink (over-flag). Synthesized
calls carry the outer call's position.

Behaviour change (precision, same bar): a module-level alias of a
SANCTIONED value now clears a guard like a function-local one —
`LOADER = yaml.SafeLoader` (bound once in the module) then
`yaml.load(x, Loader=LOADER)` is clean (was E0720).

Measurement: framework corpus 0 added / 0 removed by this item alone.

### BUG-067  builtins reached through the `builtins` module were silent, and `getattr(builtins, "exec")(src)` was reported as SQL injection  [OPEN]
test: tests/test_py_frontend_sinks.py
(`::test_builtins_spelled_through_the_module_are_the_builtin`)

Found 2026-09-24 by the audit (B9, B10, PM-9/PM-10), confirmed on
`47139a1`: `builtins.eval(x)`, `from builtins import exec as run; run(src)`,
`__builtins__["eval"](src)` silent; `getattr(builtins, "exec")(src, {})`
reported E0713 (the by-method `exec` row — sqlmodel `Session.exec` — ran
because the builtin row matched bare names only).

Fix (`a45ad9d`): `_sink_match` treats a spelling `builtins.<X>` (from an
import, a from-import, `getattr(builtins|__builtins__, "X")`,
`__builtins__["X"]`) as the builtin `X`, decided before the by-method rows;
`session.exec(stmt)` stays E0713.

### BUG-068  spellings of already-modeled sinks were silent (sink-table gaps)  [OPEN]
test: tests/test_sink_rows.py (every row pinned);
tests/test_py_frontend_sinks.py (`::test_wave4_sink_rows_fire_and_safe_forms_clear`)

Found 2026-09-24 by the audit (B9, PM-9). Each row was run on `47139a1`
through the same generated snippet `test_sink_rows` uses — every one
silent, except `duckdb.execute` (already E0713 via the `execute` method
row at 0.6; the qualified row raises it to 0.95):

- E0718 `redirect`: `werkzeug.utils.redirect`, `quart.redirect`,
  `django.http.HttpResponsePermanentRedirect`, `aiohttp.web.HTTPSeeOther`,
  `.HTTPTemporaryRedirect`, `.HTTPPermanentRedirect`, `.HTTPMovedPermanently`.
- E0713 `sqlQuery`: `duckdb.sql`, `duckdb.execute`, `duckdb.query`;
  methods `execute_sql` (peewee/ODPS), `sql` (duckdb connection, pyspark,
  snowflake, rockset, manticore — all 16 corpus `.sql(` calls are SQL
  executors), `extra` (Django `QuerySet.extra`: only the strings of
  `select=`/`where=`/`tables=`/`order_by=` (or those positional slots) are
  judged; `extra(where=["a = %s"], params=[x])` stays clean).
- E0720 `deserialize`: `_pickle.loads`, `_pickle.load`; guards
  `ruamel.yaml.YAML.load`/`.load_all` on the constructor's `typ` —
  `"unsafe"` or unresolvable is a sink, absent/`"safe"`/`"rt"` clean.
- E0719 `renderTemplate`: `jinja2.nativetypes.NativeTemplate`,
  `tornado.template.Template`; guards on `template_format="jinja2"` for
  `PromptTemplate.from_template` / `ChatPromptTemplate.from_template`
  under `langchain_core.prompts` and `langchain.prompts`.
- E0731 `evalCode`: `runpy.run_path`, `runpy.run_module`,
  `code.InteractiveInterpreter.runsource`, `code.InteractiveConsole.runsource`,
  `code.InteractiveConsole.push`. **E0731, not E0711:** the existing E0731
  doctrine is "the caller picks the code that runs" (CWE-94). `run_path`
  executes the file at the path and `run_module` the module named — nothing
  is read back, the argument selects the code, which is E0731's class;
  E0711 (path traversal) describes reading/writing a path and is also
  strict-only, which would hide an RCE by default. The `code.*` rows are
  spelled through the constructor (`code.InteractiveConsole().push(s)` or
  `i = code.InteractiveConsole(); i.push(s)`): a `push`/`runsource` METHOD
  row on an unresolved receiver would match every queue's `.push(x)`.

Two supporting changes: `Guard(on_receiver=True)` reads the deciding
keyword off the receiver's constructor (directly or through a
single-binding name); and a guard's deciding keyword never takes the
judged slot of a keyword-only call — `from_template(template_format="jinja2",
template=t)` would otherwise have judged the literal `"jinja2"` and CLEARED
it. Side effect (precision): `subprocess.run(shell=True, args="ls -l")` is
clean (was E0714 on the literal-`True` slot); `args=cmd` still fires.

Measurement: `min_py_table_rows` 93 → 121 (28 rows: 19 qualified, 3
method, 6 guard). Framework corpus: +18 E0713 (`.sql`/`execute_sql`
executors and LanceDB), +2 E0731 (runpy).

### BUG-069  E0723 inside an f-string reported line 0, column 0; a credential in a bytes literal was never scanned  [OPEN]
test: tests/test_py_frontend_sinks.py
(`::test_credential_in_fstring_and_bytes_is_positioned`)

Found 2026-09-24 by the audit (B10, B9), confirmed on `47139a1`:
`{"Authorization": f"Bearer sk-proj-…"}` → E0723 at `(0, 0)`;
`AWS_KEY = b"AKIA…"` → nothing (a bytes constant translated to an opaque
leaf, and a module whose only assignment is bytes was not a scope).

Fix (`a45ad9d`): f-string literal parts and constant-only f-strings carry
`pos` (on Python < 3.12 the f-string's own start, 3.12+ the part's); a
bytes constant stays an opaque `PyExpr` to every argument rule (so
`cur.execute(b"SELECT " + n)` is judged exactly as before) but carries its
latin-1-decoded text as a positioned `StringLit` under `parts`, where only
the literal scan walks; `_scope_has_content` counts a bytes assignment.

Measurement: no E0723 moved or appeared on the framework corpus or the
in-repo trees except the new test's own AWS documented-example fixture.

## LOOP_LOG block

## Iteration 59 — Wave 4 of the 2026-09-24 audit: the Python scanner stops missing (no new detector)

- **Target:** not a backlog row. Plan Wave 4 (B4, B5, B8, B9, B10; B1–B3
  and B7 already fixed as BUG-032..035; B6 is Wave 5): silent false
  accepts inside the modeled surface.
- **Probe-confirmed first (on `47139a1`):** 43 of the audit's `pymiss`
  repros in this scope were wrong — 41 silent, `getattr(builtins,
  "exec")` reported as E0713, E0723 at `(0, 0)` in an f-string: raw
  `text()`/`literal_column`/`db.text` outside an executor, str-shaped
  `.where`/`.filter`, aliases and dynamic callees, `builtins.*`, table
  spellings, bytes credentials. Of the 28 new table rows, 27 were silent
  through their generated snippet (`duckdb.execute` fired at 0.6).
- **Fixes (each once, where every caller routes through):** a raw SQL
  string entry is the sink itself (`_raw_sql_entry`), deduplicated
  against the executor that judges the same value; one alias resolver
  (`_ModuleFacts` + `_FnScope.value_of`, `_alias_target`, `_attr_spelling`,
  `_unwrap_indirect`) used by `_callee_spelling` and `_call_expr`;
  `builtins.X` before the by-method rows; 28 pinned rows; receiver-side
  guards; positioned f-string parts; bytes scanned for E0723 only.
- **Measured:** framework corpus (4,946 files) 676 → 707, +31 / −0, 0
  confidence changes on kept findings, 0 errors, 0 unparseable; in-repo
  trees 110 → 111 (the new test's own fixture). Every addition read at
  source: 26 true by rule, 5 over-flags of the any-receiver `.text` row.
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** a receiver's TYPE decides three of
  this wave's rows and only a constructor call in the same scope can name
  it (`code.InteractiveConsole().push`, `YAML(typ=)`, `db.text`); an
  attribute receiver (`self.console.push(src)`, `self.db.text(q)`) is
  still unresolved. A per-class attribute-binding summary
  (`self.x = Ctor(...)` in `__init__`) is the next lever — measure its
  reach on the corpus before building it (q3).
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally).

## q1 rows

| NEW residual: a raw SQL string's finding is deduplicated only against an executor in the same function | iter-59 (Wave 4, audit B4/B5): `text(f"...")` inline in an executor's argument, or bound to a name that executor judges, reports once, at the executor. Built in a helper (`def build(n): return text(f"...")` then `execute(build(n))`) or stored on `self` and executed in the same method, it reports twice — at the entry and at the executor, which judges the computed call/attribute as a dynamic query. Over-flag (a duplicate), never a miss `[source: diagnostics, section: E0713, key: sqlQuery]` | high |
| NEW residual: the any-receiver `.text(x)` row is matched by NAME and signature | iter-59: Flask-SQLAlchemy's `db.text` is an instance attribute no import resolves, so any one-argument `.text(x)` with a non-literal `x` is an E0713 raw-SQL entry at the method floor (0.6). Measured on the 4,946-file framework corpus: 5 additions, all non-SQL (`st.text`, outlines `generate.text` ×2, LanceDB FTS `.text(query)`) — q5's direction, priced. A `.text(a, b)` or `.text(q, k=v)` (a canvas, a search client) is not SQLAlchemy's signature and is not an entry outside a builder chain, so SQLAlchemy 1.x `db.text(sql, bindparams=...)` outside an executor or chain is silent `[source: README, section: Python, key: check-py]` | high |
| NEW residual: aliases resolve through SINGLE bindings only | iter-59 (audit B8): `_alias_target`, `_attr_spelling` and `_unwrap_indirect` follow a name bound exactly once (function-local, else module-level bound once in the whole module) for at most 5 hops. A name bound twice (`run = os.system if a else print`), a partial/dispatch table passed as an argument or returned from a helper, a class attribute (`self.handlers[k](cmd)`), and `importlib.import_module(name)` with a computed name stay unresolved — silent, not over-flagged. Dispatch through a table with a non-literal key over-flags to ANY sink entry `[source: README, section: Python, key: check-py]` | medium |
| NEW residual: constructor-typed receivers are named only from a constructor call in scope | iter-59: `code.InteractiveConsole().push(s)` and `YAML(typ="unsafe").load(s)` are resolved from the constructor call, directly or through a single-binding name; `self.console.push(s)` / a console passed in as a parameter is not (no `push`/`runsource` method row: every queue has `.push`). The ruamel guard reads `typ=` off that constructor; an unresolvable `typ` is a sink `[source: diagnostics, section: E0731, key: evalCode]` | medium |
| NEW residual: a bytes credential is scanned, a split one is not | iter-59 (B9/B10): E0723 now sees `b"AKIA..."` and positions f-string parts (the f-string's start on Python < 3.12, the part's on 3.12+). Still unseen: a key split across a concatenation of literals (`"sk_live_4eC3" + "9Hq..."` — no constant folding) and the Stripe restricted-key prefix `rk_live_` (a pattern-table row in `passes/effects.py`, not added here — see Skipped) `[source: diagnostics, section: E0723, key: credential_kind]` | medium |

## Skipped / not reproduced / deferred

- **`rk_live_` (B9) — needs `passes/effects.py`, owned by Wave 2.**
  Probe-confirmed silent on `47139a1` (`STRIPE = "rk_live_<24-char suffix elided for push protection>"`).
  Exact change for the coordinator, in `_CREDENTIAL_PATTERNS` right after
  the `sk_live_` row:
  `(re.compile(r"rk_live_[0-9A-Za-z]{20,}"), "Stripe live restricted key"),`
  plus a `tests/test_py_frontend_sinks.py` case built from split string
  literals so the fixture is not credential-shaped in source
  (`src = "K = '" + "rk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "'\n"`,
  assert `[(1, "E0723")]`). GitHub push protection rejects a literal
  Stripe-shaped fixture (memory: push-protection fixtures).
- **Coordinator decision — the any-receiver `.text` row.** The brief said
  "any receiver's `.text` attribute is enough — over-flag rather than
  miss". The first measurement of exactly that cost 8 additions on the
  corpus, 8 of 8 non-SQL (`draw.text` excluded already by the tuple-arg
  rule; `canvas.text(x, y, c)` ×1, `ddgs.text(q, max_results=n)` ×2
  remained). I narrowed it by SQLAlchemy's own signature (exactly one
  argument) — a shape rule, not a name that clears anything, and inside
  a builder chain any non-literal `.text(...)` still sanctions nothing.
  The remaining 5 are all non-SQL. Options: keep (0.6, hidden by
  `--min-confidence 0.9`), or require SQL context (argument of a
  `filter/where/having/from_statement/execute/scalars` call, or a
  str-shaped argument) — which would drop all 5 and miss `cond =
  db.text(q)` bound first.
- **Not reproduced as a miss / out of this wave:** `p_q04`/`p_q05`
  (`select(t).where(cond)` / `.order_by(col)` with a PARAMETER — a column
  expression in ordinary code; not str-shaped, left sanctioned), `p_q07`
  (BigQuery `.query`), `p_s14` (LangChain `db.run`), `p_s16` (bare
  `fetch`, a closed design point), `p_c08..c10/c12/c13` (`os.spawnlp`,
  `os.execl`, `pty.spawn`, argv list bound to a name,
  `create_subprocess_exec("sh", "-c", ...)`), `p_k08` (split credential),
  `p_k23` (class keyword), `p_r08` (`Location` header) — not in this
  wave's item list; each would be its own row/class decision.
- **Pre-existing, not changed:** `db.session.execute(db.text("SELECT 1"))`
  is E0713 at `47139a1` and still is — a literal `db.text` is not named
  `sqlBind`, because clearing through an unresolved receiver's method name
  is exactly what q5 forbids.
- **`bench/framework_scan/REPORT.md`** is outside this wave's ownership.
  Text for its §9, for the coordinator, is under Measurements.
- **No `bench/py_frontend/corpus/` repro file added:** every PM repro in
  scope is a test case in `tests/test_py_frontend_sinks.py` (the plan's
  "Done when"), which the gate runs; a corpus file would be a second,
  unasserted copy.

## Measurements

- **Framework corpus** (`bench/framework_scan/_work/src`, 4,946 files,
  `check-py --json`, same interpreter): `47139a1` 676 → `a45ad9d` **707**
  (+31, −0); 0 errors / 0 unparseable both sides; 0 confidence changes on
  the 676 kept findings. By code: E0713 600 → 629, E0731 8 → 10, all other
  codes unchanged (E0714 14, E0718 5, E0719 26, E0720 17, E0727 6).
- **In-repo trees** (`bench tests tools playground demos`, 211 files):
  110 → 111; the one addition is `tests/test_py_frontend_sinks.py`'s
  AWS documented-example key (`AKIAIOSFODNN7EXAMPLE`) in the new BUG-069
  test — the fixture doing its job. No removal, no moved position.
- **Every addition read at source** (all 31: 29 E0713 + 2 E0731):
  - E0731 ×2, true by rule: `agno/tools/python.py:71,100`
    `runpy.run_path(str(file_path), ...)` — runs the file the agent just
    wrote; the interpreter is the product (same bucket as REPORT §8's
    `exec` sites).
  - E0713 ×4, true by rule, 0.95: `agno/db/postgres/postgres.py:505`,
    `async_postgres.py:366`, `agno/db/sqlite/sqlite.py:523`,
    `async_sqlite.py:377` — `Index(..., postgresql_where=text(idx_config["where"]))`,
    raw SQL from a config dict, never inside an executor, previously
    silent.
  - E0713 ×1, true by rule, 0.95: `langchain_community/document_loaders/sql_database.py:83`
    `self.db._execute(sa.text(self.query), ...)` — caller SQL by design
    (REPORT §4's "agent SQL toolkit" bucket); `_execute` is no executor row.
  - E0713 ×15, true by rule, 0.6 (`.sql` / `.execute_sql` executors):
    `agno/tools/csv_toolkit.py:168`, `agno/tools/duckdb.py:68,140`
    (LLM-provided SQL by design), `chat_message_histories/rocksetdb.py:65`,
    `chat_models/snowflake.py:287,290,374,377` (f-string warehouse
    identifier + caller SQL), `utilities/max_compute.py:69`,
    `utilities/spark_sql.py:105,131,153` (`SHOW CREATE TABLE {table}`,
    `SELECT * FROM {table}`, caller command), `vectorstores/manticore_search.py:182,303,370`
    (`self.schema`, `DESCRIBE {table}`, `DROP TABLE IF EXISTS {table}`).
  - E0713 ×4, true by rule, 0.6 (str-shaped `.where` on LanceDB, whose
    filter is SQL parsed by DataFusion): `agno/vectordb/lancedb/lance_db.py:928`
    `where(f"{self._id} = '{id}'")`, `crewai/memory/storage/lancedb_storage.py:366,390,488`
    (`f"id = '{safe_id}'"` after a hand-rolled quote-doubling,
    `f"scope LIKE '{like_val}'"` ×2).
  - E0713 ×5, **over-flag** (any-receiver `.text` row, 0.6):
    `aider/gui.py:320,400` (streamlit `st.text(...)`),
    `chat_models/outlines.py:329` and `llms/outlines.py:269`
    (`generate.text(self.client)`), `agno/vectordb/lancedb/lance_db.py:758`
    (LanceDB hybrid-search `.text(query)`, a full-text query).
  - Net: 26 of 31 true by rule; 5 over-flags, all from the one row the
    brief chose to over-flag, all at the method floor.
- **`.text` row, first cut (not shipped):** without the one-argument
  signature rule it added 8, all non-SQL (+`canvas.text` ×1,
  `ddgs.text(q, max_results=n)` ×2).
- **pymiss repros (`scratchpad\pymiss\p_*.py`, 222 readable):** 45
  changed verdict, every one in this wave's scope and in the intended
  direction: 41 silent → the expected code; `p_e06` E0713 → E0731;
  `p_k09` E0723 `(0,0)` → `(2,30)`; `p_q18`, `p_s05` gained the entry
  finding next to the executor's (below).
  Remaining in-scope duplicates by design: `p_s05` (helper-built `text`)
  and `p_q18` (`self.stmt`) report at the entry and at the executor (q1 row 1).
- **Rows:** `min_py_table_rows` 93 → 121; `test_sink_rows`: 88 sink rows,
  24 guard rows, 9 sanitizer rows exercised.
- **Red before:** the five new tests and `test_every_row_is_pinned`
  all FAIL against `47139a1`'s `py_frontend.py`.
- **Gate:** `python -B scripts/run_all.py` exit 0 (`smt` SKIP, z3 absent).

Suggested `bench/framework_scan/REPORT.md` §9 (coordinator):

> ## 9. Re-measured 2026-09-25, after iteration 59 (Wave 4): 676 → 707
> Same 4,946 files, same interpreter. +31, −0; no kept finding changed
> confidence. E0713 600 → 629: 5 raw `text()` entries outside any executor
> (agno partial-index `postgresql_where=text(cfg["where"])` ×4,
> langchain-community `sa.text(self.query)` into a private `_execute`), 15
> `.sql`/`.execute_sql` executors (duckdb/csv agent tools, spark, snowflake,
> rockset, manticore, ODPS), 4 f-string LanceDB `.where(...)` filters
> (agno, crewai), and 5 over-flags of the any-receiver `.text` row
> (streamlit, outlines, LanceDB full-text) at 0.6. E0731 8 → 10:
> `runpy.run_path` in agno's Python tool. 26 of 31 true by rule.

## Changed tests that pinned old behaviour

None. No existing assertion was edited; the two behaviour changes that
could have met one (`subprocess.run(shell=True, args="ls -l")` now clean;
a module-level `LOADER = yaml.SafeLoader` now clears) are precision in the
positively-identified direction and are asserted by the new tests.
