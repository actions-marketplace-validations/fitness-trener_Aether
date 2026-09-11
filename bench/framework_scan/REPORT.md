# `aether check-py` on 15 AI-agent frameworks

**Date:** 2026-09-01, re-measured 2026-09-02 after BUG-010 and BUG-011,
and again 2026-09-03 after BUG-012 (§7) and after iterations 49–50 (§8 — the
tables in §1–§5 are the 2026-09-02 numbers; §8 supersedes the totals).
Re-scanned 2026-09-11 at 0.4.0: 676 findings, the same set §8 lists, 0
analyzer errors; confidence 0.95 ×44, 0.9 ×4, 0.6 ×628.
**Question:** `bench/pypi_scan/` scanned whatever happened to be in
site-packages. What does the tool do on the population it actually claims
to be for — the frameworks that generate and execute AI-written Python?

**Reproduce:** `python -B bench/framework_scan/run_scan.py`
(`--json` for every finding). Wheels only, via
`pip download --only-binary`, so no sdist build step runs; nothing is
imported or executed.

**Headline, stated first and unflatteringly.** The first run found no
vulnerability worth reporting to anyone, and found that 97% of its own
output came from one rule (E0713), most of it one false-positive class:
SQLAlchemy expressions read as dynamic SQL. Fixing that class exposed a
**false-negative class underneath it** — imports under `try:` had never
been registered, so a guarded `yaml.load(x)` was silent — and repairing
both moved the count from **1,055 findings to 411**, four of which are
sinks that were invisible before. The useful output of this run is two
bugs in Aether, not a bug in LangChain. At 0.4.0 the same files give 676
findings — the scanner seeing code it had been blind to (§7), plus a new
code-injection rule (§8) — and still no vulnerability.

---

## 1. Corpus and robustness

| | |
|---|---|
| distributions | 15 |
| `.py` files | **4,946** |
| files that failed to parse | **0** |
| analyzer crashes | **0** (in all three passes over the corpus) |

Zero crashes and zero parse failures on a corpus with a very different
shape from `site-packages` — heavy `async`, pydantic models, decorators,
generated protocol code. Combined with the 1.19M-line PyPI run, the
frontend has now read ~1.2M lines of third-party Python without an
unguarded exception.

| distribution | files | before | **after** |
|---|---:|---:|---:|
| agno | 1,024 | 868 | **245** |
| langchain-community | 1,204 | 139 | **118** |
| semantic-kernel | 555 | 17 | 17 |
| openhands-ai | 165 | 8 | 8 |
| crewai | 512 | 7 | 7 |
| aider-chat | 81 | 4 | 4 |
| smolagents | 20 | 4 | **5** |
| langchain | 36 | 3 | 3 |
| llama-index-core | 480 | 2 | 1 |
| mcp | 123 | 2 | 2 |
| haystack-ai | 283 | 1 | 1 |
| langchain-core, langgraph, autogen-agentchat, browser-use | 463 | 0 | 0 |
| **total** | **4,946** | **1,055** | **411** |

## 2. BUG-010 — the E0713 flood was Aether's

1,029 of the original 1,055 findings were `E0713`, and read at the source
line they were overwhelmingly **SQLAlchemy Core expression objects**:

```python
conn.execute(select(table.c.client_metadata).where(table.c.client_id == client_id))
conn.execute(delete(table).where(table.c.expires_at < now))
```

That is the *safest* form of SQL in Python: the expression is compiled
with bound parameters, and no string is assembled anywhere. Two correct
rules composed into refusing it — `execute` is a sink by method name (the
over-flag q5 sanctions) and any non-literal argument read as dynamic — so
**every ORM call site in the corpus was a finding.**

Neither rule changed. The frontend now names a call rooted at a
`sqlalchemy`/`sqlmodel` builder as E0713's wrapper, `sqlBind`, the way
`shlex.quote` is already named `shellArg`. Three shapes, each with its
own soundness argument (`bench/py_frontend/REPORT.md` §3c):

- a builder call at the sink, resolved **through the file's imports** —
  a bare name spelled `select` from anywhere else clears nothing;
- a statement **built incrementally** (`stmt = select(t)`, then
  `stmt = stmt.where(...)`), resolved by a least fixpoint that allows
  self-reference but requires an anchor;
- the **Table-method form** (`table.delete().where(...)`), accepted only
  when the root call takes no positional argument.

The line that does not move: `text(...)` or `literal_column(...)` handed
a non-literal, **anywhere inside the expression**, sanctions nothing.

It took three rounds to get from 1,029 to 381, and the second round is
the interesting one.

## 3. BUG-011 — the second round cleared almost nothing, because of a false negative

The first cut cleared 43 of 1,029. Reading the survivors showed that
bindings like `stmt = select(t)` — the anchor case — were still firing,
which meant `select` was not resolving to `sqlalchemy.select` at all.
agno imports it the way every framework does:

```python
try:
    from sqlalchemy.sql.expression import select, text
except ImportError:
    raise ImportError("`sqlalchemy` not installed. ...")
```

`py_to_ir` registered imports only as direct children of the module
body. Anything under `try:`, under `if`, or inside a function was never
seen. For a builder that is a precision problem. For a sink it is a
**false accept**: confirmed by execution before the fix, this produced no
finding at all —

```python
try:
    import yaml, pickle
except ImportError:
    raise
def load(raw):    return yaml.load(raw)      # silent
def unpickle(b):  return pickle.loads(b)     # silent
```

An unresolved qualified sink matches no table and is translated as
`py:load`, which every detector looks past. Same family as BUG-004: the
unknown case defaulted to "not a sink".

Imports are now collected from the whole module. A local name bound by
two imports to *different* targets is ambiguous and resolves to nothing:
it clears no query and sanctions no builder. Never pick a winner.

**What surfaced on this corpus once imports resolved — four sinks that
were silent on 2026-09-01:**

| | site | what it is |
|---|---|---|
| `E0727` | `langchain_community/document_loaders/docugami.py:153` | `etree.parse(io.BytesIO(content))` — lxml's default parser, `from lxml import etree` under `try:`. **Version-dependent:** lxml < 5 resolved external entities by default; lxml ≥ 5 does not, and libxml2 caps amplification (both verified here on 6.1.1). The package does not pin lxml. |
| `E0727` | `langchain_community/document_loaders/docugami.py:277` | same, on `response.content` |
| `E0727` | `smolagents/default_tools.py:443` | `ET.fromstring(response.text)` on a Bing RSS response — stdlib, so DoS-class rather than XXE |
| `E0720` | `agno/utils/pickle.py:26` | `pickle.load(...)` with a function-local `import pickle`; a persistence helper, true by shape |

The two docugami sites looked like the strongest finding of the exercise
when first read — lxml over bytes from the network — and verification cut
them down: on current lxml the payload does not parse at all, and only a
user pinned to lxml < 5 (2023) gets the old default. They are a
low-priority hardening note, drafted as such. The verification also
exposed a limit of E0727 itself: it flags `lxml.etree.parse` on an
unconfigured parser because it cannot know which lxml is installed —
**a version-dependent sink is a residual no static rule resolves.**

The same fix, measured on the PyPI corpus the same day (before → after,
same interpreter): E0720 **109 → 124**, and against the bandit oracle
B301→E0720 hits **102 → 118**, misses **26 → 10**. Independent
confirmation on a second corpus.

## 4. The 381 E0713 that remain, read at source

| n | shape | verdict |
|---:|---|---|
| 158 | `text(<non-literal>)` — a parameter, or an f-string of table/schema names in migrations | true by shape; DDL assembled from names is the classic "safe-looking" injection and stays flagged |
| 64 | name-bound, other | almost all disqualified by one binding that is a helper call (`stmt = apply_sorting(stmt, ...)`) — cross-function, the recorded residual |
| 31 + 23 + 22 + 28 + 4 | `str.format(...)`, f-string, or concatenation, directly or through a name | **true by shape** — 108 real dynamic queries, mostly in `agno/tools/*` (a SQL toolkit that takes queries from the agent, by design) and migrations |
| 20 | `stmt = self._helper(...)` | cross-function residual |
| 12 | the name is a parameter | unresolvable, correctly |
| 8 | psycopg `sql.SQL(...).format(sql.Identifier(...))` | a second safe-composition grammar; not modelled, residual |
| 11 | `Starred`, `Attribute`, `IfExp`, one-off helpers | unmodelled shapes, over-flag |

So of 381, roughly **108 are genuinely dynamic queries** (the toolkits
that run agent-supplied SQL on purpose), **~100 are cross-function or
parameter cases** no intraprocedural rule can resolve, and the rest are
unmodelled shapes. None is a reportable vulnerability; the toolkits are
the product.

## 5. The 30 findings that are not E0713

| Class | n | Verdict |
|---|---:|---|
| `E0714` shell in agent runtimes / coding tools | 13 | true by shape, by-design context |
| `E0720` pickle | 9 | 8 behind an explicit opt-in the maintainers wrote; 1 newly visible (agno, above) |
| `E0727` XML on remote content | 6 | **1 upstream note posted**, [agno#9920](https://github.com/agno-agi/agno/issues/9920): `agno/knowledge/reader/sitemap_reader.py:123` — attacker-choosable sitemap URL into stdlib `ElementTree`, which expanded a 10⁶ entity payload to 3,000,000 chars here in 0.19s where `defusedxml` refuses it. A second note, on the docugami lxml sites and relevant only to lxml < 5, was drafted and not posted |
| `E0719` the framework's own Jinja templates | 2 | by design |

**A correction to the 2026-09-01 version of this section**, which called
two of the E0714 sites "correctness bugs worth filing." Read again at
source: `aider/commands.py:964` builds `args = "git " + args` — a
*string*, the user's own `/git` command, run through a shell by design.
Not a list-plus-`shell=True` bug. `mcp/cli/cli.py:48` and `:276` do pass
a list with `shell=True`, but both sit inside `sys.platform == "win32"`
guards, where `subprocess` joins the list into a command line and it
works; the POSIX "runs only the first element" behaviour never applies.
Fragile style, not a defect. Neither is filed.

## 6. What this run established

- The frontend parses 4,946 more files of a different shape with zero
  crashes.
- **Two Aether bugs, one of each kind:** a precision ceiling (BUG-010,
  97% of output) that would have made `check-py` unusable for the first
  backend user, and a false-accept class (BUG-011) underneath it that no
  amount of reading the over-flags would have found — it took clearing
  them to see what was missing.
- **No security vulnerability in any of the 15 frameworks.** The expected
  outcome for widely-reviewed code. The nearest thing is agno's sitemap
  reader feeding an attacker-choosable URL to stdlib `ElementTree` — a
  DoS-class hardening note with a verified repro, not a CVE.

The honest one-line summary: **on the corpus Aether is aimed at, its
best-covered detector produced 97% noise, fixing the noise exposed a
class of silence, and the tool is now both quieter and less blind than
it was two days ago — measured, on the same 4,946 files.**

## 7. Re-measured 2026-09-03, after BUG-012: 411 → 628, and why more is better here

The frontend translated four statement kinds and dropped the rest, so a
sink behind an `await`, in a `for` iterable, in a tuple-target
assignment or inside `x or []` was never seen — not over-flagged,
silent (BUGS.md BUG-012). A census over these 4,946 files found **603
sink calls behind `await`** and 89 in other unmodeled positions. The
same fix made every binding form visible to the safe-name resolvers,
so `sql += uid` no longer leaves `sql` "literal-only".

Same files, same interpreter, `git archive` of the before-commit:

| distribution | 2026-09-02 | **2026-09-03** | what moved |
|---|---:|---:|---|
| agno | 245 | **424** | await-wrapped `text(f"…{table}…")` and `exec_driver_sql(f"…")` in migrations; 4 `stmt = None` sentinels cleared |
| langchain-community | 118 | **139** | 5 tuple-target `pickle.load` (`allow_dangerous_deserialization` sites) now visible; await-wrapped SQL; 2 keyword-only `client.command.exec(code=…)` (riza) — the by-name rule reaching a call that had no positional slot, over-flag by class (it is a remote code-execution call, not SQL) |
| semantic-kernel | 17 | **31** | `await cur.execute(sql.SQL(...).format(...))` — psycopg composition, the §4 residual, now visible |
| openhands-ai | 8 | **12** | `self.gateway_process = subprocess.Popen(...)` (attribute target) + await-wrapped |
| crewai | 7 | **5** | 4 module-level literal constants (`_CREATE_TABLE`, `_INSERT`, …) now resolve; 1 PEM-header docstring; 1 keyword-only `await handler.execute(client=…)` (a2a) — by-name over-flag, not SQL |
| llama-index-core | 1 | **2** | |
| others | 15 | 15 | unchanged |
| **total** | **411** | **628** | 0 analyzer errors, 0 unparseable |

By code: E0713 381 → 590 · E0720 9 → 14 · E0714 13 → 14 · E0723 0 → 2 ·
E0727 6 · E0719 2. 225 findings appeared, 8 disappeared.

**Read at source, the new ones are true by the existing rules.** A
sample of twelve of the +217 E0713: `conn.exec_driver_sql(f"DROP INDEX
IF EXISTS {quote_db_identifier(...)}")`, `await sess.execute(text(f"DROP
INDEX {…} ON {full_table}"))`, `sess.execute(text(f"SELECT COUNT(*)
FROM {self.session_table_name} …"))` — identifier interpolation into
DDL, the shape §4 already classed as "true by shape", now counted where
it was hidden. The five E0720 are `pickle.load` behind a tuple target in
langchain-community's TF-IDF, Annoy, FAISS and ScaNN loaders — real by
shape, behind the maintainers' explicit `allow_dangerous_deserialization`
opt-in, so a note rather than a report.

**The two E0723 are not credentials.** `agno/knowledge/remote_content/
github.py:53` spells `-----BEGIN RSA PRIVATE KEY-----` inside an error
message; `crewai/a2a/utils/agent_card_signing.py:85` inside a docstring.
The literal scan's PEM pattern matches the header alone; before this
change module- and class-level strings were never scanned, so the cost
was invisible. Precision item for the E0723 pass — require a key body
after the header — recorded for the next iteration, not fixed here.

**The eight that disappeared** are precision, each by positive
identification: crewai's module-level `_CREATE_TABLE` / `_INSERT` /
`_PRUNE` / `_SELECT` are str literals bound exactly once in the whole
module, so `conn.execute(_CREATE_TABLE)` is a literal query; agno's
`pinned_stmt = None` before `pinned_stmt = select(...)` no longer
disqualifies the name (executing `None` is a `TypeError`, not a query).

**§4, corrected.** The "~100 cross-function or parameter cases" line was
an estimate. All 381 pre-fix survivors were classified at source
(`e0713_census_2026-09-03.txt` in this directory): 166
`text(f"…{identifier}…")` DDL (true positives under the raw-entry
rule), 37 DB-API f-string/format/concat, 21 Cassandra CQL, 21 graph
query languages, 20 agent SQL toolkits running caller SQL by design, 17
non-SQL `execute` methods, and **34 helper-assembled statements** (14
same-module, 20 cross-module) — the only bucket a per-module helper
summary would touch. That is why the summary stays parked, and why the
identifier-interpolation majority is the natural target for a
per-finding confidence axis (iteration 46's residual) rather than for a
relaxation.

**Reading the direction correctly.** 411 → 628 on unchanged files is
the tool seeing more of the same code, not the code getting worse; the
ground-truth bench moved 29 → 41 true positives at 0 false negatives and
0 false positives, and the 76-module benign corpus did not move.


## 8. Re-measured 2026-09-03 (evening), after iterations 49–50: 628 → 676, with E0731 on the corpus

Same wheels (per-distribution file counts identical to §7's cache; the
cache was re-downloaded, and every count matched), same interpreter.

| code | §7 | **§8** | what moved |
|---|---:|---:|---|
| E0713 | 590 | **600** | `fetch_all` by name: langchain-community's HTTP loaders (`async_html`, `web_base`; over-flags the survey predicted) and cassandra's CQL wrappers (true by shape) |
| E0714 | 14 | 14 | |
| E0718 | 0 | **5** | `RedirectResponse(url)` in agno's MCP consent/media routes and mcp's OAuth `AuthorizationHandler` — dynamic targets; the repair (validate against registered URIs) is outside any argument-shape rule |
| E0719 | 2 | **26** | the `from_string` row: ~14 jinja2 prompt templates rendered from strings by design (haystack builders/routers, semantic-kernel, langchain-core `jinja2_formatter`, smolagents, openhands' invariant policy); ~8 non-jinja `.from_string` methods matched by name (momento ×3, llama-cpp ×2, bigquery, networkx, agno) — q5's cost, about a third of the row |
| E0720 | 14 | **17** | agno `code_mode`, databricks `_load_pickled_fn_from_hex_string` (cloudpickle, by design), tfidf via `joblib` |
| E0723 | 2 | **0** | the PEM header inside a docstring and an error message no longer match: a key BODY is required (iteration 49) |
| E0727 | 6 | 6 | |
| **E0731** | — | **8** | see below |
| **total** | **628** | **676** | 0 analyzer errors, 0 unparseable |

**E0731, read at source.** Four sites are the class the detector was
built for — the interpreter is the product: `agno/tools/python.py:159`
(`exec(code, ...)` running the model's code), `smolagents/tools.py:575`
(`Tool.from_code`, `exec(tool_code, module.__dict__)`),
`browser_use/mcp/cli_mcp.py:128` (`exec(code, ns)`),
`crewai/flow/runtime/_actions.py:309` (`exec(compile(module, filename,
"exec"), namespace)`). None is a reportable vulnerability — each is a
documented "run code" feature — but each is exactly what a reviewer of
an agent framework wants pointed at, with the line. The other four are
`compile()` without `exec`: `aider/linter.py:179`,
`openhands/linter/languages/python.py:11` and `:66` (syntax-checking
linters) and `langchain_community/tools/e2b_data_analysis/unparse.py:744`
(a round-trip test). `compile` yields a code object and runs nothing;
the rule treats it as the sink because `exec(compile(...))` is the
common form and the frontend already collapses that pair to one
finding. Precision item, recorded: judge `compile` only when its result
reaches `exec`/`eval`, or rate it below `exec` on the per-finding
confidence axis (q6).

**What this measures.** 48 net new findings on unchanged code is the
tool seeing more of the same code, in three ways: a class it did not
have (E0731), rows it did not have (`from_string`, `RedirectResponse`,
`fetch_all`, joblib/cloudpickle), and two false positives it no longer
has (PEM headers). The by-name rows carry their measured cost with them:
`from_string` at roughly one non-template hit in three, `fetch_all` at
four HTTP loaders — both the direction q5 sanctions, both now numbers
rather than predictions.
