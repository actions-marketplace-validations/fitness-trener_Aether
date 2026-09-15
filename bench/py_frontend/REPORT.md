# Python sink detectors — measured results

**Date:** 2026-07-26; §0–§3 re-measured 2026-09-11 at 0.4.0 (the dated
history in §3b and §3c is left as written).
**Question:** with no rewrite, no `.aeth` port and no type annotations, how
many of Aether's security detectors fire correctly on ordinary Python — and
at what noise cost?

**Reproduce:** `python -B bench/py_frontend/run_bench.py`
(add `--json` for the machine-readable form). bandit is a bench-only
optional; without it, measurement 3 prints SKIP and the rest still runs.

This report leads with the weakest number, per the house rule
(`PYTHON_RESULTS.md`: "A bad result reported honestly is the goal").

---

## 0. What this measures, and what it does not

**In scope — the sink family**, which needs no annotations: E0711 path
traversal, E0713 SQL injection, E0714 command injection, E0718 open
redirect, E0719 SSTI, E0720 insecure deserialization, E0723 hardcoded
credential, E0727 XXE, and since 0.4.0 E0731 code injection
(`exec`/`eval`/`compile` of dynamic source).

**Out of scope, by construction, not by omission:**

| Family | Why it cannot run on Python |
|---|---|
| E0801 effect composition | compares a call site against a **declared** `effects` clause; Python has none |
| E0712/E0715/E0724/E0725/E0726/E0728 taint markers | need `Secret<T>`/`PII<T>`/`Untrusted<T>` on a signature; Python has no annotation-free equivalent |
| E0729/E0730 marker laundering | same markers, at a parameter or return type |
| E0716/E0717 authorization | need `Authorized<T>`, same reason |
| E0710/E0721/E0722 SSRF, cleartext | read the **declared** `net.fetch` annotation. The frontend synthesizes `[capability, method name]` effects, so a mapped network call named `fetch` (`httpx.fetch(url)`) does reach them; `requests.get`/`post` and `urlopen` do not (measured 2026-09-15) |
| E0202–E0207 semantic | check Aether language constructs; on translated Python they describe the translation, not the program (E0205 read `cur = conn.cursor()` as a dead store) |

The `requests_repro`, `capitalone_repro` and `pyjwt_repro` files therefore
produce nothing here. That is the correct result for this scope, not a miss.

**The starting point.** Before this work, `tools/py_frontend.py` emitted
`body=[]` — the function body was discarded, so all 21 security detectors
had no input. Measured on commit `f98fdce`, a file with five textbook
vulnerabilities produced **3 diagnostics, all E0701 capability facts, and
zero security findings.**

---

## 1. Detection vs ground truth

Ground truth: `bench/py_frontend/LABELS.json`, **122 labelled functions
across 14 files** at 0.4.0 (72 labelled with a sink code, 50 labelled
clean), each label taken from the file's own header comment naming the CWE
and the documented fix. The `bench/realworld_*` repros were written earlier,
for the Aether ports, so their labels were not chosen to flatter this
frontend. The set grew as later fixes (BUG-004, BUG-010 to BUG-012) and
E0731 added their repro files with labels.

| | 0.4.0 (2026-09-11) | first run (2026-07-26) |
|---|---|---|
| **false negatives** | **0** | **0** |
| **false positives** | **0** | **0** |
| true positives | 72 | 10 |
| labelled-clean functions correctly silent | 50 | 9 |
| labelled functions / files | 122 / 14 | 19 / 8 |

Every vulnerable function produced its expected code; every `*_safe`
function produced nothing. The safe half matters as much as the vulnerable
half: a checker that flags the fix trains people to ignore it.

**Independence caveat.** Author-established ground truth — the same repo
wrote the repros and the detectors. Same caveat as
`tools/py_corpus2/LABELS.json`. The differential in §3 is the partial
antidote: bandit was not written by this repo.

---

## 2. False positives on benign code — and the decision it forced

Corpus: all 76 parseable modules in `tools/py_corpus/` (26) and
`tools/py_corpus2/` (50). These were written for the **capability**
experiment — realistic FastAPI/Flask/SQLAlchemy/pandas code, not curated to
pass and not written as vulnerabilities.

| Code | Findings | Modules |
|---|---|---|
| E0711 | 11 | 10 |
| E0713 | 1 | 1 |
| E0720 | 1 | 1 |
| E0731 *(from 0.4.0)* | 1 | 1 |

Read individually rather than counted:

- **E0720 in `trap_05_pickle.py` is a TRUE positive.** `pickle.load(fh)` is
  CWE-502; the corpus author planted it as a soundness trap.
- **E0713 in `orm_03_migrations.py`** executes SQL read from a file. Intended
  in a migration runner, genuinely suspicious in general. Provenance-unknown.
- **E0731 in `17_template_render.py`** (from 0.4.0) is
  `eval(expr, {"__builtins__": {}}, context)`, the "sandboxed" eval.
  True by shape: emptying `__builtins__` does not stop attribute walking
  from reaching them again.
- **E0711 in `fa_04_upload.py` is a TRUE positive**, and a good one:
  ```python
  dest = "/data/uploads/" + file.filename   # attacker-controlled
  with open(dest, "wb") as out:             # CWE-22 upload write-traversal
  ```
- **The other 8 E0711** are all `open(path_param)`, where the path is the
  function's own parameter and nothing in the module constrains it. Not
  proven safe, not proven unsafe. Aether's rule — a path must be a literal
  or `safeJoin`ed — flags them because Python has no `safeJoin` convention.

**Decision, driven by that ratio.** `aether check-py` holds **E0711** out of
its default output; `--strict` turns it on. It is not deleted and not
silently downgraded: the rule is correct, its precision on Python is not yet
good enough to lead with. The capability stage (E0701) is opt-in for a
different reason — on Python the module policy is empty by construction, so
every I/O call yields one. That is an inventory, and `tools/py_surface.py`
already reports it properly.

Everything else ships default-on. Measured with the default `aether
check-py` at 0.4.0, **3 of 76 benign modules produce a default-set
finding**: `trap_05_pickle.py` (a real bug, planted), `17_template_render.py`
(the restricted-builtins `eval`, true by shape) and `orm_03_migrations.py`
(SQL read from a file, provenance unknown). With `--strict` it is 11, and
the 8 extra modules are all E0711. The first version of this report said
9 of 76 here, which its own table did not support (two non-E0711
findings); the 3 is measured with the CLI's default set.

---

## 3. Differential vs bandit

**At 0.4.0** `run_bench.py` runs this comparison over all 14 labelled
files, and Aether models 9 rows on Python (E0731 code injection joined in
0.4.0; bandit reports B102/B307 on `code_injection_repro.py`, and
`run_bench.py --json` has the per-line comparison). bandit 1.9.4 registers
75 test ids: 42 plugins plus 33 blacklisted calls and imports, counted
from `bandit.core.extension_loader.MANAGER` (`plugins`, `blacklist_by_id`;
counted again 2026-09-15). The "~70 plugins" below is the 2026-07-26
wording. The 9 rows are E0711 plus the 8 default-on codes. The table and the
narrow claim below are the 2026-07-26 run over the first 8 files, kept as
written.

Same 8 labelled files. `python -m bandit -f json -q <file>`, bandit 1.9.4
on CPython 3.11.15.

| File | Aether | bandit |
|---|---|---|
| `sqli_repro.py` | E0713 | B608 |
| `pyyaml_repro.py` | E0720 | B506 |
| `subprocess_repro.py` | E0714 | B602, B603, B607, B404 |
| `hardcoded_secret_repro.py` | E0723 | — |
| `open_redirect_repro.py` | E0718 | — |
| `path_traversal_repro.py` | E0711 | — |
| `flask_repro.py` (SSTI) | E0719 | — |
| `lxml_repro.py` (XXE) | E0727 | — |

**Where the two agree:** SQL injection, unsafe YAML load, `shell=True`
command injection. On its core overlap bandit is a perfectly good tool and
finds the same bugs.

**Aether-only here:** the hardcoded AWS key, open redirect, SSTI, XXE, and
path traversal. bandit's default plugin set does not cover lxml XXE or
Flask SSTI, and its hardcoded-secret checks (B105/B106) match password-ish
variable names rather than provider key shapes.

**bandit-only here — stated, not omitted:** B404 on `import subprocess`
(line 13), an advisory that fires on the import itself; and B603/B607 on
**line 24**. Line 24 is `make_thumbnail_safe` — the documented fix, the
argv-list form with no shell. Aether reports nothing there.

That difference is the whole argument, and it is checkable:
`python -m bandit -f json -q bench/realworld_subprocess_cmdi/subprocess_repro.py`.
A pattern matcher sees `subprocess.call(...)` and warns; the sink mapping
gates on `shell=True`, which is what actually decides whether a shell is
involved.

**What this comparison does NOT show.** bandit ships ~70 plugins across
crypto, Django, Flask config, SSL/TLS, tempfile, assert-in-production and
more; Aether models 8 rows on Python. On breadth bandit wins outright, and
this corpus was built from Aether's rows, so it is scoped to where Aether
has something to say. The honest claim is narrow: **on the eight classes
Aether models, its dataflow-and-argument-shape reading distinguished the
bug from the documented fix on every pair, and a pattern matcher did not.**
Nothing here supports a general "better than bandit".

---

## 3b. Re-measured after BUG-004 (2026-07-26, same day)

**The §1 and §2 numbers above were produced by a build containing three
false accepts.** Probing this report's own "guard bound elsewhere"
residual found them. They are not listed as false negatives above because
**the labelled corpus did not contain these shapes** — the measurement was
honest about what it measured and blind to what it did not.

Silent before the fix, all four:

| Shape | Expected |
|---|---|
| `yaml.load(raw, Loader=yaml.Loader)` | E0720 |
| `loader = yaml.Loader` … `yaml.load(raw, Loader=loader)` | E0720 |
| `sh = True` … `subprocess.run('x ' + cmd, shell=sh)` | E0714 |
| `cur.execute('SELECT ... ' + name, extra)` | E0713 |

The first needed no "elsewhere" at all — the unsafe value is at the call
site, and the gate read *any* `Loader=` as safe. Root cause of all three:
the unknown case defaulted to "not a sink". See BUGS.md BUG-004.

`bench/py_frontend/corpus/guard_bound_repro.py` now carries all four plus
their fixes, so the corpus can no longer be blind to this class.

**Re-measured after the fix:**

| | before (§1) | after |
|---|---|---|
| false negatives | 0 *(of 19 labelled)* | **0** *(of 28 labelled)* |
| false positives | 0 | **0** |
| true positives | 10 | **15** |
| benign-corpus findings | E0711 11 · E0713 1 · E0720 1 | **E0711 11 · E0713 1 · E0720 1** |

**The benign counts did not move.** Making every unresolvable guard a sink
cost **zero** measured precision on 76 real modules — the guarded shapes
in benign code use `yaml.safe_load` or a literal `shell=`, both of which
still resolve. Soundness here was free; that is a measurement, not a
prediction, and it could have gone the other way.

One further translation hole surfaced, and it was the **bench** that found
it, not a hand-written test: `subprocess.run(...).returncode` is an
attribute READ of a call result, so the call inside it vanished. The same
shape without `.returncode` was flagged, which is why every unit test
passed. Fixed by carrying the base expression; pinned by
`test_attribute_read_of_a_call_result_is_not_lost`.

## 3c. Re-measured after BUG-010 (2026-09-01)

`bench/framework_scan/` ran `check-py` over 15 AI-agent frameworks and
found that **1,029 of 1,055 findings were E0713 on SQLAlchemy expression
objects** — `conn.execute(select(t).where(t.c.id == cid))`, the safest
SQL in Python. Two correct rules composed into a wrong answer: `execute`
is a sink by method name (q5), and any non-literal argument read as
dynamic. Neither rule changed. The frontend now recognises a call rooted,
through the file's imports, at a `sqlalchemy`/`sqlmodel` builder and
names it as `sqlBind`, the way `shlex.quote` is already named `shellArg`.

The soundness line is the raw-string entry points — `text`,
`literal_column`, `column`, `table`. A non-literal first argument to any
of them, **anywhere inside the expression**, sanctions nothing, so
`select(t).where(text("name='" + n + "'"))` still fires. A bare name
spelled `select` from any other module clears nothing.

The first cut recognised only a direct builder call at the sink and
cleared 43 of 1,029. Reading the survivors at source gave three more
shapes, each with its own soundness argument:

- **A statement built incrementally** — `stmt = select(t)` then
  `stmt = stmt.where(...)`. Resolved by a least fixpoint that allows
  self-reference but **requires an anchor**: a name qualifies only if at
  least one binding is a builder expression with no reference to the
  name, and every binding stays rooted at a builder, a qualifying name,
  or itself. Two parameters rebound to methods on each other have no
  anchor and never qualify. One raw-string rebinding disqualifies the
  name for every use.
- **The Table-method form** — `table.delete().where(...)`. The receiver
  is a bare name, so no import vouches for it; it is accepted only when
  the root call takes **no positional argument**, because a builder that
  returns a raw string has to be handed one. A receiver whose *state* is
  a raw string is outside any argument-shape rule and is the residual.
- **`text(name)` with the name bound only to a literal** — resolved with
  the `_local_constants` discipline (every binding agrees). A parameter
  is bound nowhere and stays a sink.

`bench/py_frontend/corpus/sqlalchemy_repro.py` carries 11 safe and 10
vulnerable shapes, all labelled, so the corpus can no longer be blind to
this class.

**The second cut still cleared only 194, and the reason was a false
negative, not a precision gap (BUG-011).** Every framework imports
SQLAlchemy under the optional-dependency guard —
`try: from sqlalchemy.sql.expression import select, text` — and
`py_to_ir` registered imports only as direct children of the module body.
A guarded `select` was a rootless name, so nothing resolved to a builder.
The same blindness made a guarded `import yaml` leave `yaml.load(raw)`
**silent**: an unresolved qualified sink matches no table and is
translated as `py:load`, which every detector looks past. Confirmed by
execution before the fix. Imports are now collected from the whole
module; a local name bound by two imports to different targets is
ambiguous and resolves to nothing — it clears no query and sanctions no
builder. `bench/py_frontend/corpus/guarded_import_repro.py` pins both
directions. The bench's own slicer had the same bug (a column-0
`import`/`from` header) and was fixed alongside.

| | before | after |
|---|---|---|
| labelled functions | 28 | **57** |
| false negatives | 0 | **0** |
| false positives | 0 | **0** |
| true positives | 15 | **29** |
| benign-corpus findings | E0711 11 · E0713 1 · E0720 1 | **E0711 11 · E0713 1 · E0720 1** |

The benign counts did not move, for the same reason as §3b: the 76
benign modules use raw DB-API cursors or literal queries, not SQLAlchemy
Core, so there was nothing there for the recogniser to clear. The cost
was measured on the corpus that had the problem — see
`bench/framework_scan/REPORT.md` §2 for the after-numbers there.

## 4. Limits

- **Intraprocedural and syntactic.** Over-flag, never miss *within the
  modeled surface*. Not a soundness proof.
- **Sinks are matched by method name** on receivers of unresolved type —
  `cursor.execute(...)` is a SQL sink whatever `cursor` is. Over-flag, not
  inference. Why that is legitimate here when it was unsound for purity:
  `vault/wiki/questions/q5-sink-matching-vs-purity-matching.md`.
- **Guard-bound-elsewhere: keyword and local-binding forms are handled;
  object state and import-time config are not.** A guard clears a call only
  when its value is positively identified as sanctioned — unrecognized,
  computed, unresolvable, or absent all mean sink (BUG-004). A local name is
  resolved only when every binding in the function agrees. What remains
  unhandled: state **mutated after construction** (`s = requests.Session()`
  then `s.verify = False`), and configuration set at import time. Both need
  a different traversal and their own probe.
- **`from yaml import SafeLoader` then `Loader=SafeLoader` over-flags.** A
  from-imported name has no local binding for `_local_constants` to
  resolve, so it stays unresolved and therefore a sink. Correct direction,
  known imprecision.
- **Single file.** No cross-module resolution, matching `py_frontend` today.
- **No control flow.** Neither these passes nor the frontend model branches
  or loops.
- **A finding is a sound positive, not a complete inventory** — the same
  caveat `PYTHON_VIABILITY.md` states for capabilities. Unresolved regions
  remain UNPROVABLE and are reported as such.
- **SQL expression builders are recognised by module root only**
  (`sqlalchemy`, `sqlmodel`). Django's ORM does not route through
  `execute` and is unaffected; other query builders (`peewee`, `pypika`,
  `sqlglot`) still read as computed queries — over-flag, until each is
  measured and added. Inside a recognised expression, `text(name)` where
  `name` is bound to a literal elsewhere is NOT resolved — the raw-string
  check reads the argument as written, so it over-flags. Same direction as
  the SafeLoader-subclass limit above: correct by policy, imprecise in fact.
