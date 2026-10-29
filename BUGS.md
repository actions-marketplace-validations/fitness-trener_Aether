# Aether upstream bug list

Aether's bug log. Most entries were found in this repo, by the improvement
loop, the benchmark scans and the pre-release checks; some are appended by
agents using Aether in other projects on this PC
(prompt/upstream-bug-report.md). BUG-017 to BUG-019 were reserved for a
parallel work slice on 2026-09-03 and never assigned.

## Fix protocol
Run fix sessions from this repo with the most capable Claude model
currently available (today: Fable 5 / `claude-fable-5`; use whatever
supersedes it). Per session: pick [OPEN] entries, reproduce first, fix
root cause, add regression test, run `python -B scripts/run_all.py`,
then mark entry `[FIXED <commit>]` AND add a `test: tests/<file>.py`
line to the entry naming the regression test that keeps it fixed.

The ratchet (`tests/test_ratchet.py`, in the gate) enforces that every
real `[FIXED <commit>]` entry names an existing `test:` file — so a
repaired bug can never silently reappear, and Aether only moves forward.
Entry shape:

    ### BUG-NNN  <one-line title>          [FIXED <commit>]
    test: tests/test_regressions.py
    <repro + root-cause notes>

---

### BUG-001  match-arm bindings dropped taint (false accept)  [FIXED 8d928d9]
test: tests/test_effect_scope.py

Found 2026-07-09 (iter-41 gap probe, this repo). Repro: `case Some(v) do
print(v) end` over an `Option<Secret<String>>` checked CLEAN (exit 0) —
a genuine MISS inside the modeled surface, violating the
over-flag-never-miss contract of every confidentiality-marker pass
(E0712/E0715/E0724/E0725/E0726/E0728/E0729/E0730). Root cause: the
shared fixpoint `_marked_tainted_names` collected only Let/Assign
bindings; match-pattern `BindPat` names were fresh, untainted names.
Fix: destructure propagation — every arm-pattern binding over a leaking
scrutinee is tainted (all arms, conservative). Regression tests:
`test_match_destructured_secret_rejected` and 4 siblings in
tests/test_effect_scope.py.

### BUG-002  function aliases laundered the taint boundary (false accept)  [FIXED f6b8bf3]
test: tests/test_effect_scope.py

Found 2026-07-09 (iter-42 probes, this repo). Two repros, both exit 0:
`let f = logIt; f(password)` bypassed E0729's callee lookup (callee
name "f" is not a declared function), and `let f = getToken; f()`
defeated return-type seeding (source set keyed by declared names).
Root cause: every boundary mechanism resolved callees by literal name
only. Fix: per-function alias map (`_fn_aliases`, straight-line bare-
Ident bindings, chains followed, union on rebinding) applied FLAG-MORE
only — aliases join the source set, single-target aliases extend the
sanctioned-crossing mask, E0729 checks every alias target; an aliased
unwrapper (`let r = reveal`) is deliberately NOT honored (documented
over-flag). Regression tests: `test_fn_alias_launder_rejected` and 5
siblings in tests/test_effect_scope.py.

### BUG-003  mixed-arg effect list crashed the effect check (compiler crash)  [FIXED 27abede]
test: tests/test_effect_scope.py

Found 2026-07-26 (Python-frontend work, this repo). Repro — 16 lines of
legal Aether, `python -B -m transpiler.aether.cli check`:

    function helper() returns Unit
      effects fs.write
    do
      let _r: Result<Unit, String> = writeFile("/tmp/x", "y")
    end

    function go() returns Unit
      effects net.fetch, net.fetch("https://api.example.com/x")
    do
      helper()
    end

-> `TypeError: '<' not supported between instances of 'str' and
'NoneType'`, uncaught, from `_format_effect_list`. The compiler DIES
instead of emitting the E0801 it had already decided to emit.

Root cause: `EffectEntry = Tuple[Tuple[str, ...], Optional[str]]` and
the formatter called `sorted(effs)` on the entries themselves. Two
effects that share a path but differ in arg presence — `net.fetch` and
`net.fetch("https://...")`, a legal and meaningful pair — make tuple
comparison fall through to the arg slot and compare `None` with `str`.
Only reachable on the DIAGNOSTIC path (the caller list is formatted
solely when a violation is being reported), which is why the corpus
never hit it: every corpus program with mixed args is otherwise clean.

Surfaced by `tools/py_frontend.py`, which synthesizes exactly this shape
(`_add_effect` records the first constant string argument, or None), but
the bug is in the Aether pass and reproduces with no Python involved.

Fix: sort on an explicit ordering key, `(path, arg or "")`, so the arg
slot is always str-vs-str. Regression test:
`test_mixed_arg_effect_list_does_not_crash` in tests/test_effect_scope.py.

### BUG-004  three sink guards defaulted "unknown" to "safe" (false accepts)  [FIXED a22c424]
test: tests/test_py_frontend_sinks.py

Found 2026-07-26, probing the guard-bound-elsewhere residual recorded in
`vault/wiki/questions/q5`. Expected a precision gap; found three MISSES
inside the modeled surface — the contract-breach class, same as BUG-001
and BUG-002. All three are one mistake: the unknown case defaulted to
"not a sink".

Repros, all SILENT before the fix (stages effects/semantic/capability
skipped, as `aether check-py` runs them):

1.  yaml.load(raw, Loader=yaml.Loader)                    -> expected E0720
2.  loader = yaml.Loader; yaml.load(raw, Loader=loader)   -> expected E0720
3.  sh = True; subprocess.run('x ' + cmd, shell=sh)       -> expected E0714
4.  cur.execute('SELECT * FROM t WHERE n=' + name, extra) -> expected E0713

(1) is the worst and is not "bound elsewhere" at all: the unsafe value is
written at the call site. The old gate read `if _has_kw(call, "Loader"):
return None` — ANY Loader= meant safe. Adding `Loader=` is the commonest
wrong fix for PyYAML's deprecation warning, and `yaml.Loader` is the RCE.

Loader safety verified by EXECUTION on PyYAML 6.0.3, payload
`!!python/object/apply:os.system [...]`:
    yaml.Loader     -> CONSTRUCTED (unsafe)
    yaml.UnsafeLoader -> CONSTRUCTED (unsafe)
    yaml.FullLoader -> refused (ConstructorError)
    yaml.SafeLoader -> refused (ConstructorError)
FullLoader is deliberately NOT sanctioned regardless: CVE-2020-1747 and
CVE-2020-14343 are FullLoader bypasses.

(3) `_has_kw_true` required a literal `True` Constant, so a shell flag
held in a variable was read as "no shell".

(4) `_is_parameterized_query` cleared ANY two-argument execute. It was
never needed: `_SQL_RULE` has no literal_bans, so
`cur.execute("... id = ?", (uid,))` is already clean because argument 0
is a StringLit. The recognizer only ever added a false accept, and the
fix is its deletion.

Fix: one declarative `SINK_GUARDS` table whose contract is that a guard
clears a call ONLY when its value is positively identified as sanctioned.
Unrecognized, computed, unresolvable, or absent all mean SINK. This is
q5's rule ("never assume clean from a name") applied to values.
Regression tests: `test_yaml_unsafe_loader_is_still_a_sink` and 5 siblings
in tests/test_py_frontend_sinks.py.

### BUG-005  a UTF-8 BOM made a file invisible to the scanner (silent false negative)  [FIXED 70f0793]
test: tests/test_py_frontend_sinks.py


Found 2026-09-01, while testing the new `check-py` directory walk against
a tree written by PowerShell (which emits UTF-8 **with BOM** by default).
Repro — a file whose only difference from a flagged one is three leading
bytes:

    printf '\xef\xbb\xbfimport subprocess\ndef r(h):\n    subprocess.run("ping " + h, shell=True)\n' > bom.py
    aether check-py bom.py

Before: `SyntaxError`. Over a directory the walk counted it "unparseable"
and moved on, so a file containing a live command injection was reported
in a summary line as skipped — and in the tree summary that line is easy
to read as "nothing here".

Root cause: `_read` in `transpiler/aether/cli.py` opened every source with
`encoding="utf-8"`, under which a BOM survives decoding as U+FEFF at
offset 0. Python's own tokenizer strips it; `ast.parse` on the decoded
string does not, because by then it is an ordinary non-printable
character.

Severity is the point, not the parse error. A checker that cannot read a
file must not resolve that to *clean*. The single-file path failed loudly
(traceback), so the bug only became dangerous when the directory walk
turned "cannot read" into a counted, easily-skimmed line.

Fix: read with `utf-8-sig`, which strips a BOM if present and is identical
to `utf-8` when it is not. Applied in `_read`, the one function every
subcommand routes through, so `.aeth` sources get the same repair —
a BOM'd `.aeth` file previously died in the lexer for the same reason.
The walk additionally reports the unparseable count on its own line rather
than folding it into the file total. Regression test:
`test_utf8_bom_file_is_scanned_not_silently_skipped`, plus
`test_unparseable_file_does_not_abort_the_walk` in
tests/test_py_frontend_sinks.py.

### BUG-006  `pip install .` failed outright on current setuptools  [FIXED 70f0793]
test: tests/test_packaging.py


Found 2026-09-01, building a wheel to check BUG-007. Repro, setuptools
84.0.0, a clean venv:

    python -m pip install .
    ValueError: invalid pyproject.toml config: `project.license`.
    configuration error: `project.license` must be string

Root cause: `license = { text = "BUSL-1.1" }`, the PEP 621 table form,
which PEP 639 deprecated and setuptools >= 77 rejects. Removing it then
surfaced the second half: an SPDX `license` string may not coexist with a
`License ::` trove classifier, so the build failed again on
`License :: Other/Proprietary License`.

The gate did not catch this because `tests/test_packaging.py` reads
pyproject.toml with a hand-rolled mini-parser that has a branch
specifically for the inline-table license form, and asserts against the
parsed values. It never built a wheel, so it validated the config it could
read rather than the config setuptools accepts.

Fix: `license = "BUSL-1.1"` (string form, accepted by both old and new
setuptools) and drop the license classifier. Also corrected
`Operating System :: POSIX` to `OS Independent` — the CLI is developed and
run on Windows, and the POSIX-only caveat belongs to the bench harness's
SIGALRM timeout, not to the package.

Verified by building and installing the wheel into a fresh venv, not by
re-reading the config.

### BUG-007  `aether check-py` was broken in every installed copy  [FIXED 70f0793]
test: tests/test_packaging.py


Found 2026-09-01, immediately after BUG-006 let a wheel build for the
first time. Repro — install the wheel into a venv and run the headline
feature from any directory that is not the source checkout:

    aether check-py some_file.py
    ModuleNotFoundError: No module named 'tools'

Root cause: `cmd_check_py` imported the Python frontend as
`from tools.py_frontend import py_to_ir`, reaching it through a
`sys.path.insert` of the checkout root. `[tool.setuptools.packages.find]`
has `include = ["transpiler*"]`, so `tools/` is not in the wheel. From a
source checkout the import resolved and every test passed; from a wheel it
could never resolve. The gate runs from the checkout, so it saw the
working case only.

This is the whole Python story failing in exactly the configuration a user
installs, and it was invisible for as long as nobody built a wheel.

Fix: move the frontend to `transpiler/aether/py_frontend.py` — library
code the CLI depends on belongs in the library — and import it relatively
(`from .py_frontend import py_to_ir`), so no `sys.path` surgery is
involved and the installed package name (`transpiler.aether`) is
irrelevant. The nine `tools.py_frontend` import sites in bench scripts,
tools and tests were updated to `aether.py_frontend`; they already put
`transpiler/` on `sys.path`. Packaging `tools*` was the alternative and
was rejected: `tools` is far too generic a name to occupy in a user's
site-packages, and most of that directory is not library code.

Verified end to end: `pip install .` into a clean venv, then
`aether check-py` run from an unrelated working directory, reporting the
two expected E0713 findings.

### BUG-008  `sdk.run` / `sdk.grade` fail on every installed copy, and report it as your program failing  [FIXED 70f0793]
test: tests/test_sdk.py


Found 2026-09-01 by the regression test written for BUG-007
(`test_the_package_never_imports_an_unpackaged_top_level_module`) — the
same class, a second site, found on the first run.

`transpiler/aether/sdk.py:208` does `from bench.harness import
compile_and_run`, and `bench/` is excluded from the wheel by
`[tool.setuptools.packages.find]`. The import sits inside a bare
`except Exception` whose handler returns

    RunResult(ok=False, stderr="sdk.run error: ModuleNotFoundError: ...")

so in an installed copy **every** `sdk.run()` and `sdk.grade()` returns a
failed run. That is worse than the BUG-007 crash: a caller grading
candidates sees every candidate fail, and a failed run is exactly what a
bad candidate looks like. The docstring says the helper is used "where
available", which describes a fallback that does not exist.

Not blocking the scanner: `check-py`, `tools/scan.py` and the CLI do not
route through `sdk.run`. Listed in that test's `KNOWN_OPEN` set — listed,
not waived, and the test fails if the entry goes stale.

Fixed 2026-09-01 (the same move BUG-007 got, and the third instance of
this one architectural mistake — library code living outside the library):
`compile_and_run`, its timeout machinery and `format_diag_as_stderr` moved
to `transpiler/aether/runner.py`. `bench/harness.py` re-exports them under
their original names, so all six `from bench.harness import
compile_and_run` call sites are unchanged. `sdk.run` imports it at module
level, so an ImportError can no longer be swallowed by the function's own
`except Exception`.

The SIGALRM caveat was the part that needed care — it is POSIX-only and a
no-op on Windows, and moving it into the package would have made the SDK
promise a timeout it cannot keep. So the fact is now reported instead of
documented in a file nobody reads: `runner.TIMEOUT_ENFORCED`,
re-exported as `sdk.TIMEOUT_ENFORCED`, and `timeout_enforced` on every
result dict and every `RunResult`. "No timeout fired" and "this platform
has no timer" are now distinguishable by the caller.

Regression tests: `test_run_works_without_bench_importable` (runs `sdk.run`
in a subprocess with the repo root off `sys.path`, asserting `bench` is
genuinely unimportable first, so the test cannot pass vacuously) and
`test_run_reports_whether_the_timeout_was_actually_armed`, both in
tests/test_sdk.py. `test_the_package_never_imports_an_unpackaged_top_level_module`
in tests/test_packaging.py now passes with no exemptions.

Verified from a wheel installed into a clean venv, `bench` not importable:
`sdk.run` returns ok=True with the program's stdout, `sdk.grade` ok=True.

### BUG-009  the documented SDK import `from aether import sdk` does not work when installed  [FIXED 70f0793]
test: tests/test_packaging.py


Found 2026-09-01, verifying the BUG-008 fix from an installed wheel. The
wheel's top-level package is **`transpiler`** (`packages.find` has
`include = ["transpiler*"]`), so an installed user must write

    from transpiler.aether import sdk        # works
    from aether import sdk                   # ModuleNotFoundError

The second spelling is what `README.md`, `transpiler/aether/sdk.py`'s own
docstring, and every file in the repo use — it works from a checkout only
because `bench/`, `tests/` and `tools/` each `sys.path.insert` the
`transpiler/` directory. The docs describe the checkout layout, not the
installed one. Same theme as BUG-006/007/008.

`transpiler` is also a poor name to occupy at top level in someone's
site-packages, for the same reason packaging `tools*` was rejected in
BUG-007.

Fixed 2026-09-01. `[tool.setuptools] package-dir = {"" = "transpiler"}`
remaps the root, and `[tool.setuptools.packages.find] where =
["transpiler"], include = ["aether*"]` scopes discovery to it, so the
wheel ships `aether` and nothing else. The `[project.scripts]` entry point
became `aether.cli:main`. `transpiler/__init__.py` stays in the checkout —
roughly twenty call sites run `python -B -m transpiler.aether.cli` without
installing — but is no longer part of the distribution. The dual-spelling
header `cmd_pack` emits already tried both, so it needed no change.

`where` also replaced a fourteen-entry `exclude` list of top-level
directories. That list was a promise to remember every new directory
somebody adds; scoping discovery to `transpiler/` makes tests/, demos/ and
bench/ unshippable by construction.

**A second bug surfaced during the fix, and it is the reason the first
attempt looked like it worked.** After the pyproject change the wheel
shipped BOTH `aether` and `transpiler` — two full copies of the same code
in site-packages. The cause was a stale `build/lib/transpiler/` left by an
earlier build: setuptools packs what it finds under `build/lib`, so a
directory deleted from the config lives on in every subsequent wheel until
`build/` is cleared. `build/` and `UNKNOWN.egg-info/` are gitignored and
were removed; a clean rebuild ships `aether` alone. Worth knowing before
the first PyPI upload, because `python -m build` has the same failure mode
and the result is silently a superset of what was intended.

Regression test: `test_the_wheel_ships_aether_as_the_top_level_package`
in tests/test_packaging.py — asserts `package-dir` from the file text (the
3.10 fallback parser cannot model an inline table with an empty-string
key), `where == ["transpiler"]`, `aether*` in `include`, and that nothing
starting with `transpiler` is in `include`.

Verified in a clean venv: `transpiler` NOT importable, `from aether import
sdk` works, `sdk.run` and `sdk.grade` return ok, and the `aether check-py`
console script reports E0723 on the hardcoded-credential repro.

### BUG-010  E0713 flags every SQLAlchemy ORM call, at 97% of all findings  [FIXED 9b51716]
test: tests/test_py_frontend_sinks.py


Found 2026-09-01 by `bench/framework_scan/run_scan.py` over 15 AI-agent
frameworks (4,946 files). Repro — the safest form of SQL in Python:

```python
from sqlalchemy import select, delete, text
conn.execute(select(t.c.a).where(t.c.id == cid))   # -> E0713
conn.execute(delete(t).where(t.c.expires < now))   # -> E0713
conn.execute(text("SELECT 1"))                     # -> E0713
```

**1,029 of 1,055 findings in that scan are this shape.** `agno` alone
produced 868 from 31 files; `langchain-community` 137.

Root cause is two individually correct rules composing into a wrong
answer. `execute` is a SQL sink matched by METHOD NAME — the over-flag
`vault/wiki/questions/q5` sanctions, because the error direction is safe.
`_SQL_RULE` then reads any non-literal argument as a dynamic query, and a
`select(...)` call is a non-literal. So every ORM call site is a finding.

The argument is not a string at all. A SQLAlchemy Core expression is
compiled by the library with bound parameters; there is no concatenation
for an attacker to reach. Flagging it is not conservative, it is wrong in
a way that makes the row unusable: any Python backend that uses an ORM
gets thousands of findings and turns the detector off.

Precision, not soundness — Aether over-flags, it does not miss. But the
E0711 precedent (`bench/py_frontend/REPORT.md` §2) is that a row this
noisy does not ship default-on regardless of being correct-by-rule.

Fix directions, cheapest first:

1. **Recognise the safe constructors.** Treat a call to
   `select`/`insert`/`update`/`delete`/`text`/`table` (SQLAlchemy's
   expression builders) as a sanctioned query argument, the way
   `sqlBind` is. Narrow, table-driven, matches the existing
   `SINK_GUARDS` shape, and would remove ~all 1,029 without touching the
   concatenation cases that matter.
2. **Do not treat a bare call result as dynamic** for the SQL rule.
   Weaker and broader than (1) — it would also clear
   `execute(build_query(user_input))`, which is a real risk.
3. Demote E0713 to `--strict` on Python. Last resort: it is the row with
   the strongest cross-tool agreement (94.2% with bandit's B608 in
   `bench/pypi_scan/RECALL.md`) and the one users most expect.

(1) is the one to probe first. Confirm empirically that the concatenation
repros in `bench/py_frontend/corpus/sqli_repro.py` still fire afterwards,
and that the benign counts on `tools/py_corpus{,2}` do not move.

Related, much smaller, same family: a `yaml.SafeLoader` **subclass** as a
`Loader=` value is still refused (`haystack_ai/haystack/marshal/yaml.py:40`),
because BUG-004's contract is that an unrecognized guard value means SINK.
Correct by policy, wrong in fact; already listed as a known imprecision in
`bench/py_frontend/REPORT.md` §4.

**Fixed 2026-09-02, direction (1), in three rounds.** The frontend names
a call rooted at a `sqlalchemy`/`sqlmodel` builder as `sqlBind`, the way
`shlex.quote` is named `shellArg`. Three shapes, each with a soundness
argument stated in code: a builder call resolved **through imports** (a
bare `select` from any other module clears nothing); a statement built
incrementally, resolved by a least fixpoint that allows self-reference but
**requires an anchor** (a parameter-only chain never qualifies); and the
Table-method form `table.delete().where(...)`, accepted only when the root
call takes **no positional argument**, since a builder that returns a raw
string has to be handed one. Raw-string entry points — `text`,
`literal_column`, `column`, `table` — handed a non-literal anywhere inside
the expression sanction nothing; a name resolves only when every binding
is a literal. Neither Aether rule changed.

Round two cleared almost nothing, and the reason was BUG-011: the guarded
imports every framework uses were invisible, so `select` never resolved.
That is a false-negative class and is filed separately.

Measured on the same 4,946 files: **1,055 -> 411 findings, E0713
1,029 -> 381.** Of the 381, ~108 are genuinely dynamic queries (SQL
toolkits that run agent-supplied SQL by design, and DDL migrations built
from names), ~100 are cross-function or parameter cases no intraprocedural
rule resolves, 8 are psycopg's `sql.SQL(...).format(sql.Identifier(...))`
composition grammar (not modelled), and the rest are unmodelled shapes.
Benign corpus unchanged (E0711 11 · E0713 1 · E0720 1); ground truth 29 TP
/ 0 FN / 0 FP over 57 labelled functions; bandit B608 agreement unchanged
(97 hit / 14 miss). `bench/py_frontend/corpus/sqlalchemy_repro.py` pins 11
safe and 10 vulnerable shapes.

### BUG-011  an import under `try:` or inside a function was invisible, so its sinks were SILENT  [FIXED 9b51716]
test: tests/test_py_frontend_sinks.py


Found 2026-09-02 while fixing BUG-010: the first fix cleared only 43 of
1,029 SQLAlchemy findings, and reading the survivors showed `select` was
not resolving to `sqlalchemy.select` at all. agno, like most frameworks,
imports it under the optional-dependency guard:

```python
try:
    from sqlalchemy.sql.expression import select, text
except ImportError:
    raise ImportError("`sqlalchemy` not installed ...")
```

`py_to_ir`'s `collect()` registered imports only as direct children of
the module and class bodies it walked. Anything under `try:`, `if`, or
inside a function body was never seen.

**That is a false-accept class, not a precision one.** Confirmed by
execution before the fix — this file produced NO finding for the first
two functions:

```python
try:
    import yaml
    import pickle
except ImportError:
    raise

def load(raw):     return yaml.load(raw)       # silent
def unpickle(b):   return pickle.loads(b)      # silent
```

An unresolved qualified sink is not over-flagged. `yaml.load` never
reaches `SINK_GUARDS`, `pickle.loads` never reaches `SINK_BY_QUALIFIED`,
and neither `load` nor `loads` is a method-name sink, so the call is
translated as `py:load` and every detector looks past it. Same family as
BUG-004: the unknown case defaulted to "not a sink".

Fix: imports are collected from the whole module with `ast.walk` before
`collect()` runs, so guarded, conditional and function-local imports all
register. The rule that comes with it: a local name bound by two imports
to DIFFERENT targets (`try: import ujson as json` / `except: import
json`) is marked ambiguous and resolves to nothing — it clears no query
and sanctions no builder, and a sink reached through it is missed exactly
as it was before, never worse. Picking a winner would be a false accept
in one direction or the other.

The bench harness had the same bug in its own slicer: `_function_slice`
built each function's import header from lines starting at column 0 with
`import`/`from`, so the repro written to pin this class failed under the
bench while passing under `check-py`. The header now keeps every
top-level statement that contains an import, whole.

`bench/py_frontend/corpus/guarded_import_repro.py` carries the two silent
sinks, a function-local `marshal.loads`, the guarded builders, the
ambiguous-alias case, and `yaml.safe_load`, all labelled. Ground truth:
29 TP / 0 FN / 0 FP over 57 functions; benign corpus unchanged.

Residual: `collect()` still discovers FUNCTIONS only as direct children of
module and class bodies, so a `def` nested under `if TYPE_CHECKING:` or
`try:` is not analysed at all. Different gap, same shape; not fixed here.

### BUG-012  a sink in any statement position the translator did not model was SILENT, and a rebinding it did not model proved a name literal-only  [FIXED 8afdfad]
test: tests/test_py_frontend_sinks.py


Found 2026-09-02 by a five-lens survey of the Python frontend, and
confirmed by execution before the fix. `py_to_ir` translated four
statement kinds — `Assign` to a single name, `Expr` whose value is a
call, `Return`, `With` — and one expression shape, and DROPPED every
other node. Nothing was over-flagged; it was never seen:

```python
async def a(conn, uid):
    await conn.execute("SELECT * FROM u WHERE id = " + uid)   # silent
def b(cur, uid):
    for row in cur.execute("SELECT * FROM u WHERE id = " + uid):   # silent
        ...
def c(blob):
    obj, _ = pickle.loads(blob), None                           # silent
def d(cur, uid):
    return cur.execute("SELECT " + uid) or []                   # silent
try:
    def load(raw): return pickle.loads(raw)                     # never analysed
except Exception: ...
os.system(sys.argv[1])                                          # module level: n_functions 0, ok true
```

Census over bench/framework_scan (4,946 files): 603 sink calls sat
behind an `await` and 89 in other unmodeled positions (BoolOp 50,
Compare 20, tuple/attribute/subscript targets 11, dict/list displays 7,
for-iterables 17, comprehensions 20); 26 of the 89 would fire under the
existing rows. Same family as BUG-004 and BUG-011: the unknown case
defaulted to "not a sink".

**The second half is a false SAFE, not a missed position.** Three
resolvers (`_local_constants`, `_safe_xml_parser_names`,
`_sql_expression_names`) and the `Let` nodes the Aether safe-name pass
reads all saw ONE binding form, a single-Name `Assign`. So:

```python
sql = "SELECT * FROM u WHERE id = "
sql += uid                      # AugAssign: invisible
cur.execute(sql)                # `sql` proved literal-only -> silent

def load(raw, loader=None):
    if loader is None:
        loader = yaml.SafeLoader   # the only VISIBLE binding
    return yaml.load(raw, Loader=loader)   # caller-supplied loader cleared the guard
```

Parameters, `+=`, for-targets, tuple unpacks, walrus, except-as,
`global`, comprehension targets and match captures were all invisible
bindings. `_safe_xml_parser_names` additionally skipped any binding
that was not a parser constructor, so `parser = make()` after the
hardened constructor still disarmed E0727. And `_guard_verdict` read a
`**kwargs` splat as "shell= absent" and cleared `subprocess.run(cmd,
**opts)`, against its own contract that unresolvable means SINK.

Fix, in `transpiler/aether/py_frontend.py`:

- `_bindings_of(node)` — ONE walk over every binding form, consumed by
  all three resolvers and by `_FnVisitor.seed_bindings`, which emits an
  opaque `Assign` for every name bound by a form whose value cannot be
  seen. A name with such a binding can never prove literal-only.
- `_FnVisitor.visit_stmt` is total over statement kinds: bindings
  become `Let`s, and every other value expression a statement evaluates
  (`for`'s iterable, `if`/`while` tests, `assert`, `raise`, `match`
  subjects and guards, a nested `def`'s decorators and defaults, a
  non-Name assignment target's value) is translated in place.
  `_expr` carries the children of every unmodeled expression under
  `parts`, so a call inside `x or []`, `a == b`, `f()[0]`, a display, a
  lambda or a comprehension is found by `walk`; `await` and `yield`
  are transparent; keyword-argument values ride under `kwargs`.
- `collect()` finds a `def` at any statement depth outside a function
  body (under `try:`/`if`/`with`/`for`, in a class nested in a class),
  and each module and class body with a call becomes a synthetic
  `<module>` / `Class.<class>` scope run through the same machinery.
- `_guard_verdict`: a `**` or `*` splat that could carry the deciding
  argument is SINK; `shell` is also read positionally (`arg_index=8`),
  `Loader` at `arg_index=1`.
- `_callee_spelling` / `_method_name`: `getattr(obj, "execute")(...)`
  with a literal attribute, and a bare name bound once to a bound
  method (`ex = cur.execute; ex(q)`), spell the method.
- Two sink rows that were simply missing: `exec_driver_sql` (22 of 31
  corpus sites non-literal, all silent) and sqlmodel's `Session.exec`.
  And a hole INSIDE the iteration-47 sanctioned exit: `prefix_with`,
  `suffix_with`, `with_hint`, `with_statement_hint`, `op` splice a
  string verbatim into compiled SQL; they now get `text()`'s discipline.
- A scope whose expression is deeper than the interpreter stack reports
  an `unprovable` `too_deep` region instead of losing the WHOLE FILE as
  "unreadable" with exit 0; `check-py` reads source with
  `tokenize.open`, so a PEP 263 `coding:` cookie no longer makes a valid
  file "unreadable".

Precision fixes shipped alongside, each by positive identification only:
`from yaml import SafeLoader` then `Loader=SafeLoader` resolves through
the import table (ambiguous names still resolve to nothing); a
module-level str constant bound exactly once in the whole module is
inlined at its reads (`conn.execute(_CREATE_TABLE)`); a `stmt = None`
sentinel before `stmt = select(...)` binds nothing.

`bench/py_frontend/corpus/totality_repro.py` carries twelve silent
shapes and seven documented fixes, all labelled.

### BUG-013  `var` bindings and `x = ...` re-assignments were invisible to every binding walker (false accepts)  [FIXED b30d7f1]
test: tests/test_effect_scope.py


Found 2026-09-03 by the improvement survey (candidates AEDET-01/02/03),
probe-confirmed before the fix. The parser emits three binding kinds —
`Let` (name), `Var` (name) and `Assign` (target) — and `detector_specs.py`'s
`_bindings`, the marker-taint fixpoint `_marked_tainted_names`, the
literal-or-wrapper safe-name pass `_safe_names`, `_fn_aliases` and
E0717's stable-name proof all walked `Let`/`Assign` by `name` only. A
`var` was never a binding, and an `Assign` (which carries `target`) never
matched. So:

```aether
var x: String = password      // Secret<String> param
print(x)                      // exit 0: x was never tainted

let p: String = "/etc/motd"
p = userPath
readFile(p)                   // exit 0: the only VISIBLE binding is the literal

var docId: String = requestedId
let proof = authorizeResource(user, "docs:edit", docId)
docId = victimId
sqlByOwner("...", docId, proof)   // exit 0: E0717's stable-name proof missed the rebinding
```

Fix: one shared walker (`_walk_binds` / `_bind_target` over `Let`,
`Var`, `Assign`) that every consumer uses, plus `_mutable_names` for the
proofs that need "bound exactly once". Flag-more only. The survey's
in-memory rewrite over 418 parseable `.aeth` changed 0 files; the gate
confirms 0 corpus deltas.

### BUG-014  `for` loop variables and match-EXPRESSION arm bindings did not carry taint (false accepts)  [FIXED b30d7f1]
test: tests/test_effect_scope.py


Found 2026-09-03 (candidates AEDET-06/07). BUG-001 (iteration 41) made
match-STATEMENT arm bindings over a tainted scrutinee tainted; the
match-EXPRESSION form (`let r = match o do ... end`) and the `for x in
markedList do ... end` loop variable were left out, so
`for s in secrets do print(s) end` with `secrets: List<Secret<String>>`
was exit 0. Fix: the taint fixpoint treats a `For` target over a tainted
iterable and every arm binding of a tainted match expression as tainted
(every arm, every binding — conservative).

### BUG-015  an alias of a STDLIB sink hid it from every detector and from E0801 (false accept)  [FIXED b30d7f1]
test: tests/test_effect_scope.py


Found 2026-09-03 (candidate AEDET-04). Iteration 42 resolved aliases of
USER functions (`let f = logIt; f(secret)`); a stdlib sink aliased the
same way — `let run = sqlQuery; run(input)`, `let w = writeFile`, `let
p = print`, `let sh = shellExec` — matched no row (the callee name was
`run`) and no effect (`_STDLIB_EFFECTS` keyed on `shellExec`), so the
query, path, secret, command and the E0801/E0701 effect all went silent.
Fix: `_fn_aliases` targets extended with the stdlib sink names and
`_STDLIB_EFFECTS` keys; an aliased SINK is the sink, an aliased
sanitizer/unwrapper is still never honoured (flag-more only). E0716/E0717
keep demanding their proofs through the alias.

### BUG-016  a record carrying a marker field reached a sink whole, unflagged (false accept)  [FIXED b30d7f1]
test: tests/test_effect_scope.py


Found 2026-09-03 (candidate AEDET-10). Iteration 44 made a marker-typed
FIELD read a taint source (`u.email`), but the record VALUE itself was
not tainted, so `print(u)` and `writeFile(path, u)` with `u: User`
(`record User do email: PII<String> ... end`) were exit 0 — the whole
record, PII included, in the log. Fix: `_marked_records` (records whose
fields carry the marker, transitively) and `_record_names` (names whose
declared type, constructor call or seeding return is such a record);
a carrier at a sink is a leak; a PLAIN field read of a carrier
(`u.name`) is not; passing a carrier into a parameter typed with that
record is a sanctioned crossing and into a plain parameter is E0729;
returning it under a plain return type is E0730. `Authorized<T>` is
untouched (a proof marker is never widened).

### BUG-020  a sanctioned wrapper was accepted on its NAME; its pinning argument was never judged (false accept)  [FIXED c35b3f3]
test: tests/test_effect_scope.py


Found 2026-09-03 by the improvement survey (candidate AEDET-05), probe-
confirmed before the fix. The literal-or-wrapper rows accept an argument
that is "a fixed literal or the result of a sanctioned wrapper call":
`_arg_reason` returned safe for ANY call whose callee was in the row's
wrapper list, without looking at the wrapper's own arguments. Every
wrapper pins the untrusted value to its FIRST argument — the template
`sqlBind` binds into, the command line `shellArg` quotes into, the host
`safeRedirect` pins to — so a wrapper handed a non-literal there launders
the very thing the row exists to refuse:

```aether
function q(tmpl: String, v: String) returns String
  effects db.query
do
  return sqlQuery(sqlBind(tmpl, v))      // exit 0: the QUERY TEXT is tmpl
end
```

Same for `shellExec(shellArg(tmpl, v))` and `redirect(safeRedirect(host,
p))`. All three were exit 0.

Fix: `ArgRule.pin` — a reason string per row; when the callee is a
wrapper, `args[0]` must itself satisfy the rule (literal or literal-bound
name), else the call is refused with that reason. `safeJoin(base, rel)`
deliberately has no `pin`: it strips `..` and absolute roots from `rel`,
the base directory arriving as a parameter is the idiom (7 corpus sites,
both zip-slip demos' `fixed.aeth`), and the base is program-chosen, not
the untrusted half — pinning it would refuse the sanctioned exit itself.
Recorded as a residual, not enforced.

The Python frontend's wrapper calls have no template slot — `shlex.quote(x)`
arrives as `shellArg(x)`, a SQLAlchemy expression as `sqlBind(...)` — so
every Call the frontend emits carries `"py": True` and the pinning check
skips it. That marker is the ONLY difference between the two IRs the
rules see; a frontend Call without it would be judged by the Aether rule.

### BUG-021  the argv form `["bash", "-c", cmd]` was read as the safe exit (false accept)  [FIXED c35b3f3]
test: tests/test_py_frontend_sinks.py


Found 2026-09-03 (survey candidate PYSINK-07). `subprocess.run` without
`shell=` IS the documented fix — the argv form — so the guard read it as
safe. But an argv whose program is a shell and whose flag is `-c` hands
its third element to that shell to PARSE: `subprocess.run(["bash", "-c",
"ls " + user])` is `os.system("ls " + user)` with extra steps, and was
silent. Same for `os.execvp("sh", ["sh", "-c", cmd])` (recorded, not
mapped: 0 corpus sites).

Fix: `_argv_shell_payload` — when a subprocess-guard call is NOT a shell
by keyword and its first positional is a list/tuple literal whose first
element spells a shell (`sh`, `bash`, `zsh`, `dash`, `ksh`, `/bin/sh`,
`/bin/bash`, `/usr/bin/sh`, `/usr/bin/bash`, `cmd`, `cmd.exe`,
`powershell`, `pwsh`) and whose second is `-c` (or `/c` for cmd), the
call is `shellExec` and the THIRD element is the judged argument. A
literal third element stays clean; `["ls", "-l", x]` stays the argv exit.

---

### BUG-022  function-typed parameters launder markers AND effects (false accept)  [FIXED eaeb316]
test: tests/test_effect_scope.py
test: tests/test_static_effects.py

Found 2026-09-03 (iter-51, survey candidate AEDET-08; re-probed live on
`3986d38`). q1's Evidence table asserted "`grammar.ebnf` has no function
types", so the whole surface was written off in iter-42. The claim was
wrong: `grammar/grammar.ebnf` line 88 is

    type_atom = IDENT
              | "function" "(" [ type_expr {"," type_expr} ] ")" "returns" type_expr ;

and `parser.py:369` emits `{"kind": "FunctionType", ...}`. Two exit-0
probes, verbatim:

    function apply(f: function(String) returns Unit, x: Secret<String>) returns Unit
      effects log
    do
      f(x)
    end

    function main(pw: Secret<String>) returns Unit
      effects log
    do
      apply(print, pw)
    end
    -> OK (2 decls), exit 0

    function logLine(s: String) returns Unit
      effects log
    do
      print(s)
    end

    function apply(f: function(String) returns Unit, x: String) returns Unit
      effects pure
    do
      f(x)
    end

    function main(s: String) returns Unit
      effects pure
    do
      apply(logLine, s)
    end
    -> OK (3 decls), exit 0

Why these are false accepts, not over-flags. (1) `check_marker_boundary`
resolves the callee by name; `f` is a PARAMETER, so `cands` is empty and
the `if not cands: continue` branch dropped the crossing. The marker then
crossed into a callee the analysis cannot see AT ALL — strictly worse
than the plain-param case E0729 already refuses — and `print` received
the secret with every sink pass blind. (2) `check_effects` unioned only
the CALLEE's effects into the caller's obligation. A function passed as
a VALUE runs under that call just the same, so `log` was performed by two
functions that both declared `pure`. Both are misses inside the modeled
surface: the contract-breach class.

Fix. (1) When a call's callee name is a function-typed parameter of the
enclosing function and no user decl or alias resolves it, any argument
that leaks the marker raises E0729 with `extra.via = "function_type"`.
No sanctioned crossing is offered on purpose — a function TYPE's argument
types are never checked against the function that actually arrives, so
declaring `function(Secret<String>) returns Unit` would be an exit that
proves nothing. Unwrapping at the call site is the only clearance.
(2) In `check_effects`, every argument that is a bare `Ident` naming a
user `FunctionDecl` or a `_STDLIB_EFFECTS` key contributes its declared
effects to the caller's obligation, reported against the caller as the
existing E0801 with `extra.via = "function_value"` and wording that says
the value is passed, not called. A pure function value adds nothing, so
`map(double, xs)` stays clean — the corpus has 9 such sites (bench
humanize x3, three `v02_map_filter_chain` files x2 each), every one of
them declared pure, and 0 function-typed parameters, so the change fires
0x on the corpus.

Residual (recorded in q1, not invented away): a function that merely
DECLARES a function-typed parameter can still claim any effects clause it
likes. The function TYPE carries no effects clause in the grammar, so
there is nothing to check a callee's own declaration against, and
`apply(f: function(String) returns Unit) effects pure do f(x) end` stays
accepted. Closing it needs effect-polymorphic function types — a language
change, not a detector change.

### BUG-023  the boundary sanitizer is marker-wide, not sink-specific (false accept)  [FIXED eaeb316]
test: tests/test_effect_scope.py

Found 2026-09-03 (iter-51, survey candidate AEDET-09; re-probed live on
`3986d38`). q1's Recommended Actions had parked this as "probe for a MISS
before acting — if none exists it is doctrine". The probe finds the miss:

    function render(s: String) returns String
      effects pure
    do
      return htmlResponse(s)
    end

    function handle(u: Untrusted<String>) returns String
      effects pure
    do
      return render(sanitizeLog(u))
    end
    -> OK (2 decls), exit 0

while the inline shape one call closer is refused:

    function handle(u: Untrusted<String>) returns String
      effects pure
    do
      return htmlResponse(sanitizeLog(u))
    end
    -> [E0725] ... (sanitizeLog does NOT protect here), exit 2

`boundary_markers()` unions EVERY `Untrusted` row's sanitizer into one
set, so any one of them cleared the E0729 crossing regardless of which
sink the callee actually reached. E0725's own hint says sanitizeLog does
not protect at `htmlResponse`; stripping CR/LF does nothing about
`<script>`. Moving the sink one call away laundered it — a miss, and the
same class of laundering E0729 exists to refuse.

Fix. `param_sink_reach(ast)` in `detector_specs.py` summarises, per user
function and per parameter index, which marker-flow SINK names that
parameter's Ident reaches inside the body — using the same argument-index
rule `marker_flow` applies (`Sink.arg_indices`, so `writeFile`'s path
slot does not count) and honouring aliased sinks via `_sink_targets`.
`marker_sink_sanitizers()` derives (marker, sink) -> sanitizer from
`MARKER_FLOW_SPECS`; nothing restates the map. `check_marker_boundary`
then accepts a cleared crossing only when the unwrapper that cleared it
is the right sanitizer for every sink the callee's parameter feeds, and
otherwise reports E0729 naming the mismatch (`cleared_with`,
`reaches_sink`, `needs`). `trusted(...)` is nobody's row sanitizer — it
is an explicit assertion, not inference — and still clears. An empty
reached-sink set keeps the pre-fix behaviour exactly, so the change fires
0x on the corpus.

Residuals (recorded in q1): the summary is ONE LEVEL and by direct Ident.
A callee that rebinds the parameter before the sink, or passes it on to a
THIRD function, contributes no sinks, and the crossing is then accepted
on the old marker-wide rule. E0730 (return laundering) is untouched — a
return has no callee parameter to summarise, so the coarseness stands
there.

### BUG-024  the iter-51 rules over-flagged: shadowed names and self-sanitizing callees (false reject)  [FIXED 8f94e59]
test: tests/test_static_effects.py
(half (a) above; half (b) is locked by
`tests/test_effect_scope.py::test_boundary_callee_sanitizes_internally_clean`
and `::test_boundary_callee_wraps_without_sanitizing_still_rejected`)

Found 2026-09-03 by the review of iteration 51's own commit `eaeb316`.
Two over-flags shipped in that commit; both were exit 0 on `3986d38` and
exit 2 on the branch, i.e. introduced by the fix, not pre-existing.

**(a) E0801 resolved a bare Ident argument by GLOBAL name.** The `passed`
comprehension in `check_effects` asked only whether the argument's name
appears in `user_effects` / `_STDLIB_EFFECTS`, never whether the name is
bound locally. Every argument position of every call was affected:

    function logIt(s: String) returns Unit
      effects log
    do
      print(s)
    end

    function main(logIt: String) returns String
      effects pure
    do
      return concat(logIt, "x")
    end
    -> [E0801] ... passes 'logIt' as a value to 'concat', whose effect
       'log' is not covered by the caller

`logIt` here is a plain `String` PARAMETER handed to the pure stdlib
`concat`. `let notify = "hello"` shadowing a `net` function produced the
same thing for a string LITERAL. This is not over-flagging a risky shape;
it invents an effect for a String.

**(b) E0729 counted a parameter as reaching a sink it only reaches
through that sink's own sanitizer.** `param_sink_reach` passed
`frozenset()` as the unwrapper set on purpose, so the idiomatic safe
helper was reported as feeding the sink unsanitized:

    function render(s: String) returns String
      effects pure
    do
      return htmlResponse(htmlEscape(s))
    end

    function handle(u: Untrusted<String>) returns String
      effects pure
    do
      return render(sanitizeLog(u))
    end
    -> [E0729] ... it was cleared with sanitizeLog(...), but 'render'
       passes it to 'htmlResponse', whose sanitizer is htmlEscape
       hint: apply htmlEscape(...) instead

`render` does not pass `s` to `htmlResponse`; it passes `htmlEscape(s)`.
Following the hint gives `render(htmlEscape(u))`, so `htmlEscape` runs
twice and the response body carries `&amp;lt;`. The message was factually
false and the suggested fix corrupted output.

Fix. (a) `check_effects` computes `local` — this function's parameter
names plus every `_walk_binds` target in its body — and a shadowed Ident
argument resolves ONLY through `_fn_aliases`, which already maps a local
binding to the function it aliases. The same edit closes the gap iter-51
documented but left open: `let g = logIt  apply(g, s)` now reports
E0801 naming `g` as an alias of `logIt`. (b) `_marker_sink_unwrappers()`
derives, per sink, every sanitizer a marker row demands there (plus the
sink-agnostic `trusted`), and `param_sink_reach` summarises with that set
— so a value that arrives at the sink already sanitized is not counted as
reaching it. Any other wrapper still leaks: `htmlResponse(concat(s, "!"))`
is still reported, and the message now says "reaches ... unsanitized"
rather than "passes it to".

Residual. The shadow set is function-wide, not scoped: a call textually
BEFORE a later `let` of the same name is also treated as shadowed, which
is the accept direction. The sanitizer prune is syntactic at the sink
call, which the pre-existing one-level/direct-Ident limit already bounds.

### BUG-025  an alias of a function-typed parameter reopened BUG-022 (false accept)  [FIXED 8f94e59]
test: tests/test_effect_scope.py

Found 2026-09-03 by the review of iteration 51. `check_marker_boundary`
matched `ftparams` against the LITERAL callee name, and `_fn_aliases`
resolves aliases against `frozenset(decls)` only, so an alias bound to a
function-typed PARAMETER was never a target and the crossing fell through
`if not cands: ... if cname not in ftparams: continue`:

    function apply(f: function(String) returns Unit, x: Secret<String>)
      returns Unit
      effects log
    do
      let g = f
      g(x)
    end
    -> OK (1 decls), exit 0   [both on 3986d38 and on eaeb316]

while the identical program without the `let` fires E0729 after BUG-022.
One line of aliasing reopened exactly the laundering that slice claims to
have closed — the same alias class q1 already records as CLOSED for named
functions (BUG-002).

Fix. `check_marker_boundary` resolves the callee through
`_fn_aliases(d, frozenset(ftparams))` before giving up, and reports the
underlying parameter with `extra.param` naming it and the message adding
"(through alias 'g')". The alias map is built separately from the marker
alias map so nothing else in the pass changes behaviour.


### BUG-026  `aether fix-loop` was broken in every installed copy since 0.3.0  [FIXED 8fb3c59]
test: tests/test_fix_loop_cli.py


Found 2026-09-11 by the pre-release check for 0.4.0, which runs every probe
through the pip-installed `aether` console script from outside the
checkout. Verbatim, exit 2:

    aether fix-loop: deterministic path import failed: No module named 'fix_loop'

The same file through `python -B -m transpiler.aether.cli fix-loop` exited
0. `cmd_fix_loop` found its engine by walking up from `__file__` to
`<repo>/demos/payment_workflow/` and importing `fix_loop` from there. No
wheel has ever shipped `demos/` — the package is scoped to
`transpiler/aether*` since BUG-009 — so in site-packages the walk lands in
`venv/Lib`. `git show v0.3.0:transpiler/aether/cli.py` has the same code:
broken in both released versions, while `aether --help` listed the
subcommand and the README documented it. Same class as BUG-006..009: it
works from the checkout, and is invisible to every test that runs in it.

Fix: the deterministic engine is library code (the stdlib plus
`aether.sdk`, `parser` and `pretty`), so it moved into the package as
`aether/fix_loop.py`; `demos/payment_workflow/fix_loop.py` stays as the
demo's by-path entry point. `--live` drives a 275-line Anthropic demo and
stays source-checkout-only, and now says so instead of reporting an import
failure. `tests/test_fix_loop_cli.py` runs the CLI from a temp dir holding
only a copy of `aether/` — an installed wheel's shape — and `gate.yml`'s
installed-wheel job runs `aether fix-loop`.

### BUG-027  a sink inside an assignment target's subscript or attribute was SILENT (false accept)  [FIXED 8fb3c59]
test: tests/test_py_frontend_sinks.py


Found 2026-09-11 by the 0.4.0 release-notes audit, which tested the
claim that BUG-012 made the frontend total over syntax. Exit 0:

```python
del d[os.system("ls " + x)]
d[os.system("ls " + x)] += 1
for d[os.system("ls " + x)] in xs: ...
with cm as d[os.system("ls " + x)]: ...
```

while `d[os.system("ls " + x)] = 1` fired. BUG-012 treated a binding
target field as "names, not values" and skipped it whole; only a plain
`Assign` target's sub-expressions were translated. But only a bare name is
purely a binding site: a subscript or attribute target evaluates its base
and index first. BUG-012's entry and q7 claimed totality over positions;
this is the counterexample, found by a probe of the claim rather than by a
reader of it.

Fix: `_target_loads(t)` yields what a target evaluates — nothing for a
name, the base and index of a subscript, the base of an attribute,
recursively through tuples, lists and starred — and every consumer of a
target field (`_exprs_in`, `_stmt_expr_children`, and the `Assign`,
`AugAssign` and `With` branches) takes the loads instead of skipping.
`test_sink_in_every_statement_position_is_seen` pins all four positions,
each seen exactly once.

### BUG-028  a sink in a match-case guard or an `except` type was reported twice  [FIXED 8fb3c59]
test: tests/test_py_frontend_sinks.py


Found 2026-09-11 by the same audit: `case _ if os.system("ls " + x):`
emitted the same E0714 twice (same line, column and `extra`), and
`except <sink>:` had the identical shape. `py_to_ir` visited `match_case`
and `excepthandler` nodes as statements of their own, while the parent
`Match` / `Try` statement already reached the guard and the exception type
as its expression children, so each was translated twice. It inflates
counts; it never hides a finding. Introduced by BUG-012's rework, which
added the separate visits; 0.3.1 translated neither position at all.
Never released.

Fix: the walk visits statements only; guards and handler types are
translated once, through their parent. Both positions are in the
exactly-once test.

### BUG-029  a file too deep for CPython's own parser was reported as an Aether crash, exit 2  [FIXED 8fb3c59]
test: tests/test_py_frontend_sinks.py


Found 2026-09-11 by the same audit. `ast.parse` itself raises
`RecursionError: maximum recursion depth exceeded during ast construction`
on a 3,000-term `a + a + ...` chain under CPython 3.11 and 3.13 (probed
both). Such a file was reported as `ANALYZER ERROR ... this is a bug in
Aether` and failed the run with exit 2. 0.3.1 caught `RecursionError`
beside `SyntaxError` and counted the file unparseable; the BUG-012 rework
narrowed that clause so a `RecursionError` from Aether's own translator
would go red rather than silent, and the parser's `RecursionError` fell in
with it. Never released. CPython cannot compile or import such a file
either, so it is unparseable input, not a bug in Aether.

Fix: `py_to_ir` converts a `RecursionError` or `MemoryError` raised by
`ast.parse` itself into a `SyntaxError`; one raised by the translator still
reaches the analyzer-crash path. The test puts a 20,000-term chain beside a
real sink and requires that no ANALYZER ERROR appears.

### BUG-030  `exec(compile(src))` was rated as a compile that runs nothing  [FIXED 8fb3c59]
test: tests/test_py_frontend_sinks.py


Found 2026-09-11 by the same audit. `exec(compile(src, "<s>", "exec"))` is
collapsed to one E0731 finding on the inner `compile()`, and iteration 52
rated that kind `builtin_compile`, 0.6 — the rating for a `compile()` whose
result nobody runs. This source IS executed, so `--min-confidence 0.9` hid
real execution; crewai's `flow/runtime/_actions.py:309` is that shape.
Introduced by iteration 52, never released.

Fix: `_call_expr` re-rates the inner compile to `builtin` when a builtin,
unshadowed `exec`/`eval` wraps it. A `compile()` on its own, or one under a
local `def exec`, stays at the floor.

### BUG-031  E0727 told ElementTree users a caller's parser "never" expands external entities (false reassurance)  [FIXED fbec07c]
test: tests/test_py_frontend_sinks.py
(`::test_xxe_elementtree_text_is_scoped_to_calls_without_a_parser`; the
detection shapes the same audit found untested are in
`::test_xxe_guard_and_parser_binding_shapes`)


Found 2026-09-15 by a skeptic review of iteration 53's commit `11efc72`,
confirmed twice by measurement. The `xml.etree.cElementTree.` rows and the
`xml.` fallback rows (ElementTree, expatbuilder) printed "this parser never
expands external entities, so there is no XXE file read or SSRF through
entities on any Expat". That holds only for a call with no parser:
`ET.parse(source, parser=None)` and `ET.fromstring`/`ET.XML(text,
parser=None)` use a caller's parser as given, keyword or positional, and
`xml.etree.cElementTree` is still importable on 3.11 as the same function
objects. Measured on CPython 3.11.15 / Expat 2.7.4 / lxml 6.1.1 with a
local HTTP server: an lxml `XMLParser(resolve_entities=True)` returned a
local file's contents through `ET.fromstring`, `ET.XML`, `ET.parse` (both
slots) and `cElementTree.fromstring`, and with `no_network=False` made 1
request through `ET.parse` and `ET.fromstring`; a `make_parser()` with
`feature_external_ges` delivered the file's contents to its handler through
`ET.parse` (both slots) and `ET.fromstring`, and made 1 request through
`ET.parse`. E0727 fired on every one of those calls (a `qualified` match,
0.95); only the text was falsely reassuring, and it steered a reader away
from the one argument that made the call an XXE. The claim was copied into
`grammar/diagnostics.md`, q1 and the violation taxonomy. Two smaller
wording defects in the same rows: `_LXML_MSG` ended "so a crafted
<!ENTITY SYSTEM ...> reads local files", which read as unconditional
(lxml 6.1.1's default parser raises `Entity 'x' not defined` and reads
nothing), and `_DOM_MSG` dated minidom's default to "Python 3.7.1", which
is the `xml.sax` `feature_external_ges` change (minidom without a parser
goes through expatbuilder, which never resolved them). Introduced by
iteration 53, never released.

Fix: ElementTree and cElementTree get their own message (`_ET_MSG`): "never"
is scoped to a call without a parser argument, and a parser passed in is
said to be used as given, with the two measured consequences. expatbuilder
keeps an exact "never" (`_EXPATBUILDER_MSG`): its second positional is
`namespaces`, `parser=` is a TypeError, and it dropped the entity with 0
requests. The `xml.` fallback rows become explicit `xml.etree.ElementTree.`
and `xml.dom.expatbuilder.` rows, and the test requires every one of the 20
callees mapped to `parseXml` to match a Python row. The lxml file-read
clause is conditional; the minidom/pulldom text drops the date. The stdlib
hint says "no parser argument, parser= or positional", and its fallback
("otherwise pass no parser argument and check pyexpat.version_info >= (2, 7,
2)") keeps that condition: the version check covers only the DoS clause, and
on Expat 2.7.4 a positional lxml or `feature_external_ges` parser still read
the file. Detection, confidence and the DoS clause are unchanged.


### BUG-032  HTML/URL escapers were mapped onto `trusted`, clearing SSTI, code-injection and deserialization sinks (false accept)  [FIXED 3ccf848]
test: tests/test_py_frontend_sinks.py
(`::test_html_escapers_are_not_trusted`)

Found 2026-09-24 by the whole-repo audit (`audits/audit_2026-09-24_plan.md`
B1), confirmed by execution. `render_template_string(html.escape(x))`,
`jinja2.Template(markupsafe.escape(x))`, `eval(html.escape(x))`,
`exec(urllib.parse.quote(x))` and `pickle.loads(html.escape(x))` all
checked clean (exit 0), as did `render_template_string(render_template(...))`
(a rendered page rendered again as a template). `html.escape` leaves
`{{7*7}}` intact (`jinja2.Template(html.escape('{{7*7}}')).render()` returns
`49`) and leaves `__import__(chr(111)+chr(115)).getcwd()` runnable.

Root cause: `SANITIZER_BY_QUALIFIED` (`py_frontend.py`) mapped `html.escape`,
`markupsafe.escape`, `urllib.parse.quote`, `urllib.parse.quote_plus` and
`flask.render_template` to `trusted`, which is the only wrapper of
`_TEMPLATE_RULE`, `_CODE_RULE` and `_DESERIALIZE_RULE`. The rows date from
`2f72c71` (2026-07-26), so 0.3.x and 0.4.0 carry the miss. `trusted` is an
assertion, not a sanitizer (vault closed design point), and no Python call
may stand for it. E0718 was not affected: its only wrapper is
`safeRedirect`.

Fix: the two HTML escapers map to Aether's `htmlEscape`, the HTML-context
sanitizer that clears only the HTML sink (E0725, which does not run on
Python). `urllib.parse.quote(_plus)` and `flask.render_template` are
unmapped, so they are ordinary unknown calls. The test crosses 4 escapers
with 5 trusted-only sinks and asserts that no `SANITIZER_BY_QUALIFIED` value
is `trusted`. Measured non-breaking: the framework corpus (4,946 files) gives
676 findings before and after with identical (file, line, code) keys, and the
repo's bench/tests/tools/playground/demos (208 files) gives 110 before and
after.

### BUG-033  an import bound two ways resolved to nothing, so every sink behind the fallback idiom was silent (false accept)  [FIXED 3ccf848]
test: tests/test_py_frontend_sinks.py
(`::test_ambiguous_import_is_a_sink_if_any_candidate_is`)

Found 2026-09-24 by the whole-repo audit (B2), confirmed by execution.
`try: import cPickle as pickle / except ImportError: import pickle` then
`pickle.loads(b)` checked clean. So did the lxml/ElementTree fallback before
`etree.fromstring(x)`, `subprocess32` before `subprocess.call(cmd,
shell=True)`, the flask/werkzeug fallback before `redirect(u)`, and one
function-local `import json as pickle` elsewhere in the file before
`pickle.loads(b)`.

Root cause: `_Imports` put a name bound to two different targets into
`ambiguous`, and `resolve_attr` / `resolve_name` returned None for it. Its
own comment admitted that "a sink reached through it is missed". The README
did not say so. Resolving to nothing is right for the clearing direction (a
builder or sanitizer must not clear anything on a guess). In the sink
direction it is a false accept.

Fix: `_Imports` keeps every candidate target. An ambiguous name resolves to
the first candidate that is a sink (`SINK_BY_QUALIFIED` or `SINK_GUARDS`),
and otherwise to nothing, as before. So the name is a sink if ANY candidate
is one and sanctioned only if ALL are. The existing
`test_ambiguous_import_clears_nothing_and_sinks_nothing_new` still passes:
its `update` is not a sink. Where both candidates are sinks, the message
names the first one bound. Measured non-breaking on the same two corpora as
BUG-032.

### BUG-034  `shlex.quote(cmd)` as the WHOLE shell command was read as the safe exit (false accept)  [FIXED 3ccf848]
test: tests/test_py_frontend_sinks.py
(`::test_whole_command_shlex_quote_is_not_the_exit`)

Found 2026-09-24 by the whole-repo audit (B3), confirmed by execution.
`subprocess.run(shlex.quote(p), shell=True)`, `c = shlex.quote(p);
os.system(c)` and `subprocess.run(["bash", "-c", shlex.quote(p)])` checked
clean. Quoting the entire command turns it into one shell word, and the
input still chooses which program runs.

Root cause: `_arg_reason` accepted a frontend-emitted (`py`) wrapper call
whole, exempt from the BUG-020 pin check, because `shlex.quote(x)` has no
template slot. That is right when the quote is one piece of a command. It is
wrong when the quote is the whole command.

Fix: `ArgRule.py_whole` is the reason given when a frontend wrapper call is
the entire judged argument. `_SHELL_RULE` sets it ("the whole command is
one quoted word - the input still chooses the program; pass an argv list").
Every other rule leaves it None, so a SQLAlchemy expression as `sqlBind`, or
`json.loads` as `schemaDecode`, is still accepted whole. The other half of
the audit row, that `"ls " + shlex.quote(p)` is still flagged (C1, a false
positive), is left for 0.4.2 because it moves the corpus finding set.
Measured non-breaking on the same two corpora.

### BUG-035  a ValueError inside a detector was reported as "could not parse", exit 0, findings lost  [FIXED 3ccf848]
test: tests/test_py_frontend_sinks.py
(`::test_detector_value_error_is_a_crash_not_unreadable`)

Found 2026-09-24 by the whole-repo audit (B7). A mutation that made one
security detector raise `ValueError`, run on a file with 3 real findings,
printed `aether: could not parse ...` and exited 0. A `KeyError` in the same
place was correctly an ANALYZER ERROR, exit 2. `passes/__init__.py` says a
crashing detector must go red.

Root cause: `_scan_one` (`cli.py`) wrapped both `py_to_ir` and
`analyze_flat` in `except (SyntaxError, ValueError)`, the clause meant for
unparseable input such as py2 sources.

Fix: only `py_to_ir` is inside that clause, so a detector exception of any
type reaches the crash handlers.

### BUG-036  the ratchet compared the baseline against the commit under test, counted detector existence only, and accepted any mention of a code as its proof  [FIXED e355774]
test: tests/test_ratchet.py
(`::test_baseline_never_lowered`, `::test_recall_floor`,
`::test_legitimacy_counts_assertions_only`, `::test_detectors_legitimately_checked`)

Found 2026-09-24 by the whole-repo audit (F1). Three holes in
`tests/test_ratchet.py`, each probe-confirmed on `99f09cc`:
- `test_baseline_never_lowered` diffed the working tree against `HEAD`. In
  CI the checkout IS the commit under test, so a commit that lowers
  `min_emitted_codes` and deletes a detector compares the lowered file
  with itself and passes.
- The floor counted detectors that exist. A detector reduced to
  `return []` still counts; nothing measured what the detectors find.
- Legitimacy (`test_detectors_legitimately_checked`) looked for the code
  as a substring of the concatenated text of every file under `tests/`,
  so a comment, a docstring or an assert message legitimised a code.

Fix (`e355774`, `9991e52`, `8fb3d3c`):
- The baseline must meet or exceed its value at `HEAD`, `HEAD~1` and the
  merge-base with `origin/main` (warning printed when the ref is missing).
  `gate.yml` checks out with `fetch-depth: 0`. Every integer key is
  compared, not two named ones.
- Recall floor added to `tests/ratchet_baseline.json`:
  `min_corpus_claimed_findings` = 117 (the sum of every `// expect:`
  header over the 93 corpus files `test_corpus.py` scans) and
  `min_py_table_rows` = 93 (`SINK_BY_QUALIFIED` 48, `SINK_BY_METHOD` 14,
  `SINK_BY_BUILTIN` 4, `SINK_GUARDS` 18, `SANITIZER_BY_QUALIFIED` 9).
- A code is proven only when it appears in a string constant inside the
  test expression of an `assert`, in a suite `scripts/run_all.py` runs,
  and not under a negative comparison (`not in`, `!=`, `is not`, `not`).
  All 34 protected codes still qualify.

Proof it bites (scratch commits, dropped afterwards): a commit lowering
`min_emitted_codes` 55 → 54 is red ("LOWERED against 11efc72ec6"); a
commit lowering the new key `min_py_table_rows` 93 → 92 is red ("LOWERED
against 9991e5217c", the parent). Deleting any of the five audit rows
turns `test_ratchet.py` red through `min_py_table_rows`.

### BUG-037  the runtime syscall oracle certified "sound" when it had observed nothing, and its test never ran  [FIXED d7732f9]
test: tests/test_mining.py (`::test_runtime_oracle_catches_fn`)

Found 2026-09-24 by the whole-repo audit (F3). `scripts/run_all.py` listed
its suites by name; `test_cause_b.py`, `test_phase1.py` and
`test_mining.py` never ran, and `test_mining.py` was red (6/7). Repro on
`99f09cc`: `python -B tests/test_mining.py` → exit 1,
`[FAIL] test_runtime_oracle_catches_fn`.

Root cause: `tools/runtime_oracle.py` shells out to `strace` and parses
Linux strace output. On Windows, Git for Windows puts a Cygwin `strace`
(3.6.5) on PATH; it runs, none of the patterns match, the oracle observes
no capability and returns `soundness_ok: True` for a change that writes a
file — a vacuous "sound". The test caught it; nothing ran the test.

Fix (`d7732f9`): `runtime_oracle.available()` (Linux and `strace` on
PATH); `_trace` raises `OracleUnavailable` otherwise. The test asserts the
refusal where the oracle is unavailable and runs the original check where
it is. `tools/mining/swebench_harness.py` already records a raised error
as `oracle_error` instead of an empty observation. `run_all.py` now globs
`tests/test_*.py` with an explicit, commented `EXCLUDE` (empty); the
three orphans run and pass (cause_b 3/3, phase1 5/5, mining 7/7 with the
oracle case as a refusal check on Windows). `gate.yml` installs strace so
CI runs the real oracle path.

Not verified here: the Linux strace path (no Linux machine in this
session). The first CI run of the suite job is its first execution.

### BUG-038  `analyze(skip=...)` ignored unknown stage names; a test's copy of the Python skip list had drifted  [FIXED 032a639]
test: tests/test_ratchet.py (`::test_skip_names_are_stages`)

Found 2026-09-24 by the whole-repo audit (F4). The Python stage-skip list
existed as literals in `cli.py`, `tests/test_py_frontend_sinks.py` (twice)
and `tests/test_confidence.py` (plus the one in `py_frontend.py` the
benches import). The `test_confidence.py` copy was
`("effects", "smt", "modules", "imports", "capability")`: `smt` and
`imports` are not stages, and `semantic`, which check-py never runs, ran.
`analyze()` accepted it silently. Repro on `99f09cc`:
`analyze(ast, skip=("smt",))` returns every stage, no error.

Fix (`032a639`): `PY_SKIP_STAGES` / `PY_STRICT_ONLY_CODES` are defined only
in `py_frontend.py` and imported by `cli.py` (as `_PY_SKIP_STAGES` /
`_PY_STRICT_ONLY_CODES`, so existing references hold) and both tests;
`test_confidence.py` uses `PY_SKIP_STAGES + ("capability",)`, exactly
check-py's default. `analyze()` raises `ValueError` on a name that is not
a stage. `capability._STDLIB_EFFECT_PATHS` is derived from
`effects._STDLIB_EFFECTS` in one expression (verified equal first:
10 entries, identical path sets).

### BUG-039  E0711 (`--strict`) flags `os.path.join(base, secure_filename(name))`, the documented Werkzeug fix  [FIXED fc05e15]
test: tests/test_py_precision.py (`::test_bug039_secure_filename_join`; also tests/test_python_hints.py)

Found 2026-09-24 while writing `tests/test_sink_rows.py` (F2 sanitizer
half). `werkzeug.utils.secure_filename` maps to `safeJoin`, and
`open(secure_filename(x))` is clean, but the idiom Werkzeug documents,
`open(os.path.join(upload_dir, secure_filename(name)))`, fires E0711
("path is a computed call") — with a parameter base and with a literal
base alike. Repro: `check-py --strict` on the two-function file in the
wave scratchpad `w1/sf.py` → 2 × E0711 (plus the expected `--strict`
E0701 inventory).

Root cause: E0711's Python mapping clears only when the whole path is the
wrapper call; `os.path.join` is an unknown computed call. Not a table-only
fix — mapping `os.path.join` to `safeJoin` would be wrong (`join(base,
"../x")` escapes). Needs a frontend rule: `os.path.join(<any>, <sanitizer
call>)` as the last argument ≡ `safeJoin`. Precision, strict-only row
(E0711 is held back by default), so deferred to the precision wave
(Wave 5, next to C1).

### BUG-040  the deterministic fix-loop "repaired" by widening the declared constraint and reported `final state: clean`  [FIXED 177a173]
test: tests/test_fix_loop_cli.py (`::test_attack_demos_end_not_repaired`,
`::test_fix_loop_never_widens_any_repo_file`, `::test_widening_is_structural`,
`::test_patch_target_E0801_is_the_call_site`, `::test_live_verdict_rejects_a_widening_fix`);
tests/test_fix_loop_demo.py (`::test_fix_loop_refuses_to_widen_broken_candidate`,
`::test_allow_widen_applies_flags_and_never_says_clean`)

Found 2026-09-24 by the whole-repo audit (D1, P0). Repro on `52f04aa`:
`aether fix-loop demos/capability-firewall/log_formatter.aeth` adds
`net.fetch("http://127.0.0.1:9999/*")` to `log_formatter` and `requires
capability net` to the module, and prints `final state: clean` — it grants
the exfiltration the demo exists to block. Same shape on
`03_B2_url_discipline`, `10_pii_telemetry_violation`,
`demo_02_net_glob_mismatch`, `payment_workflow/broken.aeth` (`pure` → `log`)
and `log4shell/aether/vulnerable.aeth` (adds `ldap://*`; ended `stuck` on
E0710 only after widening). Over all 417 non-generated `.aeth` files in the
repo, the `52f04aa` loop's output widened the input's declarations on 31,
and on 28 of them reported `clean`.

Root cause: both transformers (`fix_E0801` appends the missing effect /
drops `pure`; `fix_E0701` appends the capability) widen by construction,
and nothing compared the result with the input. `patch_target` offered only
the declaration (`effects` / `capabilities` field) as the E0801 target, so
widening was the only mechanical repair on offer. `--live` accepted any
model fix that `sdk.check` passed.

Fix (`177a173`): `fix_loop.widening(before, after)` — structural: a
function effect not covered (`_effect_covered`) by its old clause, a new
function's effect not declared anywhere in the input, or a new module
capability. Every candidate edit is judged by it, whichever transformer
produced it. Default: a widening edit is not applied; the loop ends
`not_repaired` with, per blocked diagnostic, `would_widen`, a `reason`
("not repaired: fixing this would widen <fn>'s declared effects (...);
remove or replace the call to '<callee>'") and the call-site
`patch_target`; exit 1. `--allow-widen` (fix_loop.py and `aether
fix-loop`) applies it, tags the step `"weakens_constraint": true` +
`widens`, prints a WARNING, ends `widened` (never `clean`), exits 1.
`aether fix-loop --live` runs the same rule over the model's
`fixed_source` (`cli._judge_live_fix`): widening → transcript tagged
`weakens_constraint`, `rejected`, exit 1 (kept but still exit 1 under
`--allow-widen`). E0801's patch target is now the offending `Call` in the
caller's body (first call to `extra.callee`, else first call passing it as
a value; falls back to the effects clause).

Measurement: over the same 417 files, default loop at `177a173` — 0
widened outputs; statuses clean 287 / not_repaired 32 / stuck 98 (was
clean 315 / stuck 99 / crash 3). `--allow-widen` widens 32 files, every
widening step tagged, none ends `clean`.

### BUG-041  SDK, LSP, fix-loop and tools/scan.py never resolved imports; a cross-file E0801 and an unresolved-import E0705 were "clean" everywhere except `check`  [FIXED 177a173]
test: tests/test_surfaces_agree.py (`::test_cross_file_E0801_on_every_surface`,
`::test_unresolved_import_E0705_on_every_surface`)

Found 2026-09-24 by the audit (D2, P0). Repro (`tool\mf\prog.aeth` imports
`lib.aeth`, whose `exfil` declares `net.fetch("https://evil.example/*")`;
`tool\imp.aeth` imports a file that does not exist): on `52f04aa`
`aether check` → E0801 / E0705; `sdk.check`, the LSP, `tools/scan.py` and
the fix-loop → no diagnostics. `sdk.check`'s docstring claimed "same
membership the CLI runs".

Root cause: only `cli.py` called `resolve_imports`; every other surface
parsed a single file.

Fix (`177a173`): `passes.imports.load_program(source_or_ast, filename, *,
collect, resolve)` → `(ast, parse_diags, import_diags)`, never raising for
lex/parse errors. It is the only loader: CLI `check`/`run`/`emit`/`pack`/
`test` (via `cli._load`), `sdk.check` (so the LSP and the fix-loop), and
`tools/scan.py`. An import error stops before analysis on every surface,
as `check` always did. LSP `uri_to_path` now maps `file:///C:/x%20y.aeth`
to a real path (it sliced `file://` off, leaving `/C:/...` on Windows);
`interFileDependencies` is now advertised true. Both repros now give
E0801 / E0705 on all five surfaces. `sdk.check` docstring rewritten.

### BUG-042  tools/scan.py exited 0 when every file failed to parse, and read a UTF-8 BOM as E0101  [FIXED 177a173]
test: tests/test_surfaces_agree.py (`::test_scan_reads_bom_and_fails_on_parse_errors`)

Found 2026-09-24 by the audit (D3, P0). Repro (`tool\scandir\`: a BOM'd file
`check` rejects for E0801, and an unterminated string): on `52f04aa`
`python tools/scan.py tool/scandir --json` → `files_with_findings: 0,
parse_errors: 2`, exit 0; the BOM file's "parse error" is `[E0101]
unexpected character '\ufeff'`.

Root cause: `scan_file` opened with `utf-8`; `main` counted `parse_errs`
but `failed` ignored them; `parse_error` was prose.

Fix (`177a173`): `utf-8-sig`; load through `load_program`; `parse_error` is
`{code, message, line, column}`; a parse error fails the run (exit 1)
unless `--allow-parse-errors`, in plain and `--expect` mode; parse errors
become SARIF tool-execution notifications; `path` is forward-slashed.

### BUG-043  `--json check` stopped at the first non-empty stage, so surfaces disagreed and an agent needed one round-trip per stage  [FIXED 177a173]
test: tests/test_surfaces_agree.py (`::test_json_check_reports_every_stage_tagged`)

Found by the audit (D4). Repro (`tool\mix.aeth`): `aether --json check` →
E0801 ×2 only; `sdk.check`/LSP/scan → E0801 ×2 + E0713.

Fix (`177a173`): `--json` emits every stage's diagnostics, each tagged
`"stage"` (`effects`, `security`, ...); text mode keeps the short-circuit
and prints `(N more diagnostic(s) from later stages not shown: security 1;
run with --json to see every stage)`. Exit codes unchanged.

### BUG-044  `fmt --write` and the fix-loop deleted every comment, the `// expect:` header included  [FIXED cdf1b02]
test: tests/test_surfaces_agree.py (`::test_fmt_keeps_comments`,
`::test_fmt_check_passes_on_commented_corpus_files`,
`::test_fix_loop_keeps_expect_header_when_it_edits`);
tests/test_pretty_roundtrip.py (`::test_roundtrip_full_corpus`)

Found by the audit (D7). The lexer drops comments and `pretty` printed the
AST only.

Fix (`cdf1b02`, `177a173`): `pretty(ast, source)` re-attaches each run of
full-line `//` comments above the declaration or statement that followed
it (matched by first `pos.line`, so an AST edited in place keeps them) and
keeps the tail block. `fmt` and `sdk.edit` (the fix-loop's edit primitive)
pass the source; the fix-loop writes the input verbatim when it applied
nothing. Still lost (documented on `pretty`): a comment above a `case`
arm, a clause line or inside a multi-line expression, one right before a
block's `end`, trailing `code // comment`, `/* */` blocks. Measured: `fmt
--check` passes on 112 of the 407 parseable `.aeth` files (57 before); 3
still fail only because of such comments.

### BUG-045  the fix-loop overwrote its input with the transcript when the path lacked `.aeth`, and wrote cp1252/CRLF on Windows  [FIXED 177a173]
test: tests/test_fix_loop_cli.py (`::test_outputs_never_overwrite_the_input`)

Found by the audit (D8). `out_tr = args.source.replace(".aeth",
".transcript.json")` is a no-op on `noext`, so the transcript replaced the
input; `open(..., "w")` used the platform encoding and newline.

Fix (`177a173`): `Path.with_suffix`; input, `--out-source` and
`--out-transcript` must be three different files (exit 2 otherwise);
outputs written `encoding="utf-8", newline="\n"`; input read `utf-8-sig`.
`--live`'s default transcript path uses `with_suffix` too and refuses the
input path.

### BUG-046  a lex error made `sdk.check` raise, and the LSP published nothing for the document  [FIXED 177a173]
test: tests/test_surfaces_agree.py (`::test_lex_error_is_a_diagnostic_on_sdk_and_lsp`)

Found by the audit (D9). Repro (`tool\lex.aeth`, unterminated string):
`sdk.check` raised `AetherError`; LSP `didOpen` hit the request boundary's
`except`, logged it and published no diagnostics — the file showed clean.

Fix (`177a173`): `load_program` returns lex errors as diagnostics with
`ast=None`; `sdk.check` keeps its return type and returns `[E0103]`; the
LSP publishes it (and `aether_check_payload` lost its now-dead `except`).

### BUG-047  `fmt` and the fix-loop crashed on every function type (`KeyError: 'ret'`)  [FIXED cdf1b02]
test: tests/test_pretty_roundtrip.py (`::test_function_types_print_as_parsed`,
`::test_roundtrip_full_corpus`)

Found by the audit (A9). `aether --json fmt --check
playground/examples/32_function_typed_param.aeth` → traceback. `pretty`
read `args`/`ret`; the parser emits `params`/`returns`. The round-trip
test sampled 3 directories and missed the file.

Fix (`cdf1b02`): prints `function(<params>) returns <T>`. The round-trip
test now walks every `.aeth` in the repository that parses (407; the 11
that do not are malformed-input fixtures), with and without comment
keeping, and checks idempotence.

### BUG-050  `remove` on a `Set` raises a Python `TypeError`; stdlib.md documents it for `Set<T>`  [FIXED 8722ce6]
test: tests/test_compiler_refuses.py (`::test_bug050_remove_on_set`; fixed in Wave 2, `8722ce6`)

Found 2026-09-24 while writing `tests/test_spec_docs.py` (E4, reading every
documented stdlib signature against `runtime.py`). `grammar/stdlib.md`
documents `remove<T>(s: Set<T>, x: T) returns Set<T>` beside
`remove<K, V>(m: Map<K, V>, k: K)`. The runtime has one `_ae_remove(m, k)`
that does `new = dict(m)` — written for a Map. Repro on `99f09cc` and
`52f04aa`:

    function main() returns Int effects pure do
      let s: Set<Int> = setUnion([1], [2])
      let t = remove(s, 1)
      return size(t)
    end

`check` exit 0; `run` → `TypeError: cannot convert dictionary update
sequence element #0 to a sequence`. (A Set can only be obtained from
`setUnion`/`setIntersection`/`setDifference`/`add`; there is no Set
literal — `{1, 2}` is `E0201`.)

Root cause: `_ae_remove` in `transpiler/aether/runtime.py` handles only
`dict`. Proposed fix (for the wave that owns runtime.py): branch on
`isinstance(m, (set, frozenset))` → `frozenset(m) - {k}`; regression test
in `tests/test_stdlib_d1.py` asserting `remove(setUnion([1],[2]), 1)` has
size 1. Measurement: none needed (no detector touches `remove`).
`grammar/stdlib.md` "Set<T>" now carries a "Known defect" note — delete it
with the fix.

### BUG-055  `for` / `match` binders (and parameters) re-bound a name the safe / stable / authorized proofs had proven  [FIXED c193b21]
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

### BUG-056  effects and injections in `requires` / `ensures`, refinement predicates and `const` initializers were never checked  [FIXED c193b21]
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

### BUG-057  function values laundered effects and capabilities unless they were a bare Ident argument  [FIXED c193b21]
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

### BUG-058  name mangling was not injective and shared the namespace of the runtime's own helpers  [FIXED 8722ce6]
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

### BUG-059  the runtime enforced no capabilities  [FIXED 8722ce6]
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

### BUG-060  a net.fetch glob `*` crossed `/ @ :` in the authority  [FIXED 065ee74]
test: tests/test_compiler_refuses.py (`::test_a7_glob_does_not_span_the_path`,
`::test_a7_glob_does_not_span_userinfo`, `::test_a7_subdomain_and_path_globs_still_cover`)

Audit A7 (`lang/g01`): `https://*.corp.example/*` covered
`https://evil.com/.corp.example/x` (E0801 silent). Fix (`065ee74`): for
URL globs the cover is decided per part of the parsed URL; `*` in the
scheme or authority is `[^/@:?#]*`, in the path `.*`. `.aeth` corpus
200 = 200.

### BUG-061  refinements were checked only on direct `TypeName` parameters  [FIXED b02eafe]
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

### BUG-062  deep input crashed the parser / passes / emitter with a Python traceback  [FIXED eaa5d91]
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

### BUG-065  a non-literal raw SQL string was judged only inside an executor's argument; bound to a name, passed to `Query.filter`/`scalars`/`from_statement`, or built in `.where(...)`, it was silent (false accept)  [FIXED a45ad9d]
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

### BUG-066  a sink reached through a literal dynamic import, a module-level alias, a local builtin alias, `functools.partial` or a dispatch table was silent (false accept)  [FIXED a45ad9d]
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

### BUG-067  builtins reached through the `builtins` module were silent, and `getattr(builtins, "exec")(src)` was reported as SQL injection  [FIXED a45ad9d]
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

### BUG-068  spellings of already-modeled sinks were silent (sink-table gaps)  [FIXED a45ad9d]
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

### BUG-069  E0723 inside an f-string reported line 0, column 0; a credential in a bytes literal was never scanned  [FIXED a45ad9d]
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

### BUG-073  E0714 flagged the documented shell fix — `"ls -l " + shlex.quote(p)`, the f-string form, `" ".join(shlex.quote(a) for a in args)`, `shlex.join` — at 0.95  [FIXED fc05e15]
test: tests/test_py_precision.py (`::test_c1_quoted_pieces_compose`);
tests/test_sink_rows.py (`::test_every_sanitizer_maps_and_its_fix_is_clean`);
tests/test_python_hints.py (`::test_every_python_hint_converges`)

Found 2026-09-24 by the whole-repo audit (C1, P0). Repro on `a60b16e`:
`subprocess.run("ls -l " + shlex.quote(path), shell=True, check=True)` →
E0714 0.95 ("command is built by string concatenation - use shellArg(...)");
the same through an f-string and through `" ".join(<genexpr of
shlex.quote>)` bound to a name; `subprocess.run(shlex.join(["git", "log",
*args]), shell=True)` → E0714 0.95 ("computed call"). The hint names
exactly this fix, so an agent fix-loop cannot converge.
`tests/test_sink_rows.py` pinned it as `KNOWN_FLAGGED_FIX`.

Root cause: `_arg_reason` refused every `+` concatenation without looking
at its operands (`detector_specs.py`), and `shlex.join` / `str.join` were
opaque `py:` calls.

Fix (`fc05e15`): `_concat_reason` judges a `+` tree by its operands. Every
operand a literal or a proven-safe name is a literal for every rule (bans
read per run of adjacent literals). A frontend wrapper call as an operand
is accepted only by a rule with a `pieces` check; E0714's
(`_shell_pieces_ok`) requires the leading literal run to END the
program's word (`"ls" + q` lets the input extend the program name), no
literal word to be a program that runs its argument
(`_CODE_TAKING_PROGRAMS`: shells, `eval`, `env`, `sudo`, `ssh`, `xargs`,
interpreters, `find`, `awk`, ...), and every piece to start outside quotes
and not after `\` or `$`. `sep.join(...)` of a display / comprehension /
`[x] * n` is spelled as the concatenation it builds (`_join_expr`);
`shlex.join` maps to `shellArg` (a piece; a literal list display is spelled
element by element, literals quoted as written, so its literal program is
visible). `{x!r}` / `{x:spec}` and `%r`-style conversions are opaque (repr
re-quotes). Still E0714: the whole command as one quoted word (BUG-034,
now rated 0.6, see BUG-076), `shlex.quote(prog) + " -l"`, `"sh -c " +
shlex.quote(c)`, `"sudo rm " + shlex.quote(p)`, `"ls '" + shlex.quote(p) +
"'"`, `f'echo "{shlex.quote(p)}"'`, `"ls \\" + shlex.quote(p)`, a raw
element in the join.
Measured: framework corpus 0 E0714 changes (no site used the idiom);
probes `cmd_shlex_quote`, `cmd_shlex_quote_fstr`, `cmd_shlex_join`,
`cmd_list_join_shell` 0.95 → clean.

### BUG-074  E0718: no Python spelling cleared it — `redirect(url_for(...))`, `redirect(reverse(...))`, `request.url_for`, Django's allow-list check all fired at 0.95  [FIXED fc05e15]
test: tests/test_py_precision.py (`::test_c2_own_origin_redirects`);
tests/test_sink_rows.py (4 `safeRedirect` pins)

Found 2026-09-24 by the audit (C2, P0). Repro on `a60b16e`:
`return redirect(url_for("index"))`, `redirect(url_for("login",
next=request.path))`, `redirect(reverse("detail", args=[pk]))`,
`RedirectResponse(request.url_for("home"))` with `request: Request`, and
`if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=...): nxt =
"/"` then `redirect(nxt)` → E0718 0.95 each ("target is a computed call -
use safeRedirect(host, path)").

Root cause: no `safeRedirect` entry in `SANITIZER_BY_QUALIFIED`; guards
dominating a redirect were not modeled.

Fix (`fc05e15`): `flask.url_for`, `quart.url_for`, `django.urls.reverse`,
`django.urls.reverse_lazy` → `safeRedirect` (whole-target; they build a
URL of the app's own routes). `django.shortcuts.resolve_url` is
deliberately absent: it returns an absolute URL passed to it as is.
`request.url_for(...)` clears only when `request` is a parameter
annotated, through the imports, as `fastapi.Request` /
`fastapi.requests.Request` / `starlette.requests.Request`; any other
`.url_for` / `.url_path_for` / unresolved bare `url_for` stays a finding
and is marked `own_origin` (rated 0.6, BUG-076). `_redirect_guards`: a
redirect to `x` is cleared when Django's
`url_has_allowed_host_and_scheme(x, ...)` / `is_safe_url(x, ...)` guards it
at the function's own statement level — inside `if check(x):`, or after
`if not check(x):` whose body ends in return/raise/`abort(...)` or rebinds
`x` only to str literals — and `x` is not rebound where guarded.
Measured: framework corpus E0718 5 → 5 — none of the 5 is an own-origin
builder or a Django check (OAuth `redirect_uri` round-trips in
agno/mcp and a storage URL; validated elsewhere, outside the
intraprocedural model); probes `rd_url_for`, `rd_url_for_next`,
`rd_django_reverse`, `rd_fastapi_url_for`, `rd_django_is_safe`,
`rd_referrer_or` 0.95 → clean, `rd_starlette_url_path_for` 0.95 → 0.6.

### BUG-075  E0713/E0719 precision: constants, psycopg `sql`, attribute Tables, IN-list placeholders; Jinja's sandbox and a same-file `from_string`  [FIXED fc05e15]
test: tests/test_py_precision.py (`::test_c3_sql_constants_and_composition`,
`::test_c4_sandbox_and_own_from_string`)

Found 2026-09-24 by the audit (C3, C4, P1). Repro on `a60b16e` (E0713 0.6
unless noted): `TABLE = "users"` then `"SELECT * FROM " + TABLE + " WHERE
id = %s"`; `LIMIT = 10` in an f-string; `"a " + "b"`; class-level `Q =
"..."` read as `self.Q`; module-level `Q = text("... :id")`;
`sql.SQL("... {}").format(sql.Identifier(t))` (psycopg2 and psycopg);
`sess.execute(self.table.delete().where(...))`; `",".join("?" *
len(ids))` / `", ".join(["%s"] * n)`. E0719 0.6 on
`SandboxedEnvironment().from_string(t)` and on `Mode.from_string(s)`
where `Mode` is this file's class with its own `from_string`.

Root cause: `_safe_names` sees only the function body; no constant
folding; psycopg's `sql` module unknown; `_SQL_TABLE_METHODS` accepted a
bare-name receiver only; the by-method `from_string` row had no receiver
exception.

Fix (`fc05e15`): module-level names bound once to a str/int/float literal
inline as that literal (`_scalar_text`), and names bound once to a
sanctioned call (sanitizer row, SQLAlchemy expression, psycopg
composition) read as that wrapper (`_sanctioned_value`); class constants —
UPPER_CASE, bound once in the class body, bound by no other class in the
file, never an attribute-assignment target anywhere (nor `setattr`) —
inline at `self.X` / `cls.X`; literal + literal folds (BUG-073's
`_concat_reason`); `_psycopg_composed` accepts `sql.SQL(<literal>)`,
`Identifier`/`Literal`/`Placeholder`, `.format(...)` / `.join(...)` of
those, `Composed([...])`; the argument-free Table form accepts an
attribute receiver; a `sep.join` over literal elements is literal.
`_sandboxed_env`: `.from_string` on `jinja2.sandbox.SandboxedEnvironment`
/ `ImmutableSandboxedEnvironment` constructed there or bound once is not a
sink. `_own_class_method`: `Cls.m(...)` / `Cls(...).m(...)` where `Cls` is a
top-level class this file binds once with its own `def m` is not a
by-method row (its body is judged where it is defined) — for every
`SINK_BY_METHOD` row, not only `from_string`; `self.m` is not (a subclass
may override).
Measured (framework corpus): E0713 629 → 608 and E0719 26 → 24, every
removal listed under Measurements.
The case rule was added after measurement: the first cut (any case)
removed openhands' `Environment(loader=BaseLoader).from_string(self.prompt)`
through `class MicroAgent: prompt = ''` — a placeholder the registry's
subclasses fill in, i.e. a miss. With UPPER_CASE only it fires again.

### BUG-076  confidence measured the callee, not the argument; Python findings named Aether functions under `category: capability`; C7 small rows  [FIXED fc05e15]
test: tests/test_confidence.py (`::test_argument_shape_demotion_is_output_only`,
`::test_docstring_credential_rates_at_the_floor`,
`::test_sanitizer_name_set_matches_the_frontend`);
tests/test_python_hints.py (`::test_every_python_hint_converges`,
`::test_python_findings_name_no_aether_function`);
tests/test_py_precision.py (`::test_c7_compile_exec_xml_and_docstring`,
`::test_fp_probe_shapes_are_quiet_above_the_floor`)

Found 2026-09-24 by the audit (C5, C6, C7). Repro on `a60b16e`:
`subprocess.run(shlex.quote(path), shell=True)` E0714 0.95 — so
`--min-confidence 0.9` kept the fix-shaped findings; every Python
E0713/E0714/E0718/E0719/E0720/E0731 message said `'sqlQuery'` /
`'shellExec'` / ... and the hint `sqlBind(...)`, `shellArg(...)`,
`safeRedirect(...)`, `schemaDecode(...)`, `trusted(...)`; E0723's hint said
`getEnv("...")`; all `category: "capability"`.
`compile(src, fn, "exec", ast.PyCF_ONLY_AST)` E0731; `code = compile(...)`
then `exec(code)` two E0731s; `AKIAIOSFODNN7EXAMPLE` in a docstring E0723
1.0; stdlib `ET.fromstring(s)` E0727 0.95 while its own text says no XXE.

Fix (`fc05e15`):
- C5: output-only `argument_shape` demotion — a Python finding whose
  judged argument contains a frontend-named sanitizer call
  (`PY_SANITIZER_NAMES`, kept equal to `SANITIZER_BY_QUALIFIED` +
  `sqlBind` by test) or an `own_origin` URL builder rates `FLOOR` (0.6),
  `extra.demoted: "argument_shape"`. The finding set is unchanged.
- C6: each literal-or-wrapper row gets a catch-all Python `CalleeText`
  (prefix `""`): message names `{callee}`, the reason drops its Aether
  remedy (`_py_reason`), the suggestion names a Python fix the frontend
  clears (per code, see `grammar/diagnostics.md`); E0723 on Python
  (`Program.lang == "python"`) names `os.environ["NAME"]`. Python
  findings' `category` is `"security"`; Aether-source findings keep the
  Aether text and `"capability"`. `tests/test_python_hints.py` is the
  plan's LLM-free fix loop: for one repro per code (9 codes incl. E0711
  under --strict) it applies each named fix mechanically and asserts it
  is clean (21 fixes).
- C7: `compile(...)` with `PyCF_ONLY_AST` in its flags is no sink;
  `exec`/`eval` of a LOCAL name bound once to a `compile()` sink is not a
  second finding and the compile rates `builtin` (0.9) like
  `exec(compile(...))` (BUG-030); a stdlib XML parse that cannot have been
  handed a parser (`xml.sax.*`, `expatbuilder`, or ElementTree/minidom/
  pulldom with no 2nd positional / `parser=` / splat) matches as the new
  kind `stdlib_xml` (0.6); an E0723 shape in a bare string statement
  (docstring) rates 0.6, `extra.demoted: "docstring"`.
- AWS example key: option (a) — keep firing on it, rate only the
  docstring case at 0.6. The README demo (`hardcoded_secret_repro.py`,
  the key in code) stays truthful at 1.0 with zero churn; allowlisting it
  would have needed a new push-protection-safe fixture in README, bench
  and two test files.
Measured: framework `--min-confidence 0.9` 55 → 51 (the 4 stdlib
`ET.fromstring`/`parse` sites → 0.6; 0 corpus findings demoted by
argument shape); probes ≥ 0.9: 20 → 6.

### BUG-077  exit codes conflated findings, parse errors, usage errors and crashes; a crash under `--json` was a raw traceback  [FIXED 50ed1f1]
test: tests/test_exit_codes.py (`::test_check_exit_table`,
`::test_check_crash_is_3_and_json_survives`, `::test_check_py_exit_table`,
`::test_check_py_crash_is_3`, `::test_scan_exit_table_and_json`,
`::test_fix_loop_exit_table`, `::test_real_process_exit_codes`);
tests/test_action.py (`::test_scan_step_obeys_the_exit_code_table`)

Found 2026-09-24 by the audit (D5, P1). Repro on `a60b16e`: `aether check
demos/payment_workflow/broken.aeth` → exit 2; `aether check` on a file with
a parse error → exit 2; `aether check nope.aeth` → exit 2; `aether check
--bogus` → exit 2 (argparse); a detector exception → raw traceback, exit 1,
even under `--json`; `aether check-py` → 2 on findings and 2 on a per-file
analyzer crash; `tools/scan.py` → 1 on findings and 1 on parse errors, and
**0 on a path that does not exist** (it globbed nothing). `action.yml`'s
"an analyzer crash always fails the job" was false: the step detected a
crash only as `rc == 2 && findings == 0`, so a crash in one file of a tree
with findings elsewhere passed with `fail-on-findings: false` (reproduced
by running the step's own script against a stand-in `aether` exiting 3 with
two findings: step exit 0).

Root cause: no shared table. Each command returned literal integers; `main`
caught only `AetherError`/`FileNotFoundError`; argparse exited on its own.

Fix (`50ed1f1`): `diagnostics.py` defines the table once —
`EXIT_CLEAN 0 · EXIT_FINDINGS 1 · EXIT_USAGE 2 · EXIT_CRASH 3 ·
EXIT_INCOMPLETE 4` and `exit_code(findings, incomplete, crashed)` (precedence
3 > 1 > 4 > 0) — imported by `cli.py`, `fix_loop.py` and `tools/scan.py`.
`cli.main` wraps everything: argparse errors (a `_Parser` subclass raising
instead of exiting) and in-command usage errors → 2; an escaped
`AetherError` → 4 for lex/parse, 3 for emit/internal, else 1; unreadable
input → 4; any other exception → 3 with a JSON error document under
`--json` (traceback on stderr in text mode or with the new `--debug`).
`check`: a load failure (parse error, E0705/E0706) → 4; findings and E0901
→ 1; `--prove` without z3 → 2. `run`: a runtime contract violation or an
exception raised by the program itself → 1. `fix_loop.main`: a crash in the
loop → 3, unreadable input → 2. `tools/scan.py`: per-file crash wall →
3, unreadable/unparsed → 4 (unless `--allow-parse-errors`), a missing
path → 2. `action.yml` reads the table: 3 always fails, 2 fails, an
incomplete scan (counted from the SARIF's warning notifications, so it is
seen even when findings make the exit 1) fails unless the new
`allow-incomplete: true`; findings stay with the fail-on-findings step.
`aether test` keeps its fixture table (0/1/2) on purpose — `run_all.py` and
`bench/harness.py` grade on it.

### BUG-078  five JSON shapes: `--json check` wrote JSONL to stderr, `check-py --json` said `ok: true` with nothing analysed, `patch_target` existed only in the LSP  [FIXED 50ed1f1]
test: tests/test_exit_codes.py (`::test_check_json_is_one_document_on_stdout`,
`::test_check_py_json_complete_and_ok`, `::test_check_py_no_unprovable`,
`::test_sdk_and_lsp_speak_to_dict`, `::test_sarif_rules_carry_descriptions`)

Found by the audit (D6, P1; D10 partial; survey TC-08). Repro on `a60b16e`:
`aether --json check broken.aeth` → nothing on stdout, three
`{"ok": false, "diagnostic": {...}}` lines on **stderr**; `--collect-errors`
→ the same diagnostics on stdout AND stderr; `check-py --json` on a file
that does not parse → `{"ok": true, ...}`, exit 0; LSP `aether/check` →
`position.col`, no severity/category/confidence; `tools/scan.py` findings
→ their own dict (`line`, `column` top-level), `parse_error` a third shape;
`patch_target` only in the LSP; SARIF rules → `shortDescription` = the bare
code, no description, no help.

Fix (`50ed1f1`): `Diagnostic` gains `stage` (set by every surface
that runs `analyze()`: CLI, `sdk.check`, `check-py`'s `_scan_one`,
`tools/scan.py`; `smt` for E0901/E0902) and `to_dict(ast=None)` always
emits `stage` and `patch_target` (computed by `passes/patch_target.py`,
called, not edited, when an AST is given). Every surface serializes with
it: `check --json`, `--collect-errors`, `check-py --json`,
`sdk.CheckResult.to_dict()` (new, with `complete`), LSP `aether/check` and
`publishDiagnostics` `data`, SARIF, `tools/scan.py` (`to_dict()` + `risk`;
`parse_error` = the parse diagnostic's `to_dict()`). Every `--json` run
prints exactly one document on stdout — usage errors and crashes included
(`{"ok": false, "complete": false, "diagnostics": [], "error": {kind,
message}}`); stderr carries only human text; `aether --json fix-loop`
prints `{ok, complete, status, final, fixed_source, transcript}`.
`check-py --json`: `ok` is exactly "exit 0", new `complete`; new
`--no-unprovable` empties the `unprovable` rows (default unchanged). SARIF:
rules gain `fullDescription`/`help` (the first finding's message and
suggestion) and `helpUri` (`grammar/diagnostics.md`); results gain
`properties.stage`; an analyzer crash is an error notification and
`executionSuccessful: false`. LSP severity now maps warning → 2 (E0902
published as Error before). The Action runs `check-py` once (it ran twice)
and prints the human report from the SARIF. `diagnostics.py` documents the
category enum actually emitted (lex, parse, type, effect, capability,
module, contract, refinement, runtime, timeout, emit, internal); nothing
renamed.

**LSP choice (recorded as asked):** `aether/check` returns the unified
`to_dict()` rows and, for the 0.5.x series only, keeps the old
`position.col` and `data: {suggestion, extra, patch_target}` as aliases;
remove both in 0.6. `tools/alsp_surface.py` and `tools/py_surface.py` build
their own dicts (with `col`) and were not changed (not owned, not
`aether/check`).

### BUG-079  `check-py` exited 0 with `ok: true` when the files could not be parsed — valid 3.12 source scanned on 3.10/3.11 included  [FIXED 50ed1f1]
test: tests/test_exit_codes.py (`::test_newer_python_syntax_is_incomplete_with_hint`,
`::test_check_py_exit_table`); tests/test_py_frontend_sinks.py
(`::test_unreadable_and_skipped_are_visible_in_every_mode`)

Found by the audit (B6, P1). Repro on `a60b16e` under Python 3.11:
`import os\ndef f(d):\n    os.system(f"echo {d["k"]}")` (PEP 701) →
stderr note `could not parse ... f-string: unmatched '['`, stdout
`{"ok": true, "files": [], ...}`, exit 0 — an E0714 missed with a green
result. Same for a PEP 695 `type X = ...` line.

Root cause: the documented policy "unparseable input never fails the run".

Fix (`50ed1f1`): an unreadable/unparsed file makes the run incomplete:
exit 4 when nothing was found, 1 when something was (`complete: false`
either way), in text, `--json` and `--sarif`. On 3.10/3.11 a SyntaxError
whose message starts `f-string` or whose line has a PEP 695 shape
(`type X =`, `def f[T]`, `class C[T]`) gets "— valid on a newer Python?
scan with 3.12+ (this is Python 3.x)" appended to its detail (stderr,
JSON, SARIF). A heuristic on the error text, hence the question mark: a
genuinely malformed f-string on 3.11 gets the hint too; py2 `print 'x'`
does not. Verified on 3.13: the PEP 701 repro parses and exits 1 (E0714).

### BUG-080  Every detector re-walked every function; on Python half the analysis time went to eight marker rows that cannot fire there  [FIXED 5bd1334]
test: tests/test_perf_index.py (`::test_walk_budget_per_function`,
`::test_marker_skip_is_output_identical`, `::test_shared_index_is_output_identical`)

Found 2026-09-24 by the architecture audit (F5, P2). Measured on
`0653115`: `check-py --jobs 1` over the framework corpus (4,946 files)
365.9 s wall; in-process, 94.8 s frontend + 249.1 s analysis. cProfile on
the three slowest files (`agno/workflow/workflow.py`,
`browser_use/beta/service.py`, `agno/db/postgres/postgres.py`): 5.38M
`walk()` frames, 28.5 of 37.2 s under the profiler; `binders()` alone
22.8 s. Per detector (same three files, 7.36 s): E0730 12.6%, E0729 12.4%,
the six marker-flow rows ~4.2% each (≈ 50% together), each
literal-or-wrapper row ~4.5%.

Root cause: `contexts()`, `binders()` and `walk(fn_exprs(d), "Call")` are
recomputed by each of ~25 detectors per function (`_safe_names` alone
walked the binders twice per row); and the marker rows (E0712, E0715,
E0724, E0725, E0726, E0728, E0729, E0730) ran their whole per-function
fixpoint even when the program has no marker type and no marker
constructor, which is every Python program (the frontend emits neither).
Their early-exit guard `not tainted and not src_l and not mfields` never
fired because `src_l` always holds the stdlib constructors.

Fix (`5bd1334`): `passes/ast_walk.py` gains `shared_index()`, entered by
`passes.analyze()`: `contexts()`, `binders()`, a new `fn_calls()`,
`all_nodes()` and `names_in()` are computed once per node per analysis
(keyed by node identity, the node kept in the entry and compared with
`is`, so a recycled `id` cannot alias; scoped to one `analyze()` call,
so a detector called directly is uncached exactly as before). Every
`walk(fn_exprs(d), "Call")` in the passes now reads `fn_calls(d)`.
`detector_specs.marker_absent(ast, marker)` is True when no node anywhere
is named the marker or one of its stdlib constructors (`classify`,
`classifyPII`, `classifyUntrusted`); then every input the row reads
(carriers, marked params/fields/annotations, source functions other than
the constructors, aliases of them) is empty, no name is tainted and no
leak test can succeed, so the six marker-flow rows, E0729 and E0730 skip
it — output-identical by construction, checked by forcing them to run on
every corpus `.aeth` and a Python module. E0716 obligations 2 and 3 skip
when there is no `Authorized` anywhere / no gated function (they could
yield nothing). E0723's literal scan reads `all_nodes()`.

Measurement: walks per function on a 40-function Python module 97 → 14.
The three slowest files, analysis only: 7.36 s → 0.48 s. Output
byte-identical (see Measurements).

### BUG-081  The Python frontend re-walked each function six times for its bindings  [FIXED 2c65c12]
test: tests/test_perf_index.py (the framework-corpus byte-identity is the
check; the timing is in Measurements — no walk-count test pins it)

Found 2026-09-25 by this wave's profile after BUG-080: with analysis cut
to ~20 s, the frontend was the top hotspot. `_bindings_of` was 8.5 of
14.2 s of frontend time on the three slowest files (4,011 calls for
668 functions): its call sites in `py_frontend.py` (binding tables, the
alias resolver, the XML parser binder, the guard scan, parameter seeding,
the per-def counts) each re-walked the same function's Python AST.

Fix (`2c65c12`): `_bindings_of` is memoized per node while `py_to_ir`
translates the `def`s (a `ContextVar` set around that loop only). The
scope phase then strips `def`s out of class and module nodes in place
(`_ScopeStripper`), which would make a cached entry stale, so nothing is
cached there. Callers get a fresh list each time. Frontend on the three
slowest files 2.8 s → 1.7 s; framework-corpus JSON byte-identical.

### BUG-082  E0801 pointed at the function declaration, not the offending call; Aether `Call` and `ExprStmt` had no position  [FIXED 881a3b5]
test: tests/test_call_positions.py (all five)

Found 2026-09-24 by the tool auditor (D10, P2); deferred by Wave 5a
(`parser.py` outside its set). Repro on `0653115`:

    function main() returns Unit
      effects pure
    do
      let x = 1
      print("one")
      if x > 0 then
        print("two")
      end
    end

→ two E0801, both at `1:1`, and `compute_patch_target` sent both to the
first `print`. A dead `print(...)` after `return` was reported (E0204) on
the `return` line; `fmt` dropped a comment above a bare call with no
literal in it (nothing on that line carried a position).

Root cause: `parser.py` built `{"kind": "Call", "func", "args"}` and
`{"kind": "ExprStmt", "expr"}` with no `pos`, so every driver fell back to
the declaration's; `check_effects` used the declaration's position even
where a call position existed.

Fix (`881a3b5`): `Call` carries the position of the first token of its
callee expression (`_parse_postfix` records it before the primary — a
chain `a.b(c)(d)` shares one start); `ExprStmt` the statement's first
token. E0801 is reported at the call (the declaration only for an
unpositioned call — none from the parser now), for the direct,
function-value and unknown-callee variants alike. `_patch_E0801` takes the
call at the reported position (the one whose callee is `callee` when a
chain shares the start), then falls back to the old first-by-name search.
Everything that already read `call.get("pos") or <decl pos>` moves to
the call without code change. E0701 stays at the declaration on purpose:
it is a per-function aggregate over the transitive effect closure, not a
per-call finding. `parse(pretty(parse(src))) == parse(src)` still holds
(`asts_equal_ignoring_pos` strips `pos`); `pretty` gains anchor lines,
which only lets it keep comments it used to drop.

Measurement: every tracked `.aeth` (418) through `check --json --no-prove`
before/after: 98 outputs change, 113 positions move, codes and exit codes
identical in all 418 (list below). Python (`check-py`, framework corpus
and in-repo trees, default and `--strict`) byte-identical — the frontend
already positioned its calls.

### BUG-083  `effects pure, log` passed `check` and failed `--effect-strict`  [FIXED 881a3b5]
test: tests/test_module_validation.py (`::test_A11_pure_alongside_other_effects_is_a_parse_error`)

Found 2026-09-24 by the language auditor (A11, P2; repro
`scratchpad\lang\e06_pure_plus.aeth`). The static checker read the clause
as `{log}` (`pure` is the empty path set), the runtime as `pure` (E0501 on
the first `print`) — the two disagreed on what the function may do.

Root cause: `parse_effect_list` accepted `pure` as one element of any
list (`grammar.ebnf`: `effect = "pure" | dotted_ident ...`).

Fix (`881a3b5`): a list of more than one effect containing `pure` is
E0201 at the `pure` token ("'pure' declares no effects and cannot be
combined with other effects"), in either order. The corpus never writes
it (0 of 418 files). E0201 row text updated.

### BUG-084  An effect naming an unknown capability was accepted silently  [FIXED 881a3b5]
test: tests/test_module_validation.py (`::test_A11_effect_with_unknown_capability_is_E0704`)

Found 2026-09-24 by the language auditor (A11). Repro: `effects log,
bogus.effect, fs` in a module-less program → `check` OK. Under a module it
surfaced only as E0701 against a capability (`bogus`) that E0704 forbids a
module to declare — a requirement no program can ever satisfy, reported
as if it were a missing grant.

Root cause: nothing validated effect names; `effect_capability()` maps an
effect to its first path segment and nobody checked that segment.

Fix (`881a3b5`): `check_modules` (modules stage, runs with or without a
module) reports E0704 for an effect in Aether source whose first path
segment is not in `_KNOWN_CAPABILITIES` (and is not `pure`), positioned
at the function, `extra` = `function`, `effect`, `capability`, `known`.
Existing code, row extended; no new code. A known head with any tail
(`fs.delete`) stays a declaration — `grammar/effects.md` says any other
dotted path is accepted. Python ASTs (`lang == "python"`) are skipped:
their effects are inferred by the frontend, which emits `env` and
`process` heads outside the vocabulary (0 new Python findings, measured).
Corpus: 0 new findings (every declared head in the 407 parseable files is
`db`, `exec`, `fs`, `log`, `net`, `time` or `pure`).

### BUG-090  `aether --json run` breaks the one-document contract: the program's stdout precedes (or replaces) the JSON  [FIXED 6ece638]
test: tests/test_exit_codes.py::test_run_json_captures_the_program_output

Repro on `a2f13db` (the program prints a line that looks like JSON):

    function main() returns Unit
      effects log
    do
      print("{\"ok\": true, \"fake\": 1}")
      print("hello")
    end

`aether --json run p.aeth` → stdout is the program's two lines and
**nothing else**, exit 0: a clean run printed no document at all, and the
first line parses as `{"ok": true}`. With a `requires` violation after a
`print`, stdout was the program's line followed by the diagnostic document
(two JSON-looking lines; `json.loads` → "Extra data"). With an exception
the program raised (`10 / 0`), stdout was the program's output, the
traceback went to stderr, exit 1, and no document was printed.

Root cause: `cli.cmd_run` executed the program with stdout attached to
the process, reported only through `main`'s `AetherError` handler, and
returned `0`/`1` on the other paths without calling `_report`.

Fix (`transpiler/aether/cli.py`): under `--json`, `cmd_run` redirects the
program's stdout and stderr into buffers and every `run` document gets
`stdout` and `stderr` fields. `_report` merges `args.run_output`, which
`cmd_run` sets, so the parse/import-failure document, the static-finding
document and the runtime-violation document raised through `main` all
carry the two keys (`""` when the program never started). A clean run now
prints `{ok: true, complete: true, diagnostics: [], stdout, stderr}`. An
exception the program raised is reported as the documented `E9003`
(category `runtime`, the code the in-process runner already used), with
the traceback in `stderr`. `sdk.RunResult.to_dict()` (new) returns the
same keys; the test asserts the CLI document equals it for a clean
program. Exit codes are unchanged: 0 ran clean, 1 static finding /
E03xx / program exception. Text mode is unchanged (asserted).

Red before the fix: the new test fails with `JSONDecodeError: Extra data:
line 2 column 1` (cli.py and sdk.py reverted, test kept: 13/14).

Measurement: no detector or frontend change; framework corpus `--json
check-py` output byte-identical (below).

### BUG-091  stdlib.md parameter lists drifted from the runtime in six functions; no test compared signatures  [FIXED 5809adb]
test: tests/test_spec_docs.py::test_stdlib_doc_signatures_match_runtime

`tests/test_spec_docs.py` checked that every documented stdlib name
exists in the runtime, but not its signature, so a documented parameter
list could drift and a documented overload could crash (BUG-050: `remove`
on a Set). The new test reads every `function` signature in
`grammar/stdlib.md` (120 signatures, 115 names) and checks
`inspect.signature(build_namespace()[mangle(name)])`:

- **arity**, for every signature, overloads included: **0 drifts**.
- **parameter names in order**, for each of the 110 names documented
  once. Aether has no named arguments, so ORDER is the contract and equal
  names are how a test can see a swap. One documented name Python cannot
  spell (`replace`'s `from` → runtime `frm`) is allow-listed. **6
  drifts found**:

  | function | stdlib.md | runtime before |
  |---|---|---|
  | `startsWith?` | `(s, prefix)` | `(s, p)` |
  | `endsWith?` | `(s, suffix)` | `(s, p)` |
  | `reveal` | `(s)` | `(x)` |
  | `csvEscape` | `(x)` | `(v)` |
  | `redirect` | `(target)` | `(url)` |
  | `pow` | `(base, exp)` | `(a, b)` |

  None is a positional-order drift: the runtime used different names in
  the same positions. Fixed in the runtime (the spec is the reference):
  parameters renamed, bodies unchanged. No behaviour change is possible:
  Aether calls are positional, the emitter emits positional calls, and a
  grep finds no caller of these helpers outside the emitted code.
- **every overload documented for several types runs**: the test
  derives the overload set from the doc (`length` on List/String, `get` on
  List/Map, `size` on Map/Set, `remove` on Map/Set, `contains?` on
  Set/String: 10) and requires a probe program for each; each is run
  through `sdk.run` and its stdout compared. **0 failures** on `a2f13db`:
  BUG-050's fix (8722ce6) holds. A new overload without a probe fails the
  test.

Red before the fix: on `a2f13db`'s runtime the test fails listing the six
drifts above. The probe half on a deliberately broken copy (the
pre-BUG-050 Map-only `_ae_remove` monkeypatched in) fails with
`remove on Set: ... runtime error: TypeError: cannot convert dictionary
update sequence element #0 to a sequence`.

Measurement: runtime-only rename; framework corpus output byte-identical.

### BUG-085  A second `effects` clause silently replaced the first  [FIXED abb964c]
test: tests/test_static_effects.py (`::test_repeated_effects_clause_is_a_parse_error`)

Found 2026-09-24 while probing audit A11 (Wave 7 record, q1 row
"effect names are validated by capability head only"); fixed in the
2026-09-29 known-gaps round (G2). Repro: `function f(x: Int) returns Int
effects log ... effects pure do ... end`. `check` read it as `pure`: the
declared `log` was gone, with no diagnostic.

Root cause: `Parser.parse_function_decl` loops over interleaved
`requires` / `ensures` / `effects` clauses and assigned
`effects = self.parse_effect_list()` on every `effects`, so the last one
won. `grammar.ebnf` has exactly one `effects_clause`.

Fix (`abb964c`): a second `effects` keyword in one declaration is E0201 at
that keyword ("function 'f' has more than one 'effects' clause", hint:
merge them into one list). Repeated `requires` / `ensures` stay legal —
`{ contract_clause }` in the grammar, each checked at runtime. The EBNF
now spells out that contract clauses may follow the effects clause (the
parser always accepted that): `{ contract_clause } effects_clause
{ contract_clause }`. E0201 row text extended; no new code.
Measurement: 0 of 418 tracked `.aeth` files repeat the clause; the
`check --json` output of all 418 is unchanged.

### BUG-086  A reference to an undeclared name passed `check`; a misspelt sink hid the injection  [FIXED abb964c]
test: tests/test_name_resolution.py (`::test_misspelt_sink_is_E0208`, `::test_undeclared_call_and_value`, `::test_block_scoping_and_shadowing`, `::test_const_sees_only_earlier_decls`)

Found 2026-09-24 by the language auditor (A8); recorded in Wave 6 as a
scope fact (q1, iter-57). Known-gaps round G3. Repro:
`sqlQeury("SELECT * FROM users WHERE name = '" + u + "'")` → `check`
exit 0, no E0713; `run` → Python `NameError`. `frobnicate(1)`, never
declared: `check` exit 0. Also found while building the fix:
`const A: Int = B` above `const B: Int = 1` → `check` exit 0, `run`
`NameError: name '_ae_B' is not defined` at module load.

Root cause: no pass resolved names. The emitter mangles every
identifier and runs the program against the runtime's `_ae_*` exports
plus the program's own definitions, so an unbound name only surfaced
when Python reached it; the taint passes match sinks by name, so a sink
they cannot name is invisible to them.

Fix (`abb964c`, `710e79c`): new static-semantic code **E0208** "reference
to an undeclared name", `transpiler/aether/passes/names.py`
(`check_name_resolution`), registered in the `semantic` stage. A name
resolves if it is a parameter (`self` in a refinement predicate, `result`
in `ensures`), a local bound earlier in the same or an enclosing block
(`let` / `var` / assignment / `for` variable / `match` pattern
bindings — the binder kinds of `ast_walk.binders()`), a top-level
function / `const` / record / union case (imports fused in by
`load_program`; inside a `const` initializer, only one declared above
it), or a runtime export (`runtime.unmangle` over `vars(runtime)`: 119
names, derived, not listed). Not resolved because not evaluated: the
right side of `is`, the qualifier of `Union.Case(...)`, patterns, type
annotations, `effects` arguments. `extra` = `function`, `name`, `kind`
(`call` | `value`), `suggestion` (closest known name by
`difflib.get_close_matches`, or null). Positioned at the nearest
positioned ancestor (the call, or the statement) — `Ident` nodes carry no
position and the AST shape was not changed. Silent on a program it
cannot see whole: `parse_collect` marks a partial AST `partial`, and
`resolve_imports` marks its combined program `imports_resolved`; a
program with an `ImportDecl` but no mark (`--no-import-resolution`, or a
caller that parsed without `load_program`) gets no E0208.
This is name resolution, not type checking (`grammar/types.md` says so).

Measurement: see Measurements — 0 new diagnostics on the in-repo `.aeth`
corpus, `check-py` byte-identical.

### BUG-095  The Python frontend walked every file about seven times  [FIXED 5ae433f]
test: tests/test_perf_index.py (`::test_frontend_walks_each_scope_once`);
the byte-identity of `--json check-py` over the framework corpus and the
in-repo trees is the output check (Measurements)

Found 2026-09-25 by Wave 7 (LOOP_LOG iteration 62, "TYPE gap surfaced": the
frontend was ~75% of `check-py` time). Measured on `a2f13db`: on the three
slowest framework files (`agno/workflow/workflow.py`,
`browser_use/beta/service.py`, `agno/db/postgres/postgres.py`; 151,204 AST
nodes together) the frontend's `ast.walk` calls yielded 1,068,633 nodes, 7.1
per AST node: the imports, the module's bindings and its attribute
assignments were three module-level walks, then each `def` was walked for
its bindings, its calls, its statements and, per statement, for walrus
targets. On the 40-function module in `tests/test_perf_index.py`: 6.8 walked
nodes per AST node.

Root cause: each per-def consumer (`_bindings_of`, the `visit_call` loop, the
`visit_stmt` loop, `_walrus_lets`) and each module-level fact walked the
node itself; Wave 7's `_bindings_of` memo removed only the repeated binding
walks.

Fix (`5ae433f`): `_DefIndex(node)` builds a scope's bindings, its Call nodes
and its statement nodes (both in `ast.walk`'s breadth-first order, which is
the order the two passes visited them in) and a has-walrus flag in one walk;
the consumers take the bindings list; `_walrus_lets` returns at once when the
scope has no `:=`. The module-level imports, bindings and attribute
assignments share one walk. The two one-finding-per-flow fixes over the
translated IR (`_dedupe_bound_raw_entries`, `_rerate_bound_compiles`) became
`_fix_bound_flows`, one walk of the IR (the second never names a call the
first renames). `_walk` is `ast.walk` without its two generator layers per
node, same order (checked on 800 corpus files). The `_bindings_of` memo and
its `ContextVar` are gone.

Measurement: walked nodes on the three files 1,068,633 → 342,117; on the
test module 6.8 → under 3 per AST node. Frontend on the three files,
min of 5 interleaved runs: 1.78 s → 1.09 s. Frontend over the whole corpus,
in-process: 76.1 s → 46.2 s. `--json check-py` byte-identical (below).

### BUG-096  Argument injection through an argv list was silent: `subprocess.run(["git", "clone", url])`, `["git", "-c", x]`, `["ssh", host, cmd]`, `["tar", "--to-command", x]`, `asyncio.create_subprocess_exec("git", *args)`  [FIXED 9c8014d]
test: tests/test_py_frontend_sinks.py
(`::test_argv_option_injection_is_a_command_injection`);
tests/test_sink_rows.py (`::test_every_argv_program_flags_and_clears`)

Found 2026-09-24 by Wave 5a (LOOP_LOG iteration 60, "TYPE gap surfaced"; q1
row "a quoted shell piece is accepted by a program LIST"). Repro on
`5ae433f`: a module with `subprocess.run(['git', '-c', x, 'log'])`,
`subprocess.run(['git', 'clone', url, 'dest'])`,
`subprocess.run(['ssh', host, 'uptime'])`,
`subprocess.run(['tar', '--to-command', x, '-xf', 'a.tar'])` and
`await asyncio.create_subprocess_exec('git', *args)` → `check-py` exit 0,
0 findings. All 16 flagged shapes in the new test were silent.

Root cause: the argv form is the `shell=` guard's sanctioned exit, and only
`["bash", "-c", cmd]` (BUG-021) was recognised as still running code. A
program that runs code through an OPTION takes that option from any word
the input supplies: a clone URL `--upload-pack=touch /tmp/x` (GitPython
CVE-2022-24439), an ssh host `-oProxyCommand=...` (git CVE-2017-1000117).
No shell is involved, so quoting the word does not help.

Fix (`9c8014d`): `_ARGV_CODE_OPTIONS` names six programs and their
code-running options — git (`-c`, `--config`, `--config-env`,
`--upload-pack`, `-u`, `--receive-pack`, `--exec`), ssh (options, host,
remote command), tar (`--to-command`, `--checkpoint-action`,
`--use-compress-program`, `-I`, `--info-script`, `-F`, `--new-volume-script`,
`--rsh-command`), find (`-exec`, `-execdir`, `-ok`, `-okdir`), rsync (`-e`,
`--rsh`, `--rsync-path`), zip (`-T`, `-TT`, `--unzip-command`). An argv
whose program word (literal, a name bound only to literals, basename,
`.exe` dropped) is one of them, handed a non-literal word before a literal
`--`, is `shellExec` (E0714, match `argv`, 0.9), and that word is the judged
argument. The argv is a subprocess runner's first argument or `args=`, a
list/tuple display, a name bound once to one, or `[...] + x`; or the
positional arguments of `asyncio.create_subprocess_exec`. `--` does not
clear ssh (the words after the host run in the remote shell) or find
(every word is its expression). A constant of any type is literal (`-n 5`).
`shlex.quote(x)` as the word stays a finding (the `py_whole` reason: it is
not the exit here). `mapping_table()` publishes the table as
`argv_option_programs`. The option lists are for the record, the pins and
`mapping_table()`; the rule judges EVERY non-literal word before `--`,
because such a word can be any of the options.

Measurement: framework corpus 683 → 684, +1 / −0 (agno `git *args`
wrapper, true by rule); `--min-confidence 0.9` 51 → 52. In-repo trees
107 → 113, +6 / −0 (list and triage below). No kept finding changed.
