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

### BUG-004  three sink guards defaulted "unknown" to "safe" (false accepts)  [FIXED 6606fe1]
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
