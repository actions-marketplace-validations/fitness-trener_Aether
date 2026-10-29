# Wave 5a record — stop flagging the fix; findings speak Python (iteration 60)

Plan: `audits/audit_2026-09-24_plan.md` §C, Wave 5 items 1–3 (C1–C7) plus
BUG-039 and D10. Exit codes / JSON contract (D5/D6/D9) are Wave 5b's.
Branch forked from `v0.5-audit-waves` @ `a60b16e`; every "before" below is
`a60b16e`. Ids: BUG-073..076, iteration 60.

Commits:
- `fc05e15` fix(py): stop flagging the fix; findings speak Python (audit C1-C7, BUG-039)
- this record

Files changed (all inside the wave's ownership list):
`transpiler/aether/py_frontend.py`, `transpiler/aether/passes/detector_specs.py`,
`transpiler/aether/passes/effects.py` (E0723 wording/rating only),
`transpiler/aether/confidence.py`, `grammar/diagnostics.md` (field/hint
text, no new code), `tests/test_sink_rows.py`, `tests/test_confidence.py`,
`tests/test_py_frontend_sinks.py`, `tests/ratchet_baseline.json`
(`min_py_table_rows` 121 → 128), new `tests/test_py_precision.py`, new
`tests/test_python_hints.py`. Not touched: `cli.py`, `sarif.py`, `sdk.py`,
`lsp.py`, `diagnostics.py`, `tools/scan.py`, `action.yml`,
`patch_target.py`, README, BUGS.md, LOOP_LOG, vault.

Red first: every item was reproduced on `a60b16e` with the precision
auditor's probes (`scratchpad\fp\p\*.py`, `p2\*.py`, 108 files: 37
findings, 20 of them at ≥ 0.9) plus 56 adversarial near-miss shapes
(`scratchpad\w5a\neg.py`). The new tests were copied into an `a60b16e`
tree and run function by function: all 7 of `test_py_precision.py`, 2 of 3
of `test_python_hints.py` (the third, `test_aether_source_keeps_its_wording`,
guards behaviour that must NOT change and passes on both sides), the 3 new
`test_confidence.py` tests, and `test_sink_rows.py::test_every_row_is_pinned`
/ `::test_every_sanitizer_maps_and_its_fix_is_clean` FAIL there; all pass
at `fc05e15`.

## BUGS entries

### BUG-073  E0714 flagged the documented shell fix — `"ls -l " + shlex.quote(p)`, the f-string form, `" ".join(shlex.quote(a) for a in args)`, `shlex.join` — at 0.95  [OPEN]
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

### BUG-074  E0718: no Python spelling cleared it — `redirect(url_for(...))`, `redirect(reverse(...))`, `request.url_for`, Django's allow-list check all fired at 0.95  [OPEN]
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

### BUG-075  E0713/E0719 precision: constants, psycopg `sql`, attribute Tables, IN-list placeholders; Jinja's sandbox and a same-file `from_string`  [OPEN]
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

### BUG-076  confidence measured the callee, not the argument; Python findings named Aether functions under `category: capability`; C7 small rows  [OPEN]
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

### BUG-039 closure (coordinator: stamp the existing entry)
`[FIXED fc05e15]`, test: tests/test_py_precision.py
(`::test_bug039_secure_filename_join`); tests/test_python_hints.py (E0711
`os.path.join(BASE_DIR, secure_filename(name))`). Fix:
`_sanitized_path_join` — `os.path.join` / `posixpath.join` /
`ntpath.join` whose LAST argument is a safeJoin-row call (no splat, no
keywords) is `safeJoin`; `werkzeug.utils.safe_join` /
`werkzeug.security.safe_join` added as safeJoin rows (the E0711 hint's
fix). `os.path.join(base, user)` and a sanitized part that is not the last
one stay E0711. Measured: `--strict` framework E0711 310 → 310 (no corpus
site); the BUG-039 repro shapes 2 × E0711 → clean.

## LOOP_LOG block

## Iteration 60 — Wave 5a of the 2026-09-24 audit: stop flagging the fix; findings speak Python (no new detector)

- **Target:** not a backlog row. Plan Wave 5 items 1–3 (C1–C7) + BUG-039:
  the checker flagged the remediation its own hint names, so an agent
  fix-loop could not converge, and a Python finding named Aether
  functions a Python user cannot call.
- **Probe-confirmed first (on `a60b16e`):** 108 precision-auditor probes
  gave 37 findings (20 at ≥ 0.9) — `"ls -l " + shlex.quote(p)`,
  `redirect(url_for(...))`, psycopg `sql`, module/class constants,
  `self.table.delete()`, `SandboxedEnvironment().from_string`,
  `compile(..., PyCF_ONLY_AST)`, the docstring example key; plus BUG-039.
- **Fixes (each once, where every caller routes through):** a `+`
  concatenation is judged by its operands (`_concat_reason`; shell pieces
  by `_shell_pieces_ok`); joins spelled as the concatenation they build;
  own-origin URL builders and Django's check (`_redirect_guards`);
  module/class constants and psycopg composition; receiver exceptions on
  the by-method rows; output-only `argument_shape` / `docstring` /
  `stdlib_xml` ratings; a Python `CalleeText` per row + `category:
  security`.
- **Measured:** framework corpus (4,946 files) 707 → 683, −24 / +0, every
  removal a documented safe idiom (21 E0713, 2 E0719, 1 E0731), 4
  confidence changes (stdlib XML → 0.6), 0 errors / 0 unparseable;
  `--min-confidence 0.9` 55 → 51; `--strict` 1,017 → 993 (E0711 310
  unchanged). In-repo trees 115 → 107: 8 `code = compile(...); exec(code)`
  pairs in tests now report once. Probes 37 → 11 findings, ≥ 0.9 20 → 6.
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** argument injection. The argv form
  and the quoted-concat form now agree that a quoted word is safe unless
  the program runs it, but "runs it" is a program list, not a model:
  `git -c core.pager=...`, `ssh host <cmd>` spelled with an absolute path
  under another name, `tar --to-command` are accepted in both forms. A
  per-program argument-semantics row (which flags take code) is the
  next lever — measure the corpus's argv programs first (q3).
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally); two new suites
  (`py_precision`, `python_hints`).

## q1 rows

| NEW residual: a quoted shell piece is accepted by a program LIST, not a model of the program | iter-60 (Wave 5a, audit C1): `"<literal program> ... " + shlex.quote(x)` is clean unless a literal word is in `_CODE_TAKING_PROGRAMS` (shells, eval/exec/source, env, xargs, sudo/su/doas, ssh, nohup, timeout, nice, python/perl/ruby/node/php, awk, find). A program outside it that interprets an argument as code (`git -c core.pager=...`, `tar --to-command=`, an interpreter under another name) accepts the quoted word silently — the same limit the argv form `subprocess.run(["git", "-c", x])` already had. A quoted piece reached through a name (`q = shlex.quote(p); "ls " + q`) is refused — over-flag `[source: diagnostics, section: E0714, key: shellExec]` | medium |
| NEW residual: class constants are trusted by the UPPER_CASE convention | iter-60 (audit C3): `self.Q` / `cls.Q` inlines a class body's literal when `Q` is UPPER_CASE, bound once there and by no other class in the file, and never assigned as an attribute anywhere in it. A subclass in ANOTHER file (or built with `type(...)`) overriding `Q` with a computed value is not seen — a miss; a lower-case placeholder (`prompt = ''`, measured: openhands' MicroAgent) stays a name. Module-level constants (now str/int/float, and names bound once to a sanctioned call) carry the existing limit: rebinding from another module or through `globals()` is not seen `[source: diagnostics, section: E0713, key: sqlQuery]` | medium |
| NEW residual: E0718's clears trust the builder and the check, not their arguments | iter-60 (audit C2): `url_for`/`reverse` clear whatever endpoint and values they get (they cannot leave the app's routes; `_external=True` uses the request's own host). `url_has_allowed_host_and_scheme(x, allowed_hosts=H)` clears a dominated redirect to `x` without judging `H` — an attacker-influenced `allowed_hosts` defeats it silently. The check is recognised only at the function's own statement level (not under another `if`, a loop or a helper), and only Django's two spellings; a hand-rolled `urlparse(x).netloc` check stays a 0.95 finding. `request.url_for` clears only on a parameter annotated as a Starlette/FastAPI Request; unannotated it rates 0.6 `[source: diagnostics, section: E0718, key: redirect]` | medium |
| NEW residual: Jinja's sandbox clears E0719 regardless of Jinja version | iter-60 (audit C4): `SandboxedEnvironment` / `ImmutableSandboxedEnvironment` constructed in scope or bound once make `.from_string(x)` no sink — the documented control, not a proof; the sandbox has had breakouts (CVE-2024-56326 among them) fixed in later 3.1.x releases, which no row judges (torch's `weights_only` carries the same shape). A same-file class's own method is not the by-method row for ANY `SINK_BY_METHOD` name `[source: diagnostics, section: E0719, key: renderTemplate]` | medium |
| NEW residual: the argument-shape demotion reads the whole judged argument | iter-60 (audit C5): a sanitizer call anywhere in the judged argument — receiver chains and carried parts included — rates the finding 0.6. `pandas.read_sql(select(t).order_by(f"{c}"), con)` (a real injection behind a qualified executor) would rate 0.6 because `select(t)` is a sanctioned receiver; 0 framework-corpus findings were demoted by it. Output-only: the finding stands `[source: README, section: Python, key: check-py]` | low |

## Skipped / not reproduced / deferred

- **D10 (E0801 at the call site) — deferred, needs a file outside Wave
  5a's set.** Reproduced: E0801 is positioned at the function decl. It
  cannot be moved in `passes/effects.py` alone: Aether `Call` nodes
  (`parser.py:686`) and `ExprStmt` nodes (`parser.py:469`, the `print(x)`
  statement E0801 most often names) carry no position at all. Adding one
  in the parser also moves every Aether-source literal-or-wrapper and
  marker-flow finding (their drivers read `call.get("pos")` before the
  decl's), and `pretty.py` places comments by positioned children — a
  cross-cutting change for the coordinator to schedule (parser + the
  `tests/alsp_corpus/*.expected.json` positions), not a precision-wave
  edit.
- **`category: "security"` needs a `diagnostics.py` enum entry** (Wave
  5b's file). Nothing in the tree consumes `category` programmatically
  (SARIF, `risk.py`, `tools/scan.py` do not read it; CLI text and LSP pass
  it through), and no test pins `"capability"` on a Python finding. If 5b
  lands a check that every emitted category is in the documented enum,
  add `security` to it at merge.
- **README (coordinator's file) — sentences this wave changes:**
  (1) the `subprocess_repro.py` demo line becomes `[E0714] error
  (security) at line 18, col 12: function 'make_thumbnail' builds a shell
  command for subprocess.call unsafely ...`; (2) the
  `hardcoded_secret_repro.py` demo line becomes `[E0723] error
  (security) ...` (the finding, line and column are unchanged: option (a)
  keeps the AWS example key firing in code); (3) the `--min-confidence
  0.9` sentence ("628 of 676") — at this build the default run is 683
  findings, 51 at ≥ 0.9, so 632 of 683 are hidden; (4) the gate count
  gains two suites (`py_precision`, `python_hints`).
- **E0716 on Python `.executescript`** keeps its Aether wording (not in
  the C6 code list; it is a documented quirk of the SQL row, not a
  Python-fixable finding).
- **Not in scope, left as found:** `rd_allowlist` (hand-rolled
  `urlparse(x).netloc` check, E0718 0.95), `de_pickle_hmac` (HMAC-verified
  pickle, E0720 0.95), `de_pickle_local_cache` (literal cache path, E0720
  0.95), `code_exec_version_file` (`exec(open(...).read())`, E0731 0.9),
  `cr_aws_example_kw` (the example key in code, E0723 1.0 by option (a)).
- **The 5 framework E0718s are not cleared:** none is an own-origin
  builder or a Django check (see BUG-074). The audit's "5/5 corpus E0718s
  are not open redirects" stays true and stays reported; clearing them
  needs cross-function validation (the OAuth client's registered
  `redirect_uri`), outside the intraprocedural model.

## Measurements

- **Framework corpus** (`bench/framework_scan/_work/src`, 4,946 files,
  `check-py --json`, same interpreter): `a60b16e` **707** → `fc05e15`
  **683** (−24, +0); 0 errors / 0 unparseable both sides. By code: E0713
  629 → 608, E0719 26 → 24, E0731 10 → 9; E0714 14, E0718 5, E0720 17,
  E0727 6 unchanged.
- **Every removal read at source (24), each a documented safe idiom:**
  - E0713 ×5, attribute-receiver Table (C3):
    `agno/vectordb/pgvector/pgvector.py:1635,1651,1667,1689,1718`
    (`stmt = self.table.delete().where(self.table.c.x == v)`, two with
    `stmt = stmt.where(...)`).
  - E0713 ×1, attribute-receiver Table (C3):
    `langchain_community/cache.py:1600` `session.execute(self.cache_schema.delete())`.
  - E0713 ×2, literal + literal (C3):
    `langchain_community/document_loaders/oracleai.py:453`,
    `langchain_community/embeddings/oracleai.py:140`
    (`"select t.column_value from " + "dbms_vector_chain...(:content, ...)"`).
  - E0713 ×13, psycopg `sql` composition (C3):
    `langchain_community/chat_message_histories/postgres.py:85`
    (`query = sql.SQL("INSERT INTO {} ...").format(sql.Identifier(self.table_name))`),
    `langchain_community/vectorstores/yellowbrick.py:187,548`,
    `semantic_kernel/connectors/memory_stores/postgres/postgres_memory_store.py:142,173,214,263,306,347,370`
    (`SQL("...").format(scm=Identifier(...), ...)`),
    `semantic_kernel/connectors/postgres.py:495,533,652`
    (`sql.SQL(", ").join(sql.Identifier(n) for ...)`, `sql.Literal(key)`).
  - E0719 ×1, same-file class's own method (C4):
    `langchain_community/graphs/networkx_graph.py:35`
    `KnowledgeTriple.from_string(s)` (a NamedTuple classmethod parser).
  - E0719 ×1, Jinja sandbox (C4, the plan's decision):
    `langchain_core/prompts/string.py:72`
    `SandboxedEnvironment().from_string(template).render(**kwargs)` — the
    upstream comment itself calls the sandbox best-effort; see the q1 row.
  - E0731 ×1, `PyCF_ONLY_AST` (C7):
    `langchain_community/tools/e2b_data_analysis/unparse.py:744`.
- **Confidence changes on kept findings (4):** E0727 0.95 `qualified` →
  0.6 `stdlib_xml` at `agno/knowledge/reader/sitemap_reader.py:123`,
  `agno/tools/pubmed.py:43,51`, `smolagents/default_tools.py:443`
  (stdlib ElementTree, no parser argument). 0 findings demoted by
  argument shape.
- **`--min-confidence 0.9` on the corpus:** 55 → 51 kept (652 → 632
  hidden of 707 → 683).
- **`--strict` on the corpus:** 1,017 → 993; E0711 310 → 310 (BUG-039's
  shape has no corpus site); the same 24 removals.
- **In-repo trees** (`bench tests tools playground demos`): 115 → 107.
  −8 E0731: the `code = compile(src, ...); exec(code, ...)` pairs in
  `tests/test_compiler_refuses.py` (×2), `test_diagnostic_catalog.py`,
  `test_regressions.py`, `test_release_emit.py`,
  `test_runtime_enforcement.py`, `test_stdlib_bytes.py`,
  `test_stdlib_d1.py` now report once, at the compile, re-rated 0.6 → 0.9.
  E0727 `bench/py_frontend/corpus/sink_coverage_repro.py:190` 0.95 → 0.6
  (`stdlib_xml`). 3 E0723 in `tests/test_py_frontend_sinks.py` moved line
  (10-11 lines down: this wave's edits above them). The two new test files add 0
  findings (their fixture keys are split literals).
- **Probes** (`scratchpad\fp`, 108 files): 37 → 11 findings, ≥ 0.9 20 →
  6; flagged files 35 → 11. Adversarial near misses
  (`scratchpad\w5a\neg.py`, 56 shapes): 56/56 at their expected codes.
- **Rows:** `min_py_table_rows` 121 → 128 (+7 sanitizer rows:
  `shlex.join`, `werkzeug.utils.safe_join`, `werkzeug.security.safe_join`,
  `flask.url_for`, `quart.url_for`, `django.urls.reverse`,
  `django.urls.reverse_lazy`); `test_sink_rows`: 88 sink, 24 guard, 16
  sanitizer rows.
- **Gate:** `python -B scripts/run_all.py` exit 0 at `fc05e15` (`smt`
  SKIP, z3 absent).

## Changed tests that pinned old behaviour

- `tests/test_sink_rows.py`: `KNOWN_FLAGGED_FIX` (an inverted pin: "the
  day `"ls " + shlex.quote(x)` goes clean this test goes red") removed,
  as the entry itself asked; every documented sanitizer fix must now be
  clean. 7 new pins (additive).
- `tests/test_py_frontend_sinks.py::test_xxe_python_text_names_the_callee_and_a_python_fix`
  asserted every E0727 shape rates `qualified` ("same confidence"); the
  stdlib no-parser shapes now rate `stdlib_xml` (C7), lxml stays
  `qualified`. Codes, messages and hints unchanged.
- `tests/test_py_frontend_sinks.py::test_xxe_elementtree_text_is_scoped_to_calls_without_a_parser`
  asserted `match == "qualified"` for all 8 shapes; now `qualified` with a
  caller's parser and for lxml, `stdlib_xml` without one.
- `tests/test_py_frontend_sinks.py::test_match_kind_reaches_extra_for_every_sink_match`
  gains a `stdlib_xml` shape (its own vocabulary check requires one per
  published kind). Additive.
- `tests/test_confidence.py`: 3 tests added (9 → 12); none changed.
