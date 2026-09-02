# Improvement survey, 2026-09-03 — 65 probe-confirmed candidates, ranked

Produced by a five-lens survey (Python-frontend misses, Aether-side detectors, Python sink coverage, toolchain, SQL helper census) with one surviving soundness judge; every row was probe-confirmed by the finder and re-run by the judge (`probe_valid`). Full records (probe command, observed output, design, prevalence, breaking risk, judge reasoning): `survey_2026-09-03_ranked.json`. This file is the backlog for iterations 49+; LOOP_LOG iteration 48 records what Slice 1 took from it.

| pri | id | kind | dir | loc | title |
|---|---|---|---|---:|---|
| P0 | PYFE-01 | false_accept | fixes_miss | 45 | Rebinding forms the safe-name pass cannot see (AugAssign, for-target, tuple-unpack, walrus, except-as) make a tainted name look literal-only |
| P0 | PYFE-03 | false_accept | fixes_miss | 8 | A sink call assigned to a non-Name target (attribute, subscript, tuple-unpack, chained `a = b =`, AnnAssign attribute) is dropped from the IR |
| P0 | PYFE-04 | false_accept | fixes_miss | 15 | `_expr` drops the children of every unmodeled expression node, so a sink call inside BoolOp / Compare / UnaryOp / IfExp / Subscript / Tuple / List / Dict / Lambda / Starred is invisible |
| P0 | PYFE-02 | false_accept | fixes_miss | 12 | Function parameters are not bindings, so `if q is None: q = "SELECT 1"` makes a caller-supplied query, Loader, or command look literal-only |
| P0 | AEDET-01 | false_accept | fixes_miss | 15 | `var` bindings and `x = …` assignments are invisible to the marker-taint fixpoint (E0712/E0715/E0724-E0730) |
| P0 | AEDET-02 | false_accept | fixes_miss | 8 | Literal-or-wrapper safe-name proof ignores later `x = untrusted` re-assignment (E0711/E0713/E0714/E0718/E0719/E0720/E0727) |
| P0 | PYFE-06 | false_accept | fixes_miss | 5 | `_safe_xml_parser_names` ignores rebindings to non-constructor values, so a parser rebound to an unknown call still disarms E0727 |
| P0 | PYFE-07 | false_accept | fixes_miss | 6 | The subprocess `shell=` guard reads `**kwargs` as "shell absent" and clears the call, against the guard contract that unresolvable means SINK |
| P0 | AEDET-03 | false_accept | fixes_miss | 4 | E0717 stable-name proof ignores `var`: id rebound between guard and sink is accepted (IDOR) |
| P0 | AEDET-05 | false_accept | fixes_miss | 20 | Sanctioned wrapper's pinning argument is never checked: `sqlBind(userTemplate, v)`, `shellArg(userTemplate, v)`, `safeRedirect(userHost, p)` are accepted |
| P0 | AEDET-06 | false_accept | fixes_miss | 5 | `for x in markedList` loop variable is never tainted (sibling of BUG-001 match-destructure) |
| P0 | AEDET-07 | false_accept | fixes_miss | 2 | Match-EXPRESSION arm bindings over a tainted scrutinee are not tainted (BUG-001 fixed only the statement form) |
| P0 | PYFE-05 | false_accept | fixes_miss | 30 | Code outside any collected `def` — module level, `if __name__ == "__main__":`, class bodies, module-level lambdas — is never analysed at all (n_functions: 0, ok: true) |
| P0 | AEDET-10 | false_accept | fixes_miss | 30 | A whole record carrying a marker field reaches a sink unflagged (`print(u)`, `writeFile(path, u)` with u: User{email: PII}) |
| P0 | SQLSUM-03 | false_accept | fixes_miss | 25 | Raw-SQL methods `.prefix_with/.suffix_with/.with_hint/.with_statement_hint/.op` are not raw entries, so `select(t).prefix_with("/*+ " + x)` is laundered as sqlBind |
| P0 | AEDET-04 | false_accept | fixes_miss | 30 | Aliasing a STDLIB sink (`let run = sqlQuery; run(x)`) hides it from every detector and from E0801 |
| P0 | AEDET-09 | false_accept | fixes_miss | 50 | Boundary-sanitizer coarseness IS a miss: `render(sanitizeLog(u))` clears E0729 while the callee feeds `htmlResponse` (q1's open probe) |
| P0 | TC-01 | false_accept | fixes_miss | 20 | RecursionError on a deep expression skips the WHOLE file silently (exit 0, ok:true) |
| P1 | SQLSUM-01 | false_accept | fixes_miss | 15 | `exec_driver_sql` is not a sink: SQLAlchemy's raw DB-API pass-through with an f-string is SILENT |
| P1 | PYSINK-01 | new_detector | flag_more | 90 | exec/eval/compile on model output is a capability NOTE, never a finding — needs E0731 code-injection detector (evalCode) |
| P1 | PYSINK-08 | false_accept | flag_more | 6 | jinja2 Environment(...).from_string(x) / env.from_string(x) and mako Template(x) are silent — the prompt-template SSTI shape agent frameworks actually use |
| P1 | PYSINK-07 | false_accept | flag_more | 18 | argv-form shell: subprocess.run(["bash","-c", cmd]) and os.execvp("sh", ["sh","-c",cmd]) are silent (shell= absent means 'safe') |
| P1 | TC-02 | false_accept | fixes_miss | 4 | PEP 263 non-UTF-8 source (coding: latin-1) is skipped as UnicodeDecodeError -- valid Python, findings lost |
| P1 | PYFE-09 | false_accept | fixes_miss | 18 | A sink reached through a bound-method alias or `getattr(obj, "execute")(...)` has no callee spelling and is named `<expr>` |
| P1 | AEDET-08 | false_accept | fixes_miss | 40 | Function-typed parameters exist in the grammar; a call through one launders markers and effects (q1's 'no HOF surface' claim is false) |
| P2 | PYFE-08 | widening | flag_more | 14 | Shell-always and pickle-family sinks missing from the sink tables: subprocess.getoutput/getstatusoutput, asyncio.create_subprocess_shell, cloudpickle/dill/joblib/torch.load, numpy.load(allow_pickle=True) |
| P2 | AEDET-14 | widening | flag_more | 25 | E0723 knows 6 credential shapes; OpenAI, Anthropic, HuggingFace, Groq, Google OAuth, GitLab, SendGrid, npm, PyPI, JWT, Slack webhook/app, GitHub fine-grained, Stripe rk_/test, Discord webhook, age keys all pass |
| P2 | PYSINK-03 | false_accept | flag_more | 10 | joblib.load / dill.load(s) / cloudpickle.load(s) / pandas.read_pickle / jsonpickle.decode are pickle-equivalent and silent |
| P2 | PYSINK-04 | false_accept | flag_more | 6 | numpy.load(p, allow_pickle=True) is silent — pickle re-enabled by keyword |
| P2 | PYSINK-06 | false_accept | flag_more | 8 | Implicit-shell runners are silent: subprocess.getoutput/getstatusoutput, asyncio.create_subprocess_shell, paramiko exec_command, pexpect.spawn/run |
| P2 | PYSINK-09 | false_accept | flag_more | 5 | asyncpg/`databases` query methods fetch/fetchrow/fetchval/fetch_all/fetch_one are not SQL sinks — concatenated SQL through them is silent |
| P2 | TC-04 | perf | neutral | 8 | Marker-flow detectors are O(n^2) in FunctionDecl count: per-function copy of the whole-program param mask |
| P2 | TC-06 | perf | neutral | 45 | check-py is single-process; a process pool gives a measured 2.5x on Windows |
| P2 | AEDET-11 | widening | flag_more | 30 | E0722 recognises only the `169.254.` spelling; IPv6 IMDS, GCP/Alibaba names, decimal/hex/octal and userinfo forms pass |
| P2 | AEDET-12 | widening | flag_more | 12 | E0721 loopback exemption is a string prefix: `127.0.0.1.evil.com` and `127.0.0.1@evil.com` pass; `[::1]` is flagged |
| P2 | AEDET-13 | widening | flag_more | 10 | E0710 host-pinning check misses `*.*`, `api.*`, `a*`, `api.example.com*`, `[*]` and userinfo-masked `trusted@*` |
| P2 | PYSINK-02 | false_accept | flag_more | 8 | torch.load(path) without weights_only=True is silent (CVE-2025-32434 class) |
| P2 | PYSINK-11 | false_accept | flag_more | 8 | Framework redirect constructors (starlette/fastapi RedirectResponse, django HttpResponseRedirect, aiohttp HTTPFound) are not E0718 sinks |
| P2 | TC-07 | toolchain | neutral | 15 | --json is 98% `unprovable` (17.1 MB of 17.5 MB on agno) for 245 findings; a fix loop pays for 49,933 boilerplate rows |
| P2 | TC-09 | false_accept | fixes_miss | 30 | E0710/E0721/E0722 are dead on Python (frontend emits net.get, detectors match only net.fetch), the CLI's NOT-checked line omits them, and when wired they would report the def line |
| P2 | SQLSUM-07 | precision | relax | 6 | `stmt = None` sentinel before `stmt = select(...)` breaks the fixpoint's all-Call requirement |
| P2 | SQLSUM-08 | precision | relax | 8 | Table-method form only accepts a bare-Name receiver: `self.table.delete().where(...)` fires |
| P2 | PYFE-10 | precision | relax | 3 | `Loader=SafeLoader` bound by `from yaml import SafeLoader` is flagged E0720 because `_dotted_of` never consults imports for a bare Name |
| P2 | AEDET-15 | toolchain | neutral | 3 | E0723 always reports `line 0, col 0` — string literals carry no position |
| P2 | PYSINK-05 | false_accept | flag_more | 4 | yaml.load_all / unsafe_load_all / full_load_all bypass the yaml.load guard |
| P2 | PYSINK-13 | false_accept | flag_more | 22 | --strict E0711 misses the receiver-carried path: Path(x).read_text()/read_bytes()/open()/write_text() |
| P2 | TC-03 | toolchain | fixes_miss | 35 | Unparseable files are invisible in SARIF/JSON-ok and the exit code disagrees across output modes |
| P2 | TC-05 | perf | neutral | 80 | Every detector re-walks every function body (~296 walk() passes per function; walk = 47% of profiled time) and py_to_ir walks each function 5x |
| P2 | TC-08 | toolchain | neutral | 30 | SARIF drops column, suggestion, extra and rule descriptions that the JSON already carries |
| P2 | TC-11 | toolchain | fixes_miss | 20 | _PY_SKIP_DIRS silently drops any directory named build/dist/env/venv anywhere in the tree, with no trace in JSON/SARIF/text |
| P2 | SQLSUM-06 | precision | relax | 25 | Module-level literal SQL constants are not `lit_names`: `conn.execute(_CREATE_TABLE)` fires |
| P2 | SQLSUM-10 | precision | relax | 45 | psycopg `sql.SQL(literal).format(Identifier(...))` composition is unrecognised — 17 of 381 (yellowbrick, semantic_kernel) |
| P2 | SQLSUM-11 | docs | neutral | 40 | Correct the record: helper-shaped E0713 survivors are 34 (14 in-module + 20 cross-module), not ~100; 166 (44%) are `text(f"...{ident}...")` DDL — true positives by rule |
| P2 | AEDET-16 | precision | relax | 25 | Record field matched by NAME over-flags a plain `email` on an unrelated record (q1 residual, now live-confirmed) |
| P2 | AEDET-17 | precision | flag_more | 15 | E0202 over-flags an `as`-aliased constructor arm, and a bare capitalised name in a pattern is a silent catch-all binding |
| P2 | PYSINK-10 | false_accept | flag_more | 5 | pandas.read_sql/read_sql_query, cursor.mogrify and django RawSQL are not SQL sinks |
| P2 | PYSINK-12 | false_accept | flag_more | 2 | xml.dom.minidom.parse(f) missing while minidom.parseString is mapped (asymmetric row); xmltodict.parse unmapped |
| P2 | TC-10 | docs | neutral | 12 | Python stage-skip / strict-only lists live in four literal copies (cli, pypi_scan, run_bench, tests); only one pair is drift-tested |
| P2 | SQLSUM-02 | false_accept | fixes_miss | 30 | sqlmodel `Session.exec(text(... + x))` is SILENT — `exec` is not a method sink although sqlmodel is already a builder root |
| P2 | AEDET-18 | widening | flag_more | 8 | E0207 treats Int bounds as reals: `Int where self > 5 and self < 6` is not reported |
| P2 | PYSINK-15 | docs | neutral | 0 | SSRF (E0710) does not fire on Python at all: requests.get(url)/httpx/urlopen are capability effects only — keep out of scope, document |
| park | PYSINK-14 | false_accept | flag_more | 40 | Zip-Slip in Python is silent: tarfile.open(p).extractall(dst) / ZipFile(p).extractall(dst) without filter= (default and --strict) |
| park | SQLSUM-04 | precision | relax | 180 | Per-module SQL-helper summary: root `stmt = self._base_query(t)` / `stmt = helper(t)` / `stmt = apply(stmt, ...)` (measured gain 14 of 381, not ~100) |
| park | SQLSUM-09 | precision | relax | 15 | An import ambiguous only between two sqlalchemy dialect modules (`postgresql.insert` vs `sqlite.insert`) clears nothing |
| park | SQLSUM-05 | precision | relax | 200 | Cross-module helper summary (sibling-module `apply_sorting` imported into every agno backend) — 20 of 381; defer, record as residual |
