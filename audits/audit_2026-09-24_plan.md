# Whole-repo audit, 2026-09-24 — findings and fix plan

Six adversarial lenses at `dcd824d` (language core, Python misses, Python
precision, agent toolchain, claims, architecture/tests). Every row below was
reproduced by a run, not read off the code; the P0 rows were re-run a second
time independently. Gate at `dcd824d`: `python -B scripts/run_all.py` exit 0
— **none of the P0s below is caught by the gate**, which is itself a finding
(§F).

Ordered by Aether's own principles (CLAUDE.md, README "Design principles"):
the compiler **refuses** bad compositions; the scanner **over-flags, never
misses within the modeled surface**; it **does not flag the fix**; its
diagnostics are **structured and actionable by an agent**; every claim is
**measured**; the ratchet means Aether **only moves forward**.

Bug ids are proposals (BUG-032+); assign on filing. Each fix follows the
LOOP method: probe red → fix root cause → regression test → gate → stamp.

---

## A. The compiler does not refuse what it promises to refuse (language core)

| id | P | Finding | Minimal repro (all `check` exit 0) | Root cause | Fix |
|---|---|---|---|---|---|
| A1 | P0 | Effects in `requires`/`ensures`, refinement `where` predicates and `const` initializers are never checked — a `pure` fn writes files, a `requires shellExec("rm -rf "+n)` gets neither E0801 nor E0714 | `function double(x: Int) returns Int requires isOk?(writeFile("p","x")) effects pure do ... end` → `check` OK, `run` writes the file | `check_effects`, `capability.py:184` and every security detector walk only `d["body"]` (`effects.py:1949`) | One `fn_exprs(decl)` iterator = body + requires + ensures; walk `TypeDecl.where` and `ConstDecl.value` as pure contexts. All detectors consume it. |
| A2 | P0 | Function values launder effects/capabilities unless they are a bare `Ident` argument: returned fn, `const g = print`, `[writeFile][0](...)`, `if … then print else print end`, map-valued fn | `let ws = [writeFile]; ws[0](path, s)` in a `pure` fn under a module granting only `log` → check OK, file written | `effects.py:1961` credits only `Ident` args; `callee_name` returns None for index/call callees and the call is skipped; `capability.py` treats let/indexed values as pure | A call whose callee is not a resolved decl/stdlib name = **unknown effects**: over-flag E0801 in any non-`*` caller unless every reachable fn value is proven pure. Over-flag is the contract. |
| A3 | P0 | Runtime enforces no capabilities; README says "the runtime grants only what is declared", `effects.md` says a runtime assertion at load and first invocation | module `requires capability log`, fn calls `writeFile`; `run --no-static-effects --no-capability-check` writes the file | `emitter.py:142` emits `ModuleDecl` as a comment; `runtime.py` has no capability code | Emit the module's grant set; `record_effect` asserts effect ∈ grant (E0701 at runtime). ~20 loc. Until shipped, correct README/effects.md. |
| A4 | P0 | Name mangling collides with runtime helpers and with itself: user `function assert_contract` disables every `requires`; `check_refinement` disables refinements; `valid?` and `valid_q` both mangle to `_ae_valid_q` (checker and runtime run different fns) | `n01_contract_shadow`: `withdraw(10,-1000)` prints 1010 | `runtime.py:33 mangle()` shares the `_ae_` namespace with helpers and is not injective | Injective mangling (`?`→`__q`, reject user `__`), helpers under a prefix user names cannot produce. Add a collision test over all runtime exports. |
| A5 | P0 | `for`/`match` bindings re-bind a name proven safe/stable/authorized — four detectors accept it (E0711, E0713, E0717, match variant) | `let s = "SELECT 1"; for s in xs do sqlQuery(s) end` → OK; `let id="doc-1"; proof=authorizeResource(u,"e",id); for id in ids do sqlByOwner(stmt,id,proof) end` → OK | Six binding fixpoints; only `_marked_taint` (`detector_specs.py:381`) knows For/BindPat. `_safe_names:1160`, `_mutable_names:81`, `_record_names:333`, `_authorized_names` (`effects.py:1370`), `_stable_names` (`effects.py:1675`) use `_BIND_KINDS=("Let","Var","Assign")` | **One** `binders(fn) -> [(name, value|None, kind)]` used by all six; a value-less binder disqualifies safe/stable/authorized. This is the BUG-013/014 class — fix it once, at the root. |
| A6 | P1 | Refinements checked only on direct `TypeName` params: return types, typed `let`, record fields, `List<PositiveInt>`, consts, and the base predicate of a refined alias (`type Small = PositiveInt where self < 10` accepts -50) all pass at runtime | `r01..r06` | `emitter.py:205-217` | Check at returns, typed lets, consts, constructors; chain base predicates. Runtime guarantee — document as runtime. |
| A7 | P1 | `net.fetch` glob `*` crosses `/ @ :` — `https://*.corp.example/*` covers `https://evil.com/.corp.example/x` | `g01_glob_host` | `effects.py:121` `*`→`.*` | In the authority, `*` → `[^/@:?#]*`; decide cover on the parsed authority (`_scope_authority` exists). |
| A8 | P1 | No type checker and no name resolution: `returns Int` with `return "x"` passes; `frobnicate(1)` passes `check`, `run` raises a raw `NameError` traceback. `types.md:3` claims "everything else is checked statically" | claims lens items 2–3 | no pass exists | Minimum honest step: an unresolved-name pass (new code only after `grammar/diagnostics.md` row; do not invent — spec it first). Full type checking is a language project; until then **retract** the static claim in `types.md`/`effects.md`. |
| A9 | P1 | `fmt` crashes on every function type (`KeyError: 'ret'`), including `playground/examples/32_function_typed_param.aeth`; the fix-loop crashes on it too. Only round-trip failure over 461 files | `aether --json fmt --check playground/examples/32_*.aeth` | `pretty.py:374` reads `args`/`ret`, parser emits `params`/`returns` | Print `function(<params>) returns <T>`; add a round-trip test over every corpus `.aeth` (the gate's pretty_roundtrip evidently does not include it). |
| A10 | P2 | Parser `RecursionError` at ~40 nested parens; a 500-term flat `+` chain crashes `ast_walk`; `const X = old(1)` → `NotImplementedError` traceback | `m01`, `m07`, `m02` | recursive walk; uncaught at CLI | Iterative `walk`; CLI boundary turns these into structured E0201/E9001. |
| A11 | P2 | Static and runtime disagree on `pure`: `effects pure, log` passes `check`, fails `--effect-strict`; unknown effect names accepted without a module | `e06_pure_plus` | effects clause not validated | Reject `pure` with siblings; reject unknown effect names (spec'd list). |

## B. The Python scanner misses inside its modeled surface (over-flag, never miss)

| id | P | Finding | Repro | Root cause | Fix |
|---|---|---|---|---|---|
| B1 | P0 | `html.escape` / `markupsafe.escape` / `urllib.parse.quote(_plus)` / `flask.render_template` map to `trusted`, the one exit for SSTI, code-injection and deserialization — `eval(html.escape(x))` and `render_template_string(html.escape(x))` are silent; `html.escape` leaves `{{7*7}}` and `__import__(...)` intact (measured) | `pm1.py` | `py_frontend.py:374-376`; `detector_specs.py:706-728` | Never map a Python call onto `trusted`. HTML escapers → `htmlEscape` (context-specific, clears only HTML sinks). Test: each escaper × each trusted-only sink fires. |
| B2 | P0 | An import bound two ways (the `try: import cPickle as pickle / except ImportError: import pickle` idiom, lxml/ET fallback) resolves to `None` and every sink through it is silent; one function-local `import json as pickle` silences `pickle.loads` file-wide | `pm2.py` | `_Imports._bind` / `resolve_attr` / `resolve_name`, `py_frontend.py:864-894` (comment admits the miss; README does not) | Keep all candidates: sink if **any** candidate is a sink; sanctioned only if **all** are. |
| B3 | P0 | `shlex.quote(cmd)` as the **whole** command with `shell=True` is clean — attacker still picks the program | `subprocess.run(shlex.quote(p), shell=True)` | `"py": True` exemption, `detector_specs.py:1144` | A frontend `shellArg` that is the entire command is not the exit (see C1 for the other half). |
| B4 | P1 | `text(col)` bound to a name, then nested in `select().order_by(order)` is sanctioned — README says it "is still an injection … built in one statement or across several" | `order = text(col); session.execute(select(t).order_by(order))` | raw-entry loop only inspects `Call` nodes, `py_frontend.py:693-703` | Resolve Names in the expression to their local binding. |
| B5 | P1 | Dynamic `text()` / `literal_column()` that never reaches an `execute`: `Query.filter(text(f"..."))`, `session.scalars/scalar(text(...))`, `from_statement` | `pm` PM-4 | `SINK_BY_METHOD` has no `scalars`/`scalar`; legacy Query executes at `.all()` | Make non-literal `text()`/`literal_column()` a finding **wherever it appears** (dedup vs executor). Closes B4, B5 and `db.text` (PM-5) together. |
| B6 | P1 | Valid 3.12+ source scanned on 3.10/3.11 (PEP 701 f-strings, PEP 695) → stderr note, `ok: true`, **exit 0** | `os.system(f"echo {d["k"]}")` | `cli.py:468-475` policy | Any unparseable file → non-zero (distinct code, see D5) and "valid on a newer Python; scan with 3.12+". |
| B7 | P1 | A `ValueError` raised inside **a detector** is reported as "could not parse" and the file's findings are lost, exit 0 | mutation: detector raises ValueError on a 3-finding file | `cli.py:338-340` wraps `analyze_flat` in `except (SyntaxError, ValueError)` | Move `analyze_flat` out of that `try`; only the frontend can make a file "unreadable". |
| B8 | P2 | Aliases/dynamic callees: `importlib.import_module("os").system`, `__import__("os")`, module-level `system = os.system`, local `e = eval`, `functools.partial(os.system, cmd)()`, dict-dispatch | PM-8 | `_callee_spelling`, `_local_constants` fn-scoped | Literal-arg `import_module`/`__import__` → that module; module-level single-binding aliases; `_dotted_of` resolves builtins. |
| B9 | P2 | Sink-table gaps (spellings, not classes): werkzeug/quart redirect, `HttpResponsePermanentRedirect`, `HTTPSeeOther`; Django `.extra(where=)`, peewee `execute_sql`, `duckdb.sql`; `builtins.eval`, `runpy.run_path`, `code.InteractiveInterpreter.runsource`; LangChain `from_template(template_format="jinja2")`, `NativeTemplate`, tornado `Template`; `_pickle`, ruamel `YAML(typ="unsafe")`; E0723 bytes literals and `rk_live_` | PM-9 | tables | Table rows + one generated test each (F2). Probe corpus prevalence first (method step 3). |
| B10 | P2 | E0723 inside an f-string reports line 0; `getattr(builtins,"exec")(src)` reported as E0713 | PM-10 | `py_frontend.py:1016`; by-method `exec` row | Carry f-string positions; bare-builtin resolution before by-method. |

## C. It flags the fix (precision that breaks the agent loop)

README: "A checker that flags the remediation trains people to ignore it." Two classes contradict it at 0.95 confidence, and in both an agent fix-loop **cannot converge**.

| id | P | Finding | Root cause | Fix |
|---|---|---|---|---|
| C1 | P0 | E0714 flags `"ls -l " + shlex.quote(p)`, f-string with quote, `" ".join(shlex.quote(a) for a in args)` — the fix README names; `shlex.join` flagged as "computed call" | `_arg_reason` rejects any `+`/f-string without looking at operands, `detector_specs.py:1130-1157` | Accept concatenation/f-string/`join(genexpr)` whose every non-literal part is a sanitizer call; map `shlex.join` → `shellArg`. Pairs with B3. |
| C2 | P0 | E0718: no Python spelling clears it — `redirect(url_for(...))`, `reverse(...)`, `request.url_for`, an allow-list guard all fire at 0.95; 5/5 corpus E0718s are not open redirects | no `safeRedirect` entry in `SANITIZER_BY_QUALIFIED` | Map own-origin URL builders (`flask.url_for`, `django.urls.reverse`, Starlette `url_for`) → `safeRedirect`; recognise `url_has_allowed_host_and_scheme` guard; until then rate computed-call targets at 0.6. |
| C3 | P1 | E0713 on module-level/class-level literal constants (`Q = text("… :id")`, `TABLE`, `LIMIT`, `"a" + "b"`), psycopg `sql.SQL(...).format(sql.Identifier(x))`, `self.table.delete()`, IN-list placeholders `",".join("?"*len(ids))` | `_safe_names` sees only the fn body; `_SQL_TABLE_METHODS` bare-name receiver | Seed safe names from module-level single literal bindings; constant-fold literal+literal; psycopg `sql` as an expression root; the `"?"*n` join as literal. |
| C4 | P1 | E0719 on `SandboxedEnvironment().from_string` (Jinja's own control) and on unrelated `from_string` classmethods (8/17 corpus E0719s) | by-method row | Sandboxed env = sanctioned; same-file class defining `from_string` shadows the row. |
| C5 | P1 | Confidence measures callee resolution, not argument safety — `--min-confidence 0.9` keeps the near-certain FPs (`redirect(url_for)`, quote-concats, AWS example key at 1.0) | `confidence.py:61-72` | Argument-shape demotion: sanitizer-containing or own-origin-builder args drop to the floor. Output-only, per closed design point. |
| C6 | P1 | Python findings name Aether functions (`sqlBind`, `shellArg`, `safeRedirect`, `schemaDecode`, `trusted`) and use `category: "capability"` for SQLi; an LLM given E0718/E0720/E0731 has no Python action | per-code hint text | Per-callee Python hints (`callee_text` exists, E0727 did it); category `security`. |
| C7 | P2 | E0731 on `compile(..., ast.PyCF_ONLY_AST)`; `code=compile(...); exec(code)` double-reported; E0723 at 1.0 on `AKIAIOSFODNN7EXAMPLE` in docstrings; E0727 0.95 on stdlib `ET.fromstring` whose own text says no XXE | various | Skip `PyCF_ONLY_AST`; dedup by bound name; allowlist AWS example value (keep README demo working with another fixture); rate the no-XXE stdlib case below the lxml case. |

## D. Agent-facing toolchain: the loop can be told "clean" when it is not

| id | P | Finding | Root cause | Fix |
|---|---|---|---|---|
| D1 | **P0** | **The deterministic fix-loop repairs by widening the declared constraint and reports `final state: clean`.** On `demos/capability-firewall/log_formatter.aeth` it adds `requires capability net` and `net.fetch("http://127.0.0.1:9999/*")` to `log_formatter` — it grants the exfiltration the demo exists to block. Same on `03_B2_url_discipline`, `10_pii_telemetry_violation`, `demo_02_net_glob_mismatch`, `broken.aeth` (`pure`→`log`), `log4shell` (adds `ldap://*`) | `fix_loop.py:67-89` `fix_E0801` appends the effect / drops `pure`; `:92-106` `fix_E0701` adds the capability; `patch_target.py:18-21` offers only the declaration as target; the hint puts widening first | This is the single sharpest contradiction of the project's purpose. Widening is never "clean": remove it from the deterministic set (or `--allow-widen`, each step tagged `weakens_constraint: true`, non-zero exit); give E0801 a **call-site** patch target; hint order: remove/replace the call first. Never widen `net.fetch` or add a capability automatically. |
| D2 | P0 | SDK, LSP, fix-loop and `tools/scan.py` never resolve imports: a cross-file E0801 and an unresolved-import E0705 are "clean" everywhere except `check`. SDK docstring claims "same membership the CLI runs" | only `cli.py:80-100` calls `resolve_imports`; `sdk.py:153-170`, `tools/scan.py:70-84`, `lsp.py:393` don't | Move import resolution under `analyze()` (or one `load_program(path)` every surface calls). The STAGES registry fixed this drift once for detectors; do the same for loading. |
| D3 | P0 | `tools/scan.py` exits 0 when every file fails to parse; reads UTF-8-BOM files as `utf-8` (E0101 on a file `check` rejects for E0801) | `tools/scan.py:72` encoding; `:218-230` ignores `parse_errs` | `utf-8-sig`; parse errors fail the run. |
| D4 | P1 | CLI short-circuits at the first non-empty stage (an E0801 hides E0713/E0714); SDK/LSP/scan don't — so surfaces disagree and an agent needs N round-trips | `cli.py:207-219` | `--json`: all stages, each diagnostic tagged `stage`. Text mode may keep the short-circuit. |
| D5 | P1 | Exit codes conflate findings / parse error / import error / usage error / crash (all 2, crash = raw traceback exit 1 even under `--json`); `scan.py` uses 1 for findings; `action.yml`'s "an analyzer crash always fails the job" is false (detected only when `rc==2 && findings==0`) | `cli.py:949-963`, `:501,516,559` | 0 clean · 1 findings · 2 usage · 3 analyzer/crash · 4 incomplete (unparseable). Wrap `main` so `--json` always emits JSON. Update action.yml. **Breaking** — ship as a minor version with a changelog line. |
| D6 | P1 | Five JSON shapes across `check` (JSONL on stderr), `--collect-errors` (stdout **and** stderr), `check-py` (stdout object), LSP (`col`, drops severity/category/confidence), `scan.py` (prose `parse_error`); `patch_target` only in LSP and only for 6 codes; `check-py` `ok: true` when nothing was analysed | per-surface serializers | One `Diagnostic.to_dict()` (+ `stage`, `patch_target`, `confidence`) used everywhere; one JSON document on stdout; `ok` false / `complete: false` on unreadable. |
| D7 | P1 | `fmt --write` and fix-loop delete all comments, including the `// expect:` header `test_corpus.py` requires | `pretty.py:10` (known) via `fix_loop.py:132` | Preserve leading comment block at minimum; fix-loop writes to `--out-source` only. |
| D8 | P1 | fix-loop overwrites its input with the transcript when the path lacks `.aeth`; writes cp1252/CRLF on Windows | `fix_loop.py:167-174` | `Path.with_suffix`; refuse out == in; `encoding="utf-8", newline="\n"`. |
| D9 | P1 | LSP `didOpen` with a lex error publishes nothing (file shows clean); `sdk.check` raises on lex errors despite "returns every diagnostic" | `lsp.py:393-404` | Catch `AetherError` → publish it. |
| D10 | P2 | E0801 points at the fn decl, not the offending call; categories outside the documented enum (`refinement`, `module`, `timeout`, `emit`, `internal`); `--json` still 78% `unprovable` rows with no flag to drop them; Action runs `check-py` twice; `·`/`×` mojibake on Windows console | various | call-site position; update enum in `diagnostics.py:22`; `--no-unprovable`; single Action run; ASCII fallback. |

## E. Claims the code does not support

| id | P | Claim | Reality | Fix |
|---|---|---|---|---|
| E1 | P0 (release) | README pins `fitness-trener/Aether@v0.4.1` | origin has `v0.4.0` newest; main 8 commits unpushed | Already step 5 of the 0.4.1 runbook — push main and tag together, verify the tag URL 200 before anything else. |
| E2 | P0 | "modules declare their capabilities and **the runtime grants only what is declared**" (README principles), `effects.md` runtime assertion | no runtime enforcement (A3); programs without a module get everything | Ship A3, or change the sentence to "the checker refuses…" today. |
| E3 | P1 | `grammar/types.md:3,56,76`, `effects.md:29,80`: static type checking | no type checker (A8) | Retract now; spec + build later. Hard honesty rule. |
| E4 | P1 | `grammar/stdlib.md:472-476` documents `plus(Instant, Duration)`, `minus(Instant, Instant)` | not in runtime; `check` passes, `run` NameError | Implement or delete the rows; add a doc↔runtime test (arch lens has the diff script). |
| E5 | P1 | `effects.md` lattice (`db.read/db.write`, no `db.query/db.exec/exec.run/net.redirect`, no `exec` capability; "static checks parked for v0.2") | stale | Regenerate from `_STDLIB_EFFECTS` / `_KNOWN_CAPABILITIES`; test they match. |
| E6 | P1 | `keywords.md`: "47 reserved words, locked" | lexer has 56; `trait` contradicts itself; `?`-iff-Bool not enforced | Regenerate from `lexer.KEYWORDS`; test count. Enforce `?`→Bool or drop the rule. |
| E7 | P1 | `SECURITY_POSTURE.md`: "14 concrete classes", table stops at E0723, Python default list omits E0731, `tools/py_frontend.py` path; `docs/SCANNING.md`: "nothing to install", ".aeth firewall", "86.8% agreement" without "comparable categories" (raw 34.2%), aether-scan.yml "fails if anything is found" (it's `--expect`) | stale since July | Rewrite both against README; qualify 86.8%. |
| E8 | P1 | `--prove` advertised (`.[smt]`); gate counts `smt: SKIP` as PASS; z3 absent locally and in CI; `check` prints OK with no "contracts not proved" note | untested path shipped | Install z3 in one CI job; print SKIP distinctly; `check` says "contracts: runtime-checked, not proved". |
| E9 | P1 | 676 / 628 / 241 s→69 s framework figures undated; `run_scan.py` downloads unpinned latest | not reproducible from a clone | Date them; pin versions in a lock file. |
| E10 | P2 | Three identities: CLAUDE.md "language… ten detectors E0710–E0719, q1–q3"; README "security checker for Python"; SCANNING.md ".aeth firewall" | drift | One-paragraph positioning shared by all three; CLAUDE.md counts updated (22 security codes, q1–q7). |
| E11 | P2 | 17 root `.md` reports (STATUS "v0.1 Phase 1", `AETHER_UADD_DRIFT_REPORT` "VERDICT: DRIFT (HALT)", …) unlinked, no historical banner; `SPEC_ISSUES.md` lists resolved S-002/S-008 under Open; vault q7 cites a scratchpad path not in the repo | clutter | `git mv` to `docs/history/` + index; fix SPEC_ISSUES; move the q7 census script into `tools/`. |

## F. The gate cannot see the regressions that matter (ratchet integrity)

| id | P | Finding | Fix |
|---|---|---|---|
| F1 | P0 | All P0s in §A–§D pass a green gate. The ratchet counts detector **existence** (a `return []` detector counts; any string in any test file, comments included, legitimises a code); `test_baseline_never_lowered` diffs against `HEAD`, which in CI **is** the commit under test — lowering the baseline and deleting a detector in one commit passes CI | Compare against merge-base with `origin/main`; add a **recall floor** = total `// expect:` findings across the corpus + number of sink-table rows; legitimacy = code asserted in an actual test assertion. |
| F2 | P1 | 21 of 78 Python sink/sanitizer rows appear in no test; deleting `mogrify`, `os.popen`, `executemany`, `pandas.read_pickle`, `HttpResponseRedirect` each survived the suite | One table-driven test: generate a minimal vulnerable snippet per row, assert the exact code; and per sanitizer, the safe snippet is clean. Makes rows ratchetable. |
| F3 | P1 | `run_all.py` lists tests by name: `test_cause_b.py`, `test_phase1.py`, `test_mining.py` never run, and `test_mining.py` is **red** (`test_runtime_oracle_catches_fn`, 6/7) | Glob `tests/test_*.py` with an explicit exclude list; fix or delete the three. |
| F4 | P2 | Stage-skip list in 4 literal copies, one drifted (`test_confidence.py` skips non-stage names `smt`/`imports`, omits `semantic`); `analyze(skip=)` silently ignores unknown names; `_STDLIB_EFFECT_PATHS` is a verbatim copy of `_STDLIB_EFFECTS` | Single definition imported everywhere; `assert set(skip) <= stage_names`; derive the copy. |
| F5 | P2 | Perf: ~564 AST walks per function; on Python 60% of analysis time goes to the eight marker rows that **cannot** fire there (frontend emits no marker types); kubernetes `core_v1_api.py` (34k lines) 29.7 s | Early return when the program has no marker type (one check, ~60% saving); later a per-function index shared by all rules — which is also A5's root fix. |
| F6 | P2 | `tests/_tmp_broken_for_c6.aeth` tracked and unreferenced | delete. |

---

## What held (do not re-probe)

Determinism (byte-identical `--json` with `--jobs 1`/`4`); diagnostic catalog ↔ emit sites both directions; registries (runtime ↔ `_STDLIB_EFFECTS` ↔ `_STDLIB_EFFECT_PATHS` ↔ `_KNOWN_CAPABILITIES` ↔ `stdlib.md` ↔ frontend targets) — no mismatch; wheel from `git archive` installs and runs; every README command and number reproduced (bandit comparisons, 55/31, 38 suites, 628/676); q1 BUG-025 alias closure and q7 frontend totality (19 positions) hold; emitted Python has no string/field escape hatch; parse errors structured on the malformed corpus; 6,000-input mutation fuzz clean outside depth; canonical safe forms silent for SQL params, SQLAlchemy `bindparams`/`select`, argv lists, `yaml.safe_load`, `defusedxml`, autoescape Jinja, `render_template`, env-var credentials, placeholder keys; Aether-side detector tests catch 14/15 mutations.

---

## Plan

Sequenced so that each wave restores one principle end to end, cheapest root
cause first. Every wave ends with `python -B scripts/run_all.py` exit 0,
BUGS.md entries stamped `[FIXED <commit>]` + `test:`, a LOOP_LOG block, and
residuals pushed to vault q1 (method step 7).

### Wave 0 — decide before the 0.4.1 upload (owner call)
0.4.1 is built on claims about Python. B1 (`html.escape` → `trusted`), B2
(try/except import) and B3 (whole-command `shlex.quote`) are **silent false
accepts already on PyPI in 0.4.0**; C1/C2 make the README's own fix flagged.
Options: (a) ship 0.4.1 as planned and do Wave 2 as 0.4.2; (b) fold B1–B3 +
B7 (each ≤ ~30 loc, non-breaking in the accept direction) into 0.4.1 before
the tag. **Recommend (b)** for B1, B2, B3, B7 only — they are misses, the
thing a security scanner must not ship knowingly — and keep C1/C2 for 0.4.2
because they change the framework-corpus finding set and need the 676-row
re-measure. Either way E1 (tag before push) stands.

### Wave 1 — make the gate see what matters (F1–F4, D3, B7) · ~1 day
Rationale: every later wave is only trustworthy if the gate would go red on
its reversal. Do this first.
1. F3: glob test discovery; fix/delete the three orphans.
2. F1: ratchet vs merge-base; recall floor (expect-header totals + sink rows); legitimacy = assertion, not substring.
3. F2: table-driven per-row test (this also turns B9's rows into ratchet units).
4. F4 + D3 + B7: single skip list, `skip` assertion, scan.py BOM/exit, detector ValueError not "unreadable".
**Done when:** each of the 5 surviving mutations and a baseline-lowering commit go red.

### Wave 2 — the compiler refuses again (A1, A2, A5, A4, A3) · ~3–4 days
Core promise. One mechanism per root cause, not per instance:
1. A5 `binders(fn)` — one binding iterator for all six fixpoints (closes the whole BUG-013/014 class; also the index F5 needs).
2. A1 `fn_exprs(decl)` — body + contracts + refinements + consts, consumed by effects, capability and every security detector.
3. A2 unknown-callee = unknown effects (over-flag), mirrored in `capability.py`.
4. A4 injective mangling + helper namespace + collision test.
5. A3 runtime capability grant in `record_effect` (and fix E2 text in the same commit).
**Done when:** every `lang/` repro in this audit is a regression test that fires; corpus expect-headers unchanged (non-breaking check); A3 turns the capability-firewall demo's `--no-capability-check` run red at runtime.

### Wave 3 — the fix-loop never weakens a constraint (D1, D2, D4, D7, D8) · ~2 days
1. D1: widening out of the deterministic set; call-site patch target for E0801; `weakens_constraint` flag; non-zero exit. Demos' fix-loop tests must now assert **"not repaired"** on the attack demos — that is the correct outcome.
2. D2: one `load_program(path)` (parse + resolve imports) used by CLI, SDK, LSP, scan, fix-loop.
3. D4: `--json` emits all stages with `stage` tags.
4. D7/D8: comments preserved, input never overwritten, utf-8/LF.
**Done when:** fix-loop over every corpus file never produces a program whose declared effects/capabilities ⊋ the input's; all five surfaces agree on the cross-file repro.

### Wave 4 — the scanner stops missing (B1–B6, B8) · ~2–3 days (B1–B3 may already be in 0.4.1)
1. B1 no Python call maps to `trusted`; escapers → `htmlEscape`.
2. B2 multi-candidate imports (any-sink / all-sanctioned).
3. B5 non-literal `text()`/`literal_column()` anywhere (closes B4, PM-5).
4. B3 whole-command quote; B6 unparseable → non-zero; B8 alias/dynamic callees.
**Done when:** every PM repro is a `test_py_frontend_sinks` case; framework corpus re-measured, delta triaged and recorded in `bench/framework_scan/REPORT.md` (new findings must be true-by-rule).

### Wave 5 — stop flagging the fix; make findings speak Python (C1–C7, D5, D6, D9, D10) · ~3 days
1. C1/C2 sanitizer-composition acceptance + own-origin URL builders — the two non-converging loops.
2. C3/C4 precision rows; C5 argument-shape confidence demotion; C7 small rows.
3. C6 Python-native hints for every default-on code, `category: security`.
4. D5/D6 exit-code table + one serializer (breaking → minor version bump, CHANGELOG, action.yml).
**Done when:** a scripted "LLM-free fix loop" (apply the hint's Python form mechanically) converges on one repro per code; `--min-confidence 0.9` count on the framework corpus re-measured and its README sentence updated.

### Wave 6 — tell the truth everywhere (E2–E11, A6–A11) · ~2 days, parallelisable with 4–5
1. Retract static type-checking claim (E3); regenerate `effects.md`/`keywords.md` from code with a test (E5/E6); resolve E4.
2. Rewrite `SECURITY_POSTURE.md`, `docs/SCANNING.md` (E7); one positioning paragraph across README/CLAUDE.md/SCANNING (E10); CLAUDE.md counts.
3. z3 CI job + distinct SKIP (E8); pin and date framework corpus (E9).
4. `docs/history/` move + SPEC_ISSUES + q7 citation (E11); F6.
5. Language follow-ups: A6 refinement sites, A7 glob authority, A9 fmt function types + round-trip over all corpus files, A10 iterative walk, A11 effects clause validation. A8 (name resolution / type checking) gets a vault question page first — it is a language-scope decision, not a detector.

### Wave 7 — performance (F5) · ~1 day
Marker-type early return (≈60% of Python analysis time, measured), then the per-function index built in Wave 2 shared by all rules. Re-measure `--jobs` numbers and update README with a date.

### Deliberately not in this plan
Re-litigating closed design points (memory/vault: `safeJoin` base unpinned, bare `fetch` not SQL, builtins by bare name, no effects syntax for function types, `Authorized<T>` never widened, `trusted` is an assertion). Note A2 does **not** add effects syntax to function types — it over-flags unknown callees, which the closed point permits. Parked survey rows (PYSINK-14, SQLSUM-04/05) stay parked.
