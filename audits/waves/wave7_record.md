# Wave 7 record — performance (F5), E0801 at the call (D10), effects-clause validation (A11) (iteration 62)

Plan: `audits/audit_2026-09-24_plan.md` §F5 + Wave 7, plus the D10 leftover
(deferred by Wave 5a: `Call`/`ExprStmt` carried no position) and A11.
Branch forked from `v0.5-audit-waves` @ `0653115`. Every "before" below is
`0653115`: a pristine `git archive 0653115` tree, run on the same machine
(8 logical cores, `os.cpu_count() == 8`, Windows 11, CPython 3.11). Ids:
BUG-080..084, iteration 62.

Commits:
- `5bd1334` perf(passes): one shared per-function index; skip marker rows with no marker (audit F5)
- `2c65c12` perf(py): memoize _bindings_of per def while translating (audit F5)
- `881a3b5` fix(parser): positioned calls, E0801 at the call; validate effects clauses (audit D10, A11)
- this record

Files changed (all inside the wave's ownership list):
`transpiler/aether/passes/{ast_walk,__init__,capability,detector_specs,effects,modules,patch_target}.py`,
`transpiler/aether/py_frontend.py` (perf only), `transpiler/aether/parser.py`,
`grammar/diagnostics.md` (E0201 / E0704 / E0801 row text; no new code),
`tests/test_module_validation.py` (two tests added), new
`tests/test_perf_index.py`, new `tests/test_call_positions.py`. Not touched:
`pretty.py` (round-trip held without it), `tests/alsp_corpus/*.expected.json`
(they pin codes and patch-target kinds, not positions; all still pass),
README, BUGS.md, LOOP_LOG, vault, `grammar/effects.md`, `grammar/grammar.ebnf`
(see "Coordinator decisions").

Red first: `tests/test_perf_index.py::test_walk_budget_per_function`
fails on `0653115` (97.0 walks per function, budget 20; 14.0 after). All five
`tests/test_call_positions.py` checks fail on `0653115` (Call has no `pos`;
E0801 at `1:1` twice; both E0801 patch the first `print`; E0204 on the
`return` line; the comment above `print(a)` dropped by `fmt`). Both A11
tests in `tests/test_module_validation.py` fail on `0653115` (`effects pure,
log` accepted; `bogus.effect` produces no diagnostic).

## BUGS entries

### BUG-080  Every detector re-walked every function; on Python half the analysis time went to eight marker rows that cannot fire there  [OPEN]
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

### BUG-081  The Python frontend re-walked each function six times for its bindings  [OPEN]
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

### BUG-082  E0801 pointed at the function declaration, not the offending call; Aether `Call` and `ExprStmt` had no position  [OPEN]
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

### BUG-083  `effects pure, log` passed `check` and failed `--effect-strict`  [OPEN]
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

### BUG-084  An effect naming an unknown capability was accepted silently  [OPEN]
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

## LOOP_LOG block

## Iteration 62 — Wave 7 of the 2026-09-24 audit: 4.3× faster scans, findings at the call, validated effects clauses (no new detector)

- **Target:** not a backlog row. Plan F5 (perf) + the D10 and A11
  leftovers.
- **Probe-confirmed first (on `0653115`):** `check-py --jobs 1` over the
  framework corpus 365.9 s (analysis 249 s of it); 97 AST walks per
  function; marker rows ≈ 50% of analysis on Python, where they cannot
  fire. Two E0801 in one body both at `1:1` and both patched to the same
  call. `effects pure, log` and `effects bogus.effect` accepted.
- **Fixes (each once, where every caller routes through):** one
  per-analysis index in `passes/ast_walk.py` (`shared_index()`, entered
  by `analyze()`); `marker_absent()` early return for the eight marker
  rows; `_bindings_of` memo in the frontend's def phase; `Call`/`ExprStmt`
  positions in the parser and E0801 at the call; `pure`-with-siblings is
  E0201, an unknown effect capability is E0704.
- **Measured (8 logical cores):** framework corpus `--jobs 1` 365.9 s →
  85.0 s, default jobs 111.3 s → 25.5 s; single largest files 4.1 / 3.5 /
  3.4 s → 1.1 / 1.0 / 1.0 s. Findings byte-identical: 683 (framework,
  default), `--strict`, in-repo trees. `.aeth` corpus: 113 positions moved
  in 98 files, codes/exit codes identical, 0 new findings.
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** the frontend is now ~75% of
  `check-py` time (95 s of the pre-wave 344 s in-process total; analysis
  is ~20 s). Its remaining cost is one Python-AST walk per function per
  consumer family; a single visitor pass building the per-def tables is
  the next lever, not another detector-side cache.
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally); two new suites
  (`perf_index`, `call_positions`).

## q1 rows

| NEW residual: effect names are validated by capability head only | iter-62 (audit A11): an effect whose first segment is not a known capability is E0704; a known head with an invented tail (`fs.delete`, `log.debug`) is still accepted as a declaration and takes part in composition by exact path, so `effects fs.delete` does not cover `writeFile`'s `fs.write` (over-refuses, never under). Repeated `effects` clauses are not rejected: the LAST one wins (`effects log` then `effects pure` checks as `pure`) `[source: effects, section: Composition rule, key: E0801]` | low |
| NEW residual: E0701 is positioned at the function, not a call | iter-62 (audit D10): E0801 and every call-anchored security row now report at the call; E0701 stays at the declaration because it is an aggregate over the transitive effect closure (one finding per function per capability, possibly reached through several calls and callees) `[source: diagnostics, section: E0701, key: capability]` | low |
| NEW residual: the marker-row skip keys on names, not types | iter-62 (audit F5): a program in which no node is NAMED `Secret`/`PII`/`Untrusted` or a stdlib constructor skips that marker's rows. Equivalent today because a marker can only enter through those names; a future way to introduce a marker without either (a type alias imported from another file under another name, a new constructor not added to `_STDLIB_MARKER_CONSTRUCTORS`) must extend `marker_absent`, or the rows would go silent — `tests/test_perf_index.py` forces the rows on over the corpus to catch a divergence it can see `[source: diagnostics, section: E0712, key: Secret]` | medium |

## Skipped / not reproduced / deferred

- **README perf sentence (plan: "update README with a date")** — README is
  outside this wave's files. Proposed replacement for README lines 278–279:
  "(measured 2026-09-25 on the 4,946-file framework corpus, 8 logical
  cores: 85 s serially, 26 s on 8 workers, byte-identical output)". The
  current sentence (2026-09-03, 1,024 files, 241 s / 69 s) predates this
  wave.
- **`grammar/effects.md`** (Wave 6's text, outside this wave's files) still
  says "Not decided statically at this version: `pure` written alongside
  other effects is not rejected, and effect names are not validated
  against a list (…A11)." It is now false. Proposed replacement: "`pure`
  written alongside another effect is a parse error (`E0201`), and an
  effect whose first path segment is not a known capability is `E0704`
  (no module could grant it); a known capability with any action is
  accepted as a declaration." The sentence "Any other dotted path is
  accepted as a declaration" needs "whose first segment is a known
  capability".
- **`grammar/grammar.ebnf`** line 108–111 still admits `pure` inside a
  list. Proposed: `effects_clause = "effects" ( "pure" | effect_list ) ;`
  with `effect = dotted_ident [ "(" expr ")" ]`.
- **Repeated `effects` clauses** (last wins, silently) — seen while
  probing A11, not in the plan; recorded as a q1 row, not fixed.
- **Frontend single-pass visitor** — not done; see the LOOP_LOG gap.

## Measurements

Machine: 8 logical cores (`os.cpu_count()`), Windows 11, CPython 3.11.
Before = `git archive 0653115`; after = `881a3b5`. Wall times from
`python -B -m transpiler.aether.cli --json check-py <path>`, output to
NUL, runs sequential on an otherwise idle machine.

| run | before | after |
|---|---|---|
| framework corpus, `--jobs 1` | 365.9 s | 85.0 s |
| framework corpus, default (8 workers) | 111.3 s | 25.5 s |
| `agno/agno/workflow/workflow.py` | 4.1 s | 1.1 s |
| `browser_use/browser_use/beta/service.py` | 3.5 s | 1.0 s |
| `agno/agno/db/postgres/postgres.py` | 3.4 s | 1.0 s |

After `5bd1334` alone (analysis only): `--jobs 1` 123.0 s, default 38.7 s.
In-process on `0653115`: frontend 94.8 s + analysis 249.1 s over the
corpus. (The audit's 29.7 s kubernetes `core_v1_api.py` is not in this
corpus; the three largest-by-time files here were used instead.)

Byte-identity, full JSON (stdout + stderr + exit code), before vs after:
- framework corpus `--json check-py`: identical (683 findings); `--strict`: identical.
- in-repo `bench tests tools playground demos`, default and `--strict`:
  identical except the three test files this wave adds or edits
  (`tests/test_perf_index.py`, `tests/test_call_positions.py` new;
  `tests/test_module_validation.py` gains functions — its `--strict`
  E0701 inventory lines move/add accordingly, no default findings).
- after `5bd1334`: all four Python snapshots and all 418 `.aeth` outputs
  byte-identical to before. After `2c65c12`: the two framework snapshots
  and all 418 `.aeth` outputs byte-identical; the in-repo snapshots
  differed only by this wave's then-uncommitted test edits.
- after `881a3b5`: 418 `.aeth` `check --json --no-prove` outputs — 320
  identical, 98 differ in positions only; codes (as sorted multisets) and
  exit codes identical in every file. By code, positions moved: E0801 25,
  E0206 12, E0715 11, E0712 10, E0716 8, E0713 7, E0714 6, E0729 6,
  E0711 5, E0717 5, E0718 5, E0719 5, E0720 4, E0731 2, E0725 1, E0727 1
  (113). Every change is decl position → call position (or, E0206, the
  bare call statement). Full list:

- `bench/aetherbench/results/cand_fix/t3_05_fs_roundtrip__nl__prose__a1.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand_fix/t3_05_fs_roundtrip__nl__prose__a2.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand_fix/t3_05_fs_roundtrip__nl__prose__a4.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand_fix/t3_05_fs_roundtrip__nl__structured__a2.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t3_03_audit__full__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t3_03_audit__nl__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t3_05_fs_roundtrip__full__a0.aeth`: E0206 1:1->4:3
- `bench/aetherbench/results/cand/t3_05_fs_roundtrip__nl__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t4_03_safejoin__full__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t4_03_safejoin__nl__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t5_02_reporter__full__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/results/cand/t5_02_reporter__nl__a0.aeth`: E0206 7:1->10:3
- `bench/aetherbench/tasks/t4_01_sqlbind/vulnerable.aeth`: E0713 7:1->10:20
- `bench/aetherbench/tasks/t4_02_shellarg/vulnerable.aeth`: E0714 7:1->10:20
- `bench/aetherbench/tasks/t4_03_safejoin/vulnerable.aeth`: E0711 7:1->10:34
- `bench/aetherbench/tasks/t4_05_secret/vulnerable.aeth`: E0712 6:1->10:3
- `bench/aetherbench/tasks/t4_06_pii/vulnerable.aeth`: E0715 6:1->10:3
- `bench/aetherbench/tasks/t4_07_authorize/vulnerable.aeth`: E0716 7:1->11:20
- `bench/aetherbench/tasks/t4_08_idor/vulnerable.aeth`: E0717 7:1->12:20
- `bench/aetherbench/tasks/t4_09_redirect/vulnerable.aeth`: E0718 7:1->10:20
- `bench/aetherbench/tasks/t4_10_template/vulnerable.aeth`: E0719 1:1->4:10
- `bench/architectural/T01_jwt_pure_hits_net/naive/main.aeth`: E0801 11:1->14:23
- `bench/architectural/T02_pwd_hasher_logs/naive/main.aeth`: E0801 1:1->4:3
- `bench/architectural/T03_cache_lookup_writes_disk/naive/main.aeth`: E0801 7:1->11:3
- `bench/architectural/T04_payment_gateway_admin_url/naive/main.aeth`: E0801 7:1->10:6
- `bench/architectural/T05_analytics_wrong_host/naive/main.aeth`: E0801 7:1->10:20
- `bench/architectural/T10_order_composition/naive/main.aeth`: E0801 3:1->6:3
- `bench/realworld_cve/cve_2007_4559_tarfile_vulnerable.aeth`: E0711 18:1->22:34
- `bench/realworld_cve/cve_2018_14574_django_redirect_vulnerable.aeth`: E0718 18:1->22:10
- `bench/realworld_cve/cve_2023_35078_ivanti_authz_vulnerable.aeth`: E0716 25:1->31:20
- `bench/realworld_cve/cve_2025_13526_oneclick_idor_vulnerable.aeth`: E0717 23:1->30:20
- `bench/realworld_cve/cve_2025_58763_tautulli_cmd_vulnerable.aeth`: E0714 16:1->20:10
- `bench/realworld_cve/cve_2026_1312_django_orderby_vulnerable.aeth`: E0713 16:1->20:10
- `bench/realworld_cve/cve_2026_54711_pghoard_secretlog_vulnerable.aeth`: E0712 15:1->19:3
- `bench/realworld_flask_ssti/vulnerable.aeth`: E0719 8:1->13:10
- `bench/realworld_jwt/e0716_bypass_FINDING.aeth`: E0716 27:1->32:3
- `bench/realworld_jwt/e0716_coercion_probe.aeth`: E0716 12:1->17:20
- `bench/realworld_jwt/vulnerable.aeth`: E0716 32:1->38:20
- `bench/realworld_pyyaml/vulnerable.aeth`: E0720 12:1->16:10
- `bench/realworld_subprocess_cmdi/vulnerable.aeth`: E0714 8:1->12:10
- `bench/realworld_xss/vulnerable.aeth`: E0725 8:1->12:10
- `bench/realworld_xxe/vulnerable.aeth`: E0727 7:1->11:10
- `demos/architectural-integrity/demo_01_pure_calls_log/aether/main.aeth`: E0801 10:1->13:3
- `demos/architectural-integrity/demo_02_net_glob_mismatch/aether/main.aeth`: E0801 18:1->21:10
- `demos/architectural-integrity/demo_05_composition/aether/main.aeth`: E0801 25:1->28:3; E0801 40:1->43:10
- `demos/capability-firewall/log_formatter.aeth`: E0801 33:1->37:3
- `demos/case_studies/code_injection/aether/vulnerable.aeth`: E0731 15:1->19:10
- `demos/case_studies/command_injection/aether/vulnerable.aeth`: E0714 21:1->24:10
- `demos/case_studies/composition_kitchen_sink/aether/multi_violation.aeth`: E0712 12:1->15:3; E0713 18:1->21:10; E0719 24:1->27:10; E0720 30:1->33:10
- `demos/case_studies/idor_cross_tenant/aether/vulnerable.aeth`: E0717 23:1->29:20
- `demos/case_studies/insecure_deserialization/aether/vulnerable.aeth`: E0720 13:1->17:10
- `demos/case_studies/log4shell/aether/vulnerable.aeth`: E0801 51:1->54:26
- `demos/case_studies/marker_laundering/aether/vulnerable.aeth`: E0729 24:1->28:3
- `demos/case_studies/missing_authorization/aether/vulnerable.aeth`: E0716 23:1->30:20
- `demos/case_studies/open_redirect/aether/vulnerable.aeth`: E0718 23:1->26:10
- `demos/case_studies/pii_egress/aether/vulnerable.aeth`: E0715 22:1->29:3; E0715 22:1->33:34
- `demos/case_studies/record_field_marker/aether/vulnerable.aeth`: E0715 20:1->23:3; E0715 20:1->25:34
- `demos/case_studies/secret_in_logs/aether/vulnerable.aeth`: E0712 23:1->32:3; E0712 23:1->36:3
- `demos/case_studies/sql_injection/aether/vulnerable.aeth`: E0713 22:1->25:10
- `demos/case_studies/template_injection/aether/vulnerable.aeth`: E0719 14:1->18:10
- `demos/case_studies/zipslip_traversal/aether/vulnerable.aeth`: E0711 25:1->28:34
- `demos/evidence/CVE-2007-4559/aether/vulnerable.aeth`: E0711 19:1->23:34
- `demos/evidence/CVE-2018-14574/aether/vulnerable.aeth`: E0718 19:1->23:10
- `demos/evidence/CVE-2021-35042/aether/vulnerable.aeth`: E0713 18:1->22:10
- `demos/evidence/CVE-2021-44228/aether/vulnerable.aeth`: E0801 51:1->54:26
- `demos/evidence/CVE-2022-1292/aether/vulnerable.aeth`: E0714 18:1->22:10
- `demos/evidence/CVE-2023-35078/aether/vulnerable.aeth`: E0716 26:1->32:20
- `demos/evidence/CVE-2025-13526/aether/vulnerable.aeth`: E0717 24:1->31:20
- `demos/payment_workflow/broken.aeth`: E0801 24:1->27:3
- `demos/payment_workflow/broken.fixed.aeth`: E0801 24:1->27:3
- `playground/examples/02_B1_pure_violation.aeth`: E0801 7:1->10:3
- `playground/examples/03_B2_url_discipline.aeth`: E0801 13:1->16:6
- `playground/examples/10_pii_telemetry_violation.aeth`: E0801 35:1->38:3; E0801 58:1->61:10
- `playground/examples/12_path_traversal.aeth`: E0711 20:1->24:34
- `playground/examples/13_secret_in_logs.aeth`: E0712 17:1->23:3; E0712 17:1->25:3
- `playground/examples/14_sql_injection.aeth`: E0713 18:1->22:10
- `playground/examples/15_command_injection.aeth`: E0714 19:1->24:10
- `playground/examples/16_pii_egress.aeth`: E0715 18:1->22:3; E0715 18:1->24:34
- `playground/examples/17_missing_authorization.aeth`: E0716 19:1->23:20
- `playground/examples/18_idor_cross_tenant.aeth`: E0717 20:1->25:20
- `playground/examples/19_open_redirect.aeth`: E0718 18:1->22:10
- `playground/examples/20_template_injection.aeth`: E0719 14:1->18:10
- `playground/examples/21_insecure_deserialization.aeth`: E0720 13:1->17:10
- `playground/examples/24_marker_laundering.aeth`: E0729 20:1->23:3
- `playground/examples/26_match_destructure_leak.aeth`: E0712 14:1->20:7
- `playground/examples/27_fn_alias_laundering.aeth`: E0729 20:1->24:3
- `playground/examples/28_record_field_marker.aeth`: E0715 30:1->34:3; E0715 30:1->36:34
- `playground/examples/29_sink_alias.aeth`: E0712 20:1->24:3; E0713 13:1->17:10
- `playground/examples/30_record_at_sink.aeth`: E0715 18:1->22:3; E0715 18:1->23:34
- `playground/examples/31_code_injection.aeth`: E0731 16:1->20:10
- `playground/examples/32_function_typed_param.aeth`: E0801 46:1->50:3; E0729 36:1->43:3
- `playground/examples/33_boundary_sanitizer_mismatch.aeth`: E0729 30:1->35:10
- `reference/10_temperature_classify/program.aeth`: E0712 35:1->39:5; E0729 35:1->39:38
- `tests/alsp_corpus/01_E0801_print_without_log.aeth`: E0801 1:1->4:3
- `tests/alsp_corpus/02_E0801_readfile_without_fsread.aeth`: E0801 1:1->4:36
- `tests/alsp_corpus/03_E0801_writefile_without_fswrite.aeth`: E0801 1:1->4:34
- `tests/alsp_corpus/04_E0801_now_without_time.aeth`: E0801 1:1->4:10
- `tests/alsp_corpus/05_E0801_print_with_log_missing.aeth`: E0801 1:1->4:3

## Changed tests that pinned old behaviour

None. `tests/test_module_validation.py` gained two tests; no existing
assertion changed. No `tests/alsp_corpus/*.expected.json` needed an update
(they pin codes and patch-target kinds only; all pass).

## Coordinator decisions

1. README sentence, `grammar/effects.md` A11 sentence and the
   `grammar.ebnf` effects production (texts above) belong to the docs
   owner.
2. A11 reuses E0201 (parse) and E0704 (capability vocabulary). If the
   coordinator prefers a dedicated code for an invalid effects clause,
   that is a new catalog row — not added here.
