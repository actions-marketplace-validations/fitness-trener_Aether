# Wave 3 record — the fix-loop never weakens a constraint; every surface sees the same program (iteration 56)

Plan: `audits/audit_2026-09-24_plan.md`, Wave 3 (D1, D2, D3, D4, D7, D8,
plus D9 and A9 as assigned by the coordinator). Rebased onto `main` @
`52f04aa` (Waves 0+1). Ids: BUG-040..047 (048, 049 unused).

Commits:
- `cdf1b02` pretty: print function types; keep full-line comments (A9, D7)
- `177a173` fix-loop never widens a constraint; every surface loads the same program (D1-D4, D7-D9)
- this record

Every item was reproduced red on the pre-fix toolchain first (repro files
under the audit scratchpad `tool\`), and every new/changed test was run
against the `52f04aa` sources and failed (see Measurements, "red before").

## BUGS entries

### BUG-040  the deterministic fix-loop "repaired" by widening the declared constraint and reported `final state: clean`  [OPEN]
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

### BUG-041  SDK, LSP, fix-loop and tools/scan.py never resolved imports; a cross-file E0801 and an unresolved-import E0705 were "clean" everywhere except `check`  [OPEN]
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

### BUG-042  tools/scan.py exited 0 when every file failed to parse, and read a UTF-8 BOM as E0101  [OPEN]
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

### BUG-043  `--json check` stopped at the first non-empty stage, so surfaces disagreed and an agent needed one round-trip per stage  [OPEN]
test: tests/test_surfaces_agree.py (`::test_json_check_reports_every_stage_tagged`)

Found by the audit (D4). Repro (`tool\mix.aeth`): `aether --json check` →
E0801 ×2 only; `sdk.check`/LSP/scan → E0801 ×2 + E0713.

Fix (`177a173`): `--json` emits every stage's diagnostics, each tagged
`"stage"` (`effects`, `security`, ...); text mode keeps the short-circuit
and prints `(N more diagnostic(s) from later stages not shown: security 1;
run with --json to see every stage)`. Exit codes unchanged.

### BUG-044  `fmt --write` and the fix-loop deleted every comment, the `// expect:` header included  [OPEN]
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

### BUG-045  the fix-loop overwrote its input with the transcript when the path lacked `.aeth`, and wrote cp1252/CRLF on Windows  [OPEN]
test: tests/test_fix_loop_cli.py (`::test_outputs_never_overwrite_the_input`)

Found by the audit (D8). `out_tr = args.source.replace(".aeth",
".transcript.json")` is a no-op on `noext`, so the transcript replaced the
input; `open(..., "w")` used the platform encoding and newline.

Fix (`177a173`): `Path.with_suffix`; input, `--out-source` and
`--out-transcript` must be three different files (exit 2 otherwise);
outputs written `encoding="utf-8", newline="\n"`; input read `utf-8-sig`.
`--live`'s default transcript path uses `with_suffix` too and refuses the
input path.

### BUG-046  a lex error made `sdk.check` raise, and the LSP published nothing for the document  [OPEN]
test: tests/test_surfaces_agree.py (`::test_lex_error_is_a_diagnostic_on_sdk_and_lsp`)

Found by the audit (D9). Repro (`tool\lex.aeth`, unterminated string):
`sdk.check` raised `AetherError`; LSP `didOpen` hit the request boundary's
`except`, logged it and published no diagnostics — the file showed clean.

Fix (`177a173`): `load_program` returns lex errors as diagnostics with
`ast=None`; `sdk.check` keeps its return type and returns `[E0103]`; the
LSP publishes it (and `aether_check_payload` lost its now-dead `except`).

### BUG-047  `fmt` and the fix-loop crashed on every function type (`KeyError: 'ret'`)  [OPEN]
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

## LOOP_LOG block

## Iteration 56 — Wave 3 of the 2026-09-24 audit: the fix-loop never weakens a constraint; every surface sees the same program (no new detector)

- **Target:** not a backlog row. Plan Wave 3 (D1, D2, D3, D4, D7, D8) plus
  D9 and A9: the agent-facing toolchain could tell an agent "clean" when
  it was not.
- **Probe-confirmed first (on `52f04aa`):**
  - The fix-loop granted `net` to `log_formatter` and said `clean`; 28 of
    417 repo files ended "clean" only by widening. BUG-040.
  - Cross-file E0801 / unresolved E0705 invisible to SDK, LSP, scan,
    fix-loop. BUG-041.
  - `tools/scan.py` exit 0 with every file unparsed; BOM = E0101. BUG-042.
  - `--json check` hid E0713 behind E0801. BUG-043.
  - `fmt --write` / fix-loop dropped `// expect:` headers. BUG-044.
  - fix-loop overwrote an extension-less input. BUG-045.
  - LSP showed a lex-error file as clean. BUG-046.
  - `fmt` crashed on function types. BUG-047.
- **Fixes (each once, where every caller routes through):**
  - `fix_loop.widening()` judges every edit (deterministic and `--live`);
    widening is refused by default, `--allow-widen` tags it and still
    exits 1; E0801 patch target = the call.
  - `passes.imports.load_program` is the one loader for CLI, SDK (→ LSP,
    fix-loop) and scan.
  - `--json check` = all stages, tagged; scan fails on parse errors.
  - `pretty(ast, source)` keeps full-line comments; function types print.
- **Measured non-breaking:** no detector, frontend table or stage changed;
  check-py output is untouched by construction (no file on its path
  changed). Corpus expect-headers unchanged (`test_corpus` 93/93,
  `scan --expect` green).
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** the fix-loop now stops at
  `not_repaired` with a call-site target but applies no non-widening
  repair itself; a sound mechanical one (delete a debug `print` whose
  value is unused) needs the call position in E0801's `extra` (D10,
  Wave 5) and an owner decision on whether deleting code is "repair".
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally).

## q1 rows

| NEW residual: the no-widening rule judges DECLARATIONS, not behaviour | iter-56 (Wave 3, audit D1): `fix_loop.widening` compares declared effects per function (`_effect_covered`, so glob narrowing passes and broadening fails) and module capabilities. A new function is held to the union of every effect the input declared anywhere, so an LLM fix that adds a helper using an effect some OTHER function already declared passes the rule; `check` still judges whether the caller may call it. It is a structural check on the edit, not a proof the edited program is the author's intent `[source: diagnostics, section: E0801, key: missing_effect]` | high |
| NEW residual: E0801's call-site patch target is the first call by name | iter-56: E0801's `extra` carries `caller`/`callee` but not the call position, so `patch_target` picks the caller's first call to `callee` (else the first call passing it as a value), falling back to the effects clause for a call through an alias. Two calls to the same callee both point at the first. Exact targeting needs the call's position in `extra` (plan D10, Wave 5) `[source: diagnostics, section: E0801, key: callee]` | medium |
| NEW residual: comments survive `fmt`/fix-loop only when they sit on their own lines above a declaration or statement | iter-56 (D7): the lexer discards comments; `pretty(ast, source)` recovers full-line `//` runs by line number. Lost: above a `case` arm, a clause, or a line inside a multi-line expression; right before a block's `end`; trailing `code // comment`; `/* */`. Measured 3 of 407 parseable repo files still fail `fmt --check` only for that reason `[source: diagnostics, section: E0102, key: comment]` | medium |
| NEW residual: imports of a pseudo-named source resolve against the working directory | iter-56 (D2): `load_program` anchors `import` on `dirname(filename)`. `sdk.check(src)` with the default `<sdk>` and the LSP's stateless `aether/check` request (`<aether/check>`) have no file, so an `import` resolves against the process's working directory — usually E0705, but a same-named file there would be fused in. `textDocument/didOpen` uses the document's real path `[source: diagnostics, section: E0705, key: resolved_to]` | low |

## Skipped / not reproduced / deferred

- **E0801 hint order (D1).** The hint text lives in `passes/effects.py`,
  outside this wave's ownership (Wave 2 is editing it). Desired text, for
  the coordinator, replacing `f"add {missing_pretty} to {caller_name}'s
  effects clause, or change the call site"`:
  `f"remove or replace the call to {callee!r} (it performs {missing_pretty}), or — only if {caller_name} is meant to have that effect — add {missing_pretty} to its effects clause"`.
  `grammar/diagnostics.md`'s E0801 "what an agent should do" line should
  say the same (Wave 6).
- **Docs (Wave 6):** `README.md:343` annotates `aether fix-loop
  demos/payment_workflow/broken.aeth` as "deterministic AST repair"; it now
  ends `not_repaired` (exit 1) and names the calls to remove, and
  `--allow-widen` exists. `grammar/diagnostics.md`'s agent-guidance lines
  for E0801/E0701 and any doc describing the fix-loop as reaching `clean`
  on broken.aeth need the same update. `docs/` not touched.
- **`.github/workflows/gate.yml`** (outside the listed ownership, changed
  because it would otherwise go red in CI): the "deterministic fix-loop
  works installed (BUG-026)" step ran `aether fix-loop broken.aeth` and
  then `aether check` on the output. It now asserts exit 1 +
  `not_repaired`, then runs `--allow-widen`, asserts exit 1 +
  `weakens_constraint: true`, and checks the widened output. Unverified
  locally (CI-only step). Coordinator: review.
- **No automatic non-widening repair.** The loop reports the call to
  remove/replace; it does not delete code. See the LOOP_LOG gap.
- **D5/D6/D10** (exit-code table, one serializer, call-site positions) are
  Wave 5; `--json check` still prints JSONL on stderr, now with `stage`.
- **`playground/backend/sandbox.py`** runs the fix-loop and relays its
  output; it now shows `not_repaired` for the widening examples. Not
  changed (not owned).

## Measurements

- **Fix-loop over every non-generated `.aeth` in the repo (417 files),
  default mode, judged by `widening(input, output)`:** `52f04aa` — 31
  outputs widened, 28 of them reported `clean`; statuses clean 315 / stuck
  99 / crash 3 (`32_function_typed_param.aeth` KeyError, two lex-error
  fixtures raised). `177a173` — 0 widened; clean 287 / not_repaired 32 /
  stuck 98 / crash 0. `--allow-widen`: 32 widened, all steps tagged, 0
  `clean`. The six attack demos named in the plan (+ `vulnerable_widened`,
  `CVE-2021-44228`) all end `not_repaired`.
- **`fmt --check` on the 407 parseable repo `.aeth` files:** 57 → 112 pass
  (0 → 0 crashes after A9; `32_function_typed_param.aeth` crashed before).
  Comment-keeping output is AST-identical and idempotent on all 407.
- **Pretty round-trip corpus:** 30-file sample → all 407 parseable files.
- **Surfaces on the audit repros** (`tool\mf`, `tool\imp.aeth`,
  `tool\mix.aeth`, `tool\lex.aeth`, `tool\scandir`): before, CLI alone saw
  E0801/E0705, `--json check` omitted E0713, SDK raised on E0103, scan
  exited 0 with two parse errors; after, identical codes on CLI, SDK, LSP,
  scan, fix-loop.
- **check-py / framework corpus:** not re-measured — no file on the
  check-py path changed (`cmd_check_py`, `_scan_one`, `py_frontend.py`,
  `passes/*` other than `imports.py`/`patch_target.py`, neither of which
  check-py imports). Detector output is unchanged by construction.
- **Red before:** with the eight source files restored to `52f04aa` and
  the new tests in place: `test_surfaces_agree` 0/8, `test_pretty_roundtrip`
  red (KeyError on `32_…` plus the new cases), `test_fix_loop_cli` red,
  `test_fix_loop_demo` red, `test_alsp_corpus` red (E0801 kind
  `FunctionDecl`). All green at `177a173`.
- **Gate:** `python -B scripts/run_all.py` exit 0 at `177a173` (all
  discovered suites PASS incl. `surfaces_agree`; `smt` SKIP, z3 absent).

## Changed tests that pinned old behaviour

- `tests/test_fix_loop_demo.py::test_fix_loop_resolves_broken_candidate`
  → replaced by `test_fix_loop_refuses_to_widen_broken_candidate` +
  `test_allow_widen_applies_flags_and_never_says_clean`. It asserted two
  applied fixes (both widening) and `clean` — the D1 defect as the
  expected outcome. `test_fixed_source_passes_full_check` (checked the
  widened output) folded into the `--allow-widen` test.
- `tests/test_fix_loop_cli.py::test_default_does_not_call_anthropic` —
  expected `OK rc=0` on broken.aeth; now `rc=1` (refusal). The property
  under test (no `anthropic` import) is unchanged.
- `tests/test_fix_loop_cli.py::test_deterministic_path_needs_no_demos_dir`
  — expected exit 0; now exit 1 plus a transcript whose final status is
  `not_repaired` (a traceback is also exit 1, so the transcript proves the
  installed engine ran).
- `tests/alsp_corpus/01..05_E0801_*.expected.json` —
  `patch_target_kind` `FunctionDecl` → `Call`: the target is now the
  offending call, per D1.
- `tests/test_pretty_roundtrip.py::_collect_corpus` — widened from a
  3-directory sample to every parseable `.aeth` (stricter, not looser).
- `demos/payment_workflow/broken.aeth` — its comment said the fix-loop
  "should mechanically resolve both"; it now says the loop refuses both
  (header `// expect: E0701x2, E0801` unchanged). `broken.fixed.aeth` /
  `broken.transcript.json` are regenerated by `test_fix_loop_demo` on
  every gate run and now hold the unchanged input and the `not_repaired`
  transcript.
