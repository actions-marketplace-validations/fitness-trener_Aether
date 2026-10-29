# Agent C record — Python frontend: G7 performance, G5 receiver types, G6 argument injection (iteration 65)

Known-gaps round 2026-09-29. Branch forked from `gaps-2026-09-29` @ `a2f13db`;
every "before" below is a pristine `git archive a2f13db` tree run on the same
machine: 8 logical cores (`os.cpu_count()`), Windows 11, CPython 3.11.15.
The machine was shared with Agents A and B running their own gates, so wall
times vary between runs; each number below is one run, and the serial
comparison is also given as CPU time, which that sharing distorts less.
Ids: BUG-095..099, iteration 65.

Commits:
- `5ae433f` perf(py): one walk per scope in the frontend (gaps round G7)
- `9c8014d` feat(py): argv option injection is E0714 (gaps round G6)
- this record

Files changed (all in Agent C's list): `transpiler/aether/py_frontend.py`,
`tests/test_perf_index.py`, `tests/test_py_frontend_sinks.py`,
`tests/test_sink_rows.py`, `bench/framework_scan/REPORT.md` (§11 appended),
this record. `tests/ratchet_baseline.json` is unchanged: the new program
table is not one of the five tables `tests/test_ratchet.py` counts (see
Coordinator decisions).

## BUGS entries

### BUG-095  The Python frontend walked every file about seven times  [OPEN]
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

### BUG-096  Argument injection through an argv list was silent: `subprocess.run(["git", "clone", url])`, `["git", "-c", x]`, `["ssh", host, cmd]`, `["tar", "--to-command", x]`, `asyncio.create_subprocess_exec("git", *args)`  [OPEN]
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

## LOOP_LOG block

## Iteration 65 — gaps round, Agent C: one walk per scope, argument injection is E0714 (no new detector)

- **Target:** the two TYPE gaps surfaced by iterations 62 and 60 — the
  frontend's repeated AST walks, and argument injection through an argv
  list — plus iteration 59's receiver-type gap, measured and not built.
- **Probe-confirmed first (on `a2f13db`):** 7.1 walked nodes per AST node on
  the three slowest corpus files (1,068,633 for 151,204); five argv shapes
  (`git -c x`, `git clone url`, `ssh host cmd`, `tar --to-command x`,
  `create_subprocess_exec("git", *args)`) exit 0 with 0 findings.
- **Fixes (each once, where every caller routes through):** `_DefIndex`, one
  walk per scope, feeding every per-def consumer; one module-level walk; one
  IR walk for the bound-flow fixes; a generator-free `_walk`. For G6 one
  `_argv_option_payload` read by `_sink_match` and `_call_expr`, over a
  six-program table.
- **G5 measured, not built:** of 11,886 `self.X.m(...)` calls on the corpus,
  2,398 have every binding of `X` in the file be `self.X = <one
  constructor>(...)`. Of the 90 whose method is a by-method sink row, 25
  resolve, and none of the 25 would change: no `Ctor.m` is a table row, none
  is a same-file class's own method, and the 4 haystack `from_string` sites
  are on `HaystackSandboxedEnvironment`, a `SandboxedEnvironment` subclass
  not in `_SANDBOXED_ENVS`. 0 findings and 0 confidence ratings would move
  (q3: prevalence × reuse gives nothing for the machinery).
- **Measured (8 logical cores, shared machine):** frontend over the corpus
  76.1 s → 46.2 s in-process; serial `check-py` CPU 98.6–135.7 s → 66.6–68.6 s;
  default jobs 34.3–34.9 s → 20.3–23.8 s (one after-run at 35.5 s).
  G7 output byte-identical. G6: framework 683 → 684, in-repo 107 → 113,
  every addition true by rule.
- **Residuals (pushed to q1):** see q1 rows below.
- **TYPE gap surfaced for next iter:** the E0714 text is still the shell
  text on an argv finding ("use shellArg", "pass an argv list"). The argv
  finding's fix is a literal `--` before the input, or a check that the
  word does not start with `-`. The text lives in
  `passes/detector_specs.py`; a `CalleeText` for argv-option findings is
  the next step (proposed wording under Coordinator decisions).
- **Suite:** exit 0 (`smt` SKIP, z3 not installed locally).

## q1 rows

| NEW residual: argument injection is judged per program, from a six-program table | iter-65 (gaps G6): an argv whose program is git, ssh, tar, find, rsync or zip, handed a non-literal word before a literal `--`, is E0714; ssh and find ignore `--`. Every other program is judged as before (clean in argv form), including interpreters, `docker`, `curl -K`/`-o`, `scp -S`, `hg` (CVE-2017-1000116's family) and a program named through a non-literal argv[0] or under another name (a symlink, a wrapper script). An argv built elsewhere (a parameter, a list mutated with `.append`) is not read. Over-flags: the value of a value-taking option (`git -C <dir>`, `tar -f <file>`) is judged as if it could be an option, and so is a word after a subcommand with no code-running option (`git status <x>`). The quoted-shell form is not covered: `"git clone " + shlex.quote(url)` with `shell=True` stays clean, because `_CODE_TAKING_PROGRAMS` in `detector_specs.py` does not list these programs `[source: diagnostics, section: E0714, key: shellExec]` | medium |
| NEW residual: an attribute receiver is not resolved, measured as costing nothing today | iter-65 (gaps G5): `self.x.method(...)` is spelled `self.x.method`, never through the constructor `self.x` was bound to. On the corpus, 25 by-method sink calls have a receiver attribute bound to exactly one constructor. Resolving it would change none of them: no `Ctor.method` table row matches, and the 4 haystack `HaystackSandboxedEnvironment` `.from_string` sites need a sandbox-subclass row as well. A constructor-qualified row (`code.InteractiveConsole.push`, ruamel's `YAML.load` guard) reached only through `self.x` is still a miss `[source: diagnostics, section: E0731, key: evalCode]` | low |

## Skipped / not reproduced / deferred

- **G5 (receiver types via attributes): measured, not built.** The census
  script (`census_g5.py`, scratchpad, same rules as the proposal: every
  attribute-binding site of the name in the file is `self.X = <Call>` or
  `self.X: T = <Call>` with one callee spelling; `setattr` with a computed
  name disables the file) found 25 resolvable by-method sink calls, with
  0 findings or confidence ratings that would change. The 25:
  haystack `chat_prompt_builder.py:268,290`, `prompt_builder.py:176,246`
  (E0719, `HaystackSandboxedEnvironment`); langchain-community
  `chat_message_histories/postgres.py:64,73,85,93` (`self.connection.cursor()`),
  `chat_message_histories/tidb.py:69,97,117,134` (`Session`),
  `graphs/kuzu_graph.py` ×10 (`kuzu.Connection`),
  `vectorstores/aperturedb.py:214,237` (`aperturedb.Utils.Utils`); openhands
  `runtime/plugins/jupyter/__init__.py:73` (a same-package `JupyterKernel`,
  not defined in that file). The one lever that would move findings is
  adding `haystack.utils.jinja2_sandbox.HaystackSandboxedEnvironment` to
  `_SANDBOXED_ENVS` together with G5: −4 E0719 at 0.6. That would be a
  vendor row, and it would clear on the documented control and not on a proof, like
  the existing sandbox rows. Left for the coordinator.
- **G6 in the quoted-shell form:** the judgement lives in
  `detector_specs._shell_pieces_ok` / `_CODE_TAKING_PROGRAMS` (Agent A's
  file). 0 corpus sites: the `shell=True` commands on the corpus start with
  `beam`, `id`, `su`, `python` or a non-literal. Proposed: add `git`, `tar`,
  `rsync`, `zip` to `_CODE_TAKING_PROGRAMS` (ssh and find are already there).
- **G6 wording:** see Coordinator decisions.

## Measurements

Scripts: `python -B -m transpiler.aether.cli --json check-py <path>` (and
`--strict`) from each code root, over the framework corpus
(`bench/framework_scan/_work/src`, 4,946 files) and over the pristine
`a2f13db` tree's `bench tests tools playground demos`, so both builds read
the same input bytes. The byte comparison covers stdout, stderr and the
exit code.

### G7 (after `5ae433f`) — output

- framework `--json check-py`: byte-identical (683 findings, 51 at ≥ 0.9);
  `--strict`: byte-identical (10,839).
- in-repo trees, default: byte-identical (107); `--strict`: byte-identical
  (2,056). The `unprovable` rows are part of each document, so the
  capability side is identical too.
- Every timing run's framework output was also byte-identical to the
  baseline.

### G7 — time (8 logical cores)

| run | before `a2f13db` | after `5ae433f` |
|---|---|---|
| three slowest files, frontend only, min of 5 (two interleaved rounds) | 2.08 / 1.82 s at `a2f13db`; 1.78 / 1.78 s | 1.09 / 1.11 s |
| walked nodes, three slowest files | 1,068,633 | 342,117 |
| frontend over the corpus, in-process | 76.1 s (109.3 s in an earlier loaded run) | 46.2 s |
| `check-py --jobs 1`, in-process CPU | 135.7 s, 98.6 s | 66.6 s, 68.6 s |
| `check-py --jobs 1`, wall (subprocess) | 132.7, 124.4, 123.3 s | 79.0 s, 200.1 s (a run during another agent's gate) |
| `check-py` default jobs (8 workers), wall | 34.3, 34.9, 34.8 s (53.3 s cold) | 23.8, 23.4, 21.1, 20.3 s, 35.5 s (loaded) |

The first row's "2.08 / 1.82" is `a2f13db` against the single-walk change
without `_walk`; `_walk` took the after-time from ~1.2 s to ~1.1 s.
Wave 7 recorded 85.0 s / 25.5 s for serial / default on this corpus on an
idle machine; the serial wall times here are higher because of the other
agents' runs, which is why CPU time is given too.

### G6 (after `9c8014d`), against `a2f13db`

- framework default: 683 → 684, +1: `agno/agno/context/wiki/git_ops.py:119`
  E0714 0.9 `asyncio.create_subprocess_exec("git", *args, ...)` — a
  general `git <args>` runner; any `-c core.pager=...` / `--upload-pack=`
  in `args` runs a command. True by rule. `--min-confidence 0.9` 51 → 52.
- framework `--strict`: 10,839 → 10,841: the E0714 above, and E0701 at
  `git_ops.py:89` (`run` now performs `exec.run`: naming the call
  `shellExec` gives the strict capability inventory the process the call
  starts. True. An argv `subprocess.run` not named a sink still adds
  nothing to the inventory, an existing inconsistency this change does
  not widen).
- in-repo default: 107 → 113, +6 (each read at source):
  - `bench/py_frontend/corpus/sink_coverage_repro.py:116`
    `["git", "status", cmd]`. True by rule, though `git status` has no
    code-running option of its own: an over-flag of the word-after-subcommand
    kind (q1 row).
  - `tests/test_ratchet.py:276` `["git", *args]`. The same wrapper shape as
    agno. True by rule.
  - `tools/aether_pr_check.py:94` and `tools/diff_ingest.py:233`
    `["git", "-C", repo, "show", f"{ref}:{path}"]`. The judged word is
    `repo` (the value of `-C`, an over-flag), but the f-string word
    beginning with `ref` is a real injection: `ref = "--output=/path"` makes
    `git show` write a file. True by rule.
  - `tools/py_corpus/04_subprocess_runner.py:8`
    `["git", "-C", repo, "rev-parse", ...]`. The `-C` value only, an
    over-flag (q1 row).
  - `tools/py_corpus2/trap_06_from_subprocess.py:4`
    `run(["tar", "-czf", dest, directory])`. `directory` is an operand, and
    `--checkpoint-action=exec=...` there runs a command. True by rule. (`dest`
    is the value of `-f` and is judged first. That is an over-flag on that
    word; the call is still an injection site.)
- in-repo `--strict`: 2,056 → 2,072: the 6 above and 10 E0701 `exec.run`
  inventory rows for the same functions and their module scopes.
- No finding was removed. No kept finding changed confidence.
- `bench/py_frontend/REPORT.md` counts on `tools/py_corpus{,2}` move by +1
  E0714 each (04_subprocess_runner, trap_06). That report is outside this
  agent's files; its numbers predate this change.

## Changed tests that pinned old behaviour

None. Two tests were added
(`test_py_frontend_sinks.py::test_argv_option_injection_is_a_command_injection`,
`test_sink_rows.py::test_every_argv_program_flags_and_clears`) and one was
added to `test_perf_index.py` (`test_frontend_walks_each_scope_once`). All
three are red on `a2f13db`: 16 of 16 flagged shapes silent, 6.8 walked nodes
per AST node against a budget of 3, and `pf._ARGV_CODE_OPTIONS` absent.

## Coordinator decisions

1. **E0714 wording for argv findings** (Agent A's `detector_specs.py`). An
   argv-option finding currently reads "(command is a dynamic expression -
   use shellArg(template, value)) ... pass an argv list and no shell". It is
   already an argv list, and `shlex.quote` is not the fix (and stays a
   finding). A fix-loop following this text would not converge. Proposed: a
   `CalleeText` keyed on the finding's `match == "argv"` plus a non-shell
   program. That needs `CalleeText` to key on match kind, or the frontend to
   set a distinguishing `extra.callee`; the choice is Agent A's. Suggested
   message: "function {fn!r} passes an untrusted word to {program} in an
   argv list ({reason}); a word that begins with '-' becomes an option, and
   {program} has options that run commands". Suggested fix: "put a literal
   '--' before the untrusted words (`["git", "clone", "--", url, dest]`),
   or reject a value that starts with '-'".
2. **Ratchet coverage of the new table.** `tests/test_ratchet.py`'s
   `_PY_TABLES` counts five tables; `_ARGV_CODE_OPTIONS` (6 rows) is pinned by
   `tests/test_sink_rows.py` in both directions but not counted. Adding it
   to `_PY_TABLES` and raising `min_py_table_rows` 128 → 134 in the same
   commit would lock it. `test_ratchet.py` is outside this agent's files.
3. **G5** (see Skipped): build only with a haystack sandbox-subclass row,
   for −4 E0719 at 0.6, or leave it parked.
4. **README perf sentence**: after both waves, serial CPU is about 67 s
   and default wall about 20–24 s on the 4,946-file corpus. Any README
   number should be re-measured on an idle machine first.

## Proposed `bench/framework_scan/REPORT.md` section

Appended as §11 in the G6 commit (text identical to the file).
