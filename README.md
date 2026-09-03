# Aether

**A security checker for the Python your AI agent writes — including the
classes pattern scanners structurally miss.**

Point it at a Python file. It finds SQL injection, command injection, open
redirect, SSTI, insecure deserialization, hardcoded credentials and XXE by
reading dataflow and argument shape, not by matching patterns. No rewrite,
no annotations, no configuration.

    $ aether check-py bench/py_frontend/corpus/sqli_repro.py
    [E0713] error (capability) at line 20, col 12: function 'find_user' builds a SQL query for
    'sqlQuery' unsafely (query is built by string concatenation - use sqlBind(...)); untrusted
    input concatenated into a query is an injection
      hint: use a fixed literal, or parameterize with sqlBind("... ? ...", value) which escapes
      the value so it cannot break out of the query
    [E0713] error (capability) at line 26, col 12: function 'find_user_fstring' builds a SQL
    query for 'sqlQuery' unsafely ...

    2 finding(s) in 3 function(s); 3 unprovable region(s) in 3 function(s).
    NOT checked on Python (no declared effects clause, no marker types): ...

Exit `0` clean, `2` on findings. Every command on this page is runnable
from a fresh clone.

---

## Why it finds things other scanners don't

Aether's detectors are designed against a **typed intermediate
representation** with explicit security markers — `Authorized<T>`,
`Untrusted<T>`, `Secret<T>`, `PII<T>` — and then projected down onto plain
Python. A rule is written once against dataflow, not once per syntactic
spelling.

Two consequences you can reproduce right now.

**It reads the argument, not the call.** `bench/realworld_subprocess_cmdi/subprocess_repro.py`
holds a command injection on line 18 and its documented fix — the argv-list
form, no shell — on line 24.

    $ python -m bandit -f custom -q bench/realworld_subprocess_cmdi/subprocess_repro.py
    ...:13: B404[bandit]: LOW: Consider possible security implications associated with the subprocess module.
    ...:18: B602[bandit]: HIGH: subprocess call with shell=True identified, security issue.
    ...:24: B607[bandit]: LOW: Starting a process with a partial executable path
    ...:24: B603[bandit]: LOW: subprocess call - check for execution of untrusted input.

    $ aether check-py bench/realworld_subprocess_cmdi/subprocess_repro.py
    [E0714] error (capability) at line 18, col 12: function 'make_thumbnail' builds a shell
    command for 'shellExec' unsafely ...

Both find line 18. Only one of them also warns about the fix. A checker
that flags the remediation trains people to ignore it.

**It reads literal content, not variable names.** The same corpus has a
real AWS key in `hardcoded_secret_repro.py`:

    $ python -m bandit -f custom -q bench/py_frontend/corpus/hardcoded_secret_repro.py
    (no output, exit 0)

    $ aether check-py bench/py_frontend/corpus/hardcoded_secret_repro.py
    [E0723] error (capability) at line 19, col 18: string literal contains a hardcoded AWS
    access key id; a credential in source is committed to version control and shipped in
    every build

Bandit's B105/B106 match password-*ish* variable names; `E0723` matches
provider key *shapes* (`AKIA…`, `ghp_…`, PEM blocks).

This is not a general "better than bandit" claim, and the repo says so at
length in [`bench/py_frontend/REPORT.md`](https://github.com/fitness-trener/Aether/blob/main/bench/py_frontend/REPORT.md) §3:
bandit ships ~70 plugins across crypto, Django, TLS and more; Aether models
8 rows on Python. **On breadth bandit wins outright.** The narrow claim is
the one above, and it is checkable in two commands.

## Measured on 1.19M lines nobody wrote for us

Every false-negative number in a security tool's README is usually measured
against ground truth its own authors wrote. Ours were too — so we went and
got some that weren't.

| | |
|---|---|
| PyPI distributions scanned | 111 |
| Python files / SLOC | 5,588 / **1,192,484** |
| parse failures | **0** |
| analyzer crashes | **0** |
| findings outside test dirs | 39 (**0.033 per KLOC**) |
| agreement with bandit, comparable categories | **86.8%** (125 agreed / 19 candidate misses) |

**No vulnerability was discovered in that corpus**, and roughly 56% of the
39 findings trace to one documented over-flag rule. Both facts are stated
up front in the reports, not buried:
[`bench/pypi_scan/REPORT.md`](https://github.com/fitness-trener/Aether/blob/main/bench/pypi_scan/REPORT.md) (precision,
triaged line by line) and [`bench/pypi_scan/RECALL.md`](https://github.com/fitness-trener/Aether/blob/main/bench/pypi_scan/RECALL.md)
(recall against bandit as an independent oracle — which found **5 real
false negatives**, since fixed).

Reproduce both: `python -B bench/pypi_scan/run_scan.py` and
`python -B bench/pypi_scan/run_recall.py`.

## What it checks on Python, and what it does not

Default-on, no annotations required:

| Code | Class | CWE |
|---|---|---|
| `E0713` | SQL injection | 89 |
| `E0714` | Command injection | 78 |
| `E0718` | Open redirect | 601 |
| `E0719` | Template injection / SSTI | 94 |
| `E0720` | Insecure deserialization | 502 |
| `E0723` | Hardcoded credential | 798 |
| `E0727` | XML external entity (XXE) | 611 |

`--strict` adds `E0711` (dynamic filesystem paths) and the `E0701`
capability inventory. Both are **held back by measurement, not taste**:
E0711 alone fired 476 times on the PyPI corpus against 39 for the entire
default set.

A SQLAlchemy or SQLModel expression — `conn.execute(select(t).where(...))`,
built in one statement or across several, or the `table.delete()` form —
is read as the parameterized query it is, not as a dynamic string. The
line that does not move: `text(...)` or `literal_column(...)` handed a
concatenation is still an injection, nested inside a `select()` or not.
This was measured, not assumed — see
[`bench/framework_scan/REPORT.md`](https://github.com/fitness-trener/Aether/blob/main/bench/framework_scan/REPORT.md).

**Not checked on Python at all**, and the CLI prints this every run rather
than letting you assume otherwise: `E0801` effect composition and the
taint-marker family (`E0712`/`E0715`/`E0716`/`E0717`/`E0724`). Those need a
declared `effects` clause or a marker type, neither of which Python has.
They run on Aether source, where the access-control rows live — see
[Where the rules come from](#where-the-rules-come-from).

Further limits, stated plainly: the analysis is **intraprocedural and
syntactic** — over-flag, never miss *within the modeled surface*, which is
not a soundness proof. Sinks are matched by method name on receivers of
unresolved type. Single file, no cross-module resolution, no control flow.
Full list in [`bench/py_frontend/REPORT.md`](https://github.com/fitness-trener/Aether/blob/main/bench/py_frontend/REPORT.md) §4.

## Install

Python 3.10+. The core toolchain is stdlib-only — zero third-party
packages.

    pip install aether-lang
    aether check-py <your_file.py>

From a checkout, to get the corpus and the benchmarks the commands on this
page reference:

    git clone https://github.com/fitness-trener/Aether.git
    cd Aether
    pip install .

Without installing, every command works through the module path:

    python -B -m transpiler.aether.cli check-py <your_file.py>

Optional extras: `pip install '.[smt]'` adds Z3 for `--prove` contract
checking; `pip install '.[llm]'` adds the Anthropic SDK for the live
fix-loop.

Point it at a whole repository — directories are walked recursively for
`.py`, skipping `.git`, `.venv`, `node_modules`, `build` and the other
vendored trees, because a repo scan that becomes a dependency scan buries
the findings you can actually fix:

    $ aether check-py src/ scripts/
    src/handlers/search.py
    [E0713] error (capability) at line 41, col 12: function 'lookup' builds a SQL query ...

    scanned 128 file(s) · 3 with findings · 1 unparseable · 0 analyzer error(s)
    findings by code: E0713x2, E0723x1

Findings sort worst-first by the per-code risk rating, so the top of a long
scan is the part worth reading.

## CI and GitHub Code Scanning

Findings carry `security-severity` derived from a per-code risk table
([`risk.py`](https://github.com/fitness-trener/Aether/blob/main/transpiler/aether/risk.py)), so they land in the **Security →
Code Scanning** tab already ranked, and appear inline on the PR diff.

```yaml
name: aether
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fitness-trener/Aether@v0.3.1
        with:
          path: 'src tests'      # default: .
          strict: 'false'        # adds E0711 + the E0701 inventory
```

Inputs: `path`, `strict`, `fail-on-findings`, `upload-sarif`, `sarif-file`,
`category`, `setup-python`, `python-version`. Outputs: `findings`,
`sarif-file`, `exit-code`. Full contract in [`action.yml`](https://github.com/fitness-trener/Aether/blob/main/action.yml).

Or drive the CLI yourself:

    aether check-py src/ --sarif > aether.sarif

`.aeth` corpora go through `tools/scan.py`, which additionally supports
`--min-risk high` as a triage filter and `--expect` for a repo that
deliberately contains violations;
[`.github/workflows/aether-scan.yml`](https://github.com/fitness-trener/Aether/blob/main/.github/workflows/aether-scan.yml)
is the working reference for that path.

---

## Where the rules come from

Aether is also a **language**, and that is why the detector set looks the
way it does rather than being a marketing line.

The compiler refuses to compose components that violate declared
architectural constraints — effect locality, URL discipline, module
capability scope, refinement-typed boundaries — and emits structured
diagnostics an agent fix-loop can act on mechanically. Because the type
system carries `Authorized<T>` and `Untrusted<T>` as first-class markers,
whole classes become expressible that a pattern matcher has no vocabulary
for:

- **`E0716` missing authorization** (CWE-862/863) — a data-mutating sink
  reachable with no authorization proof in its dataflow.
- **`E0717` cross-tenant access / IDOR** (CWE-639) — an authorization proof
  that is not bound to the *same resource id* the sink mutates.

Nine named companies' own public CVEs and incidents are ported and refused
at check time in [`outreach/CUSTOMER_EVIDENCE.md`](https://github.com/fitness-trener/Aether/blob/main/outreach/CUSTOMER_EVIDENCE.md)
— Copilot, Cursor, Lovable, Replit, Vercel, Atlassian, Ivanti, GitLab,
crawl4ai. **Five of the nine are access-control cases that mainstream SAST
does not cover.** These are retrospective ports of public incidents, not
live scans of anyone's systems, and the file says so first.

Current surface: **55 diagnostic codes across 31 gated detectors**, held by
a monotonic ratchet (`tests/ratchet_baseline.json`) that turns the build red
if a detector is ever removed or weakened. Security family `E0710`–`E0731`;
static-semantic family `E0202`–`E0207` (non-exhaustive match, unreachable
arm, dead code, dead store, ignored `Result`, unsatisfiable refinement).

Working with the language directly:

    aether check demos/payment_workflow/aether/main.aeth
    aether run   demos/payment_workflow/aether/main.aeth
    aether fmt   demos/payment_workflow/aether/main.aeth
    aether fix-loop demos/payment_workflow/broken.aeth       # deterministic AST repair
    aether fix-loop demos/payment_workflow/broken.aeth --live # LLM repair (needs ANTHROPIC_API_KEY)

`--json` on any command emits structured output for an agent to consume;
the Python SDK is `from aether import sdk`, the same spelling installed or
from a checkout.

**Design principles.** One syntactic form per semantic operation · every
public function declares its contracts and effects · modules declare their
capabilities and the runtime grants only what is declared · the AST is
canonical (`parse(print(ast)) == ast`) · errors are structured and
suggestions are machine-readable.

**Honest framing, enforced repo-wide.** Refinement, capability and
effect-scope checks that fire at *runtime* are described as runtime
guarantees, never as static proof. Taint passes are syntactic and
intraprocedural and are described as "over-flag, never miss within the
modeled surface", never as "sound".

## Layout

    transpiler/     The compiler, runtime and CLI — pure Python, no third-party deps
    tools/          py_frontend.py (Python → IR), scan.py (SARIF scanner), risk.py
    grammar/        Specification: keywords, types, effects, EBNF, stdlib, diagnostics catalog
    bench/          Measurement harnesses — py_frontend, pypi_scan, architectural
    demos/          Case studies, including the improvement-loop log
    vault/          Long-term design analysis (Karpathy LLM-wiki method)
    reference/      Reference programs with canonical AST + expected output
    tests/          Integration tests and the monotonic ratchet
    scripts/        run_all.py — the full gate

Full gate: `python -B scripts/run_all.py` (exit 0 = green; 37 PASS suites).

## Documentation

- [`docs/SCANNING.md`](https://github.com/fitness-trener/Aether/blob/main/docs/SCANNING.md) — scanner and CI setup
- [`SECURITY_POSTURE.md`](https://github.com/fitness-trener/Aether/blob/main/SECURITY_POSTURE.md) — the violation classes and the four detector families
- [`grammar/diagnostics.md`](https://github.com/fitness-trener/Aether/blob/main/grammar/diagnostics.md) — every diagnostic code
- [`demos/case_studies/LOOP_LOG.md`](https://github.com/fitness-trener/Aether/blob/main/demos/case_studies/LOOP_LOG.md) — how each detector was built and what it still misses
- [`BUGS.md`](https://github.com/fitness-trener/Aether/blob/main/BUGS.md) — open and fixed defects in Aether itself

## License

Business Source License 1.1 — see [`LICENSE`](https://github.com/fitness-trener/Aether/blob/main/LICENSE). Source is public.
Using Aether on your own code, in production and in CI, is free; so is
research, teaching and evaluation. Code you write in Aether and the Python
the transpiler emits are yours and carry no obligation from this license.

What the license reserves is selling Aether itself — a hosted, embedded or
paid product whose value derives substantially from the compiler,
diagnostic suite or scanner. That needs a commercial license until the
Change Date (2030-07-19), when each released version converts to Apache-2.0.
