# Aether v0.1 — Phase 1 Status Report

**Date:** 2026-05-03 (post-audit)
**Scope:** Phase 1 bootstrap as described in the project plan: spec, reference programs, transpiler, system prompt, benchmark harness. Independent review on 2026-05-03 surfaced three critical issues; all three are now fixed.

## End-to-end verification

`python3 -B scripts/run_all.py` reports:

    # reference:    10/10
    # bench:        5/5
    # regression:   PASS

Exit code 0 from the project root.

## Post-audit fixes (2026-05-03)

| ID | Fix | Verified |
|---|---|---|
| S-001 | `ensures` postconditions are now runtime-checked at every return site, including the implicit fall-through path. Violations raise `[E0301]` with the failing clause text and function name. | Regression test in `tests/test_regressions.py::test_S001_*` |
| S-011 | Lexer no longer mis-tokenizes `x!=3`. The `!` trailer is consumed only when the next char isn't `=`, so `!=` lexes as a single 2-char symbol. Predicate (`isVowel?`) and effectful (`readFile!`) idents still tokenize correctly. | `tests/test_regressions.py::test_S011_*` |
| S-012 | Harness enforces `timeout_ms` via POSIX `SIGALRM` + `setitimer`. Infinite-loop candidates fail with code `E0601`, category `timeout`. Verified at 301ms against a 300ms budget. On Windows (no SIGALRM) timeouts degrade to no-op; the harness header documents the workaround. | `tests/test_regressions.py::test_S012_*` |

The audit also corrected a stale issue (S-003): higher-order functions actually work; the original log entry was wrong. Three new entries (S-013, S-014, S-015, S-016) were added for spec-vs-implementation gaps the audit surfaced (value-level `as`, zero-position diagnostics, `result` reservation, mangling collision).

## What ships in v0.1

### Specification (`grammar/`)

| File | Status |
|---|---|
| `keywords.md`      | 47 reserved words, locked, organised by category |
| `types.md`         | Primitives, generics, records, tagged unions, refinement types, capability types — v0.2-only forms (brace record literal, value-level `as`) are now explicitly flagged |
| `effects.md`       | Effect lattice with 11 categories + capability mapping |
| `grammar.ebnf`     | LL(1)-friendly EBNF, Pratt precedence documented inline |
| `stdlib.md`        | ~70 functions across List/Map/Set/String/IO/Time/Hash/Math/Result/Option |

### Reference programs (`reference/`)

10 programs, each with `program.aeth` source and `expected_stdout.txt`. They cover: pure functions, recursion, iteration, conditional chains, list iteration, string manipulation, `Result`/`Option` matching, `Map` building and lookup, tagged-union construction and matching.

### Transpiler (`transpiler/aether/`)

| Module | Purpose |
|---|---|
| `lexer.py`       | Hand-written, ~270 LOC, produces token stream with positions; handles `?` and `!` ident trailers without colliding with `!=` |
| `parser.py`      | Recursive descent + Pratt precedence, ~690 LOC, full v0.1 grammar |
| `emitter.py`     | AST → Python, ~510 LOC, emits `requires` AND `ensures` runtime checks, supports effects, patterns, unions, HOFs |
| `runtime.py`     | Mangled stdlib functions + EffectTracker + Result/Option constructors |
| `diagnostics.py` | Structured `Diagnostic` records with code/category/severity/suggestion |
| `cli.py`         | `aether parse|emit|check|run|test` subcommands; `--json` for agents |

### Generation prompt (`prompt/system_prompt.md`)

Locked, ~3,500 tokens. Includes syntax cheat sheet, type system summary, effect system, stdlib quick reference, a complete worked example, and 12 common-mistake warnings (the original 8 plus four added in the audit: `result` is reserved; brace record literal not in v0.1; value-level `as` not in v0.1; tight `x!=3` works but spaces help readers).

### Benchmark harness (`bench/`)

| Component | Notes |
|---|---|
| `bench/harness.py`     | Compile + run + grade against expected stdout. Now enforces `timeout_ms` via SIGALRM. |
| `bench/tasks/t01–t05/` | 5 tasks with `prompt.md`, `grader.json`, `reference.aeth` |

The harness emits structured JSON suitable for an agent to parse:

    {
      "task_id": "t01_sum_to_n",
      "candidate": "...",
      "stage": "parse|emit|exec|grade",
      "ok": true|false,
      "diagnostic": null | { ... },
      "expected": "...",
      "actual": "...",
      "elapsed_ms": ...
    }

Plus a new diagnostic for timeouts:

    "diagnostic": {
      "code": "E0601",
      "category": "timeout",
      "severity": "error",
      "message": "candidate exceeded timeout_ms=...",
      "suggestion": "check for infinite loops or runaway recursion"
    }

### Regression suite (`tests/`)

`tests/test_regressions.py` exercises each of the three audit fixes (lexer, ensures, timeout) so they cannot silently regress in v0.2.

## How to use this with Claude

The harness deliberately does not call any LLM. The intended loop is:

1. `python3 -B -m bench.harness show-prompt <task_id>`
2. Send the prompt to Claude (or any model) along with `prompt/system_prompt.md`
3. Save the model's response as `candidate.aeth`
4. `python3 -B -m bench.harness run-task <task_id> --candidate candidate.aeth`
5. If `ok` is false, hand the diagnostic back to the model and ask it to fix

The diagnostic output is structured so the model can act on it without parsing free text. The `stage` field tells the agent whether the failure was in parse, emit, exec, or grading; the `suggestion` field gives a one-line hint generated by the parser.

## Quick start

    cd <project-root>

    # Everything: 10 reference programs + 5 benchmark references + regression suite
    PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/run_all.py

    # Just the regression tests
    PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_regressions.py

    # Inspect a single task's prompt
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m bench.harness show-prompt t04_balanced_brackets

    # Run the reference solution for a task
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m bench.harness run-task t04_balanced_brackets \
      --candidate bench/tasks/t04_balanced_brackets/reference.aeth

The `PYTHONDONTWRITEBYTECODE=1 python3 -B` form suppresses `__pycache__` writes that interact badly with mounted Windows filesystems (see SPEC_ISSUES S-010).

## Honest assessment

v0.1 was a runnable language but with caveats large enough to distort an experimental run: ensures was silently disabled, the lexer ate `!=`, and an infinite-loop candidate hung the harness. After the audit-driven fixes, the contract claim is genuine for both directions (precondition + postcondition), the lexer accepts the syntax models are likely to produce, and the harness can survive misbehaving candidates.

What's still parked for v0.2 (open in `SPEC_ISSUES.md`): refinement-type runtime enforcement (S-002), effect-glob subset matching (S-004), record-update brace literal (S-006), property-based fuzzing (S-008), deterministic mode (S-009), better contract diagnostic positions (S-014), contextual reservation of `result` (S-015), and the mangling separator (S-016). None block running the v0.1 generation/test loop today; all are either small fixes or non-blocking ergonomic improvements.

The system is now sufficient for the core experiment.
