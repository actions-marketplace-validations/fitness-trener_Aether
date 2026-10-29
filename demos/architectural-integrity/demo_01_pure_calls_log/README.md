# Demo 1 — pure caller leaks log effect (B.1: static effect checking)

## What this shows

A function declared `pure` calls `print`. In Aether the static effect
pass refuses to compile this: `[E0801] function 'validate' (effects
'pure') calls 'print' which has effect 'log' not covered by the caller`.
In Python the equivalent code runs and prints, with no warning.

## Why this matters at scale

In multi-component systems, "pure" functions are the leaves of trust:
auditors assume they have no side effects, caches assume calls are
idempotent, parallel runtimes assume reordering is safe. A pure
function that learned to print is the canonical example of an
AI-generated refactor that compiles, passes unit tests, and silently
poisons every architectural assumption downstream.

## How to reproduce

```sh
# Aether: rejected at check time, exit 1 with structured diagnostic
python3 -B -m transpiler.aether.cli check \
    demos/architectural-integrity/demo_01_pure_calls_log/aether/main.aeth

# Python: runs, prints, exit 0 — bug is invisible
python3 demos/architectural-integrity/demo_01_pure_calls_log/python/main.py
```

## Grading

The Aether side is wedge-graded: `expected_exit_code: 2`,
`expected_stderr_pattern: "E0801.*validate.*'log'"`. A regression
against this demo can drop into `bench/tasks/` and be graded by the
existing harness.
