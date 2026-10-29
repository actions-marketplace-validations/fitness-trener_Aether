# Architectural-Integrity Demo Corpus

Five paired demos that illustrate Aether's central claim:
**the compiler refuses architecturally-incorrect compositions that the
equivalent Python program accepts.**

Each demo is a wedge: the Aether side is rejected at check time (or
refinement-boundary time) with a structured diagnostic and exit 1; the
Python side runs to completion with exit 0 and silently breaks the
intended architectural promise.

| Demo | Phase | Architectural promise broken                         | Aether code | Python result            |
|------|-------|------------------------------------------------------|-------------|--------------------------|
| 01   | B.1   | "this `pure` function has no side effects"           | `E0801`     | prints + exit 0          |
| 02   | B.2   | "this gateway only reaches `api.x/users/*`"          | `E0801`     | hits admin URL + exit 0  |
| 03   | B.3   | "this module only requires the `log` capability"     | `E0701`     | writes /tmp file + exit 0|
| 04   | B.4   | "the discount % is between 0 and 100"                | `E0302`     | returns price -20 + 0    |
| 05   | comp. | all four of the above broken in one payment workflow | `E0801`×2   | prints debug + admin URL |

Each subdirectory has `aether/main.aeth`, `aether/grader.json`,
`python/main.py`, and a per-demo `README.md`. The grader files are
compatible with `bench/harness.py` — a regression against any demo can
drop into `bench/tasks/` unchanged.

## Run them all

```sh
python3 -B demos/architectural-integrity/run_demos.py
```

prints a per-demo PASS/FAIL summary against each grader and confirms
the Python counterparts run to a non-zero exit nowhere in the corpus.
