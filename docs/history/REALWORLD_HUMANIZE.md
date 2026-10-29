# Real-World Evidence Run: Aether vs. `humanize` (PyPI)

**Date:** 2026-07-05
**Question answered:** Can Aether demonstrate legitimacy against a real program with real users — not a synthetic benchmark — and what does that say about its selling potential?

**Headline result:** Porting four production functions from `humanize` (44.1M downloads/month) to Aether and differential-testing 247,294 inputs surfaced a **previously-undocumented correctness regression shipping in the current PyPI release of humanize (4.16.0)**, plus deterministic contract-catches of two documented historical bugs from humanize's issue tracker. Every one of the 223 output divergences between the Aether port and the real library was machine-attributed to a defect or float artifact on the *library's* side — zero on the port's side.

---

## 1. Target selection and legitimacy

Requirement: a program with real users on the open-source internet, small enough to port honestly, algorithmic enough to sit inside Aether v0.3's expressible subset (pure functions over Int/Float/String/List; no regex, no i18n).

Chosen target: **[humanize](https://github.com/python-humanize/humanize)** — "python humanize functions" (number/size/date formatting).

| Legitimacy signal | Value | Source |
|---|---|---|
| PyPI downloads, last month | 44,147,742 | [pypistats.org/packages/humanize](https://pypistats.org/packages/humanize) (read 2026-07-05) |
| PyPI downloads, last day | 881,939 | same |
| GitHub stars / forks | 737 / 113 | [GitHub API](https://github.com/python-humanize/humanize), read 2026-07-05 |
| Version under test | 4.16.0 (current release), installed from PyPI | `pip install humanize` |

This is not a toy: it is a maintained library (release 4.16.0 is current; PRs merged as recently as 2026-06-30) with an active issue tracker and tens of millions of monthly installs.

## 2. What was built

All artifacts are in `bench/realworld_humanize/`:

| File | Purpose |
|---|---|
| `humanize_port.aeth` | Faithful Aether port of `ordinal`, `intcomma` (int path), `intword` (default `%.1f`), `naturalsize` (decimal, non-gnu, `%.1f`) — with `requires`/`ensures` contracts |
| `differential.py` | Harness: compiles the port with the Aether emitter, executes 247,294 differential cases against real humanize 4.16.0, machine-classifies every divergence |
| `buggy_intword_hist86.aeth` | Historical issue [#86](https://github.com/python-humanize/humanize/issues/86) defect ported verbatim + the contract it should have had → `E0304` |
| `buggy_intword_carry416.aeth` | The **currently-shipping** 4.16.0 carry defect ported + normalization contract → `E0304` |
| `boundary_guards.aeth` | Boundary contracts for issues [#57](https://github.com/python-humanize/humanize/issues/57) and [#171](https://github.com/python-humanize/humanize/issues/171) → `E0301` |
| `ordinal_intcomma.aeth` | First-pass smoke port (superseded by `humanize_port.aeth`, kept for the record) |

Reproduce everything:

```
pip install --target <dir> humanize==4.16.0
HUMANIZE_PYLIBS=<dir> python bench/realworld_humanize/differential.py
python -m transpiler.aether.cli run bench/realworld_humanize/buggy_intword_hist86.aeth
python -m transpiler.aether.cli run bench/realworld_humanize/buggy_intword_carry416.aeth
python -m transpiler.aether.cli run bench/realworld_humanize/boundary_guards.aeth
```

## 3. Result 1 — Expressiveness: Aether can carry real production code

Differential run (Python 3.13.7, humanize 4.16.0, fixed seed 20260705):

```
ordinal:      42001/42001 match (100.0000%)
intcomma:     56001/56001 match (100.0000%)
intword:      77556/77681 match (99.8391%)
naturalsize:  71513/71611 match (99.8631%)

total cases: 247294
total divergences: 223 (223 attributed, 0 unexplained)
PASS
```

The 223 divergences fall into exactly two machine-checked classes, both on humanize's side:

1. **195 exact-half decimal ties** (inputs like 1050, 2450 at their power bracket). humanize formats through `int → float → "%.1f"`, i.e. two roundings; whether 2.45 renders "2.4" or "2.5" depends on the bit pattern of the nearest double. The Aether port rounds the exact rational value once, half-to-even. On these inputs the port is the correctly-rounded answer; the divergence direction on humanize's side is float-bit-pattern noise in both directions.
2. **28 instances of the carry regression described in §4** — a real defect in the shipping release.

The differential harness verifies the attribution mechanically (`is_decimal_tie`, `is_carry_bug` in `differential.py`) and fails the run if even one divergence escapes both classes. Zero did.

## 4. Result 2 — A previously-undocumented regression in the current humanize release, found by this run

**The defect.** `intword`'s rollover check in humanize ≥ 4.15.0 ([number.py](https://github.com/python-humanize/humanize/blob/main/src/humanize/number.py)):

```python
if not largest_ordinal and rounded_value * power == powers[ordinal + 1]:
```

`rounded_value * power` is a float; `powers[ordinal + 1]` is an exact int. From 10**24 upward the power's `5**k` factor exceeds 2**53, the power is not representable as a double, the equality is always False, and the carry never fires. Verified live on 4.16.0:

```
humanize.intword(999_999_999)   == '1.0 billion'          # carry works at small scale
humanize.intword(10**24 - 1)    == '1000.0 sextillion'    # should be '1.0 septillion'
humanize.intword(10**27 - 1)    == '1000.0 septillion'    # should be '1.0 octillion'
humanize.intword(10**100 - 1)   == '9999999999999999827…336.0 decillion'
                                   # a 67-digit coefficient from a "human-readable" library;
                                   # should be '1.0 googol'
1000.0 * 10**21 == 10**24       # False  <- the broken comparison
1000.0 * 10**15 == 10**18       # True   <- why it works below 10**24
```

**It is a regression, bisected to a specific release.** Testing each PyPI release on the probe `intword(10**24 - 1)`:

| Version | Output |
|---|---|
| 4.11.0 – 4.14.0 | `1.0 septillion` (correct) |
| **4.15.0 – 4.16.0** | `1000.0 sextillion` (**regressed**) |

The 4.15.0 rewrite came from [PR #273 "Fix plural form for `intword` and improve performance"](https://github.com/python-humanize/humanize/pull/273) (merged 2025-11-07). The pre-4.15 code compared `float(format % chopped) == powers_difference` — float against float, which held at every bracket. The rewrite changed it to float-against-exact-int, which silently fails from 10**24. A bug-fix/performance PR introduced a correctness regression that the project's CI did not catch — and still doesn't: [PR #304](https://github.com/python-humanize/humanize/pull/304) (merged 2026-06-30) added a googol test, but only for the exact power `10**100`, which is unaffected; `10**100 - 1` remains broken in 4.16.0.

**Prior-art check (honesty).** GitHub issue search on 2026-07-05 (`intword 1000.0`, `sextillion OR septillion OR carry` in `repo:python-humanize/humanize`) found no existing report of this defect. Closest neighbors: [#86](https://github.com/python-humanize/humanize/issues/86) (closed; the older googol-gap bug at 10**36) and [PR #329](https://github.com/python-humanize/humanize/pull/329) (the same rollover class fixed in `naturalsize` only). We cannot prove it is unreported everywhere; we can say a direct search of the project's own tracker found nothing.

**Why this run found it.** The Aether port's carry is integer-exact because Aether's contract discipline pushed the port toward the exact rational form (`t * power == 10 * nextPower`), and the differential harness refuses to leave any divergence unattributed. The bug is invisible to eyeball testing — nobody calls `intword(10**24 - 1)` by hand — and invisible to humanize's own suite.

**Contract catch, in-language.** `buggy_intword_carry416.aeth` ports the float-mediated carry faithfully and declares the normalization contract humanize itself enforces at small scale. Output of `aether run`:

```
[E0304] error (contract) at line 0, col 0: ensures clause failed in intwordFloatCarry:
  (((n >= 1000) and (n < pow10(...))) implies (not startsWith?(...)))
1.0 billion          <- 999999999: carry works, contract silent
1.0 quintillion      <- 10**18-1:  carry works, contract silent
                     <- 10**24-1:  contract violation, structured diagnostic, exit 2
```

Same defect, same inputs: the real library ships the wrong string to users; the Aether version refuses to return it and says which clause failed, machine-readably (`--json` gives the full structured diagnostic).

## 5. Result 3 — Documented historical bugs, caught deterministically by declared contracts

Three closed, real-user-reported humanize issues were reproduced in Aether with the contract each function should have had:

**Issue [#86](https://github.com/python-humanize/humanize/issues/86) — "Failing for 1000 decillion" (production Discord bot showed "0 googol" for a nonzero balance).** `buggy_intword_hist86.aeth` ports the buggy ≤4.4-era loop verbatim, plus one contract line: `ensures (n >= 1000) implies (not startsWith?(result, "0"))`. On the issue's exact input (10**36):

```
[E0304] error (contract): ensures clause failed in intwordBuggy: ((n >= 1000) implies (not startsWith?(...)))
```

The bug that reached that bot's users cannot ship past an `aether run`.

**Issue [#57](https://github.com/python-humanize/humanize/issues/57) — `metric(0)` crashed with `ValueError: math domain error`.** The domain restriction existed in the math (`log10`), but not in the signature. The Aether port states it: `requires value > 0.0 or value < 0.0`. The failure mode changes from an unstructured traceback deep inside `number.py` to `E0301` naming the violated clause at the boundary.

**Issue [#171](https://github.com/python-humanize/humanize/issues/171) — negative timedelta silently rendered "a day".** The wrong-branch bug lived past an unguarded boundary. `boundary_guards.aeth` declares `requires seconds >= 0` on the bucket function:

```
[E0301] error (contract): requires clause failed in naturalDeltaBucket: (seconds >= 0)
3
a moment
a day       <- valid inputs unaffected
```

A silently wrong user-visible string becomes a loud, located, machine-actionable refusal — the input class the fix commit later handled with `abs()`.

Additionally, issue [#24](https://github.com/python-humanize/humanize/issues/24) (`intcomma(num, ndigits=0)` ignored `ndigits`) is an instance of Python's `if ndigits:` falsy-zero trap. In the Aether port the parameter would be `Option<Int>`; `isSome?`/`unwrapOrElse` is the only way to read it, so the `0`-vs-`None` conflation that caused the bug has no syntax to be written in. This one is an analysis claim, not a test artifact.

## 6. Honest limits of this run

- **Scope of the port.** Four functions, English locale, default `%.1f` format, integer inputs, decimal non-gnu `naturalsize`. Not ported: i18n/locale machinery, custom format strings, float/str inputs, `binary`/`gnu` modes, and `intcomma`'s float path. Aether v0.3 has no regex and no float-format primitive, which is why the port renders tenths from exact integers.
- **The tie divergences are not a humanize "bug."** `%.1f` double-rounding is standard C/Python behavior. The claim is only that the port is the exact-rational rounding and every divergence is attributed — not that humanize is wrong on ties.
- **The carry regression is a genuine defect** by humanize's own normalization intent (it carries at 10**9; its own comment says "After rounding, we end up just at the next power") — but it affects magnitudes ≥ 10**24, which is far outside most users' inputs. Impact is real but niche; the evidentiary value is that the method found it, not that the sky is falling.
- **Aether Int is spec'd as 64-bit** (`grammar/types.md`); the transpiled runtime inherits Python's arbitrary-precision ints, which this run relies on above 2**63. Flagged as a spec/runtime gap to record in SPEC_ISSUES.md.
- **One run, one library.** This is a single well-instrumented data point, not a study. It complements — not replaces — the RW_MINING.md runbook for measuring real-world capability-delta rates.
- **Runtime, not static, enforcement.** The contract catches here are runtime `E0301`/`E0304` diagnostics (v0.3 checks refinements and contracts at boundaries at runtime; there is no SMT proof in this run).

## 7. What this evidences for selling potential

Sticking to the discipline of qualifier + metric:

1. **Expressiveness on real code (measured):** four production functions from a 44.1M-downloads/month library ported 1:1; 247,294-case differential with 0 unattributed divergences. Aether's subset is small, but it is not a toy subset — it carried real shipping code faithfully enough that every remaining delta localized a library-side artifact.
2. **The contract layer catches the bug classes this library actually shipped (demonstrated on 3 documented issues):** the exact defects real users reported (#86, #57, #171) become structured compile-run refusals when the function's implicit contract is declared — one clause each, no test-writing.
3. **The method finds new bugs, not just old ones (1 found):** a contract-driven port plus differential harness surfaced a live regression in the current release of a mature, actively-maintained library within a single session — including a version bisect to 4.15.0 and a root cause (float/int representability at 2**53). This is the concrete, repeatable artifact of the pitch "the compiler holds the spec, so drift becomes a diagnostic."
4. **Agent-consumability is real:** every catch above is available as `--json` structured output with code, clause, function, and args — the input format the fix-loop already consumes.

What this does **not** prove: willingness to pay, fit on large multi-module codebases, or that the intword regression matters commercially. The strongest use of this artifact is as a design-partner conversation opener ("we ran your library through this and here is what fell out") and as the demo backbone — an upstream issue filing to python-humanize with the bisect table would convert it into a public, third-party-verifiable reference.

## 8. Sources

- humanize downloads: https://pypistats.org/packages/humanize (read 2026-07-05)
- humanize repo: https://github.com/python-humanize/humanize
- humanize on PyPI: https://pypi.org/project/humanize/
- Issue #86 "Failing for 1000 decillion": https://github.com/python-humanize/humanize/issues/86
- Issue #57 "`metric(0)` crashes": https://github.com/python-humanize/humanize/issues/57
- Issue #171 "Negative amounts of time result in `a day`": https://github.com/python-humanize/humanize/issues/171
- Issue #24 "intcomma(num, ndigits=0)": https://github.com/python-humanize/humanize/issues/24
- Issue #239 "naturalsize output changed between 4.11.0 and 4.12.0" (precedent for silent minor-version drift): https://github.com/python-humanize/humanize/issues/239
- PR #273 (introduced the 4.15.0 carry regression): https://github.com/python-humanize/humanize/pull/273
- PR #304 (googol test, exact power only): https://github.com/python-humanize/humanize/pull/304
- PR #329 (same rollover class fixed in naturalsize only): https://github.com/python-humanize/humanize/pull/329
- 4.15.0 release notes: https://github.com/python-humanize/humanize/releases/tag/4.15.0

## Appendix A — Draft upstream issue (not filed; founder decision)

> **Title:** `intword` no longer carries to the next power at boundaries ≥ 10**24 (regression in 4.15.0)
>
> **What happened:** `humanize.intword(10**24 - 1)` returns `'1000.0 sextillion'`; 4.14.0 and earlier returned `'1.0 septillion'`. Worse at the top: `intword(10**100 - 1)` returns a 67-digit coefficient (`'9999999999999999827…336.0 decillion'`).
>
> **Cause:** in the 4.15.0 rewrite (#273), the rollover check became `rounded_value * power == powers[ordinal + 1]` — a float compared against an exact int. For `powers[ordinal + 1] >= 10**24`, `5**k > 2**53` makes the power non-representable as a double, so the comparison is always False and the carry is skipped. (`1000.0 * 10**21 == 10**24` is `False`; `1000.0 * 10**15 == 10**18` is `True`, which is why smaller brackets still work.) The pre-4.15 code compared float-to-float (`float(format % chopped) == powers_difference`) and did not have this failure.
>
> **Fix suggestion:** compare in exact integer space, e.g. compute the rounded coefficient as an integer number of tenths and check `tenths * power == 10 * powers[ordinal + 1]`, or compare against `float(powers[ordinal + 1])` explicitly if float semantics are intended. Note #304 tests only the exact `10**100`, which does not exercise this path; a `10**24 - 1` / `10**100 - 1` test would.
>
> Repro: Python 3.13.7, humanize 4.16.0, Windows and Linux (pure-Python path).
