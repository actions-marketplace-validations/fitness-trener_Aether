# Real-World Evidence Run 3 (Tier 2): bech32 checksums, IRR/NPV, cron scheduling

**Date:** 2026-07-05
**Follows:** `REALWORLD_HUMANIZE.md` (run 1), `REALWORLD_SECURITY_PACKAGING.md` (run 2).
Same discipline: real targets with real users, faithful ports, machine-checked
results, qualifier + metric on every claim, gaps surfaced not hidden.

**Headline results:**

1. **bech32 (Bitcoin segwit address checksums).** Ported BIP173 Bech32 to Aether;
   differential vs the reference `bech32` package: **2,000/2,000 addresses encode
   identically, and 46,518/46,518 single-symbol corruptions are rejected in
   lockstep — 0 corrupted addresses accepted (the fund-loss class).** PASS.
2. **numpy-financial (IRR/NPV).** Ported NPV + a bracketed IRR solver; differential
   vs numpy-financial 1.0.0: **NPV 20,000/20,000 (worst rel err 1.3e-13), IRR
   3,000/3,000 single-root cashflows (worst abs err 8.0e-15).** Where numpy-financial
   returns silent NaN, the Aether port returns an explicit `Err`. PASS.
3. **croniter (cron scheduling).** Ported the cron field matcher; differential vs
   `croniter.match`: **120,000/120,000 agree on standard-conforming expressions.**
   The run also **surfaced two croniter over-fire behaviours** — single-point
   ranges (`11-11/1` → fires every month, 11× over-fire) and full-coverage
   day-of-week (`*/1` → fires every day, 29× over-fire in a month) — where croniter
   departs from crontab(5) and from its own handling of a literal `*`.
4. **base58check: not portable in v0.3 (reported).** Its checksum needs SHA-256 over
   raw bytes, and Aether has no Bytes↔Int bridge. A real limitation, documented.

---

## Part 1 — bech32 checksums (a bad checksum = lost funds)

### Why this target

Bech32 is the BCH checksum scheme behind modern Bitcoin segwit addresses
(`bc1q...`). Its 6-symbol checksum is the last line of defence against a mistyped
or corrupted address; if a verifier accepts a corrupted address, funds go to the
wrong place, irreversibly. The reference is Pieter Wuille's `bech32` package (the
BIP173 implementation).

### What was built

`bench/realworld_bech32/`:

| File | Purpose |
|---|---|
| `bech32.aeth` | Aether port of BIP173: `polymod`, hrp expansion, checksum create/verify, `convertbits`, segwit encode + decode-validity |
| `differential.py` | (A) encode agreement on random (hrp, witver, program); (B) checksum discrimination — every single-symbol corruption must be rejected iff the reference rejects it |

**No bitwise operators in Aether**, so the port emulates the BCH arithmetic:
every mask in Bech32 is `2^k-1` (⇒ modulo), every shift is a power-of-two
multiply/divide, and XOR is a per-bit loop (`xorBits`). `ord` is needed only for
lowercase-alphanumeric hrps and is computed without an ASCII table. Scope: BIP173
bech32 (checksum constant 1); bech32m (BIP350, taproot v1+) is a one-constant
variant not covered.

**A bug the port caught in itself:** the first version used wrong decimal values
for the hex generator constants (`0x3b6a57b2` etc.). The differential flagged it
immediately — the data prefix matched but the 6 checksum symbols diverged — and
the fix (correct decimals) produced byte-exact agreement. This is the differential
harness doing its job on the port side.

### Result

```
A. encode: 2000/2000 match
B. corruption: 46518/46518 agree
   Aether-accepts-but-ref-rejects (fund-loss class): 0
PASS
```

Every generated segwit address encodes identically to the reference, and across
46,518 single-symbol corruptions the Aether checksum verifier accepted exactly the
same set as the reference — **zero corrupted addresses slipped through.** The
"fund-loss class" counter (Aether accepts what the reference rejects) is the one
that matters for a wallet; it is 0.

Reproduce:
```
pip install --target <dir> bech32
T2_PYLIBS=<dir> python bench/realworld_bech32/differential.py
python -m transpiler.aether.cli run bench/realworld_bech32/bech32.aeth
```

---

## Part 2 — numpy-financial IRR / NPV (finance correctness)

### Why this target

numpy-financial is the maintained successor to `numpy.npv`/`numpy.irr`, depended on
across quantitative finance. A wrong NPV/IRR is a mispriced deal.

### What was built

`bench/realworld_numpyfin/`:

| File | Purpose |
|---|---|
| `npv_irr.aeth` | Aether NPV (exact port) + a bracketed-bisection IRR solver |
| `differential.py` | NPV vs numpy_financial.npv; IRR vs numpy_financial.irr on single-root cashflows; NaN-vs-Err contrast |

**Scope, stated plainly:** NPV is `sum_t values[t]/(1+rate)^t` — pure Float
arithmetic, ported exactly. numpy-financial's `irr` uses `np.roots`
(companion-matrix eigenvalues); Aether has no linear-algebra or complex
primitives, so that exact algorithm is **out of scope**. The port instead solves
`NPV(r)=0` by bisection on a sign-changed bracket, which coincides with
numpy-financial on the standard single-IRR cashflow.

### Result

```
A. NPV: 20000/20000 match (worst rel err 1.31e-13)
B. IRR (single-root): 3000/3000 match (worst abs err 7.99e-15)
C. no-IRR cashflow [100.0, 39.0, 59.0]: numpy-financial=nan  aether=Err
```

NPV matches to floating-point noise (1e-13). On the 3,000 single-real-root
cashflows, the Aether bisection root agrees with numpy-financial's eigenvalue root
to 8e-15. And on a cashflow with no real IRR, numpy-financial returns a silent
`NaN` (a documented foot-gun — a caller who doesn't check `isnan` propagates
garbage), whereas the Aether port's `requires`-guarded solver returns an explicit
`Err` naming the reason. Same math, louder failure.

Reproduce:
```
pip install --target <dir> numpy-financial
T2_PYLIBS=<dir> python bench/realworld_numpyfin/differential.py
```

---

## Part 3 — croniter scheduling (misfire = wrong job runs)

### Why this target

croniter computes cron fire times for schedulers across the Python ecosystem. A
matcher off-by-one is a missed or double-fired job; croniter also carries a
misfire/DoS reputation, which is exactly the class a bounded matcher addresses.

### What was built

`bench/realworld_croniter/`:

| File | Purpose |
|---|---|
| `cron.aeth` | Aether cron field matcher: `*`, `a`, `a-b`, `*/s`, `a-b/s`, comma lists, and the Vixie dom/dow OR rule |
| `differential.py` | random cron exprs × random datetimes vs `croniter.match`; plus the two croniter findings, quantified |

Scope: standard 5-field numeric cron. Out of scope: names (`JAN`/`MON`),
`L`/`W`/`#`/`?`, `@`-keywords, seconds, timezones/DST.

### Result — agreement on standard-conforming expressions

```
cron match (well-formed exprs): 120000/120000 agree
```

Across 120,000 (expression, datetime) pairs drawn from the standard-conforming
grammar — including the both-restricted dom/dow OR-union cases — the Aether matcher
agrees with `croniter.match` exactly.

### Result — two croniter over-fire behaviours the run surfaced

The differential also found where croniter departs from crontab(5). These are
**croniter's behaviour, not Aether bugs**; the Aether port implements the standard
semantics and diverges here on purpose. Reported honestly, with the nuance:

**Finding 3a — single-point ranges over-expand.** crontab(5) says a range `a-a` is
inclusive, i.e. `{a}`. croniter expands it to a superset:

```
'0 0 1 11-11/1 *'  month field -> ['*']        (should be {11})
'0 0 1 5-5 *'      month field -> ['*']        (should be {5})
'0 0 1 5-5/2 *'    month field -> [1,3,5,7,9,11] (should be {5})
'0 0 1 11-11/1 *' croniter fires 11x in 2025 (crontab(5): 1x, every Nov 1)
```

A schedule intended to run once a year (Nov 1) fires on the 1st of every month.
This is an expansion artifact with no documented rationale.

**Finding 3b — a full-coverage day-of-week is not treated like `*`.** croniter
collapses a full-coverage *day-of-month* to `*`, but keeps a full-coverage
*day-of-week* (`*/1`, `0-6`) as an explicit list, so it counts as "restricted" and
triggers the dom/dow OR union — which a literal `*` would not:

```
'0 0 30 * */1' expanded dow -> [0,1,2,3,4,5,6]  (kept explicit, not '*')
'0 0 30 * */1' croniter fires 29x in June 2025 (crontab(5): 1x, the 30th)
```

`0 0 30 * *` fires once (the 30th); `0 0 30 * */1` — semantically identical, since
`*/1` is every day — fires *every* day. Two specs that mean the same thing produce
different schedules. Nuance for honesty: croniter's dom/dow **OR union** itself is
its *documented* default (`day_or=True`, mirroring a known Vixie-cron behaviour);
the surprising part is the `*`-vs-`*/1` asymmetry that silently switches it on.

Reproduce:
```
pip install --target <dir> croniter
T2_PYLIBS=<dir> python bench/realworld_croniter/differential.py
```

---

## Part 4 — base58check: a real Aether limitation, reported

base58check (the Bitcoin legacy-address / WIF checksum) was in scope for this run
and **could not be ported.** Its checksum is the first 4 bytes of a double
SHA-256 over the payload *bytes*. Aether's stdlib exposes `sha256(b: Bytes)
returns Bytes`, but there is **no primitive to build a `Bytes` from computed
integers, nor to read a `Bytes` back into integers** — no `ord`/`chr`, no byte
indexing, no Bytes↔Int bridge. So a payload assembled in Aether can't be hashed,
and a hash can't be compared byte-wise. The base-58 big-integer conversion is
portable; the checksum is not.

This is the same category as the Int-is-spec'd-64-bit note from run 1: a genuine
v0.3 gap worth recording in SPEC_ISSUES.md. bech32 (Part 1) was the stronger
"checksum = lost funds" target precisely because its checksum is self-contained
integer math with no byte/hash dependency.

---

## What Tier 2 adds to the selling case

Qualifier + metric, per discipline:

1. **Bit-exact on a fund-critical checksum (measured):** BIP173 Bech32, 2,000/2,000
   encodes and 46,518/46,518 corruption verdicts matching the reference, **0
   corrupted addresses accepted** — despite Aether having no bitwise operators
   (the BCH math was emulated with modular arithmetic).
2. **Float-exact on finance math (measured):** NPV to 1e-13, IRR to 8e-15 vs
   numpy-financial, with a silent-NaN → explicit-Err improvement in failure
   reporting.
3. **Semantics-exact on scheduling, and a bug-finder besides:** 120,000/120,000
   agreement with croniter on standard expressions, **plus two quantified croniter
   over-fire behaviours** (11× and 29×) that match its misfire reputation.
4. **Honest about the wall:** base58check is not expressible in v0.3 (no Bytes↔Int
   bridge) and is reported as a limitation rather than hacked around.

Across all three runs, the pattern holds: Aether's small subset ports real,
depended-on library logic and matches the reference to floating-point / exact
agreement on millions of cases, and the differential method keeps surfacing real
defects — a live `humanize` regression (run 1), a soundness gap in Aether's own
E0716 (run 2), and two croniter over-fire behaviours (run 3). What none of the runs
establish is willingness to pay; the strongest use remains the CVE corpus and these
exact-match results as trust proofs in a design-partner conversation.

## Sources

- bech32 / BIP173: https://github.com/sipa/bech32 , https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
- bech32 PyPI: https://pypi.org/project/bech32/
- numpy-financial: https://github.com/numpy/numpy-financial , https://pypi.org/project/numpy-financial/
- croniter: https://github.com/kiorky/croniter , https://pypi.org/project/croniter/
- cron dom/dow behaviour reference: https://crontab.guru/cron-bug.html
- crontab(5) range semantics: https://man7.org/linux/man-pages/man5/crontab.5.html
