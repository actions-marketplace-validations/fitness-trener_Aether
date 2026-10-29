# Python Viability Experiment — Results

> **Follow-up (2026-07-26): the SECURITY detectors now run on Python too.**
> This document measures the **capability/effect** model only, which was the
> original question. A later experiment gave the same frontend an expression
> translator and a Python→Aether sink mapping, so the annotation-free
> security rows (E0713 SQLi, E0714 command injection, E0718 open redirect,
> E0719 SSTI, E0720 deserialization, E0723 hardcoded credential, E0727 XXE,
> and E0711 path traversal behind `--strict`) fire on unmodified Python via
> `aether check-py`. Before that work the function body was discarded
> (`body=[]`), so a file with five textbook vulnerabilities produced zero
> security findings. Measurements, the benign-corpus false-positive counts,
> and a differential against bandit: **`bench/py_frontend/REPORT.md`**. The
> capability numbers below are unaffected — they measured a different thing.

**Date:** 2026-06-06
**Question:** Does Aether's capability/effect model port to Python, and on what
fraction of realistic AI-generated Python does it produce a *sound verdict*
(PROVEN_CLEAN or VIOLATION) rather than collapsing to UNPROVABLE?

**Method.** A translation frontend (`tools/py_frontend.py`) maps Python `ast`
into the existing Aether IR; the existing `aether.passes.capability` pass runs
**verbatim** over it (no new capability inference). 26 realistic modules
(`tools/py_corpus/`) — API clients, DB/file/subprocess/network handlers,
validators, pure utilities, OO services, dynamic dispatch, an unmapped 3rd-party
SDK — written as an AI agent would emit them (method-heavy, classes, `requests`/
`os`/`json`), **not** curated to pass. Policy = empty (the agent is granted
nothing), so any detected capability is a sound VIOLATION and UNPROVABLE is the
failure mode. Measured in two modes.

## Headline numbers (measured, untuned)

| Mode | Modules sound (CLEAN+VIOLATION) | Modules UNPROVABLE | Functions sound |
|---|---|---|---|
| **Strict** (no method-name guessing — the sound floor) | **17 / 26 = 65%** | 9 / 26 = 35% | 25 / 47 = 53% |
| **Pragmatic** (documented pure-method allowlist — ceiling) | **20 / 26 = 77%** | 6 / 26 = 23% | 32 / 47 = 68% |

Module breakdown — strict: CLEAN 2, VIOLATION 15, UNPROVABLE 9.
Pragmatic: CLEAN 5, VIOLATION 15, UNPROVABLE 6.
Of the UNPROVABLE modules, strict = 6 whole-module / 3 isolatable; pragmatic =
3 whole-module / 3 isolatable (the rest is a few lines a human owns, not the
whole file).

## The result that matters most: soundness held

**No module that uses a capability was ever marked PROVEN_CLEAN.** Every
capability is either detected (VIOLATION) or flagged UNPROVABLE — never silently
cleared. Verified by audit: `os.environ.get`, `self.session.get(...)`,
`cursor.execute(...)`, and a `datetime.now` table-miss all land in UNPROVABLE,
and all 5 pragmatic-CLEAN modules are genuinely pure (arithmetic, comprehensions,
string/collection methods). The pure-method allowlist did not wrongly clear a
single capability on this corpus.

Two honest caveats stated plainly:
1. A **VIOLATION is a sound positive, not a complete inventory.** A module flagged
   VIOLATION for one capability may have *additional* capability hidden behind an
   UNPROVABLE method call (e.g. `01_user_api_client`: detected `net` via
   `requests.Session()`, but the actual `.get()/.post()` calls are UNPROVABLE).
   The claim "this reaches the network" is reliable; "this reaches *only* the
   network" is not, while UNPROVABLE regions remain.
2. **Pragmatic mode is a soundness-caveated ceiling.** The pure-method allowlist
   assumes builtin-type semantics for names like `.strip()/.append()`. It
   deliberately excludes capability-homonyms (`get/read/write/send/execute/...`).
   A custom class overriding a pure-method name with I/O would defeat it. Sound
   on this corpus; not guaranteed sound in general. The **65% strict floor is the
   honest headline.**

## What drives UNPROVABLE (the diagnosis)

Unprovable records by reason (strict): `unresolved_method` 62, `unresolved_call`
9, `dynamic_dispatch` 8, `dynamic_construct` 2, `dynamic_attr` 1,
`transitive_unprovable` 1.

The blocker is overwhelmingly **one pattern: method/attribute calls on values
whose type we don't track** — `x = requests.Session(); x.get(...)`,
`cur = conn.cursor(); cur.execute(...)`, `r = requests.get(...); r.json()`. It is
**not** pervasive irreducible dynamism. Only **2 of 26 modules (≈8%)** are
genuinely dynamic — `eval` (`17_template_render`) and `importlib`+`getattr`
(`16_plugin_registry`) — and those *should* be UNPROVABLE; flagging them is
correct behavior, not a failure.

Fixability of the 9 strict-UNPROVABLE modules:
- **Irreducibly dynamic, correctly UNPROVABLE (~8%):** `16`, `17`. Leave as-is.
- **Cleared by the safe pure-method allowlist (already, in pragmatic):** `11`,
  `13`, `26`.
- **Cleared by local (intraprocedural) type inference:** track
  `name = <capability-constructor>()` and resolve `name.method()` against the
  constructor's type. Would convert `01/02`'s hidden `.get/.execute` from
  UNPROVABLE to sound VIOLATION, and dict-typed `data.get()` (`14`) to CLEAN.
- **Cleared by table completeness:** `07` (map `boto3` → aws/net),
  `24` (`from datetime import datetime; datetime.now()` resolves to
  `datetime.datetime.now`, which missed the `datetime.now` table key — a
  resolution bug, fixable).

## Viability call

**Conditionally viable — viable *with* local type inference; borderline without.**

- The capability/effect model **does** port to Python: the existing pass runs
  unchanged over translated IR and produces correct, sound three-state verdicts.
- The soundness discipline **holds** — zero false-clean across a realistic
  corpus. This is the property the product lives or dies on, and it passed.
- At the current frontend maturity, pure-AST analysis yields **65% sound verdicts
  (floor) / 77% (safe heuristic)** on realistic Python. That is usable but not
  yet compelling on its own.
- The residual UNPROVABLE is **dominated by one tractable engineering problem**
  (local type inference), not by irreducible Python dynamism (only ~8%). This is
  the hopeful finding: the path to a high sound-verdict rate is clear and
  standard, not blocked by undecidability.

**Recommended direction:** commit to **local type inference** for
capability-bearing constructors/returns (the single highest-leverage fix), keep
the safe pure-method allowlist, complete the mapping table (boto3, datetime
from-import resolution), and route the irreducible dynamic residual (`eval`,
`getattr`, `importlib` — ~8%) to a **hybrid runtime capability check** rather than
pretending to prove it statically. Pure-static-without-types alone is a weak
product (65%); static-plus-local-types-plus-runtime-residual is a strong one.

**Go / no-go:** GO on the Python direction, *conditioned* on building local type
inference next. Not a clean static win; a clear, fundable path with the
trust-critical soundness property already proven.
