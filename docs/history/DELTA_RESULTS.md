# Capability-Delta Analysis — Phase 0 Results

**Date:** 2026-06-07
**Engine:** Aether, differential (capability-DELTA) mode. Sound-mode only;
pragmatic mode deleted.
**What changed in Phase 0:** the engine now analyzes the capability *delta* of a
change-set (diff) rather than the absolute whole-module surface, and two soundness
defects were fixed (PURE_MODULES audit, pragmatic pure-method allowlist removed).
**Corpus:** a labeled PROXY — the 50 hand-labeled `py_corpus2` modules as
whole-file-ADD diffs, plus 14 curated micro-diffs exercising the modify path
(pure refactors, single-line capability adds, untyped calls, and 5 soundness
traps). Real design-partner agent PRs are **not yet available**; this is the
honest stand-in and is marked as such everywhere.

This report leads with the thesis-critical metric — **false negatives** — exactly
as `PYTHON_RESULTS.md` did.

---

## 1. SOUNDNESS — false negatives (the metric that decides the thesis)

**False-negative rate: 0 / 64 diffs = 0.0%.**

A false negative is a change-set that introduces a capability (or hides one behind
a trap) yet is reported `NO_NEW_CAPABILITY`. There are none — including all five
soundness traps:

| Trap diff | Disguised capability | Verdict | Silently cleared? |
|---|---|---|---|
| `trap_pprint` | `pprint.pprint` -> stdout (log) | INTRODUCES log | no |
| `trap_warn` | `warnings.warn` -> stderr (log) | INTRODUCES log | no |
| `trap_codecs_open` | `codecs.open` -> file (fs) | UNPROVABLE | no |
| `trap_method_override_append` | `.append()` writes disk (fs) | UNPROVABLE | no |
| `trap_from_subprocess` | `from subprocess import run` (process) | INTRODUCES process | no |

The two pre-existing engine defects are closed and locked by regression tests
(`tests/test_py_soundness.py`, 4/4 green):

- **`trap_02` (pprint):** was the one silent false negative in `PYTHON_RESULTS.md`.
  `pprint`, `warnings`, and `codecs` were removed from `PURE_MODULES`; their I/O
  functions are now positively mapped (`pprint.pprint`->log, `warnings.warn`->log,
  `codecs.open`->fs). `trap_02` is now VIOLATION, not PROVEN_CLEAN.
- **`trap_04` (pure-method override):** pragmatic mode trusted the method *name*
  `.append` and false-cleaned a disk write. Pragmatic mode is **deleted**. A method
  on an object of unresolved type is now always UNPROVABLE; `record()` is UNPROVABLE,
  not clean.

Every remaining `PURE_MODULES` entry (36) now carries a machine-readable purity
citation, surfaced via the `/pymap` audit endpoint.

---

## 2. COVERAGE — delta-UNPROVABLE, and why the split matters

Blended across all 64 diffs: **delta-UNPROVABLE = 51.6%.** But the blend hides the
finding that actually decides the strategy. The two parts answer different questions:

| Diff shape | n | UNPROVABLE | Rate | Reading |
|---|---:|---:|---:|---|
| **Whole-file ADD** (agent adds a new framework module) | 50 | 30 | **60.0%** | ~ whole-module analysis. No delta advantage. The dead regime. |
| **Modify path** (agent edits existing resolved code) | 14 | 3 | **21.4%** | The differential reframe pays off here. The 3 UNPROVABLE are genuinely unknowable (calls on untyped objects). |

**The pivot's value is conditional on the change being a LOCAL MODIFICATION.** When
an agent adds a whole new file of framework-heavy Python, the delta *is* the whole
module and you are back in the 50%+ UNPROVABLE swamp measured in `PYTHON_RESULTS.md`.
When an agent edits existing, already-resolvable code, the delta is small and
resolves ~4x better.

This is the single most important input to GATE 0, and the real-PR eval must
measure the **actual modify-vs-add mix** in agent PRs before the kill-criterion can
be applied for real.

---

## 3. POSITIVE IDENTIFICATION

Of the statically-resolvable capability-introducing micro-diffs (net, fs, process,
log, module-level net), **5/5 = 100%** were named correctly with the right
capability. Module-level (import-time) capability is no longer a blind spot: a new
top-level `requests.get(...)` is positively identified as `net` via a synthesized
module-scope region.

---

## 4. COST OF SOUNDNESS — over-reporting (sound, but noisy)

Nine truly-clean `py_corpus2` modules (e.g. `ctrl_02_pure_validate`,
`ctrl_04_pure_graph`, `pipe_05_clean`) are reported UNPROVABLE rather than clean,
because they call methods on untyped parameters (`.isdigit()`, `.strip()` on an
unannotated arg). Deleting pragmatic mode is exactly why: we will not clear a method
on an unresolved receiver. These are **over-reports, not false negatives** — sound
but noisy. Phase 1's scoped type inference on the diff frontier is the intended fix.

---

## 5. DETERMINISM & PROVENANCE

Same input -> same verdict (checked 10x). No model anywhere in the soundness path.
Every verdict carries per-region provenance (base vs head capability sets, the
changed-line attribution, and the UNPROVABLE reasons) in the JSON artifact
(`tools/delta_eval_results.json`, and per-PR via `aether_pr_check.py --out`).

---

## 6. ARTIFACTS SHIPPED

- `tools/py_frontend.py` — PURE_MODULES audited + cited; pragmatic mode removed.
- `tools/diff_ingest.py` — change-set -> changed functions/regions (+ git/unified-diff).
- `tools/cap_delta.py` — capability-delta analyzer + human comment renderer.
- `tools/aether_pr_check.py` — offline, additive PR check (GitHub/GitLab post opt-in).
- `tools/delta_eval.py` + `tools/delta_eval_results.json` — this eval.
- `tests/test_py_soundness.py` — soundness regressions (4/4 green).

---

## 7. LIMITS / HONESTY

- **Proxy data.** No real agent PRs yet. Whole-file-add is a real PR shape but the
  modify-path set is curated and small (14). The headline kill-metric cannot be
  declared met until measured on real PRs with their real add/modify mix.
- **Cross-function transitivity** uses the engine's existing effective-capability
  propagation; deep dynamic dispatch remains UNPROVABLE by design.
- **Deletions** are reported but never counted as "introducing" — correct, but a
  deleted capability is not yet surfaced as a positive "removes" signal.
