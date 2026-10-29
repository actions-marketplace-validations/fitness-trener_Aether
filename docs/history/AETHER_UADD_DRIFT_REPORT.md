# u_add Reconciliation — TASK 1 VERDICT: DRIFT (HALT)

**Date:** 2026-06-07
**Outcome:** the Phase-0 identities do **not** reproduce on the current engine.
Per the Task-1 gate, this is **DRIFT** → **HALT**. Tasks 2–6 (units.py,
rw_metrics/breakeven patches, proxy_decision_v2, reconciliation doc) were **not
started**, per "do not 'fix' by changing metrics."

**Soundness: GREEN.** `tests/test_py_soundness.py` 4/4, `tests/test_phase1.py`
5/5. No false-negative regression. This is benign coverage-distribution drift, not
a soundness break — but it invalidates the reconciliation premise, so it stops here.

---

## 1. Confirmed Phase-0 module-aggregation rule (from code, not assumed)

`cap_delta.capability_delta` sets `verdict = "UNPROVABLE"` iff `could_not_resolve`
is non-empty, i.e. **iff ≥1 inspected region is UNPROVABLE**. For a whole-file add,
inspected = all added functions + the synthesized module-scope region. Only
capability-relevant regions can be UNPROVABLE, so this is exactly:

> a whole-file-add module is UNPROVABLE iff ≥1 of its capability-relevant regions
> is UNPROVABLE.

Confirmed. (`tools/cap_delta.py` lines ~176–179.)

---

## 2. The three identity numbers — NOT reproduced

Artifact: `tools/mining/reconcile_identity.json` (137 per-region records).
Computed over the 50 add-modules + the 14 Phase-0-era micro-diffs (denominator 64).

| Metric | Phase-0 anchor | Current, inference ON (default) | Current, inference OFF |
|---|---|---|---|
| per-REGION UNPROVABLE | (~0.75 expected) | **0.707** (58/82) | 0.410 (34/83) |
| per-MODULE UNPROVABLE | **0.60 (30/50)** | **0.78 (39/50)** | 0.50 (25/50) |
| per-DIFF over 64 | **0.516 (33/64)** | **0.688 (44/64)** | 0.438 (28/64) |

Neither configuration reproduces 30/50 or 33/64. **Verdict: DRIFT.**

---

## 3. Exactly which verdicts moved, and why (three approved-Phase-1 causes)

**Cause A — capability-table extensions (lowers UNPROVABLE; sound, intended).**
Phase 1 added `os.environ.get→env` and `pandas.read_*→fs`. Seven modules flipped
UNPROVABLE→INTRODUCES because their previously-unresolved call is now a named
capability: `wrk_05_rq_worker`, `pipe_01_sales`, `pipe_03_etl`, `pipe_04_parquet`,
`auth_03_apikey`, `cfg_02_plugin_loader`, `cfg_05_env_branch`. This is why
inference-OFF per-module is 25, not Phase-0's 30.

**Cause B — inference verdict-precedence FLIP (raises UNPROVABLE; the dominant
cause, and a genuine inconsistency).** The Phase-1 inference integration in
`cap_delta._regions` recomputes a region's state as:
`UNPROVABLE if not resolved else (VIOLATION if caps else PROVEN_CLEAN)`.
This makes a region UNPROVABLE whenever **any** method site is unresolved — *even
when a capability is positively detected*. The floor (`py_surface.fn_row`) instead
uses **VIOLATION-dominance**: if a capability is detected, the region is VIOLATION
(→ INTRODUCES at the delta), with the residual noted separately.

Worked example — `api_03_github.py::list_repos`:
- `requests.get(...)` → **net is positively identified** (both modes).
- `resp.json()`, `resp.links.get(...)` → unresolved (return-value of a call).
- inference OFF: state = VIOLATION (net dominates) → module **INTRODUCES net**.
- inference ON: state = UNPROVABLE (residual dominates) → module **UNPROVABLE**.

15 modules flip INTRODUCES→UNPROVABLE this way (only `auth_04_session_ctx` flips the
other direction). This is the opposite of inference's purpose and it **inflated the
mining `u_add` to ~0.75**. It is sound (UNPROVABLE is the conservative verdict) but
it **hides positively-identified capabilities** and inflates both the per-region
cost metric and the per-PR-residual rate.

**Cause C — corpus growth.** Phase 1 appended 5 typed-receiver micro-diffs (MICRO
14→19), so the live `delta_eval` denominator is 69, not 64. Controlled for above by
using the original 14, so it is not the main driver — but it is why a naive re-run
reports n=69.

---

## 4. Why the reconciliation premise is invalid (the actual finding)

The premise was: *§C filtering holds the UNPROVABLE numerator fixed and only shrinks
the denominator, so 0.60→0.75 is unit-only.* That is false on the current engine:
the **numerator moved materially** — down by 7 modules (Cause A) and up by 15
(Cause B). `0.60` (Phase-0 floor, VIOLATION-dominant) and `0.75` (current mining,
inference UNPROVABLE-dominant) come from **different engine verdict distributions**,
not from one distribution viewed through two units. You cannot relabel units to
bridge them.

**The thing to reconcile first is not units — it is Cause B.** The floor and the
inference layer disagree on VIOLATION-vs-UNPROVABLE precedence for
capability-detected-with-residual regions. Until that single precedence is fixed,
every `u_s` the gate consumes is ambiguous (it depends on inference on/off), and the
units work (Tasks 2–6) would be built on a moving number.

Note: this does **not** retroactively break the Phase-1 GATE-1 pass. Positive-ID
(89.8%) is measured by named-capability membership, which Cause B does not affect
(net is still named in `api_03`). Only the UNPROVABLE-*rate* reporting was inflated.

---

## 5. Recommendation (surfaced, not acted on — gate discipline)

1. **Decide the canonical verdict precedence** for a region that positively
   identifies a capability *and* has an unresolved residual. Recommended: it is
   **INTRODUCES** (capability named), with a separate `also_unresolved` flag
   carrying the residual — this de-conflates *identification* (product value) from
   *cost* (runtime guard), matches the floor, and is equally sound. Align the
   inference layer to the floor's precedence.
2. **Re-anchor** the reconciliation to that fixed engine, then Tasks 2–6 (units.py,
   dual-unit rw_metrics with cluster CIs, per-PR/autonomous-threshold breakeven,
   proxy_decision_v2) become well-defined against a stable `u_s`.
3. The proxy CI remains uninformative at this n regardless; **real M (GH Archive /
   SWE-bench / design partners) is still the deciding measurement** and is out of
   scope here.

---

## 6. Deliverables produced

- `tools/mining/reconcile_identity.json` — per-region artifact (137 regions) +
  per-region/module/diff aggregates for inference ON and OFF.
- This report. No engine code changed; no metrics "fixed." Soundness green.

**HALTING at the Task-1 gate. Awaiting go/no-go on the precedence decision before
any units work.**
