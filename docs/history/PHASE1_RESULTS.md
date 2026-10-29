# Phase 1 Results — Coverage Lift, Runtime Backstop, ALLOW/BLOCK

**Date:** 2026-06-07
**Scope:** bounded diff-frontier type inference (P1.1), runtime-policy generator
(P1.2), policy DSL + coverage/conflict checker (P1.3), ALLOW/BLOCK/ESCALATE
contract (P1.4).
**Corpus:** same labeled PROXY as Phase 0 (50 `py_corpus2` modules as whole-file
adds + 19 curated micro-diffs, now including typed-receiver modifies). Real
design-partner agent PRs still pending.

Leads with the soundness metric, then the gate metric (positive-identification).

---

## 1. SOUNDNESS — false negatives: still 0

Inference can only ever turn UNPROVABLE into a proven verdict when the receiver
type is **proven by a construction we can see** (local construction, `__init__`
self-attr, module global, or literal container). Type annotations are used only to
*add* a capability (a sound over-approximation), never to clear to pure.

- **False-negative rate across 69 diffs: 0.0%** (delta eval).
- All soundness traps stay non-clean, including a NEW one: a locally-constructed
  class whose `.append()` writes disk is resolved one-hop and surfaces `fs` — it
  is never cleared. (`tests/test_phase1.py`, 5/5 green; `test_py_soundness.py`
  still 4/4.)
- trap_04 remains UNPROVABLE when the receiver is an untyped parameter (no
  construction in view): we never guess a receiver's type from its method name.

---

## 2. GATE 1 METRIC — positive identification on diffs

Kill-criterion: *if scoped inference cannot raise positive-identification from
~51% to > 75%, retreat to assurance positioning (Option B).*

| Measure | Baseline (PYTHON_RESULTS) | Floor (post-P0) | + Inference (P1) |
|---|---:|---:|---:|
| Cap-instance positive-ID (49 labeled instances) | **51%** | 55% | **89.8%** |
| Micro/modify-path positive-ID (named capability) | — | ~40%* | **100%** |
| Modify-path delta-UNPROVABLE | — | 21% | 26%** |

\* typed-receiver modify diffs specifically (the inference target).
\** small curated set (19); the genuinely-unknowable cases (untyped params,
return-value method chains) correctly stay UNPROVABLE.

**The 75% bar is cleared: 89.8% cap-instance positive-ID, 100% on the modify-path
diffs the pivot is actually about.** Honest decomposition of the lift:

- **51% -> 69%** came from *structural* inference: resolving method calls on
  receivers typed by local construction / `__init__` self-attrs / module globals
  (e.g. `self.client = httpx.Client(); self.client.post(...)` -> net).
- **69% -> 90%** came from *sound table extension*: `os.environ.get` -> env and
  the pandas file readers -> fs. These are positive mappings with no FN risk; they
  were simply missing.

The 5 residual misses are the genuinely-hard ones, and they scope the next lever:
injected DB `Session` objects (`self.db.query`, `SessionLocal`) that need
dependency-injection-aware type flow, and `os.environ['X']` *subscript* access
(not a call, so invisible to call-based analysis).

---

## 3. COST — trivially cheap

Per change-set analysis (whole-file delta over 50 modules): **median ~1.1 ms,
p95 ~1.7 ms, max ~5.2 ms.** Pure AST; no model in the path. "Sane compute cost" is
not in question — the engine is essentially free relative to a sandbox run or a CI
step.

---

## 4. RUNTIME BACKSTOP (P1.2) + ALLOW/BLOCK (P1.4)

For the residual UNPROVABLE frontier, `generate_runtime_policy` emits a
**deny-by-default** sandbox-agnostic policy (E2B / Modal / native isolation): every
taxonomy capability inside the unresolved regions is denied unless policy allows
it. Static narrows what runtime must guard — only the unresolved regions carry a
runtime cost.

`decide()` turns the delta into ALLOW / BLOCK / ESCALATE:
- a positively-identified new capability denied by policy -> **BLOCK**;
- UNPROVABLE residual, human in loop -> **ALLOW** with the runtime guard attached;
- UNPROVABLE residual, autonomous (Phase 2 preview) -> **ESCALATE** + guard;
- fully resolved, no denied cap -> **ALLOW**.

It fails safe: an ungoverned capability defaults to deny, and among equally
specific rules DENY wins.

---

## 5. POLICY DSL + COVERAGE/CONFLICT (P1.3)

Declarative rules over the taxonomy:

    default deny *
    allow new log in **
    deny  new net in payments/**
    deny  new fs  outside /tmp/**

`check_coverage()` proves the policy set governs every taxonomy class (reports any
ungoverned class) and has no allow/deny contradiction over the same capability and
scope. Both checks are demonstrated firing in `tests/test_phase1.py`.

---

## 6. ARTIFACTS

- `tools/scoped_infer.py` — bounded diff-frontier inference (augments the floor).
- `tools/admission.py` — runtime-policy generator + policy DSL + ALLOW/BLOCK.
- `tools/cap_delta.py` — now inference-backed (USE_INFERENCE).
- `tools/py_frontend.py` — sound env/pandas table extensions.
- `tests/test_phase1.py` — 5/5 green; `tests/test_py_soundness.py` — 4/4 green.
- `tools/delta_eval_results.json` — refreshed, inference-on.

---

## 7. LIMITS / HONESTY

- **Proxy data, again.** Numbers are on the labeled corpus + curated diffs, not
  real agent PRs. The whole-file-add shape still degrades (the delta IS the whole
  module); the pivot's win is on modify-path diffs.
- **Bounded by design.** One hop into local classes; no fixpoint; injected/DI
  objects and return-value typing remain UNPROVABLE — sound, but the next coverage
  frontier.
- **Part of the lift is table work, not structure.** Stated plainly above so the
  moat is not overclaimed: ~18 points structural, ~21 points table extension.
