# Python Capability Analysis — Adversarial Viability Results

**Date:** 2026-06-06
**Corpus:** 50 realistic, framework-heavy Python modules (`tools/py_corpus2/`) —
FastAPI/Flask, SQLAlchemy/ORM, requests/httpx clients, Celery workers, pandas
pipelines, auth/middleware, config/plugin loaders, plus 6 soundness-probe traps
and 4 pure controls. Written as AI agents actually emit production Python
(decorators, dependency injection, module-level wiring, dynamic imports), **not**
curated to pass.
**Ground truth:** `tools/py_corpus2/LABELS.json` — capability labels established
by manual reading, independently of Aether (author-established; see caveat).
**Modes measured:** strict (sound floor) and pragmatic (pure-method ceiling).

This report leads with the thesis-critical metric — false negatives — per the
experiment's own success criterion. A bad result reported honestly is the goal.

---

## 1. SOUNDNESS — false negatives (the metric that decides the thesis)

A proof tool that says "no capability here" when there is one has failed its
core promise. We hunted these directly against ground truth.

### Strict mode
- **Hard false negatives (PROVEN_CLEAN but capability present): 1 of 50 modules.**
  - `trap_02_pprint.py`: `pprint.pprint()` writes to stdout (a `log` effect), but
    `pprint` is in the frontend's `PURE_MODULES` allowlist, so the module is
    certified clean. **This is a real silent false negative.**
- Inventory false negatives (VIOLATION but missing a second real capability,
  with nothing flagged UNPROVABLE): **0**.
- False positives (flagged a capability that isn't real): **0**.
- **Per-capability-instance soundness:** of 49 ground-truth capability instances,
  **25 detected (51%)**, **23 missed-but-honestly-flagged UNPROVABLE (47%)**,
  **1 silently missed (2%)**.

**Reading:** the soundness model mostly holds. When Aether cannot resolve a
capability it overwhelmingly degrades to UNPROVABLE rather than lying. The single
silent miss is a **table-configuration bug, not a structural hole**: `pprint`,
`warnings`, and `codecs.open` were wrongly trusted as pure. `codecs.open` and
`trap_03`'s module-level `requests.get` did *not* produce false negatives only by
luck — the function bodies happened to touch the capability object via an
UNPROVABLE method call (`fh.read()`, `CONFIG.get()`), which masked the hole. Fix
the table and the 2% goes to ~0; leave related holes and similar masking luck
will eventually run out.

### Pragmatic mode is genuinely unsound — do not ship it
- Same single hard module-level FN, **plus a function-level false clean**:
  `trap_04_pure_method_override.py::record()` is marked PROVEN_CLEAN because the
  pure-method allowlist trusts `.append()` even though this class's `.append()`
  writes to disk (`fs`). The module-level union hid it (a sibling method exposed
  `fs`), but the per-function verdict is a lie.
- **Conclusion: the pure-method allowlist trades soundness for ~1 extra clean
  module and must be dropped or gated.** Soundness is the product; this isn't a
  acceptable trade.

---

## 2. COVERAGE — and it is poor on real framework code

| State | Strict | Pragmatic |
|---|---:|---:|
| PROVEN_CLEAN | 2 | 3 |
| VIOLATION | 23 (18 complete inventories) | 23 |
| **UNPROVABLE** | **25 (50%)** | 24 (48%) |
| **Sound verdicts (CLEAN+VIOLATION)** | **25/50 = 50%** | 26/50 = 52% |

**Half of realistic framework Python collapses to UNPROVABLE** — materially worse
than the 65% measured earlier on a simpler, toy-ish corpus. Adversarial realism
moved the number the way it was always going to: real code is method-, DI-, and
decorator-heavy, and that is exactly what defeats untyped static analysis.

Aether positively *identifies* the actual capability only ~51% of the time. The
rest of the time it is either silent (rare, 2%) or — far more often — honestly
says "I can't tell" (UNPROVABLE). It is **honest but quiet.**

---

## 3. WHY it is UNPROVABLE (causation, 133 records, strict)

| Cause | Share | Fixable? |
|---|---:|---|
| Method on an untyped object (`db.query`, `self.session.get`, `cur.execute`, `es.search`, `resp.json`) | **64%** | Partly — needs interprocedural type inference |
| Unmapped library import (pandas, jwt, celery, elasticsearch, redis, boto) | 20% | Yes — extend the table (carefully; jwt is pure, pandas is fs/net) |
| Method on `self`/expression (OO dispatch) | 11% | Hard — interprocedural |
| Irreducibly dynamic (`eval`, `getattr`, `importlib`) | 5% | No — UNPROVABLE is correct |

The dominant 64% is **one pattern**: a capability reached through an object whose
type we do not track. The tempting fix — "just read the type hints" — is weaker
than hoped: only **3** capability-bearing parameters in the whole corpus carry a
directly-resolvable annotation (`db: Session`). The rest arrive through `self`
attributes set in `__init__`, module-level globals, and untyped parameters. So
closing this requires real **interprocedural / flow type inference**, not a
quick annotation pass. Only ~5% is genuinely irreducible.

---

## 4. VERDICT — go/no-go

**Static-only capability analysis of Python is NOT viable as a product foundation
in its current form, and is borderline even with the obvious fixes. It is viable
as a *sound* tool only as a static(type-aware) + runtime hybrid.**

Plainly:

1. **Soundness is achievable and nearly there (strict mode).** One silent false
   negative, caused by a fixable allowlist bug, with everything else degrading to
   UNPROVABLE. This is the good news and it is real: the engine can be made to
   *not lie* about Python with bounded effort (fix `PURE_MODULES`; map
   `codecs.open`; drop pragmatic mode).
2. **Coverage is the problem, and it is structural.** On framework-heavy code —
   the code AI agents actually generate — **50% is UNPROVABLE** and only ~51% of
   real capabilities are identified. A proof tool that shrugs on half its inputs
   is too low-signal to anchor a product, no matter how honest the shrug.
3. **The pragmatic shortcut that would lift coverage breaks soundness.** There is
   no free lunch via method-name allowlists.
4. **The dominant blocker (64%) is fixable only with interprocedural type
   inference**, which is a substantial build, not a patch — and even then a hard
   residual (OO dispatch, dynamic imports) remains.

**Recommendation.** Do not pitch or build further on "we statically prove the
capability surface of your Python." The honest, defensible product is a **hybrid**:
static capability proof for the resolvable fraction (with the soundness bug fixed
and pragmatic mode removed), **plus a runtime capability sandbox** that enforces
the boundary for everything static analysis must leave UNPROVABLE — which, on real
framework code, is half of it. The static layer's job becomes *narrowing what the
runtime must guard*, not proving the whole program. If a pure-static product is
required, it is viable only after a multi-quarter investment in interprocedural
type inference, and it will still hand ~10-15% to UNPROVABLE.

**One-line answer to the experiment's question:** On realistic AI-generated
Python, Aether produces a *sound* verdict ~50% of the time and lies ~2% of the
time (one fixable bug); it is honest but too quiet to stand alone, and the path to
usefulness runs through type inference and a runtime hybrid, not through more
static cleverness.

### Caveat on ground truth
Labels were author-established (same author wrote the corpus), not third-party.
Bias was mitigated by applying the most scrutiny where Aether is known to be weak
(module scope, pure-module I/O, pragmatic method names) and by including traps
designed to make Aether fail. A fully independent labeling pass would strengthen
the soundness numbers further.
