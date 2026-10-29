# Real-World Diff-Shape Mining — Toolkit, Demonstration, and Runbook

**Date:** 2026-06-07
**Goal:** replace the proxy gate blend with a real-world-weighted GATE 0 number
*before any Phase 2 spend*. The single output that matters:

> Option A clears GATE 0 iff real per-region UNPROVABLE ≤ 0.50. Holding the
> measured per-shape rates, that holds iff **modify-share ≥ B**. The data says
> modify-share ≈ **M**. **Decision = sign(M − B)**, with confidence intervals.

---

## 1. What is built, and what is measured here vs. needs real data

| Piece | Status in this session |
|---|---|
| Sound diff-shape classifier (`diff_shape.py`) | **Built + tested.** Shape derived from the same `capability_delta` ingestion as the verdict (§C), with §C path filtering. |
| Metrics + Wilson 95% CIs (`rw_metrics.py`) | **Built + tested.** Shape mix, per-shape u_s, per-PR resolved fraction, positive-ID, FN rate — all with CIs. |
| Break-even + sensitivity engine (`breakeven.py`) | **Built + tested.** Solves B, sweeps modify-share, propagates CIs, emits the decision. |
| Runtime syscall FN oracle (`runtime_oracle.py`) | **Built + DEMONSTRATED LIVE** under `strace`. Observes net+fs at runtime; confirms zero FNs on a real run, and correctly *flags* an induced FN (negative control). |
| GH Archive SQL (`mining/gharchive_agent_prs.sql`) | **Written.** Needs your BigQuery access to run. |
| GitHub files enrichment (`mining/gh_enrich_files.py`) | **Built + tested** on synthetic API output. Needs `GITHUB_TOKEN` + network for the live population read. |
| SWE-bench harness (`mining/swebench_harness.py`) | **Built + tested** on a synthetic manifest. Needs the SWE-bench repos/patches for real u_s. |
| Real `M`, real `u_add`, real `u_modify` | **NOT measured.** They require GH Archive / SWE-bench / design-partner data not reachable from this session. Deliberately not fabricated. |

The end-to-end pipeline was run on the **proxy** corpus (50 labeled modules as
whole-file adds + 14 curated micro modify-diffs) purely to prove the machinery and
read off the structural finding below (`mining/proxy_decision.json`).

---

## 2. The structural finding (from the proxy, machinery-only)

Running the full pipeline on the proxy yields per-shape rates consistent with
Phase 0/1 (`u_add ≈ 0.75`, `u_modify ≈ 0.27`) and therefore a **break-even
modify-share B ≈ 0.53** (point; CI [0.25, 1.06] at proxy n).

**This is the number that decides the program.** Because B sits right around 0.5,
the GATE 0 outcome is genuinely mix-determined:

- If real agent PRs run **> ~53%** of their capability-relevant regions on the
  modify path (with CI margin), Option A clears GATE 0.
- If **< ~53%**, real per-region UNPROVABLE exceeds 0.50 and Option A fails.

The proxy's own mix is ~80% whole-file-add (an artifact of the corpus, not agent
behavior), so the proxy decision is CLEAR_FAIL — which is precisely why **M must be
measured on real PRs**, not assumed. The proxy cannot answer the question; it can
only tell you the question is "is real modify-share above ~0.53?".

**Caveat that rides on every number above:** `u_add`/`u_modify` themselves may move
on real code. The runbook re-measures them on real PRs (step 2); B is then
recomputed from the real rates, not the proxy ones.

---

## 3. Decision rule (§G), as wired into the tools

1. **Soundness gate (absolute).** Any confirmed real-world FN from the runtime
   oracle (`runtime_oracle.check_against_aether`) or hand-label → `soundness_ok =
   False` → **halt, fix, re-run.** No other metric counts until this is clean.
2. **Kill-fast.** If the modify-friendly public/SWE-bench sample already shows
   `per_region_unprovable_overall > 0.50` or `per_pr_resolved_fraction` below your
   usability floor → **stop now**; the optimistic sample failed.
3. **Proceed-to-partners.** If the public read clears with margin (`decision =
   CLEAR_PASS`, i.e. `M_lo > B_hi`) → onboard 2–3 design partners and recompute on
   the enterprise-weighted mix; apply GATE 0 to *that* number.
4. **Within-CI / no margin** (`decision = WITHIN_CI_FAIL_FOR_A`) → treat as a fail
   for Option A; the work transfers to assurance (Option B).

---

## 4. Execution sequence (the cheap, high-information path)

**Step 1 — population prior M₀ (days, no engine, no labels).**
```
# in BigQuery, edit the date wildcard, run:
tools/mining/gharchive_agent_prs.sql              # -> candidate agent PR list
# enrich a sample with per-file status (needs GITHUB_TOKEN):
#   for each PR: GET /repos/{repo}/pulls/{n}/files  -> {path,status,additions,deletions}
python3 tools/mining/gh_enrich_files.py prefetched_files.json   # -> file-shape M0
```
Apply the kill-fast check to M₀ vs B. M₀ is a FILE-level, modify-optimistic prior
— directional only.

**Step 2 — real u_add / u_modify / positive-ID / FN (1–2 weeks).**
```
# adapter: check out each SWE-bench base commit, read base_src, `git apply` patch,
# read head_src, record per-file status -> normalized manifest.json
python3 tools/mining/swebench_harness.py manifest.json --oracle
#   -> rw_metrics (u_s with CIs, resolved fraction, positive-ID, FN) + breakeven decision
```
The `--oracle` flag runs the runtime syscall FN check on the runnable subset.

**Step 3 — compute B and the sensitivity curve; make the kill-fast call.**
`breakeven.from_metrics(metrics, M=<M0 with CI>)` returns B, the curve over
modify-share, and the decision. Plot the curve with B and M₀ marked.

**Step 4 — enterprise truth (only if steps 1–3 clear).**
Instrument 2–3 design partners (one typed/modify-heavy, one greenfield/scaffold).
Re-run `swebench_harness`/`rw_metrics` on their change-sets → enterprise-weighted
`M` → final GATE 0 decision and the Phase-2 go/no-go.

---

## 5. Honesty (§H)

- **Public mining is a modify-optimistic prior and a kill-fast tripwire, not the
  enterprise mix.** Public merged agent PRs over-represent small, safe, dependency
  changes that passed human review. State this on every chart.
- **SWE-bench's bug-fix skew inflates M.** A clear pass there is necessary, not
  sufficient.
- **The runtime oracle confirms FNs; it cannot certify their absence** (it observes
  only exercised capabilities — a lower bound). It complements hand-labeling.
- **Real M requires the design partners.** The public steps exist to decide whether
  that onboarding is worth it and which partner to lead with (the typed/modify-heavy
  one).
- **No real numbers were invented here.** Every rate in this session is either from
  the proxy corpus (clearly labeled) or synthetic test input. The real decision
  awaits real data through the runbook above.

---

## 6. Artifacts

- `tools/diff_shape.py`, `tools/rw_metrics.py`, `tools/breakeven.py`,
  `tools/runtime_oracle.py`
- `tools/mining/gharchive_agent_prs.sql`, `tools/mining/gh_enrich_files.py`,
  `tools/mining/swebench_harness.py`
- `tools/mining/proxy_decision.json` — the proxy end-to-end output (machinery proof).
- `tests/test_mining.py` — toolkit regressions (classifier, CIs, break-even, oracle).
