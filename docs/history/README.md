# Historical reports — superseded, kept for the record

Everything in this directory is **historical**. Each file describes the
project at the date it was written and has not been updated since; its
numbers, verdicts, code counts and plans are not current. They were moved
here from the repository root on 2026-09-24 (audit
`audits/audit_2026-09-24_plan.md`, E11) so the root holds only live
documents.

For the current state read `README.md`, `SECURITY_POSTURE.md`,
`docs/SCANNING.md`, `grammar/`, `BUGS.md` and
`demos/case_studies/LOOP_LOG.md`.

| File | Date | What it was |
|---|---|---|
| `STATUS.md` | 2026-05-03 | v0.1 Phase 1 status report |
| `PHASE_A_AUDIT.md` | 2026-05-03 | Phase A audit of the validation tasks and the structural-similarity metric |
| `V02_CLOSEOUT.md` | 2026-05-03 | v0.2 close-out: refinement runtime checks, capability gating, parser fuzzer |
| `PYTHON_RESULTS.md` | 2026-06-06 | Python capability analysis — adversarial viability results |
| `DELTA_RESULTS.md` | 2026-06-07 | Capability-delta analysis, Phase 0 |
| `PHASE1_RESULTS.md` | 2026-06-07 | Phase 1: coverage lift, runtime backstop, ALLOW/BLOCK |
| `RW_MINING.md` | 2026-06-07 | Real-world diff-shape mining toolkit and runbook |
| `AETHER_UADD_DRIFT_REPORT.md` | 2026-06-07 | `u_add` reconciliation; its "DRIFT (HALT)" verdict is that day's |
| `REALWORLD_HUMANIZE.md` | 2026-07-05 | Evidence run 1: port of `humanize` |
| `REALWORLD_SECURITY_PACKAGING.md` | 2026-07-05 | Evidence run 2: `packaging` ordering, JWT proof tokens, CVE replay |
| `REALWORLD_TIER2.md` | 2026-07-05 | Evidence run 3: bech32, IRR/NPV, cron scheduling |
| `REALWORLD_CVE_HIGHVALUE.md` | 2026-07-06 | Evidence run 4: high-bounty bug classes |
| `PYTHON_VIABILITY.md` | 2026-07-26 | Python viability experiment — the capability/effect model on Python |

Dates are the first date each file states. Some files still name their
neighbours by bare filename (`PYTHON_RESULTS.md`, `RW_MINING.md`); those
names resolve in this directory.
