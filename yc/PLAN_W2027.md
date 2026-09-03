# YC Winter 2027 — deadline, honest state, and the 61-day plan

**Written:** 2026-09-01. **Revised:** 2026-09-02, after two days of
execution that finished week 1, pulled week 2 and week 3 forward, and
invalidated three of this plan's own assumptions. Supersedes
`GO_NOGO_MEMO.md` (2026-05-21).

---

## 1. The deadlines

| Item | Date | Source |
|---|---|---|
| **W2027 application deadline** | **2026-11-02, 8:00pm PT** | [ycombinator.com/apply](https://www.ycombinator.com/apply) |
| Decisions out | 2026-12-11 | same |
| Batch runs | Jan–Mar 2027, San Francisco | same |
| Early Decision (Spring/Summer/Fall 2027) | rolling, no published date; select "A batch after Winter 2027" | [ycombinator.com/early-decision](https://www.ycombinator.com/early-decision) |

**61 days from today.** Treat Nov 2 as hard; submit by Oct 31. An
application costs nothing and a rejection does not burn the next batch —
the same work converts into a Spring 2027 application via Early Decision.

---

## 2. What the first two days changed

### 2.1 What was done (planned for weeks 1–3)

| Planned | Done | Note |
|---|---|---|
| Claim `aether-lang` on PyPI | **2026-09-01** | 0.3.0 live, installable, page describes the scanner |
| Push local main | done | 10 unpushed commits published; now 20 |
| Repo description, topics, homepage | done | homepage → PyPI |
| README leads with `check-py` | done | every command on it verified live |
| Prune stale branches | done | main only |
| GitHub Action (week 2) | done | `action.yml` on main; **Marketplace listing needs the v0.3.0 release, cut 2026-09-02** |
| Quickstart + public reports (week 2) | done | |
| Scan the agent frameworks (week 3) | done | 15 frameworks, 4,946 files; see 2.3 |
| CI that proves the wheel works | not in plan | `gate.yml`: run_all on 3.10/3.12 + build/install/smoke |

### 2.2 What the plan did not know: the product was not installable

Every bug below existed on 2026-09-01 and none was visible from the
checkout every test ran in. `BUGS.md` 005–011, all fixed, all with a live
regression test the ratchet enforces:

- `pip install .` **failed outright** (setuptools ≥ 77 rejects the license
  table form). The README's install instructions did not work.
- `aether check-py` raised `ModuleNotFoundError` in **every installed
  copy** — the Python frontend lived outside the wheel.
- `sdk.run` reported every working program as a **failed run** in an
  installed copy.
- The wheel shipped `transpiler` as its top-level package, so the
  documented `from aether import sdk` did not work installed.
- A UTF-8 BOM made a file **silently** invisible to a directory scan.

Then, on the agent-framework corpus: **97% of `check-py`'s output was one
false-positive class** (SQLAlchemy expressions read as dynamic queries),
and fixing it exposed a **false-negative class** underneath — imports
under `try:` had never been registered, so a guarded `yaml.load(x)` was
silent. Both fixed and measured: 1,055 → 411 findings on the same files;
15 previously-silent pickle sinks surfaced on the PyPI corpus, confirmed
by the bandit oracle.

**Consequence for the plan:** the first backend developer who tried
`check-py` on Sep 1 would have hit `ModuleNotFoundError`, and the second
would have hit a thousand SQLAlchemy findings. The outreach in week 4
would have burned every contact. The two days were not a detour; they
were the prerequisite.

### 2.3 What the framework scan actually produced — and did not

The plan's week-3 target was "5 upstream issues filed, 2 acknowledged."
The honest result:

- **No security vulnerability** in any of the 15 frameworks. Expected for
  widely-reviewed code.
- **Two hardening notes** worth filing, both with verified repros: agno's
  sitemap reader parses an attacker-choosable URL with stdlib
  `ElementTree` (expanded a 10⁶-entity payload in 0.19s; `defusedxml`
  refuses it); langchain-community's docugami loader uses lxml's default
  parser, which only matters for users on lxml < 5 — low priority, and
  the draft says so.
- Two E0714 sites first read as "correctness bugs" (mcp, aider) were
  re-read at source on 2026-09-02 and are not: one is a string run
  through a shell by design, the other is a Windows-only path where a
  list with `shell=True` works. Not filed.
- The most valuable output was the two Aether bugs above.

Revised week-3 target: **2 upstream reports drafted (done, in
`outreach/upstream/`), posted by you, 1 acknowledged.** A merged
hardening PR in langchain-community is worth more in the application
than another detector — and it is the honest size of what the scan
found.

### 2.4 An assumption in this plan that was wrong

The week-8 demo script said: *point `check-py` at a real OSS repo → it
finds a real access-control issue → Semgrep finds nothing.* **That demo
cannot be made on Python.** The access-control rows (`E0716`/`E0717`) need
`Authorized<T>` markers and run on Aether source only; `check-py` runs the
sink family (injection, deserialization, credentials, XXE). The plan's
own author wrote a demo the product cannot perform.

The corrected story has two halves, and the pitch must keep them
distinct:

1. **On the Python you already have:** `check-py` finds the sink family
   and — the checkable contrast — does not flag the documented fix, where
   bandit does. Runs in CI via the Action, lands in Code Scanning.
2. **Where the access-control rows live:** the nine named-company CVEs
   in `outreach/CUSTOMER_EVIDENCE.md`, ported to Aether and refused at
   check time — five of them classes mainstream SAST does not cover.
   That is the *why the language exists* half, and it is retrospective.

The demo video shows half 1 live and half 2 as the evidence table. It
does not blur them.

### 2.5 Two process facts worth keeping

- `bench/pypi_scan`'s corpus is whatever is installed; it had drifted
  since July. Any before/after must be taken on one day from a
  `git archive` of the baseline commit. Never stash across a long run.
- The improvement loop *did* run this week (iteration 47) despite the
  cap, because a real third-party scan surfaced the gap. That is the
  exception the cap was written for. Iterations 48+ stay capped.

---

## 3. Where Aether is now (2026-09-03)

**Strong:** installable and proven so in CI · 4,946 + 5,588 third-party
files parsed with zero crashes · 31 detectors / 55 codes, ratchet-held ·
122 labelled ground-truth functions at 0 FN / 0 FP · 18 fixed bugs, each
with a live regression test · Action on main, SARIF into Code Scanning ·
nine named-prospect CVE ports.

**Still zero:** stars 0 · forks 0 · watchers 0 · outreach sent 0 of 20 ·
users 0 · design partners 0 · revenue $0 · founders 1.

The technology is now something a stranger can install and run. Nobody
outside this repo has done so yet.

---

## 4. The remaining 61 days

Rule unchanged: every week ends with something a stranger can run, or a
human who is not you has replied.

### This week — Sep 2–7 · Finish week 2, start week 4
1. **Release.** `v0.3.0` is tagged at the exact commit PyPI's 0.3.0 was
   built from, with release notes. In the GitHub release UI, tick
   **"Publish this Action to the GitHub Marketplace"** — that toggle is
   UI-only. Then `uses: fitness-trener/Aether@v0.3.0` pins.
2. **0.3.1 to PyPI** — main is bumped to 0.3.1 and carries BUG-010/011.
   `rm -rf build dist *.egg-info && python -m build && twine upload dist/*`.
   Rotate the account-scoped token first; it reached a transcript.
3. **Post the two upstream reports** from `outreach/upstream/`. Read each
   draft, adjust tone to yours, post under your account. Each is a
   one-line hardening a maintainer can merge in an afternoon; each names
   the tool that found it.
4. **Send outreach row 1** — the five access-control names (Lovable,
   Replit, Vercel, Atlassian, Ivanti). The drafts have been ready since
   June; the product they point at now works when installed.

### Sep 8–14 · Launch
5. **Show HN**, on the measurement: *"I scanned 1.19M lines of PyPI and
   15 AI-agent frameworks with a checker built on a typed IR — what it
   found, what it missed, and the 97% of its own output it had to
   fix."* The bug-hunt-on-itself is the credible angle; that audience
   rewards it.
6. r/netsec, Lobsters, the same day.
7. Target: 300+ stars, 20+ installs, 3 inbound.

### Sep 15–21 · Send the rest, convert the first
8. Remaining 15 outreach drafts, personalised with anything the scan
   said about their stack.
9. Every reply → a call → a free scan with a written report → one ask:
   permission to say "we run with `<company>`."
10. Target: 20 sent, 4 replies, 2 calls, 1 verbal.

### Sep 22 – Oct 5 · Iterate on what users hit
11. The loop resumes on **user-reported** gaps only. Expected first ones:
    statements assembled in helpers (`stmt = self._base_query()`, ~100
    of the remaining 381 E0713), other query builders, `def`s under
    `try:` not analysed. Each gets the BUG-NNN treatment.
12. Target: 1 written design partner, 3 verbal.

### Oct 6–12 · Application v9
13. **Full rewrite around the two-half story in 2.4.** The one-liner,
    the demo, the traction section (with real numbers), the "why now"
    bullet (real 2026 source or drop it).
14. Resolve or delete all 13 `[TBD]`s. Fill every `[FILL]`/`[FOUNDER]`.
    Decide the co-founder answer.

### Oct 13–19 · Video
15. Script per 2.4: half 1 live — `pip install aether-lang`, `check-py`
    on a recognisable repo, the fix not flagged, bandit flagging it;
    half 2 — the CUSTOMER_EVIDENCE table on screen. Under 90 seconds.

### Oct 20–26 · Mock and cold-read
16. Cold read of v9 by someone who has never seen the repo.
17. `interview_prep.md` re-cut for the two-half story; T-team-1 under
    25 seconds on a stopwatch.

### Oct 27–31 · Submit
18. `SUBMISSION_CHECKLIST.md` from a fresh clone. Submit **Oct 31**.

---

## 5. Division of labour

**Only you:** the Marketplace toggle · the 0.3.1 upload · posting the
two upstream reports · pressing send on outreach · every call · the
founders block · the video · Submit.

**Me, on request:** Show HN draft · the remaining outreach personalisation
· application v9 · `[TBD]` sourcing · the user-reported bug loop · mock
interview.

---

## 6. Kill criterion (unchanged)

If by **Oct 6** there are zero replies from 20 sends and zero upstream
reports acknowledged, do not spend Oct 6–26 on application polish. Submit
a short, honest v9 in one day and put the rest into users. The company is
the point; the batch is a financing event.

## 7. Odds

**Two days ago:** low. **Now:** the product exists as an installable,
CI-proven thing with a measured false-positive rate on the population it
is for — which is what the outreach needed and did not have. Still not
favourite: the zeros in §3 are the zeros that matter, and only sending
things changes them. Nothing in §4 is spent on YC alone.

---

## Status 2026-09-02 (evening) — the queue after the revision

| item | state |
|---|---|
| PyPI token rotated to project scope | **you — confirm** |
| 2FA on the GitHub account | done (Marketplace required it) |
| `Aether Python Security Scan` on the GitHub Marketplace | **done** |
| 0.3.1 on PyPI + tag `v0.3.1` + release | **done** |
| agno hardening note posted | **done** — [agno#9920](https://github.com/agno-agi/agno/issues/9920) |
| docugami note | not posted: `langchain-ai/langchain-community` is archived; draft kept as the record |
| outreach row 1 | **open** — A1 Cursor and A3 Replit first; Lovable/Vercel/Atlassian/Ivanti still need email drafts written from their `evidence/*/pitch.md` |

Signals at close of day: stars 0, PyPI downloads unknown (pypistats lags a
day). The next number that matters is a reply.

---

## Status 2026-09-03 — three improvement iterations, no outreach sent

A whole-repo survey (65 probe-confirmed candidates,
`audits/survey_2026-09-03_ranked.md`) drove iterations 48–50. What moved:

| | |
|---|---|
| detectors / codes | 30 / 54 → **31 / 55** (E0731 code injection: `exec`/`eval`/`compile` of model output) |
| fixed bugs, each test-pinned | 11 → **18** (BUG-012..016, 020, 021) |
| labelled ground truth | 57 → **122** functions, still 0 FN / 0 FP |
| framework corpus, same 4,946 files | 411 → **676** findings, 0 analyzer errors |

The corpus number went UP because the scanner was blind, not because the
frameworks got worse: a sink behind `await` was invisible (603 of them),
`var` was never a binding on the Aether side, and a wrapper was trusted
on its name. Read `bench/framework_scan/REPORT.md` §7–§8 before quoting
any of this — the by-name rows carry their measured false-positive cost
with them, and the honest version of the pitch says so.

**Unchanged and still the only thing that matters:** stars 0 · outreach
sent 0 of 20 · users 0 · design partners 0 · revenue $0. The product got
better on a day when nobody was told about it. Week 4's outreach row is
the next move, not another iteration.
