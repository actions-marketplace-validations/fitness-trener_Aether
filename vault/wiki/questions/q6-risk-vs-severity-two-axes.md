---
type: question_page
question_id: q6
status: answered
confidence: high
last_updated: 2026-08-02
---

# Q6 — Why does Aether carry two severity-like axes instead of one?

## Short Answer
`Diagnostic.severity` is a **gate** decision: it answers "does this run
fail?", and `transpiler/aether/passes/__init__.py` depends on its current
values — a pass `where severity == "warning"` must not fail the run
(`transpiler/aether/passes/__init__.py:18`). **Risk** is a
**triage** ordering: it answers "which of 4,000 findings do I read
first?". Collapsing them costs one of the two: either a `low` finding
stops failing the build — a weakening the monotonic ratchet cannot see,
because no detector was removed — or an `info`-risk parse error ranks
beside an RCE in a Code Scanning dashboard. The ratings are a fixed
per-CLASS heuristic about blast radius, not CVSS and not a measurement of
any specific finding's impact.

## Evidence
| Finding | Evidence | Confidence |
|---|---|---|
| Before this iteration every detector was flat | all 30 detectors construct with `severity="error"`; `tools/scan.py`'s `to_sarif` hardcoded `"level": "error"` | high |
| The gate axis is load-bearing | `transpiler/aether/passes/__init__.py` documents that `severity == "warning"` must not fail the run | high |
| The triage axis is free of the gate | `transpiler/aether/risk.py` is read only by output layers; no detector and no `Diagnostic` construction site changed, and the ratchet stayed at 54 codes / 30 detectors | high |
| The vocabulary is not invented | five levels (info/low/medium/high/critical) and the SARIF `security-severity` property are what GitHub Code Scanning already consumes | high |

## Recommended Actions
- Keep the two axes separate. A future "should this fail CI?" knob
  belongs on `severity`, a future "how bad is it?" knob on `risk`.
- Rate every new code in the same commit that ships its detector;
  `tests/test_risk.py` enforces it.
- Do not present a rating as CVSS in any report or README.

## Residual

**Closed (2026-09-03, iter 52): the per-finding axis now varies.** The
residual asked for "something the detectors actually compute". Iteration
50 supplied it, measured: the Python frontend names a sink in six
different ways, and they are not equally certain
(`bench/framework_scan/REPORT.md` §8). `_sink_match` now returns *how* it
matched alongside *what* it matched, `_call_expr` parks that on the Call
node as `match`, and the two `detector_specs.py` drivers set
`confidence=confidence_of(call.get("match"))` and put the kind in
`extra`. The ratings live in `transpiler/aether/confidence.py`:

| match kind | rating | why |
|---|---|---|
| `qualified` / `guard` | 0.95 | resolved through the file's imports to a known dotted path |
| `builtin` / `argv` | 0.9 | a bare builtin, or a literal `["bash","-c",cmd]` |
| `builtin_compile` | 0.6 | `compile()` builds a code object and runs nothing — 4 of 8 corpus sites are linters checking syntax |
| `method` | 0.6 | method NAME only, receiver unresolved — [[q5-sink-matching-vs-purity-matching]]'s sanctioned over-flag |
| *(absent)* | 1.0 | an Aether-source finding: the sink is spelled in the source, nothing was guessed |

An unknown non-empty kind takes the FLOOR, never 1.0 — a new frontend
match kind must not claim certainty by being new
(`tests/test_confidence.py`).

**It changed no detection.** 676 findings on the 15-framework corpus
before, 676 after, identical multiset (`bench/framework_scan/run_scan.py
--skip-download --json`, same 4,946 files; per-dist stats identical). The
axis is read at OUTPUT time, exactly like `risk.py`: `tools/scan.py` and
`check-py` sort by `(-risk, -confidence, line, code)`, both grow
`--min-confidence FLOAT`, SARIF carries it under
`properties.confidence`. The distribution: 0.95 ×44, 0.9 ×3, 0.6 ×629 —
so `--min-confidence 0.9` hides 93% of the corpus, almost all of it
`cursor.execute`-shaped SQL matched by name.

**What it still does NOT do.** It is per-MATCH-KIND, not per-flow: two
`cursor.execute` findings rank identically whether the query came from a
request handler or a test fixture, which is the same limitation this
Residual originally named one level up. It says nothing about
exploitability — a 0.6 finding is not "probably a false positive", it is
"the analysis is less sure this callee is the sink it matched".

And it reaches only the two spec-driven drivers: the ~20 hand-written
`Diagnostic` sites in `passes/effects.py` still construct at a literal
1.0. On today's Python surface that costs nothing, and the reason is
worth writing down rather than assuming: of those codes only **E0723**
can fire on translated Python at all, and its evidence is a string
literal read straight out of the source, so 1.0 is earned. E0710, E0721
and E0722 read a DECLARED `net.fetch` effect annotation that Python has
no equivalent for (the frontend emits `net.get`; survey candidate
TC-09), and E0729/E0730 need marker types Python cannot spell — all five
are dead on Python. The residual is therefore a *latent* one: the next
hand-written detector that does fire on translated Python will claim an
Aether-source finding's certainty unless it reads `call.get("match")`
like the drivers do.

## Related
- [[../clusters/violation-taxonomy]] — the class each rating rates
- [[q3-what-makes-a-good-backlog-target]] — target selection, the other
  place a per-class judgement is made
- [[q1-taint-marker-soundness-boundary]] — the residual above is a
  precision limit of the same shape
