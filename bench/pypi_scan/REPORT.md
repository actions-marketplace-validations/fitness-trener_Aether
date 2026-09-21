# `aether check-py` on 1.19M lines of real PyPI code

**Date:** 2026-07-26
**Question:** `bench/py_frontend/REPORT.md` measures against ground truth
this repo wrote, and says so. What does the tool do on a large body of
third-party code nobody wrote for it?

**Reproduce:** `python -B bench/pypi_scan/run_scan.py` (`--json` for every
finding). The corpus is the active interpreter's `site-packages` —
published PyPI distributions already on disk. Nothing is downloaded,
imported, or executed; files are read as text and parsed with `ast`.

**Reproducibility caveat, added 2026-09-02.** The corpus is *whatever is
in the running interpreter's `site-packages`*. Re-running on 2026-09-02
on the same machine touched 30 distributions and produced 370 findings
against the 170 below, because the installed set had changed in the
meantime. The numbers in this report describe the corpus of 2026-07-26 and
are not a baseline any later run can be diffed against; a run that needs
a before/after (`bench/py_frontend/REPORT.md` §3c) must take both
measurements on the same day. A pinned corpus — a requirements file and a
throwaway venv — is the fix, and is not done here.

**Headline, stated first: no vulnerability was discovered.** 39
non-test findings across 111 distributions, and triage below classifies
roughly two-thirds as a documented over-flag. What the scan did produce
is a robustness result, a precision number that is not author-supplied,
and one genuine defect in the frontend.

---

## 1. Corpus and robustness

| | |
|---|---|
| distributions | 111 |
| `.py` files | 5,588 |
| files that failed to parse | **0** |
| SLOC (non-blank, non-comment) | **1,192,484** |
| analyzer crashes | **0** |

Zero crashes and zero parse failures across 1.19M lines is the single
most reusable number here. `passes/__init__.py` deliberately does not
catch exceptions — *"a crashing detector must go red, not silent"* — so
this is an unguarded run. It is also the strongest available answer to
BUG-003, the crash that reached `main` earlier the same day: the shape
that triggered it does not recur across this corpus.

## 2. Findings

Default row set — exactly what `check-py` prints (E0713, E0714, E0718,
E0719, E0720, E0723, E0727; `effects`/`semantic`/`capability` skipped,
E0711 held back). `test_pypi_scan_row_set_matches_cli` fails the build if
the scan and the CLI drift apart.

| | count | per KLOC |
|---|---|---|
| all findings | 170 | 0.143 |
| **outside test directories** | **39** | **0.033** |
| E0711 (held back, `--strict` only) | 476 | 0.399 |

Bundled test suites deliberately contain unsafe shapes, so they are
counted separately rather than dropped — 131 of the 170 are in test
directories.

**E0711 fires 12× more often than the entire default set combined.** The
decision to demote it, taken in `bench/py_frontend/REPORT.md` on a
76-module corpus, holds at 15× the scale.

## 3. Triage of all 39 non-test findings

Read at the source line, not counted.

| Class | n | Verdict |
|---|---|---|
| distutils/setuptools `Command.execute(func, args)` | ~22 | **False positive** — the documented method-name over-flag |
| `defusedxml` hardened parsers | 2 | **False positive** — guard is a function return |
| `mcp/cli` `shell=<computed>` | 1 | **False positive** — the documented cost of BUG-004 |
| pickle over a channel the caller owns (`anyio`, `jinja2` bytecode cache) | ~4 | True by shape, safe in context |
| dynamic shell in developer tooling (`pip`, `PIL`, `fire`) | ~7 | True by shape, local-trust context |
| worth a human look | 3 | see below |

**The dominant false positive is exactly the one q5 predicts.**
`setuptools/_distutils/cmd.py` defines `Command.execute(func, args, msg)`
— a *shell-command runner*, not a DB cursor — and `SINK_BY_METHOD` maps
`execute` → `sqlQuery` from the method name alone. q5's answer says this
is legitimate because the error direction is an over-flag. This scan puts
a number on that argument for the first time: **~22 of 39, about 56%, of
non-test findings come from that one rule.**

The three worth a look, none of them a vulnerability:

- `pip/_internal/commands/configuration.py:239` —
  `subprocess.check_call(f'{editor} "{fname}"', shell=True)`. A config-set
  editor interpolated into a shell string. Local-trust by design; the
  shape is textbook CWE-78.
- `pydantic/deprecated/parse.py:54` — `pickle.loads(bb)` behind an
  `allow_pickle` flag. Deprecated by pydantic partly for this reason.
- `prompt_toolkit/formatted_text/html.py:35` —
  `minidom.parseString(f"<html-root>{value}</html-root>")`. `minidom`
  is entity-expansion-prone only on an expat older than 2.7.2 (corrected
  2026-09-11; current CPython refuses the payload); `value` is
  developer-authored in practice.

## 4. A defect the scan found

Before this run, an unmapped Python call reached the detectors under its
**raw Python spelling**, sharing a namespace with Aether's sink names. Any
method merely *spelled* like a sink became one without passing through
the mapping table:

```python
self.redirect(uri)        # -> E0718
self.renderTemplate(x)    # -> E0719
```

Neither is in `SINK_BY_QUALIFIED`, `SINK_BY_METHOD`, or anything
`mapping_table()` exposes. It over-flags rather than misses, so it is not
a soundness bug — but an **unmapped, unauditable sink** is precisely what
the auditable-surface design exists to prevent, and it would have been
invisible to anyone reviewing the tables.

Fixed by prefixing the fallback (`py:<spelling>`), pinned by
`test_unmapped_call_cannot_collide_with_an_aether_sink_name`.

Effect on the numbers, which is why this report shows both:

| | before fix | after |
|---|---|---|
| all findings | 187 | **170** |
| non-test | 53 | **39** |
| E0718 | 13 | **0** |
| E0720 | 11 | **7** |

**Every one of tornado's and websockets' E0718 hits was this collision.**
26% of the non-test findings were noise from an unmapped rule.

## 5. What this does and does not establish

**Does:**
- The frontend survives 1.19M lines of unfamiliar real code without a
  crash or a parse failure.
- The default row set is quiet on real code: 0.033 findings/KLOC outside
  tests — one finding per ~30,000 lines.
- The E0711 demotion was correct, confirmed at 15× the original scale.
- q5's method-name over-flag now has a measured cost (~56% of non-test
  findings) instead of an argument.

**Does not:**
- **Find a vulnerability.** No 0-day, and the three flagged shapes are
  local-trust or already-deprecated code.
- Measure recall. This corpus has no known-vulnerability ground truth, so
  it says nothing about what was missed — and the missing-half question is
  the one that matters most. `bench/py_frontend/` is still the only
  false-negative measurement, and it is author-established.
- Generalize beyond installed libraries. Application code — web handlers
  taking request data — is where these rows are aimed, and 111 libraries
  are not that.

## 6. Re-measured 2026-09-02, before and after BUG-010 / BUG-011

Same interpreter, same day, before taken from a `git archive` of HEAD
(`6ad43b6`), so the two runs saw an identical corpus — the caveat at the
top of this report is why that mattered.

| | before | after |
|---|---:|---:|
| findings, default row set | 370 | **386** |
| outside test directories | 123 | 126 |
| E0713 | 216 | 216 |
| E0720 | 109 | **124** |
| E0719 | 0 | 1 |
| E0711 (held back) | 1,003 | 990 |
| bandit B301 → E0720, hits / misses | 102 / 26 | **118 / 10** |
| bandit B608 → E0713, hits / misses | 97 / 14 | 97 / 14 |

E0713 did not move because this corpus's SQL hits are distutils'
`Command.execute` and DB-API cursors, not SQLAlchemy; the BUG-010
recogniser had nothing to clear here, and the benign-corpus result in
`bench/py_frontend/REPORT.md` §3c says the same. What moved is E0720:
**fifteen pickle sinks under guarded or function-local imports were
silent** (BUG-011), and bandit — written to a different specification —
had been reporting sixteen of them as misses. That agreement is the
second, independent confirmation of the false-negative class the
framework scan found. The 13-finding drop in E0711 was not investigated;
the row is held back from the default output and the change is inside its
noise.
