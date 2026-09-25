# Recall: what `aether check-py` MISSES on 1.19M lines of real PyPI code

**Date:** 2026-07-26
**Question:** every false-negative number in this repo was measured against
ground truth this repo authored. What does the tool miss on code it did
not choose, judged by someone else?

**Reproduce:** `python -B bench/pypi_scan/run_recall.py` (`--json` for
every divergence, `--dist <name>` to scope it).

## Method, and its central caveat

There is no labelled vulnerability corpus on this machine, so recall is
measured against an **oracle**: bandit 1.9.4, independently written, to a
different specification, over the same 111 distributions.

**bandit is not ground truth.** It has its own false positives and its own
blind spots. A finding it reports and Aether does not is a **candidate**
false negative. The number below is an *agreement rate*, and the
candidates were triaged by hand rather than quoted as recall.

Every bandit test id was mapped to the Aether row targeting the same CWE,
or explicitly listed as having no counterpart. Both lists are in
`run_recall.py` so the mapping can be argued with.

## The raw number, and why it is the wrong one

| | |
|---|---|
| bandit findings, all categories | 5,559 |
| ... in a mapped category | 365 |
| both tools flagged (within 3 lines) | 125 |
| bandit only — candidate miss | 240 |
| **raw agreement** | **34.2%** |

**221 of those 240 "misses" are a definitional mismatch, not a miss.**

- **B105/B106/B107 → E0723 (210).** bandit flags *variable names* that look
  like passwords (`password = "changeme"`). Aether's E0723 is a
  literal-**content** scan for provider key shapes (`AKIA…`, `ghp_…`, PEM
  blocks). Same CWE-798, disjoint predicates — neither is a superset, and
  on this corpus bandit's fires 210× where Aether's fires 0.
- **B108 → E0711 (11).** bandit flags a **hardcoded** `/tmp` literal.
  Aether's E0711 flags a **dynamic** path. The predicates are near-opposite;
  mapping them at all is generous.

## The number that means something

Restricted to categories where both tools implement the same predicate:

| bandit | Aether | agreed | missed | rate |
|---|---|---|---|---|
| B608 SQL injection | E0713 | 97 | 6 | 94.2% |
| B602/B605 shell | E0714 | 11 | 3 | 78.6% |
| B301/B302 pickle, marshal | E0720 | 14 | 9 | 60.9% |
| B313–B320 XML | E0727 | 3 | 1 | 75.0% |
| **total** | | **125** | **19** | **86.8%** |

**86.8% agreement with an independently written tool on comparable
categories.** That is the first recall-shaped number in this repo that
this repo did not author the answer key for.

It is not 100%, and the 19 remaining candidates are not all bugs — a
sample includes pickle over channels the caller owns, which Aether reports
elsewhere in the same file at a different line and the ±3-line matcher
therefore scores as a miss.

## What the oracle actually caught

Four confirmed false negatives — an independent tool flagged the shape and
Aether said nothing. *Corrected 2026-09-15:* this section and its commit
(`8363e13`) first said five, but list four silent shapes; the table's last
row, `ET.fromstring` through a module alias, was already reported before
the fix and still is.

| Shape | Was | Now |
|---|---|---|
| `marshal.load(f)` | silent | E0720 |
| `pickle.Unpickler(f).load()` | silent | E0720 |
| `pulldom.parseString(s)` | silent | E0727 |
| `xml.sax.parseString(s, None)` | silent | E0727 |
| `ET.fromstring(s)` via module alias | E0727 | unchanged |

All four were missing table rows. `xml.sax.parseString` also exposed a
**structural bug**:
`import xml.sax` + `xml.sax.parseString(...)` arrives as
`Attribute(Attribute(Name))`, and `_callee_spelling` resolved only one
level, returning the bare method name so the dotted table never matched —
while `from xml.dom import minidom` + `minidom.parseString(...)`, the same
sink, matched fine. Chained module paths now flatten.

Fixing that exposed a second bug in the same code, present in the
pre-existing `_flatten_attr` too: `import xml.sax` binds the **root** name,
so `alias_to_path["xml"]` is `"xml.sax"` and naive substitution produced
`xml.sax.sax.parseString`. Substitution now happens only for a genuine
rename (`import numpy as np`).

Effect on the oracle run: B302 0→6 agreements, B319 0→2, B301 7→8;
agreement 31.8% → 34.2% raw, and 86.8% on comparable categories.

**Only shapes the oracle actually flagged were added.** No speculative
rows — that discipline is why this is a measurement and not a wishlist.

## A second, independent check: bandit's published spec

`bandit/plugins/injection_sql.py`'s docstring enumerates the six shapes
B608 claims to detect. Run against Aether verbatim:

```python
cur.execute("SELECT %s FROM derp;" % var)                       # E0713
cur.execute("SELECT thing FROM " + tab)                         # E0713
cur.execute("SELECT " + val + " FROM " + tab)                   # E0713
cur.execute("SELECT {} FROM derp;".format(var))                 # E0713
cur.execute(f"SELECT foo FROM bar WHERE id = {product}")        # E0713
cur.execute("SELECT * ... '[VALUE]'".replace("[VALUE]", ident)) # E0713
```

**6 of 6.** `.format()` and `.replace()` were never explicitly modeled —
they reach the rules as computed calls, which the literal-or-wrapper rule
already refuses.

## Cost, and the limits

Closing the five misses moved precision slightly the wrong way, as
expected: total findings 170 → 179, non-test 39 → 48. That is the trade
the over-flag doctrine predicts, and the number is published rather than
buried.

**What this still does not establish:**

- **bandit's blind spots are invisible here.** Anything both tools miss is
  counted as agreement. This measures divergence, not truth, and it cannot
  find a class neither tool models.
- **No open-redirect or SSTI signal at all** — bandit ships no
  open-redirect plugin, and its B701 checks jinja2 autoescape (XSS), a
  different defect. E0718 and E0719 have no oracle here and remain
  measured only against this repo's own corpus.
- **Libraries, not applications.** These rows target request-handling code;
  111 installed libraries are not that.
- The ±3-line matcher scores a same-file finding at a distant line as a
  miss, which makes the 86.8% a floor rather than a point estimate.
