# Aether Security Posture — the violation classes the checker refuses

Aether is a security checker for Python, built on the typed intermediate
representation of the Aether language. `aether check-py` translates an
unmodified Python file into that IR and runs the security rules on it;
Aether source (`.aeth`) is checked by the same rules plus the language's
effect, capability and marker-type checks, which Python code has no
declarations for.

On Aether source, beyond the base passes (effect composition `E0801`,
capability scope `E0701`–`E0704`, static-semantic `E0202`–`E0208`), a
default-on security stage refuses **22 security-violation codes,
`E0710`–`E0731`**. Every one is opt-out with `--no-scope-check`, emits a
structured, machine-readable diagnostic an agent fix-loop can act on, and
has a row in `grammar/diagnostics.md` (the full catalog). Refinement
predicates and `requires`/`ensures` contracts (`E0301`–`E0305`) are
checked at **runtime** and are runtime guarantees, not static proof (see
`grammar/types.md`).

## The 22 codes (built by the improvement loop, `demos/case_studies/LOOP_LOG.md`)

| Code | Class | CWE | Family | Sanctioned repair | Default on Python |
|------|-------|-----|--------|-------------------|:---:|
| E0710 | SSRF — unpinned fetch scope | 918 | effect-string | pin the host | — ¹ |
| E0711 | Path traversal / Zip-Slip | 22 | sink+literal | `safeJoin` | `--strict` |
| E0712 | Secret reaches a log/disk sink | 532 | taint | `reveal` | — |
| E0713 | SQL injection | 89 | sink+literal | `sqlBind` | ✓ |
| E0714 | Command injection | 78 | sink+literal | `shellArg` | ✓ |
| E0715 | PII reaches a log/disk sink | 359 | taint | `redact` | — |
| E0716 | Missing authorization | 862/863 | taint (inverted) | `authorize` | — ² |
| E0717 | Cross-tenant / IDOR | 639 | taint (resource-bound) | `authorizeResource` | — |
| E0718 | Open redirect | 601 | sink+literal | `safeRedirect` | ✓ |
| E0719 | Template injection / SSTI | 94 | sink+literal | fixed template / `trusted` | ✓ |
| E0720 | Insecure deserialization | 502 | sink+literal | `schemaDecode` / `trusted` | ✓ |
| E0721 | Cleartext transmission | 319 | effect-string | `https://` | — ¹ |
| E0722 | SSRF to cloud metadata (IMDS) | 918 | effect-string | use the credential provider | — ¹ |
| E0723 | Hardcoded credential | 798 | literal-content | source from env / secret manager | ✓ |
| E0724 | Log injection | 117 | taint | `sanitizeLog` | — |
| E0725 | Reflected XSS | 79 | taint | `htmlEscape` | — |
| E0726 | Response-header injection | 113 | taint | `sanitizeHeader` | — |
| E0727 | XML external entities / untrusted XML parse | 611 | sink+literal | `parseXmlSafe` | ✓ |
| E0728 | CSV / formula injection | 1236 | taint | `csvEscape` | — |
| E0729 | Marker erased at a call (taint laundering) | — | taint (boundary) | unwrap at the call, or a marker-typed parameter | — |
| E0730 | Marker erased at a return | — | taint (boundary) | declare the marked return, or unwrap | — |
| E0731 | Code injection (`evalCode`; `exec`/`eval`/`compile` on Python) | 94/95 | sink+literal | fixed source / `trusted` | ✓ |

¹ On Python these fire only on a call named `fetch` through a mapped
network module, not on `requests.get` or `urlopen` (measured; README,
"What it checks on Python").
² `E0716` does fire on Python, on every `.executescript(...)` method call:
the frontend maps it to `sqlExec`, which requires an authorization proof no
Python spelling supplies. Read it as "this call runs a SQL script".

## Four detector families (the reusable shapes)

1. **sink+literal** — a dangerous sink (`sqlQuery`, `shellExec`,
   `readFile`/`writeFile`, `redirect`, `renderTemplate`, `deserialize`,
   `parseXml`, `evalCode`) must receive a fixed literal or a sanctioned
   sanitizer's result; a concatenation or other dynamic expression is
   refused.
2. **taint** — a marker type (`Secret<T>`, `PII<T>`, `Untrusted<T>`,
   `Authorized<T>`) whose value must not reach a sink unwrapped
   (`E0712`, `E0715`, `E0724`–`E0726`, `E0728`), must not lose its marker
   at a call or a return (`E0729`, `E0730`), or — inverted — whose proof a
   sink *requires* (`E0716`, `E0717`). Syntactic and intraprocedural:
   over-flag, never miss within the modeled surface (see
   `vault/wiki/questions/q1-taint-marker-soundness-boundary.md`). Markers
   survive the two containers the language has: a generic type argument
   (`List<PII<String>>`) and a record field (`record User do email:
   PII<String> end`). Record fields are matched by NAME, not by resolved
   record type: over-flag, not inference.
3. **effect-string** — a property read straight off the declared
   `net.fetch` effect annotation: host pinning (`E0710`), scheme
   (`E0721`), destination range (`E0722`).
4. **literal-content** — a scan of string literals for provider-credential
   shapes (`E0723`).

## What runs on unmodified Python (`aether check-py`)

`transpiler/aether/py_frontend.py` translates Python into the same IR, so
the **sink+literal** and **literal-content** families run on ordinary
Python with no rewrite and no annotations. Default-on: `E0713`, `E0714`,
`E0718`, `E0719`, `E0720`, `E0723`, `E0727`, `E0731`. `--strict` adds
`E0711` and the `E0701` capability inventory, both held back by
measurement (`bench/py_frontend/REPORT.md` §2, `bench/pypi_scan/REPORT.md`
§2).

The other families **cannot** run there, and the CLI says so on every run
rather than implying parity:

| Family | Why not on Python |
|---|---|
| effect composition (`E0801`) | compares against a **declared** `effects` clause; Python has none |
| **taint** (`E0712`, `E0715`, `E0717`, `E0724`–`E0726`, `E0728`–`E0730`) | needs marker types on a signature; Python has no annotation-free equivalent |
| **effect-string** (`E0710`, `E0721`, `E0722`) | reads the **declared** `net.fetch` annotation (fires only on a mapped call named `fetch`) |
| static-semantic (`E0202`–`E0208`) | checks Aether constructs; on translated Python it would describe the translation |

Findings on Python name Aether's sanitizers (`sqlBind`, `shellArg`,
`safeRedirect`, …); the README's *What it checks on Python* section maps
each to its Python fix. Measurements, the benign-corpus false-positive
counts and a differential against bandit: `bench/py_frontend/REPORT.md`.
The name-matching doctrine that licenses it:
`vault/wiki/questions/q5-sink-matching-vs-purity-matching.md`.

## The credibility triangle (three gated suites)

A security checker is only trustworthy if it catches bad code, leaves good
code alone, AND its fixes actually work at runtime. All three are gated by
`scripts/run_all.py` (counts measured 2026-09-25 at `52f04aa`):

| Property | Suite | Evidence |
|----------|-------|----------|
| **Catches bad** | `tests/test_effect_scope.py` | every E07xx fires on its violation |
| **Passes good** | `tests/test_false_positive_corpus.py` | 37 legitimate programs, **0** diagnostics |
| **Not theater** | `tests/test_runtime_enforcement.py` | 9 sanitizers defang a real payload end-to-end |

The false-positive corpus is every `fixed.aeth` across the repo plus the
clean playground examples — if any detector ever over-flags legitimate
use of a guarded sink, that gate goes red.

## Composition is verified

`demos/case_studies/composition_kitchen_sink/aether/multi_violation.aeth`
is one module with seven independent violations; `aether check` emits all
seven diagnostics at once. `tests/test_effect_scope.py::
test_detectors_compose_additively` asserts this — the passes accumulate,
none masks another.

## Real-world validation

- `bench/pypi_scan/REPORT.md` and `bench/pypi_scan/RECALL.md`: 111 PyPI
  distributions, 1,192,484 SLOC, measured 2026-07-26 — 0 crashes, 0 parse
  failures, 0.033 findings/KLOC outside test dirs, and **86.8% agreement
  with bandit on comparable categories** (125 agreed / 19 candidate
  misses; the raw agreement over all of bandit's categories is 34.2%, and
  RECALL.md explains the difference). No vulnerability was found in that
  corpus.
- `bench/framework_scan/REPORT.md`: 15 AI-agent frameworks, 4,946 files,
  676 findings at 0.4.0 (re-scanned 2026-09-11), triaged by class.
- `bench/REALWORLD_VALIDATION.md`: the detectors on faithful models of
  documented vulnerable shapes (requests, subprocess, Flask, PyYAML, the
  Capital One 2019 breach) — 1:1 maps, not a live-repo scan.

## What is deliberately NOT covered (honest boundary)

- **Provenance / source-taint** — taint originates at marker-typed
  parameters, not from `readFile`/network reads.
- **Noisy-inference classes** — div-by-zero / index-out-of-bounds
  preconditions, TOCTOU, unbounded-resource DoS are parked until a clean
  static signal exists.
- **Types** — names are resolved statically (`E0208`: a call to an
  undeclared name, such as a misspelt sink, is refused), but there is no
  type checker (`grammar/types.md`); a detector reads the shapes it
  models, not types.
- **Runtime vs static** — refinement and contract guarantees fire at
  runtime and are runtime guarantees, never presented as static proof.

## Reproduce everything

    python -B scripts/run_all.py            # full gate, exit 0 = green
    python -B tests/test_effect_scope.py    # the security-stage suite
