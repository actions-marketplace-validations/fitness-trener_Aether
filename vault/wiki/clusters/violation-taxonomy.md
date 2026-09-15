---
type: cluster_page
cluster_id: violation-taxonomy
status: active
confidence: medium
last_updated: 2026-09-11
tags: [violation-taxonomy, security, effect-system, capability-model, detection-backlog]
---

# Cluster: Violation Taxonomy — what Aether catches, and what it does not yet

## Summary
A living map of **architecture-class failure TYPES** (the kind of bug that
survives unit tests and human review because each function is locally
fine and the lie is in the composition) against Aether's detection
coverage. Each row is a *class*, not an instance. The point of this page
is the **backlog**: the not-yet-covered rows are the queue the
improvement loop pulls from, each with a concrete detection idea so a
future iteration can eliminate the whole class, not one CVE.

Coverage legend: **CAUGHT** (a default-on pass refuses it) · **PARTIAL**
(caught only under conditions) · **OPEN** (no detection yet; detection
idea noted).

## Covered classes (default-on passes)

| Class | Precondition | Diagnostic | Notes |
|---|---|---|---|
| Effect leak (impure "pure") | a function does IO/log/net it did not declare | **E0801** | B.1; the Log4Shell shape (a logger that fetches) |
| Effect-arg mismatch (URL discipline) | callee's URL not covered by caller's glob | **E0801** | B.2; glob subsumption |
| Capability overrun | transitive effect needs a capability no module declared | **E0701** | B.3; the second lock behind E0801 |
| Refinement-boundary violation | a value outside `T where P` crosses a call boundary | **E0302/E0305** | B.4; runtime boundary check |
| Module export lie / dup / unknown cap | structural module errors | **E0702/3/4** | D.3 |
| **SSRF (unpinned fetch scope)** | `net.fetch` host/authority is a wildcard → steerable inward to `169.254.169.254` | **E0710** | *Shipped 2026-07-04, iter 1.* Closes the open-by-default fetch scope. |
| **Path traversal / Zip-Slip** | `readFile`/`writeFile` path is dynamic/untrusted, not literal or `safeJoin`ed | **E0711** | *Shipped 2026-07-04, iter 2.* `safeJoin` stdlib is the sanctioned repair. |
| **Secret exfil via log/disk** | a `Secret<T>` value reaches `print` or `writeFile` contents without `reveal(...)` | **E0712** | *Shipped 2026-07-04, iter 3 (log); widened 2026-07-07, iter 11 (disk).* First taint-lite pass: `Secret<T>` marker + `reveal`/`classify`; param-origin taint, straight-line dataflow. Sink set now `{print, writeFile-contents}` via a sink-spec dict (mirrors E0715). |
| **SQL injection** | a `sqlQuery` arg is raw concatenation, not a literal or `sqlBind(...)` | **E0713** | *Shipped 2026-07-04, iter 4.* `sqlQuery` sink (effect `db.query`) + `sqlBind` parameterizing sanitizer; sink+sanitizer+literal shape. *Precision widened 2026-09-01, iter 47 (Python frontend only):* a SQLAlchemy/SQLModel expression rooted at `select`/`insert`/`update`/`delete`/`text`/`union`/`exists` is named as `sqlBind` — a parameterized query by construction — unless a raw-string entry point (`text`, `literal_column`, `column`, `table`) anywhere inside takes a non-literal, in which case nothing is sanctioned. Was 97% of all findings on 15 agent frameworks (BUG-010). Residual in [[../questions/q5-sink-matching-vs-purity-matching\|q5]]. |
| **Command injection** | a `shellExec` arg is raw concatenation, not a literal or `shellArg(...)` | **E0714** | *Shipped 2026-07-04, iter 5 (self-teaching agent).* `shellExec` sink (effect `exec.run`, new `exec` capability) + `shellArg` quoting sanitizer; E0713 slice cloned (CVE-2022-1292 shape). |
| **PII egress (GDPR / residency)** | a `PII<T>` value reaches `print` or `writeFile` contents without `redact(...)` | **E0715** | *Shipped 2026-07-04, iter 6.* Second taint marker on the generalized taint helpers; `PII<T>` + `classifyPII` + masking `redact`; log + disk sinks. |
| **Missing authorization before mutation (CWE-862/863)** | a data-mutating sink (`sqlExec`, effect `db.exec`) is reachable with no authorization proof in its dataflow | **E0716** | *Shipped 2026-07-04, iter 7.* The taint core INVERTED: the sink *requires* an `Authorized<T>` marker (from the `authorize(principal, action)` guard or an `Authorized<T>` param) instead of refusing one. `sqlExec`'s query arg also joined the E0713 sink list. Ivanti EPMM CVE-2023-35078 shape. |
| **Cross-tenant data access / object-level authorization (IDOR, CWE-639)** | a resource-scoped mutation (`sqlByOwner`, effect `db.exec`) whose authorization proof is not bound to the SAME resource id the sink mutates | **E0717** | *Shipped 2026-07-04, iter 8.* The resource-binding extension of E0716: `sqlByOwner(stmt, resourceId, proof)` requires `proof` = `authorizeResource(principal, action, resourceId)` for the same id (identical literal, or same never-rebound name). Mismatched/unbound/unprovable id → refused. OWASP API1; Facebook "delete any photo" shape. |
| **Open redirect (CWE-601)** | a `redirect` target is not a fixed literal or a `safeRedirect(host, path)` result | **E0718** | *Shipped 2026-07-04, iter 9.* `redirect` sink (effect `net.redirect`) + `safeRedirect` host-pinning sanitizer (strips scheme/authority/leading-slash); E0711 sink+sanitizer+literal shape. OAuth `returnTo`/`redirect_uri` abuse. |
| **Template injection / SSTI (CWE-94)** | a `renderTemplate` template arg is not a fixed literal (concatenation / parameter) | **E0719** | *Shipped 2026-07-04, iter 10.* Leanest injection member: sink+literal shape with NO sanitizer (SSTI has no safe way to build a template from user input). Jinja2/Flask `{{7*7}}`→RCE shape; untrusted value must move to the escaped data arg. Residual RESOLVED (iter 13): `trusted(...)` boundary admits vetted dynamic templates. |
| **Insecure deserialization (CWE-502)** | `deserialize` fed a non-literal (untrusted) argument instead of `schemaDecode(schema, data)` | **E0720** | *Shipped 2026-07-07, iter 12.* SSTI-shaped: literal-only, no sanitizer; the repair is a sibling function `schemaDecode` pinned to a fixed schema. pickle/readObject/unsafe-YAML gadget RCE. Residual RESOLVED (iter 13): `trusted(...)` boundary admits vetted config blobs. |
| **Cleartext transmission (CWE-319)** | a `net.fetch` scope uses `http://` to a non-loopback host | **E0721** | *Shipped 2026-07-07, iter 16.* Orthogonal sibling of E0710 (scheme, not host-pinning) on the effect annotation. Loopback exempt. The fix is `https://`. Not a sink+literal or taint member — a pure effect-string check, cheapest possible new class. |
| **SSRF to cloud metadata / IMDS (CWE-918)** | a `net.fetch` scope pinned to `169.254.0.0/16` | **E0722** | *Shipped 2026-07-07, iter 17.* Effect-string family. Closes the E0710 blind spot: a metadata IP is host-*pinned* so E0710 passes it, but 169.254.169.254 is the IAM-credential-theft target. RFC-1918 private ranges deliberately NOT flagged (legit in meshes). *Widened 2026-09-03, iter 49:* one host normalizer shared with E0710/E0721 — userinfo, port, brackets, decimal/hex/octal/short and IPv4-mapped-IPv6 spellings of 169.254/16, `fd00:ec2::254`, `metadata.google.internal`, `metadata`, `100.100.100.200`; E0721's loopback exemption is host-exact; E0710 sees a wildcard anywhere inside the host. Residual: a DNS name that merely *resolves* to link-local is outside any static rule. |
| **Hardcoded credential (CWE-798)** | a string literal matches a provider-credential shape (AWS/GitHub/Google/Slack/Stripe/PEM) | **E0723** | *Shipped 2026-07-07, iter 19.* NEW family — literal-content scan (a secret scanner in the compiler), not effect/dataflow. Narrow high-confidence patterns → ~0 false positives (demo "hunter2" clean, real AKIA… flagged). #1 real-world finding. *Widened 2026-09-03, iter 49:* OpenAI (`sk-proj-`, `sk-`), Anthropic (`sk-ant-`), Hugging Face (`hf_`), Groq (`gsk_`), Google OAuth (`ya29.`), GitLab (`glpat-`), SendGrid (`SG.`), npm (`npm_`), PyPI (`pypi-`), Slack incoming-webhook URLs — 0 matches over every in-tree file and the 4,946-file framework corpus; the PEM pattern requires a key BODY after the header (a header quoted in an error message or docstring no longer matches); `StringLit` now carries a position, so the finding names its line. Residual: generic high-entropy secrets not caught (pattern list, not entropy). |
| **Log injection / forging (CWE-117)** | an `Untrusted<T>` value reaches `print` without `sanitizeLog(...)` | **E0724** | *Shipped 2026-07-07, iter 21.* Introduces the taint-SOURCE marker `Untrusted<T>` — the SOUND, explicit dual of provenance inference (mark at the trust boundary rather than infer from reads). Reuses the taint machinery; `sanitizeLog` strips CR/LF. First step of the provenance story without the unsound auto-taint. |
| **Reflected XSS (CWE-79)** | an `Untrusted<T>` value reaches `htmlResponse` without `htmlEscape(...)` | **E0725** | *Shipped 2026-07-07, iter 22.* Second sink for `Untrusted<T>` (OWASP #2). Establishes per-sink sanitizers: `htmlEscape` clears XSS, `sanitizeLog` (which clears E0724) does NOT — the right exit for one sink is wrong for another. The marker pays out one sink at a time. |
| **HTTP response splitting (CWE-113)** | an `Untrusted<T>` value reaches `setHeader` without `sanitizeHeader(...)` | **E0726** | *Shipped 2026-07-07, iter 23.* Third `Untrusted<T>` sink; completes the HTTP-output trio (log/HTML/header), each with its context-correct sanitizer. Untrusted-into-common-web-contexts now well-covered; further sinks (XML/LDAP) are lower-prevalence. |
| **XML external entity / XXE (CWE-611)** | `parseXml` fed a non-literal (untrusted) argument instead of `parseXmlSafe(data)` | **E0727** | *Shipped 2026-07-07, iter 26.* Parser-CONFIG class (E0720 sibling, not an Untrusted content-sink): `parseXml` resolves external entities → file read / SSRF / billion-laughs; `parseXmlSafe` disables them. OWASP-listed. *Iter 53 (2026-09-11):* on Python the text is per resolved callee — by default no stdlib `xml.*` parser fetches an external entity (Python docs `library/xml.html`, "XML security"; probe record `demos/case_studies/LOOP_LOG.md`, Iteration 53): ElementTree never does without a parser argument (a caller's parser, `parser=` or positional, is used as given — an lxml `XMLParser(resolve_entities=True)` or a `feature_external_ges` SAX parser reads the file through it: BUG-031, measured 2026-09-15), expatbuilder takes no parser and never does, `xml.sax.parse`/`parseString` cannot, minidom/pulldom do through a `parser=` SAX parser with `feature_external_ges` (measured: file read and URL fetch); every `parse()` spelling opens its source string as a path or URL, which no row judges (a recorded miss); the DoS clause is hedged at the docs' thresholds (2.4.1 / 2.6.0 / 2.7.2); lxml reads the file by default only below 5.0.0 (changelog 2023-12-29) and under `resolve_entities=True`, a URL only with `no_network=False`. Hints name the `defusedxml` equivalent without a parser argument, `parser=` or positional, and keep that condition beside the Expat version check, which covers only the DoS clause (defusedxml passes a caller's parser through — now a guard-keyed sink) or the three-keyword lxml parser binding, which clears in the `parser=` slot too and no longer clears when it re-enables DTD retrieval; codes and confidence unchanged `[source: diagnostics, section: E0727, key: parseXml]`. Residual and the two misses (`make_parser().parse`, the `parse()` source string) in [[../questions/q1-taint-marker-soundness-boundary\|q1]]. |
| **CSV / formula injection (CWE-1236)** | an `Untrusted<T>` value reaches `csvCell` without `csvEscape(...)` | **E0728** | *Shipped 2026-07-07, iter 28.* Fourth `Untrusted<T>` sink and first NON-HTTP context — proves the marker generalizes past web output. Leading `=+-@` → spreadsheet formula (exfil / DDE-RCE); `csvEscape` prefixes a quote. |
| **Marker laundering / taint erasure at internal boundaries (CWE-532 adjacent)** | a `Secret<T>`/`PII<T>`/`Untrusted<T>` value passed to a user-function parameter not typed with the marker, or produced by a marker-returning call that seeded no taint | **E0729** (+ seeding widens E0712/E0715/E0724/E0725/E0726/E0728) | *Shipped 2026-07-09, iter 39.* The q1 "highest-leverage upgrade", resolved the signature-level way: taint also seeds from declared marker-typed RETURN types (`classify*` constructors + user decls; bodies not analyzed), and a marked value crossing into an unmarked param is refused as laundering. Marker-typed params are the sanctioned crossing. `Authorized<T>` excluded (proof marker — widening would relax). Residuals in [[../questions/q1-taint-marker-soundness-boundary\|q1]]: ~~body-level return laundering~~ (closed iter 40, E0730), stdlib transforms, HOFs. |
| **Return laundering / lying signature (CWE-532 adjacent)** | a function returns a `Secret<T>`/`PII<T>`/`Untrusted<T>`-carrying value under a plain declared return type | **E0730** | *Shipped 2026-07-09, iter 40.* Dual of E0729; closes the signature loop (seeding in, E0729 params, E0730 returns — declared signatures ENFORCED both directions, not merely trusted). Near-zero new machinery: one Return-walker + the iter-39 helpers. Residuals in [[../questions/q1-taint-marker-soundness-boundary\|q1]]: stdlib transform propagation (the last in-surface laundering channel), boundary-sanitizer coarseness. |
| **Marker erased by a container (generic argument or record field)** | a taint marker declared one level down — `List<PII<String>>`, `Option<Secret<T>>`, or `record User do email: PII<String> end` — was invisible to every marker row: the sink read it in the clear | *no new code* — widens **E0712/E0715/E0724/E0725/E0726/E0728** + **E0729/E0730** | *Shipped 2026-07-26, iter 44.* `_type_carries_marker` searches the whole type tree; `_marker_param_mask` also emits a per-`RecordDecl` positional mask, so a marker-typed FIELD is a sanctioned crossing (the dual of a marker-typed param) and `_marker_field_names` makes a field READ a taint source. The two directions ship together on purpose: without the crossing, a record could never legitimately hold a marked value, and every construction site raised a spurious E0729/E0730 — which is why the false accept went unnoticed. `Authorized<T>` deliberately NOT widened (proof marker — widening relaxes) `[source: types, section: Records, key: record]`. Residual in [[../questions/q1-taint-marker-soundness-boundary\|q1]]: fields matched by NAME, not by resolved record type — over-flag, not inference. See also [[effect-system]]. |
| **Code injection — an interpreter fed attacker-authored source (CWE-94/95)** | `evalCode` fed a non-literal (untrusted) source instead of a fixed literal or an explicit `trusted(...)` bundle | **E0731** | *Shipped 2026-09-03, iter 49.* E0719-shaped (literal-only, NO sanitizer — there is no way to escape attacker-authored code into something safe to run; `trusted(...)` is the sole escape hatch) `[source: diagnostics, section: E0731, key: evalCode]`. THE hazard of the agent-framework population: the Python frontend maps `exec`/`eval`/`compile` on a non-literal to this sink (5 bare `exec()` + 9 `compile()` non-literal sites on `bench/framework_scan`, e.g. smolagents `tools.py:575`, agno `tools/python.py:159`), where before they were only `dynamic_construct` UNPROVABLE notes `[source: README, section: Python, key: check-py]`. `ast.literal_eval` is not a sink; a local `def exec` is not the builtin; `exec(compile(src, ...))` reports once, at `compile`. Residual in [[../questions/q1-taint-marker-soundness-boundary\|q1]]: a source bound to a literal in another function or reached via `getattr(builtins, "exec")` stays an UNPROVABLE note only. |

## Non-security architectural classes (Aether's original pitch)

| Class | Precondition | Diagnostic | Notes |
|---|---|---|---|
| **Non-exhaustive match (unhandled variant)** | a `match` on a resolvable union type omits a case with no wildcard | **E0202** | *Shipped 2026-07-07, iter 29.* Lifts exhaustiveness from a RUNTIME trap to a STATIC guarantee (Rust/Swift-style). First NON-security architectural detector — the compiler refuses an incomplete composition. Conservative: silent when the scrutinee's union type is unresolvable. |
| **Unreachable match arm (dead code)** | a `match` arm follows a wildcard, or duplicates an earlier case | **E0203** | *Shipped 2026-07-07, iter 30.* Complement of E0202 (too-few → too-many). Pure arm-ordering, no type info needed. Together: match handling is total-and-minimal — every variant handled exactly once. |
| **Dead code after terminator** | a statement follows `return`/`break`/`continue` in the same block | **E0204** | *Shipped 2026-07-07, iter 31.* Generalizes reachability beyond match: purely structural block scan. Always a logic error (stray early return, merge artifact). |
| **Unused let binding (dead store)** | a `let` (non-`_`) name is never read | **E0205** | *Shipped 2026-07-07, iter 32.* Use/def scan; `_`-prefix is the sanctioned discard. FOUND A REAL DEAD STORE in an agent-generated aetherbench candidate on first run — the detector working on unseen code. |
| **Ignored Result / unchecked error (CWE-252)** | a bare statement discards a `Result`-returning call | **E0206** | *Shipped 2026-07-07, iter 34.* Bind+match or `let _r` to discard. Non-breaking on the hand-authored corpus (uses `_r`), but FOUND 12 REAL ignored-error bugs in AI-generated candidates on first run — the "forgot to check the write" class. |
| **Unsatisfiable refinement (impossible type)** | a `T where P` predicate no value satisfies | **E0207** | *Shipped 2026-07-07, iter 37.* Light SOUND interval analysis over `self OP const` conjunctions; refuses reversed bounds / contradictory `==`. Unanalyzable clauses widen to unbounded → never false-positives. The compiler refusing an uninhabitable type. |

## Open backlog — classes NOT yet detected (detection ideas)

Ranked roughly by prevalence × fit with Aether's static surface.

| # | Class (CWE) | Precondition Aether could see | Detection idea | Blocker / cost |
|---|---|---|---|---|
| B1 | ~~Secret/PII exfil via log/disk~~ | — | **DONE (iter 3 E0712 secret→log; iter 6 E0715 PII→log+disk; iter 11 E0712 secret→disk).** Taint helpers generalized to arbitrary markers (`_marked_tainted_names`); sink sets are per-marker dicts. Remaining: taint-origin from `readFile`/network reads (not just params), and network-body egress (needs a body-carrying net sink). | small — reuse the generalized taint machinery |
| B2 | ~~Injection: **SQL** / **command** / **template**~~ (CWE-89/78/94) | — | **DONE.** SQL (iter 4, E0713), command (iter 5, E0714), template/SSTI (iter 10, E0719). All three share the sink+literal slice; SSTI is the sanitizer-free member. | done |
| B3 | **Missing precondition: div-by-zero / index OOB** (CWE-369/125) | `a / b` or `get(xs,i)` with no `requires b != 0` / bound guard | infer required preconditions at arithmetic/index sites; warn when caller can't prove them | inference; may be noisy — start as warning |
| B4 | **TOCTOU / check-then-use** (CWE-367) | a validation call and the use of the validated value are not atomic | hard statically; park unless a clear pattern emerges | likely out of scope for static v1 |
| B5 | **Unbounded resource / DoS** (CWE-400) | recursion or a loop over untrusted-sized input with no bound | flag unbounded recursion / `range` over a param without a `requires n <= K` | needs loop/recursion analysis |
| B6 | ~~Deserialization of untrusted data~~ (CWE-502) | — | **DONE (iter 12, E0720).** `deserialize` sink refused on non-literal input; `schemaDecode(schema, data)` is the schema-pinned repair. | done |
| B7 | ~~Open redirect~~ (CWE-601) | — | **DONE (iter 9, E0718).** `redirect` sink + `safeRedirect(host, path)` host-pinning sanitizer. | done |
| B8 | **Broadened capability grant** | `requires capability net` grants ALL net; no per-host capability | let capabilities carry a scope (`capability net to "host/*"`) and check module grant ⊇ used scope | capability-model extension; larger |
| B9 | ~~Cross-tenant data access / object-level authorization (IDOR)~~ (CWE-639) | — | **DONE (iter 8, E0717).** `sqlByOwner(stmt, resourceId, proof)` requires `authorizeResource(principal, action, resourceId)` bound to the SAME id (syntactic identity: identical literal or same never-rebound name). Remaining: alias/value-equality id matching (two params holding the same value, ids threaded through ops) — currently refused as unprovable (over-flag). | done |

## Implications / method
- The two shipped classes (E0710, E0711) share one **meta-pattern**:
  *an open-by-default reach (host, path) narrowed only by a blocklist
  elsewhere*. The fix is always **invert to allowlist / pin at the
  boundary** and provide a sanctioned sanitizer. Backlog rows B2 and B7
  are the same meta-pattern (sink + sanitizer + pin) and are therefore
  the cheapest next wins — they reuse the E0711 machinery shape.
- The next structural capability the loop needs is a **taint-lite
  provenance pass** (untrusted-source → sensitive-sink flow). It unlocks
  B1 and B2 at once and is the single highest-leverage addition. Strategic
  addition — not in any v0.1 source; propose as a v0.4 pass.
- Every backlog row must be confirmed **empirically** before building:
  write the bad shape, verify current Aether accepts it, then eliminate
  the class and re-run the full gate suite to exit 0.
- **On Python, the frontend is the one place the error direction
  inverts** (iter 48, BUGS.md BUG-012). Every row above refuses an unknown
  SHAPE, but the translator decides which shapes exist: a statement
  position or binding form it does not model yields no node, and a node
  that does not exist is never refused. The obligation is totality over
  syntax — every value expression translated in place, every binding
  form a binding, every opaque node carrying its children — recorded in
  [[../questions/q7-frontend-totality-over-syntax|Q7]]. It is a
  precondition for every Python row in this table, not a row of its own.

## Links
- [[effect-system]] — E0801/E0710 live here
- [[capability-model]] — E0701 and backlog B8
- [[refinement-contracts]] — B.4 and backlog B3
- [[diagnostics-and-fix-loop]] — how a new code plugs into the fix-loop
- [[../questions/q3-what-makes-a-good-backlog-target|Q3]] — how to pick the next row from this backlog
- [[../questions/q1-taint-marker-soundness-boundary|Q1]] — the soundness contract every taint row inherits
- Loop state of record: `demos/case_studies/LOOP_LOG.md`
