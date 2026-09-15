# Aether Improvement Loop — Log

Autonomous loop: find a real OSS program with an architecture-class
bug, run Aether on a faithful model, then improve Aether to eliminate
the *TYPE* of problem (not the single instance) so it won't repeat on
similar programs. Each iteration builds on the previous report.

State carried forward: the full gate suite must stay green
(`python -B scripts/run_all.py`, exit 0) after every iteration.

---

## Iteration 0 (seed) — Log4Shell (CVE-2021-44228)

- **Target:** Apache Log4j 2 JNDI RCE. A `void log(String)` that opened
  a socket via message-lookup substitution.
- **Aether result:** the composition does not compile — E0801 (effect
  leak) then E0701 (capability) on the lazy fix. Python + `mypy --strict`
  accept it.
- **Report:** `demos/case_studies/log4shell/REPORT.md`.
- **TYPE gap surfaced:** enforcement is only as deep as the declared
  scope; a broad declared scope is a hole. → drove iteration 1.
- **Suite:** 23/23 green.

## Iteration 1 — SSRF via unpinned fetch scope (crawl4ai CVE-2026-53754)

- **Target:** crawl4ai SSRF (incomplete CIDR blocklist → cloud metadata
  169.254.169.254; fixed 0.8.8 by host allowlisting). Siblings: FlaskBB
  CVE-2026-46556, OpenCTI CVE-2026-21887.
- **Gap confirmed empirically:** current Aether accepted `net.fetch("*")`
  reaching 169.254.169.254 (exit 0). Both existing gates satisfied by a
  wildcard scope.
- **Improvement (eliminates TYPE):** new default-on pass + diagnostic
  **E0710** (`check_effect_scope` in `passes/effects.py`) — a `net.fetch`
  whose host/authority is unpinned is a compile error. Path/query
  wildcards and `*.subdomain` pins still allowed. Closes the
  open-by-default fetch-scope precondition for ALL programs, not just
  the crawler. Opt-out `--no-scope-check`.
- **Wiring:** cmd_check + cmd_run; doc row in `grammar/diagnostics.md`;
  test `tests/test_effect_scope.py`; gate line in `scripts/run_all.py`;
  playground example 11.
- **Report:** `demos/case_studies/crawl4ai_ssrf/REPORT.md`.
- **TYPE gap surfaced for next iter:** the filesystem sibling —
  `fs.read`/`fs.write` with an unpinned / absolute / `..`-bearing path
  is the path-traversal (Zip-Slip / arbitrary-file-write) precondition.
  Currently stdlib fs effects carry NO path arg at all (`(("fs","write"),
  None)`), so there is no scope to pin yet. Candidate next target:
  a real path-traversal CVE (e.g. a tar/zip extractor or a static-file
  server) → give fs effects a path scope + an E0711-style pin check.
- **Suite:** 24/24 green.

## Iteration 2 — Path traversal / Zip-Slip (Snyk 2018 class, CWE-22/434)

- **Target:** archive-extractor / upload path traversal. `writeFile(baseDir
  + entryName, ...)` where entryName is `../../../../etc/...`.
- **Gap confirmed:** fs effects carried NO path scope; a dynamic path
  into writeFile/readFile passed every gate.
- **Improvement (eliminates TYPE):** new diagnostic **E0711**
  (`check_fs_path_safety`) — a fs sink path that is not a literal or a
  `safeJoin(...)` result is a compile error. New stdlib **`safeJoin`**
  (pure sanitizer, strips `..`/absolute roots) is the sanctioned repair.
  Lightweight per-function dataflow recognizes `let p = safeJoin(...)`.
- **Wiring:** folded into the `effect_scope` gate (shared `--no-scope-check`);
  doc rows in `grammar/diagnostics.md` + `grammar/stdlib.md`; tests in
  `tests/test_effect_scope.py` + `tests/test_stdlib_d1.py`; playground
  example 12.
- **Vault:** created `vault/wiki/clusters/violation-taxonomy.md` — the
  coverage matrix + OPEN backlog (B1..B8) the loop now pulls from.
- **Report:** `demos/case_studies/zipslip_traversal/REPORT.md`.
- **TYPE gap surfaced for next iter:** taxonomy backlog says the highest-
  leverage next addition is a **taint-lite provenance pass** (untrusted-
  source → sensitive-sink flow), which unlocks B1 (secret/PII exfil via
  log, CWE-532) and B2 (injection: SQL/command, CWE-89/78) together.
  Cheaper reuse-of-E0711-shape wins: B7 open-redirect, B2 injection
  (sink + sanitizer + pin).
- **Suite:** 24/24 green.

## Iteration 3 — Secret/PII exfil into logs (CWE-532, backlog B1)

- **Target:** the "accidentally logged the password/token" class.
- **Gap confirmed:** Aether had no notion of *sensitive data*; every pass
  reasoned about operations, none about the data flowing into them.
- **Improvement (eliminates TYPE):** Aether's first **taint-lite pass**.
  New marker type **`Secret<T>`** (erased at runtime), stdlib
  **`classify`** (wrap) + **`reveal`** (sanctioned unwrap), diagnostic
  **E0712** — a Secret value reaching `print` without `reveal` is a
  compile error. Param-origin taint, straight-line dataflow (reuses the
  E0711 skeleton), log sink only.
- **Wiring:** folded into `effect_scope` gate; docs in diagnostics.md +
  stdlib.md; tests in test_effect_scope.py; playground example 13.
- **Vault:** taxonomy B1 marked DONE; noted the taint pass now lowers the
  cost of B2 (injection) and the B1 extensions (net/fs sinks, source-side
  taint).
- **Report:** `demos/case_studies/secret_in_logs/REPORT.md`.
- **TYPE gap surfaced for next iter:** two cheap reuses now unlocked —
  (a) extend E0712 taint to the `writeFile`/network sinks and to
  `readFile`/network *sources* (secret-to-disk, untrusted-in); (b) B2
  injection (SQL/command) = the same taint dataflow + a modeled
  `db.query`/`exec` sink + a `param()`/`shellQuote()` sanitizer, mirroring
  safeJoin→E0711.
- **Suite:** 24/24 green.

## Iteration 4 — SQL injection (CWE-89, backlog B2)

- **Target:** untrusted parameter concatenated into a SQL query.
- **Gap confirmed:** no db sink existed; concatenated query was just a
  String, invisible to every pass (checked clean before).
- **Improvement (eliminates TYPE):** **E0713** (`check_injection`) — a
  `sqlQuery` arg that is raw concatenation, not a literal or
  `sqlBind(...)`, is a compile error. New stdlib `sqlQuery` sink (effect
  `db.query`) + `sqlBind` parameterizing sanitizer. Reuses the
  sink+sanitizer+literal dataflow shape.
- **Wiring:** effect + capability registries, folded into `effect_scope`
  gate; docs; tests; `stdlib_d1` escaping assertion; case study;
  playground 14. Non-breaking (`db` cap already known; no code calls
  sqlQuery). Suite 24/24 green.
- **Self-teaching agent established:** `tools/self_teaching_agent.md` —
  operating contract + dispatch prompt for a Fable-5 agent that reads the
  vault + toolchain, picks an undetected class, and ships a detector to
  the meta-pattern. Iteration 5 onward can be run by dispatching it.
- **Report:** `demos/case_studies/sql_injection/REPORT.md`.
- **TYPE gaps surfaced for next iter:** (a) command injection = clone the
  E0713 slice for a `shellExec` sink + `shellArg` (add `exec` to the
  capability vocab in `passes/modules.py`); (b) bigtech classes in the
  agent's §5 — cross-tenant data access, auth-before-mutation, PII
  egress/residency — each the same (source, sink, sanitizer) meta-pattern.
- **Suite:** 24/24 green.

## Iteration 5 — Command injection (CWE-78, backlog B2 remainder) — first self-teaching-agent run

- **Target:** untrusted input concatenated into a shell command line
  (OpenSSL c_rehash CVE-2022-1292 shape, CVSS 9.8: certificate file
  names concatenated into shell commands).
- **Gap confirmed empirically:** no exec sink existed; the concatenated
  `shellExec("convert " + filename + " out.png")` shape checked clean
  (exit 0) before this iteration.
- **Improvement (eliminates TYPE):** **E0714** (`check_command_injection`
  in `passes/effects.py`) — a `shellExec` arg that is raw concatenation
  (or any dynamic expression), not a literal or `shellArg(...)`, is a
  compile error. New stdlib `shellExec` sink (effect `exec.run`) +
  `shellArg` quoting sanitizer (POSIX single-quote, binds into `?` as
  ONE argument). New **`exec`** capability in the E0704 vocabulary.
  E0713 slice cloned exactly (sink+sanitizer+literal + straight-line
  dataflow).
- **Wiring:** effect + capability registries (`passes/effects.py`,
  `passes/capability.py`), `exec` in `passes/modules.py`, runtime funcs,
  folded into the `effect_scope` gate in `cli.py`; docs in
  `grammar/{diagnostics,stdlib}.md`; tests in `test_effect_scope.py` +
  `stdlib_d1` quoting assertions; case study
  `demos/case_studies/command_injection/`; playground example 15.
  Non-breaking (surveyed first: nothing in the repo used
  `shellExec`/`shellArg`/`exec`).
- **Report:** `demos/case_studies/command_injection/REPORT.md`.
- **TYPE gap surfaced for next iter:** B2's last remainder is
  template injection / SSTI (needs a template-render sink first). The
  higher-value hunt is the bigtech §5 classes, now that the marker-type
  pattern (`Secret<T>`) is proven: (a) **PII egress** — a `PII<T>`
  sibling of `Secret<T>` that must not reach a `net`/`fs.write` sink,
  which also delivers the B1 extension (secret-to-disk/wire) with the
  same machinery; (b) **auth-check-before-mutation** — an `Authorized<T>`
  marker a mutating sink requires in its dataflow. Both reuse
  `_secret_tainted_names` nearly verbatim.
- **Suite:** green, exit 0.

## Iteration 6 — PII egress (GDPR / data-residency)

- **Target:** personal data (email/name/device id) logged or persisted
  to disk in the clear — the bigtech privacy-postmortem class.
- **Gap confirmed:** the iter-3 taint pass covered only `Secret`→`print`;
  a `PII<String>` value logged + written to disk checked clean before.
- **Improvement (eliminates TYPE):** **generalized the taint core** —
  `_marked_tainted_names(fn, marker, unwrap)` + `_expr_leaks_marked`
  now back both detectors (`Secret`/E0712 became thin wrappers,
  behavior unchanged). Added **`PII<T>`** marker + `classifyPII` +
  masking **`redact`**, and **E0715** (`check_pii_flow`): a PII value
  reaching `print` or `writeFile` **contents** (arg 1 only) without
  `redact(...)` is refused.
- **Wiring:** folded into `effect_scope` gate; docs in diagnostics.md +
  stdlib.md; tests in test_effect_scope.py (+ redact `stdlib_d1`
  assertions); case study `pii_egress/`; playground example 16.
  Non-breaking (no `PII<>` in corpus). Suite 24/24 green.
- **Report:** `demos/case_studies/pii_egress/REPORT.md`.
- **TYPE gaps surfaced for next iter:** (a) the taint core is now generic
  — **auth-check-before-mutation** via an `Authorized<T>` marker that a
  mutating sink (e.g. `sqlExec`/`writeFile`) requires in scope is the
  next high-value bigtech class, near-verbatim reuse; (b) **cross-tenant
  data access** — a `TenantScoped<T>` marker requiring every data sink be
  bound to the request tenant; (c) template/SSTI = clone the injection
  slice once a template-render sink exists; (d) secret→disk/net sinks +
  source-side taint (readFile/network reads).
- **Suite:** 24/24 green, exit 0.

## Iteration 7 — missing authorization before mutation (CWE-862/863)

- **Target:** a data-mutating operation reachable with no authorization
  check on its path — the bigtech broken-authorization class (OWASP
  API1/API5; Ivanti EPMM CVE-2023-35078 shape: an unauthenticated
  mutating API path). Survives review because every function is locally
  fine; the missing guard is an *absence*, invisible locally.
- **Gap confirmed:** an unauthorized `sqlExec` mutation — effect
  declared, capability granted, query parameterized with `sqlBind` —
  checked clean (exit 0) before this iteration.
- **Improvement (eliminates TYPE):** the taint core **inverted**: every
  prior detector says "a marked value must NOT reach a sink"; **E0716**
  (`check_authorization`) says "a mutating sink REQUIRES a marked value
  in its dataflow". New stdlib mutating sink **`sqlExec(stmt, auth)`**
  (effect `db.exec`, existing `db` capability), new marker
  **`Authorized<T>`**, new guard **`authorize(principal, action)`**.
  The proof is accepted as a direct `authorize(...)` call, an
  `Authorized<T>` param (caller's proof crossing the boundary), or a
  name bound only to those (allowlist fixpoint, `_safe_path_names`
  shape + `_is_marker_type`). Absent/unproven → refused (over-flag,
  never miss). `sqlExec`'s query arg also joined `_SQL_SINKS`, so
  E0713 covers injection on the new write sink.
- **Wiring:** folded into the `effect_scope` gate in `cli.py`; registries
  in `passes/effects.py` + `passes/capability.py`; runtime
  `sqlExec`/`authorize`; docs in `grammar/{diagnostics,stdlib}.md`;
  6 tests in `test_effect_scope.py` + `stdlib_d1` runtime assertions;
  case study `demos/case_studies/missing_authorization/`; playground
  example 17. Non-breaking (surveyed first: nothing in the repo used
  `sqlExec`/`authorize`/`Authorized`; no new capability).
- **Report:** `demos/case_studies/missing_authorization/REPORT.md`.
- **TYPE gaps surfaced for next iter:** (a) **cross-tenant / object-level
  authorization (IDOR, CWE-639)** — E0716 proves *an* authorization on
  the path, not that it names the SAME resource being mutated; bind the
  proof to the resource (`TenantScoped<T>` or an
  `authorize(principal, action, resourceId)` triple matched against the
  query's id) — added as taxonomy backlog B9; (b) template/SSTI = clone
  the injection slice once a template-render sink exists (B2 remainder);
  (c) secret→disk/net sinks + source-side taint (B1 remainder); (d) a
  body-carrying net sink would unlock PII network egress AND a second
  E0716 mutation sink at once.
- **Suite:** green, exit 0 (D.2 catalog: 22 codes, all documented).

---

## Iteration 8 — cross-tenant data access / IDOR (CWE-639)

- **Target:** taxonomy backlog **B9** — broken object-level
  authorization: an authenticated, action-authorized caller mutating a
  resource that belongs to ANOTHER tenant (OWASP API1, the #1 API risk;
  the Facebook "delete any photo" / Peloton account-data shapes). The
  resource-binding extension the iter-7 report surfaced.
- **Gap confirmed:** a handler calling `authorizeResource(user,
  "docs:edit", requestedId)` then mutating a DIFFERENT `victimId`
  checked clean (exit 0) before this iteration — E0716 only proves *an*
  authorization is on the path, not that it named the mutated resource.
- **Improvement (eliminates TYPE):** **E0717** (`check_resource_
  authorization`) — the resource-binding extension of E0716. New
  resource-scoped sink **`sqlByOwner(stmt, resourceId, proof)`** (effect
  `db.exec`, existing `db` capability) requires its `proof` to be an
  **`authorizeResource(principal, action, resourceId)`** call (direct,
  or a name bound exactly once to one) whose id resolves to the SAME
  identity as the sink's `resourceId`: an identical literal, or the same
  *stable* name (a param or name bound exactly once — a `_stable_names`
  helper). Mismatched id, unbound proof (a resource-less
  `authorize(...)`), rebound/computed id, or absent proof → refused
  (over-flag, never miss). `sqlByOwner`'s stmt arg also joined the
  E0713 `_SQL_SINKS` list.
- **Wiring:** folded into the `effect_scope` gate in `cli.py`;
  registries in `passes/effects.py` (`_STDLIB_EFFECTS`) +
  `passes/capability.py` (`_STDLIB_EFFECT_PATHS`); runtime
  `sqlByOwner`/`authorizeResource` (auto-exported via `_ae_` prefix);
  docs in `grammar/{diagnostics,stdlib}.md`; 8 tests in
  `test_effect_scope.py` + `stdlib_d1` runtime assertions; case study
  `demos/case_studies/idor_cross_tenant/`; playground example 18.
  Non-breaking (surveyed: nothing used `sqlByOwner`/`authorizeResource`;
  no new capability).
- **Report:** `demos/case_studies/idor_cross_tenant/REPORT.md`.
- **TYPE gaps surfaced for next iter:** (a) **id identity is syntactic**
  — E0717 relates ids only by identical literal or same never-rebound
  name; two differently-named params holding the same value, or an id
  threaded through string/arithmetic ops, are refused as unprovable.
  A light **value-equality / alias pass** would widen this from
  over-flag to precise — highest-leverage next addition, reused by
  several backlog rows; (b) template/SSTI = clone the injection slice
  once a template-render sink exists (B2 remainder); (c) secret→disk/net
  sinks + source-side taint (B1 remainder); (d) a body-carrying net sink
  would unlock PII network egress AND a second resource/mutation sink at
  once.
- **Suite:** green, exit 0.

## Iteration 9 — Open redirect (CWE-601, backlog B7)

- **Target:** login/OAuth `returnTo` used as an unconstrained redirect
  target → off-site phishing from a trusted link.
- **Gap confirmed:** no redirect sink existed; with one added, the
  dynamic-target form checked clean under `--no-scope-check` (exit 0).
- **Improvement (eliminates TYPE):** **E0718** (`check_open_redirect`) —
  a `redirect` target that is not a literal or `safeRedirect(...)` result
  is refused. New `redirect` sink (effect `net.redirect`) + `safeRedirect`
  host-pinning sanitizer (strips scheme/authority/leading-slash; defeats
  absolute + `//evil` protocol-relative). Reuses the E0711 dataflow shape.
- **Wiring:** effect + capability registries; folded into `effect_scope`
  gate; docs in diagnostics.md + stdlib.md; tests in test_effect_scope.py
  + safeRedirect `stdlib_d1` assertions; case study `open_redirect/`;
  playground example 19. Non-breaking (`net` cap known; no code calls
  redirect). Suite 24/24 green.
- **Report:** `demos/case_studies/open_redirect/REPORT.md`.
- **TYPE gaps surfaced for next iter:** (a) **template injection / SSTI**
  (CWE-1336) — a `renderTemplate(tmpl, data)` sink requiring a literal
  template, same slice; (b) **deserialization of untrusted data** (B6,
  CWE-502) — untrusted bytes into a `deserialize` sink without a
  schema-validated decoder; (c) **alias/value-equality id matching** to
  widen E0717 beyond syntactic identity (the iter-8 residual); (d)
  scoped capabilities (B8) — `capability net to "host/*"`.
- **Suite:** 24/24 green, exit 0.

---

## Iteration 10 — server-side template injection / SSTI (CWE-94)

- **Author:** main thread (Fable 5). The subagent pool hit its session
  limit mid-iteration-10; the main thread carried it.
- **Class / target:** backlog B2 remainder — template injection. The
  Jinja2/Flask `{{7*7}}`→RCE shape: untrusted input concatenated into the
  *template* string, which the engine evaluates.
- **Gap confirmed first:** `renderTemplate("Hi " + userInput, "")` passed
  `aether check` at exit 0 before this iteration.
- **New diagnostic: E0719.** `check_template_injection` in
  `passes/effects.py`, folded into `_run_effect_scope_check`
  (`--no-scope-check` opt-out). Rule: `renderTemplate`'s first (template)
  arg must be a fixed string literal or a name bound only to literals.
  **No sanitizer** — the leanest injection member; SSTI has no safe way to
  build a template from user input. Untrusted value must move to the
  second (data) arg, which the engine escapes.
- **New stdlib:** `renderTemplate(template, data)` (pure — no new effect
  or capability; `_ae_renderTemplate` substitutes the first `{}` with
  escaped data).
- **Before → after:** vulnerable.aeth exit 0 → **E0719 exit 2**; fixed.aeth
  (`renderTemplate("<h1>Hello {}</h1>", userName)`) check+run exit 0, and
  `run` prints `<h1>Hello {{7*7}}</h1>` — payload inert, never evaluated.
- **Non-breaking:** surveyed first — zero prior uses of `renderTemplate`;
  E0719 fires zero times on the existing corpus.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (+D.2 catalog now 24 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py` (4 new tests),
  `demos/case_studies/template_injection/{aether/vulnerable,aether/fixed,REPORT}.md`,
  `playground/examples/20_template_injection.aeth`, this log, taxonomy.
- **TYPE gap surfaced for next iter:** E0719 refuses templates read from
  files/DB too (correct for untrusted stores, over-strict for trusted
  bundles). A `TrustedTemplate<T>` provenance marker — the dual of the
  taint markers — would admit vetted template sources. Also still open:
  B3 (missing precondition div-by-zero/index-OOB), B5 (unbounded
  resource/DoS), B6 (deserialization), value-equality id matching (iter-8
  residual), scoped capabilities (B8).
- **Suite:** exit 0 (all gates PASS; reach-scope tests E0710..E0719).

---

## Iteration 11 — Secret exfil to disk (E0712 sink widening, CWE-532)

- **Author:** main thread (Fable 5).
- **Class / target:** the E0712 residual surfaced back in iter 3 and
  recorded in q1 — a `Secret<T>` reaching a *persistence* sink, not just a
  log sink. Picked via q3 (cheapest reuse: no new marker, no new machinery).
- **Gap confirmed first:** `writeFile("/tmp/creds", "t=" + token)` with a
  `Secret<String>` param passed `aether check` at exit 0.
- **Change (no new code E-number):** widened E0712's sink set from
  `_LOG_SINKS = ("print",)` to a sink-spec dict
  `_SECRET_SINKS = {"print": None, "writeFile": (1,)}` — mirrors E0715's
  `_PII_SINKS`. Only the `writeFile` *contents* arg (index 1) is a sink;
  the path arg is not. The marker + dataflow core was untouched.
- **Before → after:** secret→writeFile exit 0 → **E0712 exit 2**;
  secret→print still caught; `reveal(token)` into writeFile still clean.
- **Non-breaking:** message text changed ("logs"→"logs/persists") but all
  tests assert codes not messages; E0712 still fires only where a secret
  actually reaches a sink. Two new tests (disk-rejected, path-arg-clean).
- **Files:** `passes/effects.py` (sink-spec dict + loop), `grammar/diagnostics.md`
  (row + prose), `tests/test_effect_scope.py` (+2 tests), `vault` q1 +
  taxonomy (B1 remaining narrowed), this log.
- **Compounded:** appended the sink-coverage row to
  `vault/wiki/questions/q1-taint-marker-soundness-boundary.md` — sink
  coverage is a cheap per-marker list, distinct from the (harder)
  dataflow-soundness axis.
- **TYPE gap surfaced for next iter:** the two remaining B1 items —
  taint *origin* from `readFile`/network reads (not just marker-typed
  params), which needs source-marking, and network-body egress (needs a
  body-carrying net sink). Both are bigger than a sink-list edit.
- **Suite:** exit 0 (reach-scope tests E0710..E0719, all green).

---

## Iteration 12 — insecure deserialization (E0720, CWE-502)

- **Author:** main thread (Fable 5). Target picked via q3 (cheap
  sink+literal reuse; high-prevalence RCE class).
- **Class:** pickle / Java `readObject` / unsafe-YAML gadget class —
  untrusted bytes to an unrestricted decoder = RCE.
- **Gap confirmed first:** `deserialize(raw)` on a `String` param passed
  `aether check` at exit 0.
- **New diagnostic: E0720.** `check_deserialization` in
  `passes/effects.py`, folded into `_run_effect_scope_check`. SSTI-shaped:
  `deserialize` on any non-literal argument is refused; **no sanitizer** —
  the repair is a sibling function `schemaDecode(schema, data)` pinned to
  a fixed schema. New pure stdlib: `deserialize`, `schemaDecode`.
- **Before → after:** exit 0 → **E0720 exit 2**; `schemaDecode(...)`
  check+run exit 0, gadget payload rendered inert under the schema.
- **Non-breaking:** zero prior uses of `deserialize`/`schemaDecode`;
  E0720 fires 0× on the corpus. 4 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 25 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, `demos/case_studies/insecure_deserialization/`,
  `playground/examples/21_insecure_deserialization.aeth`, taxonomy (B6 done),
  q3, this log.
- **CONVERGENT SIGNAL (compounded into q3):** iters 10, 11-residual, and
  12 all surfaced the same residual — the pass over-flags a *trusted
  dynamic source* because it can't distinguish trusted-dynamic from
  untrusted-dynamic. **A taint-origin / provenance pass is now the top
  structural investment** — it closes all three residuals + relaxes E0717.
  The cheap-clone well for new classes is nearly dry (B2/B6/B7 done).
- **TYPE gap surfaced for next iter:** build the provenance pass
  (source-marking: `readFile`/network reads → tainted; a `trusted(...)`
  boundary clears). This is the mechanism three iterations have asked for.
- **Suite:** exit 0 (reach-scope tests E0710..E0720).

---

## Iteration 13 — trusted() trust boundary (closes the convergent residual)

- **Author:** main thread (Fable 5). Target = the convergent signal q3
  recorded across iters 10/11/12: passes over-flag a *trusted dynamic
  source*.
- **Decision:** a full provenance/taint-origin pass (auto-mark
  `readFile`/network reads) would ADD violations and risk breaking the
  corpus — wrong shape for a clean closing iteration. Instead shipped the
  minimal primitive that resolves the residual: an explicit `trusted(x)`
  boundary (the dual of `reveal`/`redact`).
- **Change:** new pure stdlib `trusted<T>(x) returns T` (identity at
  runtime). `_template_expr_is_safe` (E0719) and `_deser_arg_is_safe`
  (E0720) now accept a `trusted(...)` call. Narrow by design — only the
  two no-sanitizer sinks honor it.
- **Strictly non-breaking:** the change only RELAXES two checks (more
  programs pass, never fewer) — zero corpus risk by construction.
- **Before → after:** `renderTemplate(trusted(bundleTmpl), data)` and
  `deserialize(trusted(configBlob))` now pass; `renderTemplate("Hi "+u, d)`
  and `deserialize(cookie)` still E0719/E0720. Verified: in a function with
  both, only the untrusted call is flagged.
- **Files:** `runtime.py` (`_ae_trusted`), `passes/effects.py` (`_TRUSTED`
  + two predicate arms), `grammar/diagnostics.md`, `grammar/stdlib.md`
  (Trust boundary section), `tests/test_effect_scope.py` (+2 tests),
  q1 + q3 + taxonomy (residual RESOLVED), this log.
- **Honest scope note:** `trusted()` is an *assertion*, not *inference* —
  it documents trust, it does not prove it. Real source-taint (auto-mark
  untrusted reads, so the human never has to remember to NOT wrap attacker
  input) remains the open structural investment. `trusted()` misused on
  attacker input is the one failure mode, visible in review by design.
- **Suite:** exit 0 (reach-scope tests E0710..E0720).

---

## Iteration 14 — real-world validation (loop phase 2)

- **Author:** main thread (Fable 5). First **phase-2** iteration: the loop
  directive "implement Aether into programs that have a lot of users to
  find their current issues" — never exercised across iters 1–13 (all
  phase-1 detector-building).
- **What:** took the documented vulnerable *shape* of two very-high-user
  OSS projects and showed Aether refuses the composition each real
  toolchain accepted:
  - **PyYAML** `yaml.load` (~300M downloads/mo), insecure deserialization
    (CWE-502, CVE-2017-18342 precedent) → **E0720**. `bench/realworld_pyyaml/`.
  - **Flask/Jinja2** `render_template_string` (~30M/mo), SSTI (CWE-94) →
    **E0719**. `bench/realworld_flask_ssti/`.
  - Both: `<project>_repro.py` states the real call + the 1:1 Aether map;
    `vulnerable.aeth` refused, `fixed.aeth` passes + runs the payload inert.
  - Summary: `bench/REALWORLD_VALIDATION.md`.
- **Honesty (stated in the summary):** Aether checks Aether source, so
  these are faithful MODELS of the real shape, not literal transpilations
  of upstream internals, and NOT a live-repo scan producing new CVEs. The
  claim is scoped: the architecture-class maps 1:1 and the detector fires
  on the real-world shape.
- **No transpiler code changed** — validation artifacts only (bench/*.aeth,
  *.py, *.md). Suite unaffected; re-ran to confirm exit 0.
- **TYPE gap surfaced (the real phase-2 limit):** model-not-live-scan. To
  find LIVE issues in real code, need either an in-language port of a real
  module, or the source-taint provenance pass (q3 convergent signal) so a
  Python→Aether importer can auto-flag untrusted-read→sink flows. (b) is
  the standing structural investment.
- **Suite:** exit 0.

---

## Iteration 15 — real-world validation, broadened (loop phase 2)

- **Author:** main thread (Fable 5). Continued phase 2; chose breadth of
  evidence over the risky provenance pass (which mainly cuts annotation
  burden, not new bugs, and risks corpus regressions — deferred, honestly).
- **Added two more high-user classes** to `bench/REALWORLD_VALIDATION.md`:
  - **requests** `get(user_url)` (~500M/mo), SSRF (CWE-918) → **E0710**
    on the unpinned `net.fetch("*")` scope. `bench/realworld_requests_ssrf/`.
  - **subprocess** `call(..., shell=True)` (stdlib, universal), command
    injection (CWE-78, CVE-2022-1292 shape) → **E0714**.
    `bench/realworld_subprocess_cmdi/`.
  - Validation table now spans 4 projects / 4 detectors (E0710, E0714,
    E0719, E0720); each has `<project>_repro.py` with the 1:1 map,
    `vulnerable.aeth` refused, `fixed.aeth` passing + payload inert.
- **Same honesty scope as iter 14:** faithful models of the real shapes,
  not literal transpilations nor a live-repo scan.
- **No transpiler code changed** — validation artifacts only.
- **Incidental gate fix:** the D.2 catalog walk (scans `transpiler` + `bench`)
  surfaced a latent `E9999` in an untracked, agent-created harness
  `bench/aetherbench/run.py` (absent when iter 14 was green). It was a
  "CLI produced no parseable diagnostic" fallback masquerading as a
  compiler code. Fixed to a non-E sentinel `NO_DIAGNOSTIC`, consistent
  with the file's existing `WRONG_OUTPUT` marker — the E-space now again
  means "real, documented compiler diagnostic". This is the D.2 invariant
  doing its job: it caught a fabricated code before it spread.
- **TYPE gap unchanged:** the model-vs-live-scan limit persists; the
  source-taint provenance pass remains the standing structural investment
  to move from "fires on the shape" to "finds live issues in ported code".
- **Suite:** exit 0.

---

## Iteration 16 — cleartext transmission (E0721, CWE-319)

- **Author:** main thread (Fable 5). Back to phase 1 (a new TYPE) after the
  cheap-clone sink families ran dry — found an *orthogonal* cheap class
  the effect annotation already carries the signal for.
- **Class:** cleartext transmission — a `net.fetch` scope over `http://`
  ships credentials/PII unencrypted. E0710 checks host *pinning*; a pinned
  `http://` host passes E0710 yet is still cleartext. Orthogonal, uncovered.
- **Gap confirmed first:** `net.fetch("http://api.corp.example/ingest/*")`
  passed at exit 0.
- **New diagnostic: E0721.** `check_cleartext_transmission` in
  `passes/effects.py`, folded into `_run_effect_scope_check`. Reuses
  `_declared_effects` + authority parsing; flags `http://` non-loopback
  schemes. **Loopback exempt** (`localhost`/`127.0.0.0/8`/`::1`/`0.0.0.0`)
  — that traffic never leaves the host. No new stdlib (pure effect-string
  check).
- **Before → after:** exit 0 → **E0721 exit 2**; `https://` clean;
  loopback `http://127.0.0.1`/`localhost` clean.
- **Non-breaking:** the corpus's only `http://` net.fetch is
  `demos/capability-firewall` on `127.0.0.1` (loopback, exempt) —
  confirmed E0721 fires 0× there. 3 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 26 codes), `tests/test_effect_scope.py`,
  `playground/examples/22_cleartext_transmission.aeth`, taxonomy, this log.
- **Note:** first covered class that is NEITHER a sink+literal NOR a taint
  member — a pure declared-effect-string check, the cheapest shape yet.
  Suggests a small remaining vein: other properties readable straight off
  the effect annotation (e.g. a `net.fetch` to a raw IP literal, or a
  known-bad port).
- **TYPE gap surfaced:** provenance pass still the big one; smaller vein =
  effect-annotation string properties (raw-IP host, non-TLS ports).
- **Suite:** exit 0 (reach-scope tests E0710..E0721).

---

## Iteration 17 — SSRF to cloud metadata / IMDS (E0722, CWE-918)

- **Author:** main thread (Fable 5). Worked the effect-string vein E0721
  opened.
- **Class:** server-side fetch pinned to the link-local range
  169.254.0.0/16 — the cloud metadata endpoint (169.254.169.254, AWS/GCP/
  Azure IMDS), the crown-jewel SSRF target for IAM-credential theft.
- **The blind spot it closes:** E0710 refuses *unpinned* scopes; a metadata
  IP is host-*pinned*, so E0710 (and E0721, if https) pass it. E0722 refuses
  the pinned link-local reach directly.
- **Gap confirmed first:** `net.fetch("https://169.254.169.254/latest/meta-data/iam/*")`
  passed at exit 0.
- **New diagnostic: E0722.** `check_metadata_fetch` in `passes/effects.py`,
  folded into `_run_effect_scope_check`. Reuses the authority parser;
  flags host `169.254.*`. RFC-1918 private ranges deliberately NOT flagged
  (legit in service meshes) — link-local IMDS is the non-noisy high-signal
  case. No new stdlib.
- **Non-breaking:** corpus `169.254` refs are all comments / runtime
  `crawl(...)` args, never `net.fetch` effect annotations — E0722 fires 0×.
  3 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 27 codes), `tests/test_effect_scope.py`, taxonomy,
  this log.
- **Residual (honest):** IPv6 IMDS (`fd00:ec2::254`) and DNS names that
  resolve to link-local are not covered (static string check only).
- **TYPE gap surfaced:** effect-string vein has ~1-2 more (raw-IP host in
  general as a warning, non-standard ports); then it too is dry and the
  provenance pass remains the big structural investment.
- **Suite:** exit 0 (reach-scope tests E0710..E0722).

---

## Iteration 18 — phase-2 validation of E0721/E0722 (Capital One SSRF)

- **Author:** main thread (Fable 5). Chose a clean phase-2 validation over
  forcing a hardcoded-secret detector: `classify("literal")` → CWE-798
  would flag 7+ existing demos that legitimately use `classify("hunter2")`
  to illustrate secret flow — not non-breaking without heavy migration.
  Recorded that decision honestly rather than churn the corpus.
- **What:** validated the two newest detectors (E0721 cleartext, E0722
  metadata) against the **Capital One 2019 breach** (~100M records) — the
  canonical real SSRF-to-IMDS incident. `bench/realworld_metadata_ssrf/`.
  The pinned `http://169.254.169.254/...` scope fires **both** E0722
  (metadata reach) and E0721 (cleartext) on one line; the https
  non-metadata fix is clean.
- **Point made:** this is the incident that motivated E0722 — host
  *pinning* is not enough when the pinned destination is the crown jewel.
  A wildcard-only allowlist (and E0710 alone) accepts it; E0722 does not.
- **Validation table now 5 projects / 5 detectors** (E0710, E0714, E0719,
  E0720, +E0721/E0722), `bench/REALWORLD_VALIDATION.md`.
- **Same honesty scope:** faithful model, not a live-repo scan.
- **No transpiler code changed** — validation artifacts only. Suite green.
- **TYPE gap unchanged:** provenance pass still the big structural
  investment; hardcoded-secret (CWE-798) is a real open class but needs a
  credential-pattern heuristic or corpus migration to land non-breaking.
- **Suite:** exit 0.

---

## Iteration 19 — hardcoded credential in source (E0723, CWE-798)

- **Author:** main thread (Fable 5). Revisited the class deferred in iter
  18 with the fix noted there: a **credential-pattern heuristic** instead
  of flagging all `classify(literal)`.
- **Class:** hardcoded secret in source — the #1 real-world security
  finding (millions of keys leaked to public repos yearly).
- **Why it's now non-breaking:** high-confidence provider shapes only
  (AWS `AKIA…`, GitHub `ghp_…`, Google `AIza…`, Slack `xox…`, Stripe
  `sk_live_…`, PEM private key). Whole-corpus grep for these = ZERO hits,
  so the demo secrets (`hunter2`, `s3cr3t-pg-pw`, `tok_live_abc123`) all
  stay clean. Confirmed empirically before wiring.
- **New diagnostic: E0723**, and a NEW detector family — a **literal-
  content scan** (`check_hardcoded_secret` walks every StringLit and
  regex-matches), distinct from the sink+literal, taint, and effect-string
  families. Essentially a secret scanner built into the compiler.
- **Before → after:** `return "AKIAIOSFODNN7EXAMPLE"` exit 0 → **E0723
  exit 2**; `classify("hunter2")` and env-sourced `Secret` params clean.
- **Files:** `passes/effects.py` (new family + `_walk_string_lits`),
  `cli.py`, `grammar/diagnostics.md` (D.2 catalog now 28 codes),
  `tests/test_effect_scope.py` (4 tests),
  `playground/examples/23_hardcoded_secret.aeth`, taxonomy, this log.
- **Residual (honest):** pattern list, not entropy analysis — a generic
  high-entropy secret or a non-listed provider is missed. Adding an
  entropy heuristic would broaden coverage at some false-positive cost;
  deferred (the narrow list is the non-noisy choice for now).
- **Suite:** exit 0 (reach-scope tests E0710..E0723).

---

## Iteration 20 — consolidation checkpoint (composition + posture)

- **Author:** main thread (Fable 5). Milestone iteration: instead of a 15th
  narrow detector, consolidated 19 iterations into verified, coherent
  artifacts.
- **Composition verified (a real, previously-untested correctness
  property):** one kitchen-sink module with SEVEN independent violations
  (`demos/case_studies/composition_kitchen_sink/`) — `aether check` emits
  all seven (E0712/13/19/20/21/22/23) at once. New regression test
  `test_detectors_compose_additively` asserts the passes accumulate and
  none masks another.
- **Security posture summary:** `SECURITY_POSTURE.md` — the 14 classes with
  CWE + family + repair, the four reusable detector families
  (sink+literal / taint / effect-string / literal-content), the
  composition guarantee, the real-world validation pointer, and the honest
  not-covered boundary. This is the single-page artifact a reviewer or new
  contributor needs.
- **No transpiler code changed** — a demo, a composition test, a summary
  doc. Suite green.
- **Trajectory note (honest):** the cheap-clone veins across all four
  families are now largely worked out; further NEW classes increasingly
  need real machinery (provenance, entropy analysis, loop/recursion
  analysis). The loop is reaching the point where the next high-value move
  is the deferred **provenance pass**, not another narrow detector — the
  loop's own signal that phase-1 breadth is maturing.
- **Suite:** exit 0.

---

## Iteration 21 — log injection + the Untrusted<T> marker (E0724, CWE-117)

- **Author:** main thread (Fable 5). Committed to the "provenance" move
  from iter 20 — but did it the SOUND way.
- **Key decision:** provenance-by-inference (auto-taint from `readFile`/
  network reads) is risky and mostly cuts annotation burden, not bugs.
  Instead introduced `Untrusted<T>` — an EXPLICIT taint-SOURCE marker (the
  dual of Secret/PII), applied at the trust boundary. This is the sound
  provenance story: mark, don't infer. Compounded into q3.
- **New class it unlocks: log injection (CWE-117)** — an Untrusted value
  logged raw lets embedded CR/LF forge fake log lines (audit/SIEM
  poisoning). Genuinely NOT caught before (logging dynamic values is
  normal; only *untrusted* ones are dangerous — which needed the marker).
- **New diagnostic: E0724.** `check_log_injection` reuses the generalized
  taint machinery (`_marked_tainted_names`/`_expr_leaks_marked`); marker
  `Untrusted<T>`, sanitizer `sanitizeLog` (strips CR/LF), sink `print`.
  New stdlib `classifyUntrusted` + `sanitizeLog`.
- **Before → after:** `print("req: " + userInput)` with an Untrusted param
  exit 0 → **E0724 exit 2**; `sanitizeLog(userInput)` clean, and at runtime
  strips the `\n` so a forged `[ADMIN]` payload stays on one line.
- **Non-breaking:** zero prior `Untrusted`/`sanitizeLog` uses; E0724 fires
  0× on the corpus. 3 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 29 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, taxonomy, q3, this log.
- **Why this matters beyond one class:** `Untrusted<T>` is reusable — any
  future sink can require it sanitized (untrusted → path, → header, →
  redirect target). The provenance investment is now paying out
  incrementally and soundly, one sink at a time.
- **Suite:** exit 0 (reach-scope tests E0710..E0724).

---

## Iteration 22 — reflected XSS, second Untrusted<T> sink (E0725, CWE-79)

- **Author:** main thread (Fable 5). Cashed in the `Untrusted<T>` marker
  from iter 21 on the highest-value web sink.
- **Class:** reflected XSS (OWASP #2) — an untrusted value written into an
  HTML response without escaping runs `<script>` in the victim's browser.
- **New diagnostic: E0725.** `check_reflected_xss` reuses the taint
  machinery; marker `Untrusted<T>`, sink `htmlResponse`, sanitizer
  `htmlEscape`. New pure stdlib `htmlResponse` + `htmlEscape`.
- **Key soundness property established — PER-SINK sanitizers:** the E0725
  exit is `htmlEscape`, and it is sink-specific. `sanitizeLog` (which
  clears E0724 log injection) does NOT clear E0725 — stripping CR/LF does
  not neutralize HTML. Verified by test: `htmlResponse(sanitizeLog(u))` is
  still flagged E0725. The right exit for one sink is the wrong exit for
  another; the taint machinery models this correctly because the unwrap
  name is a per-check parameter.
- **Before → after:** `htmlResponse("<div>" + userInput + "</div>")` with
  an Untrusted param exit 0 → **E0725 exit 2**; `htmlEscape(userInput)`
  clean; `sanitizeLog(userInput)` still E0725.
- **Non-breaking:** zero prior `htmlResponse`/`htmlEscape` uses; 0× on
  corpus. 3 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 30 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, taxonomy, this log.
- **Pattern proven:** `Untrusted<T>` + a new (sink, sanitizer) pair = a new
  injection-into-context class, cheaply. Remaining sinks in this vein:
  HTTP header (CWE-113 response splitting), XML/LDAP contexts.
- **Suite:** exit 0 (reach-scope tests E0710..E0725).

---

## Iteration 23 — HTTP response splitting, third Untrusted<T> sink (E0726, CWE-113)

- **Author:** main thread (Fable 5). Completed the Untrusted<T> HTTP-output
  trio: log (E0724) → HTML body (E0725) → header (E0726).
- **Class:** response splitting / header injection — untrusted CR/LF in a
  response header injects headers or a second response (cache poisoning,
  forged Set-Cookie).
- **New diagnostic: E0726.** `check_header_injection`, taint machinery;
  marker `Untrusted<T>`, sink `setHeader`, sanitizer `sanitizeHeader`. New
  pure stdlib `setHeader` + `sanitizeHeader`.
- **Before → after:** `setHeader("Content-Language", userLang)` with an
  Untrusted param exit 0 → **E0726 exit 2**; `sanitizeHeader(userLang)`
  clean.
- **Non-breaking:** zero prior uses; 2 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 31 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, taxonomy, this log.
- **Vein status (honest):** the Untrusted-into-common-web-context vein is
  now well-covered (log/HTML/header). Further sinks (XML, LDAP, CSV
  formula) are real but lower-prevalence. Next iterations should pivot off
  this vein — either a different class entirely, a real-world validation
  batch of the new E0724/25/26, or consolidation — to avoid diminishing
  returns.
- **Suite:** exit 0 (reach-scope tests E0710..E0726).

---

## Iteration 24 — runtime-enforcement proof (pivot off the sink vein)

- **Author:** main thread (Fable 5). Pivoted off the Untrusted web-sink
  vein (as flagged in iter 23) to a genuinely different, high-credibility
  move.
- **What:** `tests/test_runtime_enforcement.py` — proves the static
  refusals are NOT theater. For 8 defenses it runs the FIXED Aether program
  end-to-end (parse → emit → exec) with a real attack payload and asserts
  the payload is DEFANGED in the actual output:
  - E0713 sqlBind → injection wrapped in quotes
  - E0714 shellArg → payload one quoted argument
  - E0725 htmlEscape → `<script>` becomes `&lt;script&gt;`
  - E0724 sanitizeLog → forged `\n[ADMIN]` line collapsed
  - E0726 sanitizeHeader → CR/LF stripped from header value
  - E0715 redact → PII masked to `j***@…`
  - E0720 schemaDecode → gadget payload inert under schema
  - E0711 safeJoin → `../../` stripped, path stays under base
- **Value:** closes the "is this just a static checker?" question — if any
  sanitizer regressed to a no-op, its assertion fails even though
  `aether check` still passes. Static refusal ⇔ real runtime defense, now
  a gated invariant.
- **Caught my own test bug honestly:** the safeJoin assertion was wrong
  (expected `etc/passwd` absent, but `uploads/etc/passwd` is correctly
  CONTAINED — the real property is "no `..` escapes"). Fixed the assertion
  to the actual security property, not a sloppy proxy.
- **Wired into `scripts/run_all.py`** as a gated line
  (`runtime_enforce: PASS`).
- **Files:** `tests/test_runtime_enforcement.py` (new), `scripts/run_all.py`,
  this log. No transpiler change.
- **Suite:** exit 0 (now includes the runtime-enforcement gate).

---

## Iteration 25 — false-positive gate (completes the credibility triangle)

- **Author:** main thread (Fable 5). Continued the credibility theme from
  iter 24 with its counterweight.
- **What:** `tests/test_false_positive_corpus.py` — runs all 17 reach-scope
  detectors over a corpus of LEGITIMATE programs (every `fixed.aeth` across
  bench/ + demos/, plus the clean playground examples: 01/06/07/08/09) and
  asserts ZERO diagnostics. 31 programs, 0 false positives.
- **Why it matters:** a security checker that over-flags gets turned off.
  This is the counterweight to the positive tests. The three suites now
  form the **credibility triangle**:
    - catches bad  (test_effect_scope, catch rate)
    - passes good  (this, false-positive rate 0)
    - not theater  (test_runtime_enforcement, fixes defang at runtime)
- **Wired into `scripts/run_all.py`** as a gated line
  (`false_positive: PASS (31 clean programs, 0 diagnostics)`). If any
  detector regresses to over-flagging a legitimate fixed form, this goes
  red.
- **SECURITY_POSTURE.md** updated with the credibility-triangle table.
- **Files:** `tests/test_false_positive_corpus.py` (new),
  `scripts/run_all.py`, `SECURITY_POSTURE.md`, this log. No transpiler
  change.
- **Note:** the corpus auto-grows — every future `fixed.aeth` a case study
  adds is automatically a false-positive assertion. The gate strengthens
  itself as the loop runs.
- **Suite:** exit 0 (now includes the false-positive gate).

---

## Iteration 26 — XML external entity / XXE (E0727, CWE-611)

- **Author:** main thread (Fable 5). A genuinely distinct class off the
  Untrusted web-sink vein — a parser-CONFIG issue like deserialization.
- **Class:** XXE — an entity-resolving XML parser on untrusted input reads
  local files (`file:///etc/passwd`), reaches internal URLs (SSRF), or
  billion-laughs DoS. OWASP-listed.
- **New diagnostic: E0727.** `check_xxe` mirrors E0720 (deserialization):
  `parseXml` on a non-literal argument is refused; `parseXmlSafe` (external
  entities disabled) is the sanctioned alternative. Reused
  `_deser_arg_is_safe` + `_safe_template_names` verbatim. New pure stdlib
  `parseXml` + `parseXmlSafe`.
- **Before → after:** `parseXml(raw)` exit 0 → **E0727 exit 2**;
  `parseXmlSafe(raw)` clean; the `<!ENTITY SYSTEM ...>` payload runs inert.
- **Non-breaking:** zero prior uses; 2 new tests. Auto-covered by the new
  false-positive gate (any parseXmlSafe fixed form stays clean).
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 32 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, taxonomy, this log.
- **Family note:** the "dangerous sink + safe sibling function" shape
  (deserialize/schemaDecode, parseXml/parseXmlSafe) is distinct from both
  sink+sanitizer and Untrusted-marker — it's for parser/decoder CONFIG,
  where the safe form is a different constructor, not an escaped argument.
- **Suite:** exit 0 (reach-scope tests E0710..E0727).

---

## Iteration 27 — phase-2 validation of E0725/E0727 (Express XSS, lxml XXE)

- **Author:** main thread (Fable 5). Phase-2: validated the newest
  detectors against real high-user libraries.
- **Added two cases** to `bench/REALWORLD_VALIDATION.md`:
  - **Express** `res.send(reflected)` (~30M downloads/wk), reflected XSS
    (CWE-79, OWASP #2) → **E0725**. `bench/realworld_xss/` (+ `escapeHtml`
    fix; payload rendered `&lt;script&gt;` inert at runtime).
  - **lxml** `fromstring(resolve_entities=True)` (~50M/mo), XXE (CWE-611)
    → **E0727**. `bench/realworld_xxe/` (+ `parseXmlSafe` fix).
  - Each has `<lib>_repro.{js,py}` with the real call + 1:1 map,
    `vulnerable.aeth` refused, `fixed.aeth` passing.
- **Validation table now 7 projects / 7 detectors** (E0710, E0714, E0719,
  E0720, E0721/22, E0725, E0727).
- **Same honesty scope:** faithful models, not live-repo scans.
- **The new fixed.aeth files auto-join the false-positive gate** (iter 25):
  confirmed both stay clean there too.
- **No transpiler code changed** — validation artifacts only. Suite green.
- **Suite:** exit 0.

---

## Iteration 28 — CSV / formula injection (E0728, CWE-1236)

- **Author:** main thread (Fable 5). Extended `Untrusted<T>` to its first
  NON-HTTP context — proving the marker generalizes past web output.
- **Class:** spreadsheet formula injection — exported data whose cell
  begins with `= + - @` becomes a formula in Excel/Sheets (`=WEBSERVICE`
  exfil, DDE → RCE).
- **New diagnostic: E0728.** `check_csv_injection`, taint machinery; marker
  `Untrusted<T>`, sink `csvCell`, sanitizer `csvEscape` (prefixes a quote).
  New pure stdlib `csvCell` + `csvEscape`.
- **Before → after:** `csvCell(cell)` with an Untrusted param exit 0 →
  **E0728 exit 2**; `csvEscape(cell)` clean; runtime prefixes `'` so
  `=WEBSERVICE(...)` is inert text.
- **Also added to the runtime-enforcement gate** (now 9 defenses): proves
  csvEscape disarms a real `=WEBSERVICE` payload end-to-end.
- **Non-breaking:** zero prior uses; 2 detector tests + 1 runtime test.
- **Files:** `passes/effects.py`, `cli.py`, `runtime.py`,
  `grammar/diagnostics.md` (D.2 catalog now 33 codes), `grammar/stdlib.md`,
  `tests/test_effect_scope.py`, `tests/test_runtime_enforcement.py`,
  taxonomy, this log.
- **Marker generality proven:** `Untrusted<T>` now spans log, HTML, header,
  and CSV/spreadsheet contexts — 4 sinks, one trust-boundary primitive.
- **Suite:** exit 0 (reach-scope tests E0710..E0728).

---

## Iteration 29 — static match exhaustiveness (E0202) — a NON-security pivot

- **Author:** main thread (Fable 5). Deliberate pivot: 19 security detectors
  is thorough; more risks padding. Returned to Aether's ORIGINAL pitch —
  architectural integrity — with the first non-security detector.
- **Class:** non-exhaustive match (unhandled union variant). The classic
  Rust/Swift compile-time guarantee.
- **Gap confirmed first:** a match missing a case passed `check` at exit 0
  and only failed at RUNTIME (`RuntimeError: non-exhaustive match`). E0202
  lifts it to a STATIC refusal — the compiler-refuses-incomplete-
  composition promise applied to control flow.
- **New diagnostic: E0202** (type-check range, `check_exhaustiveness`).
  When the scrutinee's union type is resolvable (from a param or `let`
  annotation), every union case must be handled or a wildcard present.
  Default-on; opt out `--no-exhaustiveness-check`.
- **Conservative / non-breaking:** silent when the scrutinee type is
  unresolvable (no false positives). Scanned EVERY `.aeth` in the repo:
  **0 files flagged** — all existing matches are exhaustive, wildcarded, or
  unresolvable. Then adding a new variant to a union breaks stale matches
  at compile time — the whole point.
- **Value beyond security:** demonstrates Aether's core thesis isn't just a
  security-linter bolt-on — the same "refuse the unsound composition"
  machinery catches ordinary correctness bugs (a forgotten enum case is the
  most common real one). Broadens the story from "security tool" to
  "architectural-integrity compiler".
- **Files:** `passes/effects.py` (check + union/type/pattern helpers),
  `cli.py` (default-on step + flag), `grammar/diagnostics.md` (D.2 catalog
  now 34 codes), `tests/test_exhaustiveness.py` (new, 4 tests, gated),
  taxonomy (new non-security section), this log.
- **TYPE gap surfaced:** more non-security architectural classes now open —
  unhandled `Result`/`Option` (silent error swallowing), unreachable
  arms, dead code after a total match. The non-security vein is fresh.
- **Suite:** exit 0 (+ exhaustiveness gate).

---

## Iteration 30 — unreachable match arm (E0203), complement of E0202

- **Author:** main thread (Fable 5). Continued the non-security vein;
  paired with iter 29.
- **Class:** unreachable/dead match arm (CWE-561) — an arm after a wildcard
  catch-all, or a duplicate constructor case. E0202 = too few arms; E0203 =
  too many. Together match handling is total-and-minimal.
- **Gap confirmed first:** an arm after `case _` (and a duplicate case)
  passed `check` at exit 0.
- **New diagnostic: E0203** (`check_unreachable_arms`). Pure arm-ordering —
  no scrutinee type needed, so it applies to EVERY match. Folded into the
  same default-on step as E0202 (`--no-exhaustiveness-check`).
- **Non-breaking:** scanned every `.aeth` in the repo — 0 files flagged.
  3 new tests (after-wildcard, duplicate, trailing-wildcard-clean).
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 35 codes), `tests/test_exhaustiveness.py`, taxonomy,
  this log.
- **Milestone (30 iterations):** 19 security detectors (E0710–E0728) + 2
  architectural (E0202/E0203), across 4 detector families + a static
  type-completeness pair, all gated by the credibility triangle
  (catch/pass/defend) + composition + a 33-program false-positive corpus.
  D.2 catalog: 35 documented codes.
- **TYPE gap surfaced:** the non-security vein continues — dead code after
  `return`/`break` in a block (CWE-561 sibling), and `let`-bound values
  never used (dead binding). Both need block-flow walks, not the match
  helpers — slightly more machinery.
- **Suite:** exit 0.

---

## Iteration 31 — dead code after terminator (E0204, CWE-561)

- **Author:** main thread (Fable 5). Third architectural detector,
  generalizing reachability beyond match.
- **Class:** a statement after an unconditional `return`/`break`/`continue`
  in the same block — always a logic error.
- **Gap confirmed first:** `return x` followed by another statement passed
  `check` at exit 0.
- **New diagnostic: E0204** (`check_dead_code`). Purely structural — scans
  every statement list for a terminator that is not last (`_stmt_lists`
  identifies statement blocks by "every element is a kind-bearing dict").
  Folded into the same static-semantic step as E0202/E0203.
- **Non-breaking:** full-repo `.aeth` scan — 0 files flagged. 2 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 36 codes), `tests/test_exhaustiveness.py`, taxonomy,
  `scripts/run_all.py` (gate line renamed static_semantic), this log.
- **Architectural cluster now:** E0202 (exhaustive) + E0203 (no dead arm) +
  E0204 (no dead statement) = a small static reachability/completeness
  suite, the non-security half of the "refuse unsound compositions" thesis.
- **TYPE gap surfaced:** unused `let` binding (dead store), and a pure
  function whose result is ignored at the call site — both need a
  use/def walk (a bit more machinery than the structural scans).
- **Suite:** exit 0.

---

## Iteration 32 — unused let binding / dead store (E0205, CWE-563)

- **Author:** main thread (Fable 5). Fourth architectural detector,
  completing the static-semantic cluster with a use/def check.
- **Class:** a `let x = ...` whose `x` is never read — a dead store,
  usually a mistaken variable downstream.
- **New diagnostic: E0205** (`check_unused_binding`). Collects Ident reads
  across the function body; a bound name absent from that set is unused.
  The `_`-prefix (`let _r = writeFile(...)`) is the sanctioned
  intentional-discard convention and is exempt.
- **REAL FINDING on first run:** the corpus scan flagged exactly one file —
  `bench/aetherbench/results/cand/t4_02_shellarg__nl__a0.aeth`, an
  agent-GENERATED candidate that binds `let output = shellExec(...)` and
  never reads it. A genuine dead store the detector caught on code it had
  never seen. Not gated (untracked generated candidate), so suite stays
  green — but a concrete demonstration that E0205 finds real bugs, not just
  its own test fixtures.
- **Non-breaking:** the only corpus hit is that genuine finding; every
  hand-authored reference/demo/fixed form is clean (all reads or `_`).
  3 new tests.
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 37 codes), `tests/test_exhaustiveness.py`, taxonomy,
  `scripts/run_all.py`, this log.
- **Static-semantic cluster complete (E0202–E0205):** exhaustive match, no
  dead arm, no dead statement, no dead store — a coherent "no dead or
  incomplete code" suite, the non-security half of the thesis.
- **Suite:** exit 0.

---

## Iteration 33 — scan real AI-generated code (loop phase 2, authentic)

- **Author:** main thread (Fable 5). Phase-2 done on REAL code, not modeled
  CVEs: ran the full check pipeline over all 176 AI-generated `.aeth` files
  under `bench/aetherbench/`. Report: `bench/SCAN_FINDINGS.md`.
- **Three honest buckets:**
  1. **Independent security-fixture validation — 10/10 exact.** The
     aetherbench agent's own `tasks/t4_*/vulnerable.aeth` fixtures (NOT this
     project's case studies) each fire the exactly-correct expected code
     (sqlbind→E0713, shellarg→E0714, safejoin→E0711, ssrf→E0710,
     secret→E0712, pii→E0715, authz→E0716, idor→E0717, redirect→E0718,
     template→E0719). Task name ↔ code match 10/10 on an outside corpus.
  2. **A genuine finding — 1.** `cand/t4_02_shellarg__nl__a0.aeth` — a real
     E0205 dead store in a model candidate (confirmed iter 32).
  3. **Generation failures — E0201.** e.g. a candidate wrote `var result`,
     colliding with the reserved contract keyword; parser correctly refuses.
     Bucketed separately (generation-quality signal, not arch findings).
- **Honesty (in the report):** this is a spot-check on real generated code,
  NOT a controlled catch-rate study — the candidate set is small/skewed and
  the fixtures intentional. The statistical version is the RW_MINING /
  design-partner runbook's job.
- **Value:** first evidence of the detectors firing on an EXTERNALLY-
  authored corpus (stronger than self-authored tests) + a real find in
  unseen generated code. No transpiler change; evidence artifact only.
- **Suite:** exit 0 (unchanged).

---

## Iteration 34 — ignored Result / unchecked error (E0206, CWE-252)

- **Author:** main thread (Fable 5). Fifth architectural detector; the
  error-handling member of the static-semantic cluster.
- **Class:** a bare statement calling a `Result`-returning function drops
  the error case — the "forgot to check the write" bug.
- **New diagnostic: E0206** (`check_ignored_result`). Flags an `ExprStmt`
  whose call targets a Result-returning function (stdlib writeFile/readFile/
  readLine/parseInt/parseFloat, or any user `returns Result<...>`). Fix:
  bind+match, or `let _r = ...` explicit discard.
- **Non-breaking on the gate, 12 REAL FINDINGS off it:** the hand-authored
  corpus uses `let _r = writeFile(...)` (0 gated flags), but the scan of
  AI-generated aetherbench candidates found **12** bare `writeFile`
  statements silently dropping the Result — genuine CWE-252 bugs in unseen
  generated code. Updated `bench/SCAN_FINDINGS.md` (now 13 real findings:
  1 dead store + 12 unchecked errors).
- **Files:** `passes/effects.py`, `cli.py`, `grammar/diagnostics.md`
  (D.2 catalog now 38 codes), `tests/test_exhaustiveness.py`, taxonomy,
  `bench/SCAN_FINDINGS.md`, `scripts/run_all.py`, this log.
- **Pattern confirmed twice (E0205, E0206):** the architectural detectors
  are non-breaking on curated code yet find real bugs in AI-generated code
  — exactly the target-audience value proposition, demonstrated not
  claimed.
- **Static-semantic cluster now E0202–E0206** (6 checks): match
  completeness, reachability, dead store, unchecked error.
- **Suite:** exit 0.

---

## Iteration 35 — the corpus scanner (product shape of phase 2)

- **Author:** main thread (Fable 5). Turned iter-33's throwaway bash loop
  into `tools/scan.py` — the actual product: point Aether at a directory of
  AI-generated code, get a findings report.
- **What it is:** a standalone scanner running the full default-on suite
  (base effect/capability passes + 19 security detectors E0710-E0728 + 5
  static-semantic checks E0202-E0206) over every `.aeth` in a dir. Buckets
  parse errors (generation failures) separately from architectural/security
  findings. Text or `--json`. Exit 0 clean / 1 findings / 2 usage.
- **Verified behavior:** `python -m tools.scan reference` → exit 0, 0
  findings (clean curated corpus); `python -m tools.scan bench/aetherbench`
  → 23 files with findings + 6 parse errors (reproduces the iter-33/34
  results deterministically, structured).
- **Why it matters:** this is the phase-2 story made concrete and
  repeatable — Aether as a scanner for AI-generated code, not a set of
  hand-run checks. The 13 real findings (E0205×1, E0206×12) come out of one
  command now.
- **Gated:** `tests/test_scan.py` (clean→0, vulnerable→E0713, fixed→0)
  wired into `scripts/run_all.py` (`scan_tool: PASS`).
- **Files:** `tools/scan.py` (new), `tests/test_scan.py` (new),
  `scripts/run_all.py`, `bench/SCAN_FINDINGS.md`, this log. No transpiler
  change — a new consumer of the existing passes.
- **Suite:** exit 0.

---

## Iteration 36 — SARIF output (Aether as a CI gate)

- **Author:** main thread (Fable 5). Product-integration move: made the
  scanner's findings consumable by the ecosystem.
- **What:** `tools/scan.py --sarif` emits SARIF v2.1.0 — the standard
  static-analysis format GitHub Code Scanning, VS Code, and most CI
  security dashboards ingest. Each finding → a SARIF result with ruleId
  (Exxxx), file uri, and startLine; the detector set → the tool's rule
  list.
- **Why it matters:** this is the concrete path for "implement Aether into
  programs" — drop `python -m tools.scan <dir> --sarif` in CI, findings
  surface as code-scanning alerts, exit 1 fails the build. Aether stops
  being a local checker and becomes a pipeline gate on AI-generated code.
- **Verified:** SARIF for the SQLi demo is well-formed — tool.driver.name
  `aether-scan`, rule `E0713`, result with correct uri + line. Gated by a
  new `test_scan.py` case.
- **Files:** `tools/scan.py` (+`to_sarif`, `--sarif`), `tests/test_scan.py`
  (+1 test), `bench/SCAN_FINDINGS.md`, this log. No transpiler change.
- **Product arc (iters 33→36):** throwaway scan → reusable scanner →
  CI-ready SARIF. The phase-2 story is now a deployable tool, not a demo.
- **Suite:** exit 0.

---

## Iteration 37 — unsatisfiable refinement / impossible type (E0207)

- **Author:** main thread (Fable 5). A genuinely NOVEL architectural check
  (not a clone) — the compiler refusing an uninhabitable type.
- **Class:** a refinement `T where P` no value can satisfy (e.g.
  `Int where self >= 10 and self <= 5`) — always a bounds typo; every
  parameter of the type is impossible.
- **Gap confirmed first:** the contradictory type checked clean at exit 0.
- **New diagnostic: E0207** (`check_unsatisfiable_refinement`). Light,
  SOUND interval analysis: intersect the analyzable `self OP const` clauses
  of the predicate's conjunction; flag only a provably-empty interval
  (reversed bounds, contradictory `==`, exclusive-touch). Unanalyzable
  clauses (`self % 2 == 0`, `or`) widen to unbounded, so it NEVER
  false-positives — verified by a test.
- **Non-breaking:** full-repo scan — 0 files flagged (every real refinement
  is satisfiable). 4 new tests.
- **First refinement-level static check:** the base refinement guarantee is
  a RUNTIME boundary check (q2); E0207 adds a small STATIC layer catching
  the impossible-bounds subclass at compile time — a step toward the SMT
  story without the SMT dependency.
- **Files:** `passes/effects.py` (check + `_clause_bound`/`_refine_interval`/
  `_interval_empty`), `cli.py`, `grammar/diagnostics.md` (D.2 catalog now
  39 codes), `tests/test_exhaustiveness.py`, taxonomy, `scripts/run_all.py`,
  this log.
- **Static-semantic cluster now E0202–E0207** (7 checks): match, reach,
  dead store, error, and impossible type.
- **Suite:** exit 0.

---

## Iteration 38 — turnkey CI deployment (GitHub Action + SARIF upload)

- **Author:** main thread (Fable 5). Completed the deployment story — the
  literal "implement Aether into programs" directive, made drop-in.
- **What:** `.github/workflows/aether-scan.yml` — a ready-to-use GitHub
  Action that (1) checks out, (2) sets up Python (no installs — Aether is
  stdlib-only), (3) runs `python -m tools.scan <path> --sarif`, (4) uploads
  the SARIF to Code Scanning via `github/codeql-action/upload-sarif`, (5)
  fails the build if any finding. Plus `docs/SCANNING.md` — the local + CI
  quickstart.
- **Correctness care:** GitHub bash runs with `-e`, so the scanner's exit-1
  (findings present) would abort the step before the SARIF uploads. Guarded
  with `set +e`/capture/`set -e` so SARIF ALWAYS uploads and the failure is
  a separate, explicit step. Verified the exact CI command locally:
  `python -m tools.scan demos --sarif` → valid SARIF (16 rules, 70 results),
  exit 1.
- **Why it matters:** Aether is now genuinely deployable as a PR gate on
  AI-generated `.aeth` — findings surface inline on the diff like CodeQL.
  The product arc iters 33→38: throwaway scan → scanner → SARIF → CI action
  + docs. Nothing left between "AI writes Aether" and "CI blocks the unsafe
  composition".
- **Honest scope (in SCANNING.md):** Aether checks Aether source; scanning
  other-language code needs it ported first. The scanner's value today is
  on `.aeth` corpora.
- **Files:** `.github/workflows/aether-scan.yml` (new), `docs/SCANNING.md`
  (new), this log. No transpiler change.
- **Suite:** exit 0 (unchanged).

---

## Iteration 39 — marker flow across function boundaries (return-type seeding + E0729)

- **Author:** main thread (Fable 5). The q1 "highest-leverage soundness
  upgrade" (interprocedural flow), shipped the SIGNATURE-LEVEL way — no
  whole-program dataflow, declared types are the trust boundary.
- **Class:** marker laundering / taint erasure at internal boundaries.
  Two dual gaps: (A) a call returning a declared `Secret<...>`/`PII<...>`/
  `Untrusted<...>` seeded NO taint (`let t = getToken(); print(t)` — exit
  0); (B) a marked value passed to a helper's plain-typed param erased the
  marker (`logIt(password)` with `logIt(msg: String)` — exit 0). Both
  confirmed empirically before any code.
- **Gap A fix — return-type seeding:** `_marker_source_fns` (stdlib
  constructors `classify`/`classifyPII`/`classifyUntrusted` + user
  `returns <Marker><...>` decls) feeds the shared taint fixpoint of
  E0712/E0715/E0724/E0725/E0726/E0728. Inline source calls
  (`print(classify("pw"))`) flag too.
- **Gap B fix — new diagnostic E0729** (`check_marker_boundary`): a
  Secret/PII/Untrusted value into a user-declared callee param NOT typed
  with the marker is refused as laundering. Sanctioned exits: the
  marker's unwrappers (`reveal`/`redact`/per-sink sanitizers/`trusted`)
  or a marker-typed param. `Authorized<T>` deliberately excluded (proof
  marker — a widening rule there would RELAX acceptance).
- **Non-breaking, with one real interaction found and fixed properly:**
  `bench/realworld_xss/fixed.aeth` (`print(search(classifyUntrusted(x)))`)
  initially fired E0724 — the source call is CONSUMED by `search`'s
  `Untrusted`-typed param. Fixed by sanctioned-crossing pruning
  (`_marker_param_mask`): an arg feeding a marker-typed param of a
  user-declared callee is the callee's responsibility; what escapes is
  its return, covered by seeding. Corpus back to 0× (33 programs clean),
  never silenced.
- **Ratchet raised same commit:** 38→39 codes, 28→29 detectors (6aff558).
- **Files:** `passes/effects.py` (`_STDLIB_MARKER_CONSTRUCTORS`,
  `_marker_source_fns`, `_marker_param_mask`, widened `_expr_leaks_marked`/
  `_marked_tainted_names`, `check_marker_boundary`), `cli.py`,
  `grammar/diagnostics.md` (row + seeding prose), `tests/test_effect_scope.py`
  (13 tests), `tests/ratchet_baseline.json`, `playground/examples/24_*.aeth`,
  `demos/case_studies/marker_laundering/`, q1 + taxonomy updated.
- **TYPE gap surfaced for next iter:** body-level return laundering — a
  function whose body RETURNS a tainted local under a plain declared
  return type still washes the marker (declared signatures are the trust
  boundary; no body inference). Sibling residuals: stdlib transforms
  (`trim(secret)` → plain String) outside E0729 v1 scope; HOF /
  function-typed callees skipped. All three pushed to q1.
- **Suite:** exit 0 (ratchet green at floor = current 39/29).

---

## Iteration 40 — return laundering: the lying signature (E0730)

- **Author:** main thread (Fable 5). Iteration 39's surfaced residual,
  closed the same day — the q3 cheap-win profile: near-zero new
  machinery (one `_walk_returns` walker + the iter-39 helpers reused
  verbatim).
- **Class:** a function whose BODY returns a `Secret<...>`/`PII<...>`/
  `Untrusted<...>`-carrying value while its DECLARED return type is
  plain — the signature lies, the marker is washed off for every
  caller. Return-direction dual of E0729.
- **Gap confirmed first:** `function leak(pw: Secret<String>) returns
  String do return pw end` + `print(leak(password))` → exit 0 on the
  pre-iteration build (`gap_c_return_launder.aeth`).
- **New diagnostic: E0730** (`check_return_laundering`): per marker,
  skip functions with an honest marker-typed `return_type` (callers
  taint via seeding); otherwise flag any `Return` whose value leaks the
  marker. Sanctioned exits: declare the marker-typed return, or unwrap
  (`reveal`/`redact`/sanitizers/`trusted`) at the return site.
  `Authorized<T>` excluded (proof marker — plain-typed return only
  over-restricts).
- **The signature loop is now closed:** seeding (returns IN), E0729
  (params IN), E0730 (returns OUT) — declared signatures are ENFORCED
  in both directions, no longer merely trusted. "Signature-level
  interprocedural" is now a checked contract, not an assumption.
- **Non-breaking:** alsp corpus has zero marker files; false_positive
  gate (fixed.aeth + clean examples) green. One known TRUE positive on
  the ungated evidence corpus: `bench/realworld_xss/vulnerable.aeth`
  now fires E0730 alongside E0725 (header comment updated, nothing
  suppressed).
- **Ratchet raised same commit:** 39→40 codes, 29→30 detectors (8bb33db).
- **Files:** `passes/effects.py` (`_walk_returns`,
  `check_return_laundering`), `cli.py`, `grammar/diagnostics.md` (row +
  prose), `tests/test_effect_scope.py` (7 tests),
  `tests/ratchet_baseline.json`, `playground/examples/25_*.aeth`,
  `demos/case_studies/return_laundering/`, q1 + taxonomy updated.
- **TYPE gap surfaced for next iter:** stdlib transform propagation —
  `trim(secret)` / `padLeft(secret, …)` return plain values from stdlib
  signatures the marker model doesn't cover: the last laundering channel
  inside the modeled surface. Needs a stdlib marker-propagation table
  (input-marker → output-marker per stdlib fn). Sibling residual:
  boundary-sanitizer coarseness (any per-sink sanitizer clears the
  generic boundary — a `sanitizeLog`'d value returned as String could
  still XSS at an HTML sink). Both pushed to q1.
- **Suite:** exit 0 (ratchet green at floor = current 40/30).

---

## Iteration 41 — match-destructure taint (a false accept, found and fixed)

- **Author:** main thread (Fable 5). Probe-first iteration with TWO
  outcomes: a residual proven phantom, and a real MISS found and fixed
  the same session.
- **Phantom residual (correction).** Iter-40 surfaced "stdlib transform
  propagation" (`trim(secret)` washes the marker) as the next TYPE gap.
  The method's step-2 probe DISPROVED it: `print(trim(pw))` and
  `let t = trim(pw); print(t)` both already fire E0712 — the leak
  walk's generic recursion into unmodeled calls over-flags stdlib
  transforms at sinks, bindings, and returns. No-op iteration avoided.
  **Lesson (pushed to q1): residuals must be probe-confirmed before
  entering the backlog, exactly like gaps.**
- **The real gap (found in the same probe session):** `case Some(v) do
  print(v) end` over `Option<Secret<String>>` checked CLEAN (exit 0) —
  a FALSE ACCEPT, the one failure the over-flag-never-miss contract
  forbids; strictly worse than a missing detector. Root cause: the
  shared fixpoint collected only Let/Assign bindings; match-pattern
  `BindPat` names were fresh untainted names.
- **Fix:** destructure propagation in `_marked_tainted_names` — every
  arm-pattern binding over a leaking scrutinee is tainted (all arms,
  every binding, conservative). One edit widens all eight
  confidentiality passes (E0712/E0715/E0724/E0725/E0726/E0728/E0729/
  E0730). `Authorized` (E0716/E0717) uses the separate
  `_authorized_names` machinery — untouched, no silent proof
  relaxation.
- **BUGS.md BUG-001** recorded `[FIXED 8d928d9]` with a `test:` line —
  the ratchet's fixed-bugs layer now holds it (gate prints "1 FIXED
  bug(s), all with a live regression test").
- **No new diagnostic code** → floors unchanged (40 codes / 30
  detectors, still met). 5 new tests; playground example 26.
- **Files:** `passes/effects.py` (`_pattern_bind_names`, widened
  fixpoint), `tests/test_effect_scope.py`, `BUGS.md`,
  `grammar/diagnostics.md` (prose), `playground/examples/26_*.aeth`,
  q1 + this log.
- **TYPE gap surfaced for next iter:** E0717 value-equality / alias
  reasoning for resource ids (the last big q1 item — currently
  over-flag-only: `let id2 = id1` is refused; a *precision* target, not
  a miss). Miss-side remaining surface: HOF / function-typed callees
  (E0729 skips them). Probe BOTH before picking.
- **Suite:** exit 0.

---

## Iteration 42 — function-alias laundering (two false accepts closed)

- **Author:** main thread (Fable 5). Probe-first, per the iter-41 lesson.
  THREE probes run before any code:
  1. **Gap E** — `let f = logIt; f(password)`: E0729's callee lookup is
     by declared name, "f" resolves to nothing → exit 0, MISS.
  2. **Gap E2** — `let f = getToken; let t = f(); print(t)`: the source
     set is keyed by declared names → exit 0, MISS.
  3. **E0717 copy-alias** — `let id2 = docId` + proof on `docId` →
     E0717 FIRES (over-flag confirmed): a PRECISION target, recorded,
     deferred behind the misses (repro `probe_e0717_alias.aeth`).
- **Grammar finding (re-frames iter-41's residual):** `grammar.ebnf`
  has NO function types — "HOF / function-typed callees" was
  mis-framed; the only expressible indirect-call surface is a function
  ALIAS (`let f = fnName`), and E0716 already refuses gated-fn escape
  for Authorized. This iteration closes the alias surface for the
  confidentiality markers; nothing HOF-shaped remains expressible.
- **Fix:** per-function alias map `_fn_aliases` (straight-line bare-
  Ident bindings, chains via fixpoint, conservative UNION on
  rebinding), applied FLAG-MORE only: aliases resolving to a source fn
  join the local source set; single-target aliases extend the
  sanctioned-crossing mask (`_aliased_mask` — ambiguity must
  over-flag); E0729 checks EVERY function an alias may name. An aliased
  unwrapper (`let r = reveal`) is deliberately NOT honored — sanctioned
  exits are recognized by name at the call site (the audit contract);
  the over-flag is documented and pinned by a test.
- **BUGS.md BUG-002** `[FIXED f6b8bf3]` with `test:` line — gate prints
  "2 FIXED bug(s), all with a live regression test".
- **No new diagnostic code** → floors unchanged (40/30). 6 new tests;
  playground example 27.
- **Files:** `passes/effects.py` (`_fn_aliases`, `_aliased_mask`,
  per-decl locals in 8 passes, E0729 multi-target callee resolution),
  `tests/test_effect_scope.py`, `BUGS.md`, `grammar/diagnostics.md`
  (prose), `playground/examples/27_*.aeth`, q1 + this log.
- **TYPE gap surfaced for next iter:** E0717 value-equality / copy-alias
  precision — probe-confirmed TODAY (over-flag on `let id2 = id1`); the
  fix is copy-tracking for resource ids, a RELAX-direction change that
  must keep the entire E0716/E0717 test wall green and the IDOR case
  study refusing. Sibling: boundary-sanitizer coarseness (probe for a
  MISS first; if none, it is doctrine, not backlog).
- **Suite:** exit 0.

---

## Infra — monotonic ratchet (Aether may only improve)

- **Author:** main thread (Fable 5), at the human's request: guarantee the
  self-teaching agent can only move Aether FORWARD.
- **Mechanism: `tests/test_ratchet.py`** (wired into the gate, `ratchet:
  PASS`), backed by `tests/ratchet_baseline.json`:
  1. **Detector floor.** Counts distinct emitted `Exxxx` codes (38) and
     gated `check_*(ast)` passes (28); asserts current ≥ the committed
     floor. Removing a detector — even deleting its code+doc+test together
     so the rest of the suite stays green — drops the count below the floor
     and turns the gate RED. Proven: floor 39 vs current 38 → exit 1.
  2. **Gain-lock reminder.** When current > floor, the test prints the
     exact numbers to raise the baseline to, so each addition is locked
     permanently. Proven: floor 37 → "raise to 38" note.
  3. **Fixed bugs stay fixed.** Every real `[FIXED <commit>]` entry in
     BUGS.md must name an existing `test:` regression file, so a repaired
     bug can't silently reappear.
- **Contract updated:** `tools/self_teaching_agent.md` §4 and `CLAUDE.md`
  step 6 now state the one-directional rule — never remove/weaken a
  detector, never lower the baseline, raise it when you add, add a `test:`
  line when you fix a BUGS.md entry.
- **Legitimacy guard (added same session).** A raised count must be a REAL
  detector, not a bumped number: every protected detector code (E07xx +
  E02xx≠E0201) must be actually emitted by a pass AND asserted by a test
  that proves it fires. Proven: a documented-but-dead `**E0799**` doc row
  with no pass → gate RED ("not emitted by any transpiler pass").
- **Git-monotonicity guard (added same session).** Closes the one edit the
  count-floor couldn't self-catch — lowering a baseline number. The
  working-tree baseline is compared against `git show HEAD:...`; any
  decrease is RED before it can be committed. Proven via a mocked
  higher committed floor → "baseline was LOWERED ... may only be raised".
- **Ratchet now has 4 layers:** count floor · legitimacy · git
  monotonicity · fixed-bugs-stay-fixed. Aether can only move forward, and
  every forward step is a verified, tested detector.
- **Suite:** exit 0 (with the ratchet gate green at floor = current).

---

## Iteration 43 — the detectors run on unmodified Python

- **Target:** the adoption objection, not an analysis-depth one. Aether's
  detectors only ever ran on `.aeth`, so using them meant rewriting your
  code in a language with no ecosystem. `tools/py_frontend.py` already
  translated Python into the same IR for the CAPABILITY experiment.
- **Gap confirmed empirically:** `py_to_ir` emitted `body=[]` — the
  function body was discarded, and the local-call stubs it did emit
  carried `args: []`. Driven through the full 30-detector registry on
  `f98fdce`, a file with five textbook vulnerabilities (SQLi via concat,
  `shell=True` concat, `open(base+entry)`, `pickle.loads`, `os.system`
  concat) produced **3 diagnostics, all E0701 capability facts, and zero
  security findings** — what `grep -r "import subprocess"` also gives you.
- **Improvement:** no new detector, no new code. An expression translator
  (`_expr`) producing exactly the node kinds `_arg_reason` judges, and an
  auditable Python→Aether sink mapping. f-strings — the dominant modern
  injection shape, which Aether has no construct for — become `BinOp "+"`
  trees, so the existing `rule.concat` reason reports them unchanged.
  Unmodeled expressions become `PyExpr`, a kind no rule knows: refused,
  never cleared. Two mappings gate on an argument rather than a name
  (`shell=True`, `Loader=`), and XXE is resolved specially because the
  vulnerable and safe call sites are byte-identical.
- **Wiring:** `tools/py_frontend.py`; `aether check-py` (+ `--strict`) in
  `cli.py`; 24 tests in `tests/test_py_frontend_sinks.py`;
  `bench/py_frontend/` (4 new repros, LABELS.json, run_bench.py, REPORT.md);
  `vault/wiki/questions/q5-sink-matching-vs-purity-matching.md`.
- **Measured, not asserted** (`bench/py_frontend/REPORT.md`): 0 false
  negatives and 0 false positives over 19 labelled functions; on 76 benign
  modules E0713 and E0720 fired once each (both genuinely suspicious) and
  E0711 fired 11 times, so **E0711 ships opt-in behind `--strict` with its
  number published** rather than deleted or quietly downgraded. Against
  bandit 1.9.4 the two agree on SQLi/YAML/`shell=True`; bandit flags
  `make_thumbnail_safe` — the documented FIX — with B603/B607, Aether does
  not. No general "better than bandit" claim is made or supported.
- **Two bugs found on the way, both fixed here.** BUGS.md **BUG-003**: a
  compiler CRASH (uncaught `TypeError`) on 16 lines of legal Aether — two
  effects sharing a path where only one has an arg made `sorted(effs)`
  compare `None` with `str` while formatting an E0801 message. And
  `tests/test_py_soundness.py`, cited as "4/4 green" by four result
  documents, was **not in the gate** — it only ran by hand. Both suites
  are gated now.
- **Ratchet:** unchanged (54 codes / 30 detectors) — this gives existing
  detectors a new input language rather than adding one.
- **Report:** `bench/py_frontend/REPORT.md`.
- **TYPE gap surfaced for next iter:** **guard bound elsewhere.** Where a
  call's safety lives in a different STATEMENT than its arguments, no
  argument-shape rule can see it — `etree.fromstring(raw, parser)` is
  byte-identical vulnerable and safe. Handled by hand for lxml; a session
  configured at import time or a flag set in a constructor is not. Probe
  for a live instance before building the general version (iter-41 lesson).
## Iteration 44 — markers erased by containers (record fields, generic args)

- **Target:** an externally reported hole — `PII<String>` declared inside
  a `record` field was silent. Chosen over other backlog items by q3
  (reuse × prevalence ÷ new machinery): zero new machinery, and every
  real service passes personal data inside a struct rather than as a
  bare parameter.
- **Gap confirmed empirically:** four probes on `f98fdce`. `record User do
  email: PII<String> end` + `print("user=" + u.email)` + a `writeFile` of
  the same → **exit 0**. `function leak(xs: List<PII<String>>)` printing
  `xs` → **exit 0**. And the mirror image: `leak(User(classifyPII(e),
  "jane"))` raised a **spurious E0729**, `returns User` raised a **spurious
  E0730** — so the safe shape was unwritable, which is why the unsafe one
  went unnoticed.
- **Improvement (eliminates TYPE):** no new code, no new detector. Two
  changes in the shared machinery, inherited by all six marker-flow rows
  and both boundary detectors: `_type_carries_marker` searches the whole
  type tree (nested generic arguments); `_marker_param_mask` emits a mask
  per `RecordDecl` (positional, declared field order) and
  `_marker_field_names` makes a marker-typed field read a taint source.
  `_is_marker_type` keeps its top-level-only rule for `Authorized<T>` —
  widening a PROOF marker relaxes acceptance, the wrong direction.
- **Wiring:** `passes/detector_specs.py` + the two hand-written detectors
  in `passes/effects.py`; 12 tests in `tests/test_effect_scope.py`;
  `playground/examples/28_record_field_marker.aeth`; case study with a
  `fixed.aeth` that joins the false-positive corpus; `SECURITY_POSTURE.md`
  + `grammar/diagnostics.md` reach prose.
- **Ratchet:** unchanged (54 codes / 30 detectors) — this iteration widens
  existing detectors' reach rather than adding one.
- **Report:** `demos/case_studies/record_field_marker/REPORT.md`.
- **TYPE gap surfaced for next iter:** record-field matching is by NAME.
  A plain `email` field on an unrelated record is flagged (over-flag,
  documented). The type-directed version needs the base expression's
  record type resolved from a param or `let` annotation — the same
  machinery `check_exhaustiveness` already uses for union scrutinees
  (`passes/effects.py`, `_union_cases`). Probe first whether the
  over-flag is live on any real corpus file before building it.
- **Suite:** exit 0.

---

## Iteration 45 — the guard is not the argument (three false accepts)

- **Target:** iteration 43's own surfaced residual, "guard bound
  elsewhere", recorded in q5 with a probe-before-building condition
  attached. The probe is the whole story here.
- **Gap confirmed empirically — and it was NOT the expected gap.** Filed
  as a precision residual; the probe found **three FALSE ACCEPTS**, the
  contract-breach class (same as BUG-001, BUG-002). Silent before:
  `yaml.load(raw, Loader=yaml.Loader)`; the same with the loader bound
  one statement earlier; `sh = True` then `subprocess.run(..., shell=sh)`;
  and `cur.execute('SELECT ... ' + name, extra)`.
- **The worst one needed no "elsewhere" at all.** The unsafe value is at
  the call site: the gate read `if _has_kw(call, "Loader"): return None`,
  i.e. ANY `Loader=` meant safe. Adding `Loader=` is the commonest wrong
  fix for PyYAML's deprecation warning, and `yaml.Loader` is the RCE —
  verified by EXECUTION on PyYAML 6.0.3 with an
  `!!python/object/apply:os.system` payload (Loader and UnsafeLoader
  construct it; FullLoader and SafeLoader refuse). FullLoader is still
  not sanctioned: CVE-2020-1747 and CVE-2020-14343 are its bypasses.
- **Improvement (eliminates the TYPE):** one declarative `SINK_GUARDS`
  table replacing three ad-hoc gates. A guard clears a call ONLY when its
  value is positively identified as sanctioned; unrecognized, computed,
  unresolvable and absent all mean SINK. That is q5's rule — never assume
  clean from a NAME — applied one level down, to values. `_local_constants`
  then recovers precision where it is decidable, resolving a local name
  only when every binding in the function agrees. The SQL fix was a
  DELETION: `_is_parameterized_query` cleared any two-argument execute and
  was never needed, because argument 0 being a literal already clears the
  parameterized form.
- **Wiring:** `tools/py_frontend.py`; 10 tests in
  `tests/test_py_frontend_sinks.py`; `bench/py_frontend/corpus/
  guard_bound_repro.py` + 9 labels so the corpus can no longer be blind
  to this class; BUGS.md BUG-004.
- **Measured cost: zero.** Benign-corpus counts identical before and after
  (E0711 11 · E0713 1 · E0720 1 over 76 modules). Detection went 10 → 15
  true positives, 0 false negatives, 0 false positives. Soundness was free
  here — a measurement, not a prediction.
- **A second hole, found by the BENCH and not by a hand-written test:**
  `subprocess.run(...).returncode` is an attribute READ of a call result,
  so the call inside it vanished. The same shape without `.returncode`
  was flagged, which is exactly why every unit test passed. Adding the
  corpus is what exposed it.
- **Ratchet:** unchanged (54 codes / 30 detectors).
- **Report:** `bench/py_frontend/REPORT.md` §3b.
- **TYPE gap surfaced for next iter:** what remains of the class is object
  state **mutated after construction** (`s = requests.Session()` then
  `s.verify = False`) and import-time configuration — both need a
  different traversal. Note `session.verify` is silent for a DIFFERENT
  reason: no detector models TLS verification at all, so that is a
  missing-detector item for q3's normal selection, not a guard bug.
  Probing one and reporting the other would manufacture a gap.
- **Suite:** exit 0.

---

## Iteration 46 — risk ratings: the triage axis (no new detector)

- **Target:** not a violation class. The product gap the phase-2 scans
  exposed: 53 of the 54 codes are `severity="error"` (the SMT timeout
  `E0902` is the sole `warning`), and every SARIF result is hardcoded to
  `level: error` regardless, so a corpus scan returns an unordered wall.
- **Source of the idea:** nuclei's template `severity:` field — five
  levels, filterable at the CLI, carried into SARIF. The reason nuclei's
  output survives thousands of hits.
- **Gap confirmed:** `tools/scan.py` hardcoded `"level": "error"` and
  stripped everything but code/message/line off each finding.
- **Improvement:** `transpiler/aether/risk.py` — one code→rating table
  (critical/high/medium/low/info), read only at output time. Findings
  sort worst-first, `--min-risk` filters, SARIF maps level and sets
  `security-severity` so Code Scanning ranks. `tests/test_risk.py` fails
  on an unrated code or a phantom one.
  - Review caught that `--min-risk` combined with `--expect` would
    filter a declared code out before the expectation diff ran, so a
    filtered-but-still-present code would report as a regressed
    detector; the combination is refused as a usage error (exit 2)
    instead.
- **Ratchet:** unchanged (54 codes / 30 detectors) — no detector shipped.
- **Design point recorded:** why two axes, not one —
  `vault/wiki/questions/q6-risk-vs-severity-two-axes.md`.
- **TYPE gap surfaced for next iter:** risk is per-CODE, so it cannot
  separate a reachable E0713 from an unreachable one. `Diagnostic.
  confidence` is a constant `1.0` at all 30 detectors and is the unused
  half of the triage story — a per-FINDING axis needs something the
  detectors actually vary (e.g. whether taint reached the sink through a
  resolved local vs. an unresolvable one, the `_local_constants`
  distinction iteration 45 already computes).
  - This residual is recorded in the question page that owns it —
    `vault/wiki/questions/q6-risk-vs-severity-two-axes.md` — rather than
    unconditionally in q1, because it is a triage-granularity limit, not
    a taint-marker soundness boundary.
- **Suite:** exit 0.

---

## Iteration 47 — the corpus Aether is for: 97% noise, then the silence under it (no new detector)

- **Target:** not a violation class. `bench/framework_scan/` ran
  `check-py` over 15 AI-agent frameworks (langchain, llama-index, crewai,
  openhands, aider, smolagents, mcp, agno, ...) — 4,946 files, 0 parse
  failures, 0 crashes — because that is the population the Python
  scanner claims to be for, and nothing had measured it there.
- **Gap confirmed empirically, and it was Aether's:** 1,029 of 1,055
  findings were E0713 on SQLAlchemy Core expressions,
  `conn.execute(select(t).where(...))` — the safest SQL in Python. Two
  correct rules composed into a wrong answer: `execute` is a sink by
  method name (q5), and any non-literal argument read as dynamic.
  BUGS.md BUG-010. `bench/py_frontend/corpus/sqlalchemy_repro.py` proved
  all 8 safe shapes fired before the fix.
- **Improvement (precision, neither Aether rule changed):** the frontend
  names a call rooted at a `sqlalchemy`/`sqlmodel` builder as `sqlBind`,
  exactly as `shlex.quote` is named `shellArg`. Three shapes: builder call
  resolved through imports; statement built incrementally, via a least
  fixpoint that allows self-reference but requires an anchor; Table-method
  form accepted only with no positional argument. Raw-string entry points
  (`text`, `literal_column`, `column`, `table`) handed a non-literal
  anywhere inside sanction nothing.
- **Round two cleared 194 of 1,029, and reading the survivors found a
  false accept (BUG-011).** `stmt = select(t)` — the anchor case — was
  still firing, because agno imports SQLAlchemy under `try:` like every
  framework, and `py_to_ir` registered imports only as direct children of
  the module body. For a builder that is precision; for a sink it is
  silence: confirmed by execution, a guarded `import yaml` +
  `yaml.load(raw)` produced NO finding. Same family as BUG-004 — the
  unknown case defaulted to "not a sink". Imports are now collected from
  the whole module; a name bound by two imports to different targets is
  ambiguous and clears nothing. The bench harness's own slicer had the
  identical bug and re-created it on the repro written to pin it; fixed
  alongside.
- **Wiring:** `transpiler/aether/py_frontend.py` (`_SQL_EXPR_*`,
  `_FnScope`, `_sql_expression_names`, `_Imports.ambiguous`, whole-module
  import walk); 16 tests in `tests/test_py_frontend_sinks.py`;
  `bench/py_frontend/corpus/{sqlalchemy,guarded_import}_repro.py` + 28
  labels; `bench/py_frontend/run_bench.py` slice fix;
  `bench/framework_scan/` (new bench); BUGS.md BUG-010, BUG-011.
- **Measured cost and gain, same files, same day:** frameworks
  **1,055 → 411** (E0713 1,029 → 381; 4 previously-silent sinks surfaced,
  two of them lxml-with-entity-resolution over network bytes in
  langchain-community's docugami loader). PyPI corpus, pre/post on the
  same interpreter: E0720 **109 → 124**; bandit B301→E0720 **102 → 118
  hits, 26 → 10 misses**; B608 unchanged. Benign corpus unchanged. Ground
  truth 29 TP / 0 FN / 0 FP over 57 labelled functions.
- **A bench limitation surfaced:** `bench/pypi_scan/` scans the running
  interpreter's site-packages, which had changed since July (370 vs 170
  findings on "the same" corpus). Its REPORT now says so; the before/after
  above was taken from a `git archive` of HEAD on the same day.
- **Ratchet:** unchanged (54 codes / 30 detectors) — no detector shipped.
- **Reports:** `bench/framework_scan/REPORT.md`,
  `bench/py_frontend/REPORT.md` §3c; q5 extended with both rules
  (`vault/wiki/questions/q5-sink-matching-vs-purity-matching.md`).
- **TYPE gap surfaced for next iter:** of the 381 E0713 left, ~100 are a
  statement assembled in a **helper** (`stmt = self._base_query()`,
  `apply_sorting(stmt, ...)`) — the cross-function boundary, which is the
  same limit q1 records for taint. Any intraprocedural rule stops there.
  The next structural capability is a per-module summary of which local
  functions return a SQL expression, so a helper's result can be rooted;
  it is the first place the frontend would need the local-call graph
  `_FnVisitor` already collects. Separately: `collect()` still discovers
  FUNCTIONS only as direct children of module and class bodies, so a `def`
  under `if TYPE_CHECKING:` or `try:` is not analysed at all — the
  function-shaped instance of BUG-011, unfixed.
- **Suite:** exit 0.

---

## Iteration 48 — the translator was not total: 603 sinks behind `await`, and a literal-only proof that survived `+=` (no new detector)

- **Target:** not a violation class. A five-lens survey of the whole
  repo (65 probe-confirmed candidates; ranked by the contract, a false
  accept outranks every precision item) put the Python frontend's
  SILENT MISSES first. The ranked list is the input to the next
  iterations, not just this one.
- **Gap confirmed empirically first:** `await conn.execute("…" + uid)`,
  `for row in cur.execute("…" + uid):`, `obj, _ = pickle.loads(b), None`,
  `return cur.execute(q) or []`, `g(rows=cur.execute(q))`, a `def` under
  `try:`, a class nested in a class, `os.system(sys.argv[1])` at module
  level — every one exit 0, no finding (BUGS.md BUG-012). And the other
  direction: `sql = "SELECT "; sql += uid; cur.execute(sql)` and
  `if loader is None: loader = yaml.SafeLoader` before
  `yaml.load(raw, Loader=loader)` both exit 0 — the name proved
  literal-only from the ONE binding form the resolvers could see. Same
  family as BUG-004 and BUG-011: the unknown case defaulted to "not a
  sink", and the translator, not any rule, was where "unknown" lived.
- **Census (bench/framework_scan, 4,946 files):** 603 sink calls behind
  `await`, 89 in other unmodeled positions (BoolOp 50, Compare 20,
  for-iterables 17, comprehensions 20, non-Name targets 11, displays 7);
  26 of the 89 fire under the existing rows once visible.
- **Improvement (frontend only — no Aether rule changed):**
  `transpiler/aether/py_frontend.py` is now TOTAL over statement kinds
  and binding forms. One walk, `_bindings_of`, feeds every resolver and
  seeds an opaque binding for every name bound by a form whose value
  cannot be seen (a parameter, `+=`, a for-target, a tuple unpack, a
  walrus, an except-as, a `global`); `visit_stmt` translates every value
  expression a statement evaluates, in place; `_expr` keeps an unmodeled
  node opaque but carries its children; `await`/`yield` are transparent;
  keyword values ride under `kwargs`, and take the positional slots when
  there are none. `collect()` finds a `def` at any statement depth; a
  module or class body with a call or a non-docstring literal becomes a
  `<module>` / `Class.<class>` scope (which is also the first time a
  module-level `KEY = "AKIA…"` reached E0723 at all). `_guard_verdict`
  reads a `**`/`*` splat as unresolvable (SINK) and `shell=`/`Loader=`
  positionally. `getattr(obj, "execute")(…)` and a bound-method alias
  spell the method. Two missing rows (`exec_driver_sql`, sqlmodel
  `Session.exec`) and a hole inside iteration 47's own sanctioned exit
  (`prefix_with`/`suffix_with`/`with_hint`/`with_statement_hint`/`op`
  splice a string verbatim and now get `text()`'s discipline). A scope
  deeper than `_MAX_EXPR_DEPTH` (200) reports an `unprovable` `too_deep`
  region instead of losing the whole file as "unreadable" with exit 0;
  `check-py` reads source with `tokenize.open` (PEP 263 cookies).
  Precision, by positive identification only: a `from yaml import
  SafeLoader` name resolves through the import table; a module-level
  str constant bound exactly once in the whole module is inlined at its
  reads; a `stmt = None` sentinel binds nothing.
- **Measured, same 4,946 files, same day:** frameworks **411 → 628**
  (E0713 381 → 590, E0720 9 → 14, E0714 13 → 14, E0723 0 → 2), 0
  analyzer errors, 0 unreadable. The +217 E0713 are await-wrapped
  `text(f"…{table}…")` DDL and `exec_driver_sql(f"…")` in agno's
  migrations, semantic-kernel's psycopg composition, and helper-built
  statements that were behind `await` — every sampled one true by the
  existing rule — plus 3 by-name over-flags the keyword-only mapping
  newly reaches (`await handler.execute(client=…)` in crewai's a2a,
  `client.command.exec(code=…)` in langchain-community's riza tool:
  `execute`/`exec` by name, q5's accepted cost). The +5 E0720 are the tuple-target `pickle.load` sites
  in langchain-community's vector stores (`allow_dangerous_deserialization`
  — real by shape, opted-in by the maintainers). The +2 E0723 are the
  PEM header spelled inside an error message and a docstring: the
  literal scan's known cost, now reaching module-level strings — a
  precision item for the E0723 pass (require a key body after the
  header), not a frontend one. 8 over-flags gone (4 crewai module
  constants, 4 agno `None` sentinels). Ground truth **41 TP / 0 FN / 0
  FP** over 77 labelled functions (was 29 / 57); benign corpus unchanged
  (E0711 11 · E0713 1 · E0720 1). `bench/framework_scan/REPORT.md` §7.
- **Ratchet:** unchanged (54 codes / 30 detectors) — no detector shipped.
- **Design point recorded:** why totality over syntax is a soundness
  obligation and not a precision knob —
  `vault/wiki/questions/q7-frontend-totality-over-syntax.md`.
- **Correction to the record (iteration 47's "~100 helper-assembled"
  estimate):** read at source, all 381 survivors classified
  (`bench/framework_scan/e0713_census_2026-09-03.txt`): 34 are
  helper-shaped (14 same-module, 20 cross-module); 166 are
  `text(f"…{identifier}…")` DDL, true positives under the raw-entry
  rule; 37 DB-API f-string/format/concat; 21 Cassandra CQL; 21 graph
  query languages; 20 agent SQL toolkits running caller SQL by design;
  17 non-SQL `execute`. That reprices the per-module helper summary
  (~180 loc for 14 sites) below the misses it had been ranked above; it
  stays parked, and the identifier-interpolation TPs are the natural
  target for the per-finding `confidence` axis from iteration 46 (q6),
  not for a relaxation.
- **TYPE gaps surfaced for next iter (all probe-confirmed by the
  survey):** (a) `exec(model_output)` / `eval` / `compile` on a
  non-literal is a capability NOTE, never a finding — THE agent-framework
  hazard (smolagents, langchain's PythonREPL, openhands run model output
  through `exec`) has no detector; next free code E0731, literal-only
  like E0719 with `trusted(...)` as the exit. (b) On the Aether side,
  `var` bindings and `x = …` re-assignment are invisible to the marker
  fixpoint, the literal-or-wrapper safe-name pass and E0717's
  stable-name proof — the language-side instance of this iteration's
  bug. (c) The sanctioned wrappers' PINNING argument
  (`sqlBind(userTemplate, v)`, `safeJoin(userBase, p)`) is never
  checked. (d) `for x in markedList` and match-EXPRESSION arm bindings
  do not taint; aliasing a stdlib sink (`let run = sqlQuery`) hides it.
- **Suite:** exit 0.

---

## Iteration 49 — the language side had the same bug: `var` was never a binding (four false-accept classes, no new detector)

- **Target:** the Aether-side rows of the 2026-09-03 survey
  (`audits/survey_2026-09-03_ranked.md`, AEDET-01..07/10), every one a
  probe-confirmed SILENT MISS in the language the detectors were written
  for. Same family as iteration 48's BUG-012, one layer down: the parser
  emits three binding kinds — `Let` (name), `Var` (name), `Assign`
  (target) — and every walker that reasons about what a name holds read
  `Let`/`Assign` by `name`. A `var` was never a binding; an `Assign`
  never matched.
- **Gap confirmed empirically first (all exit 0 before):**
  `var x = password; print(x)` (E0712); `let p = "/etc/motd"; p =
  userPath; readFile(p)` (E0711 — the only VISIBLE binding was the
  literal); `var docId = requestedId; ...authorizeResource(..., docId);
  docId = victimId; sqlByOwner(..., docId, proof)` (E0717's stable-name
  proof missed the rebinding); `for s in secrets do print(s) end` over
  `List<Secret<String>>` and a match-EXPRESSION arm over a secret
  scrutinee (BUG-001 had fixed only the statement form); `let run =
  sqlQuery; run(input)` — an aliased STDLIB sink matched no row and no
  effect, so E0713/E0711/E0712/E0801/E0701 were all silent (iteration 42
  had resolved aliases of USER functions only); and `print(u)` with
  `record User do email: PII<String> end` — iteration 44 made the FIELD
  read a source but never the record value. BUGS.md BUG-013..016.
- **Improvement (`passes/detector_specs.py`, `passes/effects.py`,
  `passes/capability.py`, `parser.py`):** one shared binding walker
  (`_walk_binds` / `_bind_target` over `Let`/`Var`/`Assign`, plus
  `_mutable_names` for the proofs that need "bound exactly once") feeds
  the marker-taint fixpoint, the literal-or-wrapper safe-name pass,
  `_fn_aliases` and the E0716/E0717 proofs; `For` targets over a tainted
  iterable and every arm binding of a tainted match expression are
  tainted; alias targets include the stdlib sink names and the
  `_STDLIB_EFFECTS` keys (an aliased sink IS the sink; an aliased
  sanitizer is still never honoured; E0801/E0701 follow the alias edge);
  records whose fields carry a marker are carriers (`_marked_records`,
  `_record_names`): a carrier at a sink leaks, a PLAIN field read of a
  carrier does not, a record-typed parameter is a sanctioned crossing,
  a plain parameter is E0729, a plain return type is E0730;
  `Authorized<T>` untouched — a proof marker is never widened.
- **Widenings in the same slice, flag-more, 0× on the corpus:** E0710,
  E0721 and E0722 share one host normalizer — userinfo, port, brackets,
  a wildcard anywhere inside the host (`*.*`, `api.*`, `a*`,
  `[*]`, `trusted@*`), decimal/hex/octal/short and IPv4-mapped IPv6
  spellings of 169.254/16, `fd00:ec2::254`, `metadata.google.internal`,
  `metadata`, `100.100.100.200`; the E0721 loopback exemption is
  host-exact (`127.0.0.1.evil.com` and `127.0.0.1@evil.com` no longer
  pass). E0723 gains OpenAI (`sk-proj-`, `sk-`), Anthropic (`sk-ant-`),
  Hugging Face (`hf_`), Groq (`gsk_`), Google OAuth (`ya29.`), GitLab
  (`glpat-`), SendGrid (`SG.`), npm (`npm_`), PyPI (`pypi-`) and Slack
  incoming-webhook shapes — 0 matches over every in-tree file and the
  4,946-file framework corpus — and the PEM pattern now requires a key
  BODY after the header, which is exactly the two docstring/message
  hits iteration 48 reported as its precision cost. `StringLit` carries
  a position, so E0723 reports a line instead of `0:0`. E0207 treats
  `Int` bounds as integers (`Int where self > 5 and self < 6` is
  uninhabited). Marker-flow param masks are computed once per module
  (was once per function, O(n²) in function count).
- **Measured:** 33 new tests in `tests/test_effect_scope.py`; playground
  `29_sink_alias.aeth` and `30_record_at_sink.aeth`; no existing
  `// expect:` header changed (the survey's in-memory rewrite over 418
  parseable `.aeth` had predicted 0 files; the gate confirmed it).
  Merged as `60f60e6`; gate exit 0.
- **Ratchet:** unchanged (54 codes / 30 detectors at this point; iteration
  50 raises it).
- **TYPE gap surfaced for next iter:** the survey's remaining Aether-side
  P0 — boundary-sanitizer coarseness (AEDET-09: `render(sanitizeLog(u))`
  clears E0729 while the callee feeds `htmlResponse`) — is a probe-
  confirmed miss with a design cost (~50 loc) and a corpus question
  (which playground examples sanitize at a boundary); park until the
  corpus is measured. Record-field resolution by type (AEDET-16) stays a
  precision item. Residuals in q1.

---

## Iteration 50 — E0731: the interpreter fed model output (new detector), and the sink rows the agent corpus needs

- **Target:** survey candidate PYSINK-01, the top-ranked NEW detector.
  `exec(model_output)` is what an AI-agent framework does for a living —
  smolagents' `LocalPythonExecutor`, langchain's `PythonREPL`, openhands,
  agno's python tool — and until now `exec`/`eval`/`compile` on a
  non-literal was a capability NOTE under `--strict` (an UNPROVABLE
  region), never a finding. By q3's heuristic it scores highest of the
  batch: it reuses the E0719 shape exactly (literal-only, no sanitizer,
  `trusted(...)` the sole exit), the population is the scanner's own,
  and the machinery is one row.
- **Gap confirmed empirically first:** `def run(code): exec(code)` under
  `check-py` default flags — exit 0, no E07xx. AST census over
  bench/framework_scan (4,946 files): 5 bare `exec()` and 9 `compile()`
  with a non-literal first argument; `eval()` non-literal 0 (the grep
  hits are docstrings); `importlib.import_module`/`__import__` with a
  dynamic name 57 + 5 — deliberately NOT a sink (plugin loaders, CWE-470,
  a different class).
- **Improvement — the full slice:** stdlib sink `evalCode(source:
  String) returns String` (`runtime.py` stub that never executes,
  `grammar/stdlib.md`); `check_code_injection` row in
  `passes/detector_specs.py` (`_CODE_RULE` = the template rule's contract
  worded for code), bound in `effects.py`, registered in the `security`
  stage; `grammar/diagnostics.md` row + prose; `risk.py` critical
  (CWE-94/95); frontend `SINK_BY_BUILTIN` exec/eval/compile — bare names
  only (`session.exec(stmt)` is the by-name SQL row, not the builtin),
  `ast.literal_eval` is not a sink, a local `def exec` shadow is not the
  builtin, `exec(compile(src, ...))` reports once; tests on both sides;
  `demos/case_studies/code_injection/`, playground
  `31_code_injection.aeth`, `bench/py_frontend/corpus/code_injection_repro.py`
  + labels; `vault/wiki/clusters/violation-taxonomy.md` row.
  **Ratchet raised 54 → 55 codes, 30 → 31 detectors** (`tests/ratchet_baseline.json`).
- **Sink rows shipped alongside (PYFE-08, PYSINK-02..12), every one a
  silent shape before, all flag-more:** deserialize — `torch.load`
  (guard `weights_only=True`; absent is SINK, the pre-2.6 default,
  version-dependent like lxml), joblib, dill, cloudpickle,
  `pandas.read_pickle`, `jsonpickle.decode`, `numpy.load(allow_pickle=True)`,
  `yaml.*load_all`; shell — `subprocess.getoutput`/`getstatusoutput`,
  `asyncio.create_subprocess_shell`, `commands.getoutput`, paramiko
  `exec_command`, and the argv form `["bash", "-c", cmd]` (BUG-021: the
  argv "safe exit" whose third element the shell parses); template —
  jinja2 `Environment.from_string` (24 non-literal corpus sites, the
  prompt-template shape), mako `Template`; SQL — asyncpg/databases
  `fetchrow`/`fetchval`/`fetch_all`/`fetch_one`/`fetch_val`, `mogrify`,
  `pandas.read_sql`, django `RawSQL` (bare `fetch` deliberately not —
  vector stores and HTTP clients spell it); redirect — starlette/fastapi
  `RedirectResponse`, django `HttpResponseRedirect`, aiohttp `HTTPFound`;
  XXE — `xml.dom.minidom.parse`. `bench/py_frontend/corpus/sink_coverage_repro.py`
  carries every shape, labelled.
- **BUG-020 (Aether side, false accept):** a sanctioned wrapper was
  accepted on its NAME; `sqlBind(tmpl, v)`, `shellArg(tmpl, v)`,
  `safeRedirect(host, p)` with a parameter in the pinning slot laundered
  the very text the row refuses. `ArgRule.pin` now judges `args[0]`;
  every frontend-emitted Call carries `"py": True` and is exempt (a
  Python wrapper has no template slot). `safeJoin`'s base is deliberately
  unpinned: a parameter base directory is the idiom (7 corpus sites, both
  zip-slip demos' `fixed.aeth`) and the untrusted half is the relative
  part — recorded as a residual, not enforced.
- **Scanner visibility (TC-03/08/10/11):** every unreadable file is
  reported on stderr in json/sarif/text with the parser's message (JSON
  `detail`); SARIF carries `toolExecutionNotifications` for them plus
  column, suggestion and `extra` per result; pruned vendored/build
  directories are listed (JSON `skipped_dirs`, text summary); an
  unparseable file alone never fails the run in any mode, an analyzer
  crash always does; the Python stage-skip and strict-only lists are
  defined once in `py_frontend.py` and imported by the CLI, both benches
  and the tests.
- **Measured (bench/framework_scan, same 4,946 files, after iterations
  48–50):** frameworks **628 → 676** (+50, −2), 0 analyzer errors, 0 unreadable, wheel versions identical (per-distribution file counts match the 2026-09-02 cache). **E0731 × 8:** `agno/tools/python.py:159` (`exec(code, ...)` — the python tool running the model's code), `smolagents/tools.py:575` (`Tool.from_code` — `exec(tool_code, module.__dict__)`), `browser_use/mcp/cli_mcp.py:128` (`exec(code, ns)`), `crewai/flow/runtime/_actions.py:309` (`exec(compile(module, filename, "exec"), namespace)`) — four true-by-shape sites where the interpreter is the product — and three `compile()`-for-linting sites (`aider/linter.py:179`, `openhands/linter/languages/python.py:11,66`) plus `langchain_community/tools/e2b_data_analysis/unparse.py:744`, which compile without executing: over-flags by class (`compile` produces a code object; the rule treats it as the sink because `exec(compile(...))` is the common form). **E0719 +24**, the `from_string` row: ~14 are jinja2 prompt templates rendered from strings by design (haystack `PromptBuilder`/`ChatPromptBuilder`/`ConditionalRouter`/`OutputAdapter`, semantic-kernel `Jinja2PromptTemplate`, langchain-core `jinja2_formatter`, smolagents' gradio template, openhands' invariant policy) — the prompt-template SSTI shape, by-design context; the rest are non-jinja `.from_string(...)` methods matched by name (momento `CredentialProvider.from_string` ×3, llama-cpp `LlamaGrammar.from_string` ×2, bigquery, networkx, agno's chunking strategy) — q5's accepted cost, now measured at roughly a third of the row. **E0718 +5:** `RedirectResponse(url)` in agno's MCP consent/media routes and mcp's OAuth `AuthorizationHandler` — dynamic redirect targets, true by shape (validated-against-registered-URIs is the expected repair, outside any argument-shape rule). **E0720 +3:** agno `code_mode`, databricks `_load_pickled_fn_from_hex_string` (cloudpickle by design), tfidf `joblib`. **E0713 +10:** `fetch_all` by name on langchain-community's HTTP loaders (`async_html`, `web_base` — over-flags the survey predicted) and cassandra's CQL wrappers (true by shape, CQL). **−2:** the two E0723 PEM-header hits (a docstring and an error message) that iteration 48 recorded as its precision cost — closed by requiring a key body. benign corpus (76 modules): one new E0731 on `tools/py_corpus/17_template_render.py:8` — `eval(expr, {"__builtins__": {}}, context)`, the known-bypassable "sandboxed eval" — true by shape; the other rows unchanged (E0711 11 · E0713 1 · E0720 1). Ground truth 72 TP / 0 FN / 0 FP.
- **Suite:** exit 0. Merged as `7c4f19d` (branch commits `c35b3f3`, `1855c2f`).
- **TYPE gaps surfaced for next iter:** (a) `session.exec`/`execute` by
  name on non-DB receivers (a2a handlers, riza's remote code exec) are
  E0713 over-flags the keyword-only mapping now reaches — the per-finding
  `confidence` axis (q6) is where a by-name match should be distinguished
  from a resolved one; (b) boundary-sanitizer coarseness (AEDET-09) is
  the last probe-confirmed Aether-side miss in the survey; (c) Zip-Slip
  via `tarfile`/`zipfile.extractall` without `filter=` (PYSINK-14) needs
  a member-path model E0711 does not have — parked with its prevalence
  question open.

---

## Iteration 51 — the vault said the surface did not exist, and it did (four false accepts, no new detector)

- **Target:** the last two P0 rows of the 2026-09-03 survey
  (`audits/survey_2026-09-03_ranked.md`, AEDET-08 and AEDET-09), both
  re-probed live on `3986d38` before any code moved.
- **The honesty half, and it is the point of the iteration.** q1 carried
  this as settled Evidence since iteration 42: *"`grammar.ebnf` has no
  function types — nothing HOF-shaped remains in the language."*
  `grammar/grammar.ebnf` line 88 is
  `"function" "(" [ type_expr {"," type_expr} ] ")" "returns" type_expr`
  and `parser.py:369` emits `FunctionType`. The row was a grammar claim
  written without grepping the grammar, and it had been shielding two
  live false accepts for nine iterations. **The lesson recorded in q1:
  the iteration-41 rule "probe before you record it" applies to CLOSING
  an item, not only to opening one. A closed row is a claim, and claims
  expire.**
- **Gap confirmed empirically first (exit 0 on `3986d38`):**
  `apply(f: function(String) returns Unit, x: Secret<String>) do f(x) end`
  called as `apply(print, pw)` — no E0712, no E0729, the password logged;
  and `apply(logIt, s)` from a `pure` caller into a `pure` `apply` that
  calls `f` — no E0801, the logging performed under two functions that
  both declared they do none. Separately `render(sanitizeLog(u))` where
  `render` feeds `htmlResponse` — exit 0, while the inline
  `htmlResponse(sanitizeLog(u))` fires E0725 whose own hint reads
  "sanitizeLog does NOT protect here".
- **Improvement (BUG-022, BUG-023):** `check_marker_boundary` fires E0729
  when a call's callee is a function-typed PARAMETER and an argument
  leaks the marker — the callee is chosen by the caller's caller, so it
  is strictly less visible than the plain-param crossing E0729 already
  refused; there is deliberately NO sanctioned crossing there, because a
  function type's argument types are never checked against what arrives.
  `check_effects` counts a function passed as a VALUE as a callee whose
  declared effects join the caller's obligation. And the boundary
  sanitizer stopped being marker-wide: `param_sink_reach()` summarises
  which marker-flow sinks each callee parameter reaches,
  `marker_sink_sanitizers()` derives (marker, sink) → sanitizer from
  `MARKER_FLOW_SPECS`, and a cleared crossing is accepted only when the
  unwrapper that cleared it is right for every sink reached.
- **The review found the slice had shipped two NEW false positives and
  reopened one of its own fixes** (BUG-024, BUG-025), all three
  probe-confirmed, all three fixed in the same iteration:
  - E0801 resolved a bare Ident argument by GLOBAL name with no locality
    check, so a plain `String` parameter named `logIt` handed to the pure
    stdlib `concat` was reported as an escaping `log` effect — an
    invented effect for a string, in every argument position of every
    call. Fixed with a `local` set (parameters + `_walk_binds` targets)
    and alias-only resolution for shadowed names; the same edit closed
    the slice's own documented gap, so `let g = logIt; apply(g, s)` now
    reports too.
  - E0729 counted a parameter as reaching a sink it reached only through
    that sink's own sanitizer, so `render(s) = htmlResponse(htmlEscape(s))`
    was reported as feeding `htmlResponse` raw **and the hint told the
    caller to escape a second time** — a diagnostic that corrupts output
    if obeyed. Fixed by summarising reach with each sink's own sanitizers
    as unwrappers.
  - A one-line alias defeated the new function-typed-parameter rule:
    `let g = f; g(x)` was exit 0 on both the base and the fix commit,
    while the same program without the `let` fired. This is the alias
    class q1 already records as CLOSED for named functions (BUG-002),
    reopened at a new callee kind.
- **Measured:** corpus survey before wiring found 9 function-value
  argument sites (every one `effects pure`) and 0 function-typed
  parameters, so both new rules fire 0× on existing code; a differential
  over all 437 in-tree `.aeth` after the review fixes shows 0 diff. 11
  new tests across `tests/test_effect_scope.py` and
  `tests/test_static_effects.py`; playground examples 32 and 33.
- **Ratchet:** unchanged (55 codes / 31 detectors) — no detector shipped,
  four repaired.
- **TYPE gaps surfaced for next iter:** a function type carries no
  effects clause in the grammar, so a callee that declares a
  function-typed parameter may still claim any effects it likes and only
  the call site supplying the value is judged — closing that is a
  LANGUAGE change (effect-polymorphic function types), and q1 says
  explicitly not to invent an effects syntax to get around it. The sink
  summary is one level and matches the parameter by direct Ident, so a
  callee that rebinds the parameter or hands it to a third function
  contributes no sinks and falls back to the old marker-wide rule; E0730
  (return laundering) keeps the coarseness entirely, having no callee
  parameter to summarise. Both are the accept direction — real remaining
  misses, stated as such.
- **Suite:** exit 0.

---

## Iteration 52 — the axis that had been declared unused since iteration 46 (no new detector)

- **Target:** q6's Residual, open since iteration 46 and re-surfaced by
  iteration 50's own gap line. `Diagnostic.confidence` is a field on
  every diagnostic, serialized, read back by the SDK — and the constant
  `1.0` at every detector. q6 said varying it "needs something the
  detectors actually compute".
- **Iteration 50 supplied exactly that, measured.** The Python frontend
  names a sink in six different ways and they are not equally certain:
  a dotted path resolved through the file's imports is not a guess, a
  method name on an unresolved receiver is q5's sanctioned over-flag, and
  `bench/framework_scan/REPORT.md` §8 had already priced the difference —
  about a third of the new `from_string` hits are non-jinja methods, and
  4 of 8 E0731 sites call `compile()` and never execute the result —
  three syntax-checking linters and a round-trip test (corrected
  2026-09-11; this block first said all four were linters).
- **Improvement:** `_sink_match` returns HOW it matched beside WHAT it
  matched; `_call_expr` parks that on the Call node; the two spec-driven
  drivers set `confidence=confidence_of(call.get("match"))` and put the
  kind in `extra`. `transpiler/aether/confidence.py` holds the table,
  modelled on `risk.py` and read only at output time. `tools/scan.py` and
  `check-py` sort by `(-risk, -confidence, line, code)`, both grow
  `--min-confidence`, SARIF carries it. An unknown match kind takes the
  FLOOR, never 1.0 — a new frontend match kind must not claim certainty
  by being new.
- **It changed no detection, and that is the measurement that matters:**
  676 findings on the 15-framework corpus before, 676 after, identical
  multiset and identical per-distribution stats. The distribution is
  0.95 ×44, 0.9 ×3, 0.6 ×629, so `--min-confidence 0.9` hides 93% of the
  corpus — almost all of it `cursor.execute`-shaped SQL matched by name.
  Those findings are correct by Aether's rule and stay in the default
  output; the flag is a reading order, not a verdict.
- **`--jobs` alongside:** 241 s → 69 s on the 1,024-file agno package,
  8 workers, all four `--json` outputs byte-identical. A pool is used
  only above 32 files on a multi-core machine, so single-file and
  small-tree runs stay byte-identical to what they were.
- **Review found four minors, all fixed:** `--jobs 0` scanned serially in
  silence and `--jobs 999` died with a raw traceback (Windows caps the
  pool at 61); the coverage test read the frontend's match kinds with a
  regex blind to the one continuation-line return it most needed to see;
  and two docstrings claimed more than they had earned — `confidence.py`
  read as if all six ratings were measured when only the ordering of the
  two floor kinds is, and q6 named E0710/E0721/E0722 as carrying unearned
  certainty on Python when those three cannot fire on Python at all.
- **Ratchet:** unchanged (55 codes / 31 detectors).
- **TYPE gap surfaced for next iter:** the axis reaches only the two
  spec-driven drivers. Of the ~20 hand-written `Diagnostic` sites in
  `passes/effects.py`, only E0723 fires on translated Python today and
  its evidence is a literal read from the source, so its 1.0 is earned —
  the residual is latent, and the next hand-written detector that fires
  on Python must read `call.get("match")` like the drivers do.
- **Suite:** exit 0.

---

## Iteration 53 — E0727's Python text described the Aether parser, not the Python one (no new detector)

- **Target:** the residual `bench/framework_scan/REPORT.md` §3 left
  (commit 8a3b919, 2026-09-02, the BUG-011 round) — "a version-dependent
  sink is a residual no static rule resolves" — read from the user's
  side. `check-py` maps twelve stdlib `xml.*` callees (ElementTree,
  cElementTree, minidom, pulldom, expatbuilder, sax: parse plus
  parseString/fromstring each) and three `lxml.etree` callees to
  `parseXml`, and every one printed the row's Aether text: "an
  entity-resolving parser reads local files and reaches internal URLs
  (XXE)" with the hint "parse with parseXmlSafe(data)". `parseXmlSafe` is
  an Aether stdlib function; a Python user cannot call it.
- **Probe-confirmed first (2026-09-11, CPython 3.11.15,
  `pyexpat.EXPAT_VERSION` = expat_2.7.4, lxml 6.1.1 / libxml2 2.11.9;
  the URL claims measured against a local HTTP server, most of them only
  after review asked):**
  - stdlib `ElementTree` / `minidom` / `xml.sax` / `pulldom` /
    `expatbuilder` on `<!ENTITY x SYSTEM "file:///…">` by default: no
    file read — ElementTree raises `undefined entity`, the others drop the
    reference. Same for an `http://` SYSTEM entity: no request. The Python
    docs say so: "By default, Expat itself does not access local files or
    create network connections" (`library/xml.html`, "XML security"); the
    3.11 page's table footnotes: ElementTree "doesn't expand external
    entities and raises a ParseError", minidom "returns the unexpanded
    entity verbatim", sax/pulldom "Since Python 3.7.1, external general
    entities are no longer processed by default".
  - the same on entity expansion: a 6-level (10^6) billion-laughs payload
    parses; 7 levels (10^7), 8 levels and a 50 kB × 2,000 quadratic
    payload are refused with `limit on input amplification factor (from
    DTD and entities) breached`. The docs hedge, and the thresholds are
    per issue: the current page says Expat "lower than 2.7.2 may be
    vulnerable to the 'billion laughs', 'quadratic blowup' and 'large
    tokens' vulnerabilities, or to disproportional use of dynamic memory"
    and "Python bundles a copy of Expat, and whether Python uses the
    bundled or a system-wide Expat, depends on how the Python interpreter
    has been configured in your environment … Check
    `pyexpat.EXPAT_VERSION`"; the 3.11 table's footnotes put billion
    laughs / quadratic blowup at 2.4.1 and large tokens (CVE-2023-52425, a
    re-parse cost, not an entity attack) at 2.6.0, "still listed as
    vulnerable due to potential reliance on system-provided libraries".
  - the live stdlib XXE is a SAX parser with
    `setFeature(feature_external_ges, True)`: it reads the file AND fetches
    the `http://` entity (1 request on the local server). It is reachable
    through `minidom.parse/parseString(…, parser=p)` and
    `pulldom.parse/parseString(…, parser=p)` (both measured: file and URL)
    and through the parser object's own `p.parse(...)`. It is NOT
    reachable through `xml.sax.parse` / `xml.sax.parseString`: their
    source builds a fresh `make_parser()` and exposes no parser argument.
  - a `parse()` spelling opens its SOURCE argument itself, whatever the
    parser: `ET.parse(path)`, `cElementTree.parse(path)`,
    `expatbuilder.parse(path)`, `minidom.parse(path)`, `pulldom.parse(path)`
    open a str as a local file (a URL raises `OSError`);
    `xml.sax.parse(source)` opens an existing file or `urlopen()`s anything
    else (the `xml.sax` docs; measured: 1 request), and so does
    `defusedxml.sax.parse`; `lxml.etree.parse(url)` fetches it with the
    default parser AND with the hardened one the hint names (measured: 1
    request each). E0727 judges entity resolution; no row judges that
    open (E0711's Python mapping covers `open`, not XML sources).
  - lxml 6.1.1 default parser: `Entity 'x' not defined`, no read;
    `XMLParser(resolve_entities=True)`: the file IS read, but the
    `http://` entity is NOT fetched (0 requests) — `no_network=True` is the
    default (the XMLParser docstring), and only `resolve_entities=True,
    no_network=False` fetched it (1 request); `resolve_entities=False`:
    clean, but `XMLParser(resolve_entities=False, load_dtd=True,
    no_network=False)` fetched an external DTD (`<!DOCTYPE r SYSTEM
    "http://…">`, 1 request) — the hardened binding needs all three
    keywords. libxml2 2.11 refuses every expansion payload (`Maximum entity
    amplification factor exceeded`). The lxml 5.0.0 changelog
    (2023-12-29): "lxml no longer expands external entities (XXE) by
    default … The new default is resolve_entities='internal'."
  - `defusedxml` 0.7.1 refuses both the SYSTEM entity and the expansion
    payload (`EntitiesForbidden`) — but only with the parser it builds
    itself: `defusedxml.minidom.parseString(xxe, parser=ges)` returned the
    secret and `defusedxml.pulldom.parse(…, parser=ges)` fetched the URL
    (its source: `if parser is None: parser = make_parser()`). Its
    `cElementTree` module is deprecated in favour of `ElementTree`. bandit
    1.9.4 flags the stdlib calls (B313–B319, MEDIUM: "Replace … with its
    defusedxml equivalent") and has no lxml check any more (B320 is
    removed in that version).
- **Improvement — text per callee, and the four detection changes the
  probes forced:** `_call_expr` parks the callee spelling on a sink Call
  (`callee`: the spelling `_callee_spelling` resolved — a dotted import
  path on a `qualified`/`guard`/`argv` match, the builtin name on
  `builtin`, the attribute path as written, possibly chained, on a
  `method` match); `LiteralOrWrapperSpec` grows `callee_text` —
  prefix-ordered `CalleeText` rows, a prefix or a tuple of them, with an
  optional `leaf` so `parse` and `parseString` can differ — and
  `text_for(callee)` picks the wording; the driver formats `message` AND
  `suggestion` with `callee`, `callee_tail` (last two components) and
  `callee_leaf` (last one) and puts `callee` in `extra`. E0727 carries
  eleven rows: `lxml.` ×2 (file read by default before 5.0 and under
  `resolve_entities=True`, a URL only with `no_network=False`; fix = the
  three-keyword parser binding), `xml.sax.` ×2 (own parser, no parser
  argument: no XXE through entities), `xml.dom.minidom.` +
  `xml.dom.pulldom.` ×2 (a `parser=` with `feature_external_ges` reads
  files and fetches URLs), `xml.etree.cElementTree.` ×2 (the hint names
  `defusedxml.ElementTree`, the non-deprecated module), `xml.` ×2 for
  ElementTree/expatbuilder (never expand external entities, any Expat),
  and `defusedxml.` for the guard rows below. Each family's `parse` row
  adds that the source string is itself opened as a path (or, for
  `xml.sax.parse` and `lxml.etree.parse`, fetched as a URL) and that no
  row judges it. Every stdlib row ends with the docs' hedged,
  per-threshold DoS clause and a hint naming the `defusedxml` equivalent
  "and no parser= argument" or a `pyexpat.version_info >= (2, 7, 2)` check
  (`EXPAT_VERSION` is a string; comparing it is wrong). An `.aeth` source
  has no callee and keeps the row's own text, which is exact there:
  `_ae_parseXml` models an entity-resolving parser.
  Detection: (1) RELAX — the hardened lxml parser bound in the same
  function now clears the sink when passed as `parser=parser`, lxml's
  documented spelling, as it already did positionally; the `parser`
  keyword only (`base_url=parser` does not clear), never a `**kwargs`
  splat. The first draft's hint promised "that binding clears this
  finding" while the keyword form still fired (review, reproduced).
  (2) STRENGTHEN — `_safe_xml_parser_names` requires `resolve_entities=
  False` and, when present, `no_network=True`, `load_dtd=False`,
  `dtd_validation=False`, and refuses a `**kwargs` splat in the
  constructor: the DTD-retrieval shape above no longer clears. (3)
  STRENGTHEN — `xml.sax.make_parser` leaves `_XML_PARSER_CTORS`: it has no
  `resolve_entities` keyword (TypeError), so the only stdlib shape that
  cleared E0727 was one that cannot run. (4) STRENGTHEN — new `SINK_GUARDS`
  rows keyed on `parser=` for `defusedxml.minidom.parse/parseString`,
  `defusedxml.pulldom.parse/parseString` and `defusedxml.ElementTree.parse`
  (absent or `None`: not a sink; anything else: the sink, match kind
  `guard`), because the hint names defusedxml and the shape it would
  otherwise steer into was silent.
- **Why wording and not confidence:** `confidence.py` rates how sure the
  analysis is that the call IS the sink it matched — `ET.fromstring`
  resolved through the imports is a 0.95 `qualified` match and stays one.
  What is uncertain on a stdlib callee is the RUNTIME (which Expat, which
  parser object), which no static rule resolves and which the message now
  states. Lowering the rating would also move iteration 52's measured
  corpus distribution (0.95 ×44 / 0.9 ×3 / 0.6 ×629) for a reason that is
  not identification certainty.
- **Kept flagged on purpose:** every stdlib row still fires (bandit
  B313–B319 do too): a system Expat below the docs' thresholds is a real
  DoS, minidom/pulldom become a real XXE with one `parser=`, and every
  `parse()` spelling opens its source. Over-flag, never miss within the
  modeled surface.
- **Two review rounds, by measurement, rewrote this text twice.** Round
  one: "reaches internal URLs" for lxml under `resolve_entities=True`
  alone (`no_network=True` blocks it); "xml.sax resolves them once
  feature_external_ges is set" on callees that cannot set it; the definite
  "is open to … below 2.7.2" against the docs' "may be" and per-issue
  thresholds; "large tokens" filed under entity expansion; the deprecated
  `defusedxml.cElementTree` in a hint; a string comparison of
  `EXPAT_VERSION`; "bandit B313–B320"; "ten" stdlib callees; the REPORT §3
  provenance; a fix-shape test with no positive control. Round two: "not
  a file read or SSRF" on the `parse()` spellings, whose source string IS
  opened or fetched; "refuses entity declarations outright" for a
  defusedxml call that keeps the caller's parser; the keyword clearing
  keyed on the value instead of the `parser` slot; the sanctioned exit
  clearing a parser that still retrieves an external DTD; the dead
  `make_parser` constructor entry; a docs sentence attributed to a page
  that does not carry it; a paraphrase in quotation marks on the q1 row;
  a double-escaped wikilink pipe; and `callee` described as "a bare method
  name" when it is the attribute path as written.
- **Measured non-breaking:** `check-py --json` over the in-tree Python
  corpus (`bench tests tools playground demos`: 208 files, 110 findings)
  before and after: identical multiset of (path, code, confidence,
  severity, extra minus `callee`) — the only position deltas are the
  E0723 fixtures that sit below the edited test text in the two test
  files; text differs on E0727 only; `extra.callee` is now present on
  every literal-or-wrapper Python finding
  (E0713/E0714/E0718/E0719/E0720/E0727/E0731). None of the four detection
  changes touches an in-tree shape. Every fix shape the hints name checks
  clean beside eight positive controls (an unhardened, parameter-supplied
  or wrong-keyword `parser=`, a `**kwargs` splat, a DTD-retrieving
  binding, the dead `make_parser` shape, defusedxml with a caller's
  parser).
- **Ratchet:** unchanged (55 codes / 31 detectors).
- **Residuals (pushed to q1):** (a) a version-dependent sink — the
  analyzer cannot see the runtime Expat or lxml; the text names the
  boundary and the check, it cannot make it. (b) the `parser=` SAX parser
  on minidom/pulldom is not inspected: `setFeature` is untracked, so the
  default (safe) and the feature-on (XXE) states get the same finding —
  over-flag. (c) `defusedxml.defuse_stdlib()` is untracked — over-flag.
  (d) the source argument of a `parse()` spelling — a path, or for
  `xml.sax.parse` / `defusedxml.sax.parse` / `lxml.etree.parse` a path or
  URL — is opened by the library and judged by no row: the text names it,
  E0727 does not fire for it, and a literal-free `ET.parse(path)` with a
  hardened lxml parser is clean. A MISS (accept direction). (e)
  `callee_text` reaches only the literal-or-wrapper driver.
- **TYPE gap surfaced for next iter — a MISS, not text:**
  `p = xml.sax.make_parser(); p.setFeature(feature_external_ges, True);
  p.parse(raw)` is the stdlib XXE this iteration measured, and it reports
  NOTHING: `p.parse` is a receiver-bound method, in neither
  `SINK_BY_QUALIFIED` nor `SINK_BY_METHOD` (a bare `parse` method row
  would over-flag every `.parse`). The shape is the guard-bound-elsewhere
  class `_safe_xml_parser_names` already handles for lxml, in the
  opposite direction: resolve `p` to its `make_parser()` binding and treat
  `p.parse` as the sax sink. Probe prevalence on the framework corpus
  before building it. Second in line, same class: residual (d) — the
  `parse()` source string is a path/URL sink no row owns (E0711's Python
  mapping stops at `open`). Third: the same per-callee audit one row over
  — E0720's hint says `schemaDecode(schema, data)` to a `pickle.loads` /
  `yaml.load` user, and E0719's says nothing Python-specific to a
  `render_template_string` user; `callee_text` is the mechanism, each
  row needs its own probe-confirmed facts first.
- **Suite:** exit 0.

---

## Next-iteration checklist (for the loop)

1. Read the previous report's "TYPE gap for next iter".
2. Find a real, citable OSS CVE of that class (prefer high-user-count
   projects). Confirm the gap empirically first (does current Aether
   accept the bad shape?).
3. Improve Aether to reject the whole TYPE; keep the change
   one-directional/conservative so legitimate code passes.
4. Survey the repo for existing usages the new rule would flag; update
   only tests that assert the *old* permissive behavior, never silence
   the rule.
5. Add: doc row, focused test, gate line, (optional) playground example.
6. Re-run the full suite to exit 0. Write the report + append here.
