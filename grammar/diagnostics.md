# Aether Diagnostic Catalog

Every diagnostic the toolchain can emit has a stable code, a category,
a severity, and a machine-readable `extra` dict. This catalog is the
contract; the regression test `tests/test_diagnostic_catalog.py`
enforces that every code grep'd from the source tree is documented
here.

The code-number ranges are stable:

| Range       | Category               | Where emitted |
|-------------|------------------------|---------------|
| E01xx       | lex                    | `transpiler/aether/lexer.py` |
| E02xx       | parse                  | `transpiler/aether/parser.py` |
| E03xx       | contract / refinement  | `transpiler/aether/runtime.py` |
| E05xx       | effect (runtime)       | `transpiler/aether/runtime.py` (opt-in `--effect-strict`) |
| E06xx       | timeout                | `bench/harness.py` |
| E07xx       | capability             | `transpiler/aether/passes/capability.py` |
| E08xx       | effect (static)        | `transpiler/aether/passes/effects.py` |
| E09xx       | (reserved for SMT)     | unused at v0.3; reserved by `AUDIT_B.md` |
| E9xxx       | internal / harness     | `bench/harness.py` |

All codes below are listed with: short description, where they fire,
what's in `extra`, and what an agent fix-loop is supposed to do.

---

## Lex (E01xx)

| Code | Description | Fires when |
|------|-------------|------------|
| **E0101** | unexpected character | the lexer sees a character that isn't part of any token |
| **E0102** | unterminated `/* */` comment | EOF inside a block comment |
| **E0103** | unterminated string literal | EOF before closing `"` |
| **E0104** | unknown string escape | e.g. `"\q"` |
| **E0105** | expected digits after exponent | e.g. `1e` with no digits |
| **E0106** | keyword has trailing `?` / `!` | e.g. `if?` |

## Parse (E02xx)

| Code | Description | `extra` keys |
|------|-------------|--------------|
| **E0201** | parse error (unified code for every "expected X, got Y") | — |
| **E0202** | a `match` on a union omits a case and has no wildcard catch-all — non-exhaustive match / unhandled variant (static, was runtime-only) | `function`, `union`, `missing` |
| **E0203** | a `match` arm can never be reached — it follows a wildcard catch-all, or duplicates an earlier case (dead code, CWE-561) | `function`, `reason` |
| **E0204** | a statement follows an unconditional `return`/`break`/`continue` in the same block — unreachable dead code (CWE-561) | `function`, `after` |
| **E0205** | a `let` binding (not `_`-prefixed) is never read — a dead store, usually a mistaken variable (CWE-563) | `function`, `binding` |
| **E0206** | a bare statement discards the `Result<...>` of a call — an unchecked error (e.g. a failed write silently ignored, CWE-252) | `function`, `callee` |
| **E0207** | a refinement type's predicate is unsatisfiable (e.g. `Int where self >= 10 and self <= 5`) — an uninhabitable / impossible type | `type`, `lo`, `hi` |

E0201 is emitted by `Parser.err`. The lenient `parse_collect` (C.6)
accumulates all E0201 diagnostics it can recover past; strict `parse`
raises on the first.

E0202 lifts match exhaustiveness from a RUNTIME trap to a STATIC guarantee
(default-on; opt out with `--no-exhaustiveness-check`). When a match's
scrutinee has a statically-resolvable union type (from a parameter or
`let` annotation), every case of that union must be handled or a wildcard
`case _` present; otherwise the missing variants are named at check time.
Adding a new variant to a union then forces every match to be updated
before the program compiles. Conservative: if the scrutinee's union type
cannot be resolved statically, the check stays silent (no false positive).

E0203 is the complement of E0202 (same default-on step / opt-out): E0202
catches too FEW arms, E0203 catches redundant ones — an arm after a
wildcard catch-all (which already matches everything) or a duplicate
constructor case. Purely about arm ordering, so it needs no type
information and applies to every match. Together the two make match
handling total-and-minimal: every variant handled exactly once.

E0204 generalizes the reachability idea beyond match (same default-on
step / opt-out): any statement after an unconditional `return`, `break`,
or `continue` in the same block is unreachable. Purely structural — it
scans every statement list for a terminator that is not last. Always a
logic error (a stray early return, a merge artifact).

E0205 completes the static-semantic cluster with a use/def check: a `let`
binding whose name is never read is a dead store. The `_`-prefix is the
sanctioned intentional-discard convention (`let _r = writeFile(...)` keeps
the effect, drops the value) and is exempt. Same default-on step / opt-out.

E0206 is the error-handling member of the cluster (CWE-252): a bare
statement calling a `Result<...>`-returning function (stdlib `writeFile`/
`readFile`/`readLine`/`parseInt`/`parseFloat`, or any user function with a
`Result` return type) silently drops the error case. Bind and `match` it,
or use `let _r = ...` to discard explicitly. Same default-on step /
opt-out. (Scanning AI-generated candidates, this flagged 12 real ignored-
error bugs — see `bench/SCAN_FINDINGS.md`.)

E0207 closes the cluster with a light satisfiability check on refinement
types: it intersects the analyzable `self OP const` clauses of the
predicate's conjunction and refuses a type whose bounds admit no value
(reversed bounds, contradictory `==`, exclusive-touch). It is SOUND by
construction — unanalyzable clauses widen to unbounded, so it never
false-positives, at the cost of missing non-interval contradictions. Same
default-on step / opt-out.

## Contract / refinement (E03xx)

| Code | Description | `extra` keys |
|------|-------------|--------------|
| **E0301** | `requires` (precondition) violation | `function`, `clause_kind="requires"`, `clause_text`, `args` |
| **E0302** | refinement-type boundary violation (B.4) | `type`, `binding`, `predicate`, `value_repr` |
| **E0303** | refinement predicate raised exception (B.4) | `type`, `binding`, `predicate`, `value_repr` |
| **E0304** | `ensures` (postcondition) violation (D.2 split from E0301) | `function`, `clause_kind="ensures"`, `clause_text`, `args` |
| **E0305** | stdlib precondition violation (D.2 split from E0301) | `stdlib_function`, optionally `value` |

**Caller-vs-implementer split (D.2):** `E0301` always means "the caller
gave bad input"; `E0304` always means "the implementation lied about
what it returns". An agent fix-loop can read the code alone and decide
where to apply the fix.

## Effect — runtime (E05xx)

These fire at runtime when `--effect-strict` is enabled or
`set_effect_strict(True)` is called. The static checks (E0801) are
default-on and catch most cases before runtime.

| Code | Description |
|------|-------------|
| **E0501** | effect performed inside a function declared `pure` |
| **E0502** | effect not in the function's declared effect set |

## Timeout (E06xx)

| Code | Description | `extra` |
|------|-------------|---------|
| **E0601** | program execution exceeded `timeout_ms` | `timeout_ms` |

Bench-harness only. The CLI does not currently enforce timeouts;
`bench/harness.py:compile_and_run` does, via POSIX `SIGALRM`.

## Capability (E07xx)

| Code | Description | `extra` keys |
|------|-------------|--------------|
| **E0701** | function's transitive effect closure requires a capability not declared by any module | `function`, `effect`, `required_capability`, `declared_capabilities`, `via_transitive` |
| **E0702** | module exports a name that isn't declared in this file (D.3) | `module`, `exported`, `declared_names` |
| **E0703** | more than one `module ... end` in a single file (v0.3 is single-file; D.3) | `first_module`, `duplicate_module` |
| **E0704** | module requires a capability outside the known vocabulary (D.3) | `module`, `capability`, `known` |
| **E0705** | an `import` names a file that does not exist beside the importing file, or exists but cannot be read (H.E.3) | `resolved_to`, `path` (unreadable file: `resolved_to`, `os_error`) |
| **E0706** | imports form a cycle — A imports B, B imports A (H.E.3). File-level: the cycle is detected during the DFS, past the `ImportDecl` position | `file`, `stack` |
| **E0710** | a `net.fetch` effect leaves the host/authority unpinned (bare `*`, `scheme://*`, wildcard scheme, a leading `*` that is not a `*.subdomain` pin, or any other `*` in the authority — `*.*`, `api.*`, `a*`, `api.example.com*`, `[*]`, a userinfo-masked `user@*`, or a `*.tld` pin with no registrable domain), admitting SSRF to internal hosts like `169.254.169.254` | `function`, `effect_arg`, `reason` |
| **E0711** | `readFile`/`writeFile` is called with a path that is neither a fixed string literal nor routed through `safeJoin(...)`, i.e. a path steerable by untrusted input (path-traversal / Zip-Slip precondition) | `function`, `sink`, `reason` |
| **E0712** | a `Secret<...>`-marked value reaches a log sink (`print`) or is persisted to disk (`writeFile` contents) without an explicit `reveal(...)` — the "secret accidentally logged/written" class (CWE-532) | `function`, `sink` |
| **E0713** | a `sqlQuery`/`sqlExec` query argument is built by raw string concatenation (or another dynamic expression) instead of a fixed literal or `sqlBind(...)` parameterized query — SQL injection (CWE-89) | `function`, `sink`, `reason` |
| **E0714** | a `shellExec` argument is built by raw string concatenation (or another dynamic expression) instead of a fixed literal or `shellArg(...)`-quoted command — command injection (CWE-78) | `function`, `sink`, `reason` |
| **E0715** | a `PII<...>`-marked value reaches a log sink (`print`) or the contents of `writeFile` without `redact(...)` — personal data persisted/logged in the clear (data-residency / GDPR leak) | `function`, `sink` |
| **E0716** | a data-mutating sink (`sqlExec`) is called without an authorization proof in its dataflow — the auth argument is absent or not a proven `Authorized<...>` value (an `authorize(...)` call, an `Authorized<T>` parameter, or a binding of one) — missing authorization (CWE-862/863) | `function`, `sink`, `reason` |
| **E0717** | a resource-scoped mutation (`sqlByOwner(stmt, resourceId, proof)`) whose `proof` is not an `authorizeResource(principal, action, resourceId)` result bound to the SAME `resourceId` the sink mutates — missing, unbound, or wrong-resource authorization — IDOR / cross-tenant data access (CWE-639) | `function`, `sink`, `reason` |
| **E0718** | a `redirect` target is neither a fixed literal nor a `safeRedirect(host, path)` result — an untrusted/dynamic redirect target (open redirect, CWE-601) | `function`, `sink`, `reason` |
| **E0719** | a `renderTemplate` template argument is not a fixed string literal (built by concatenation or from a parameter) — server-side template injection (SSTI / RCE, CWE-94) | `function`, `sink`, `reason` |
| **E0720** | a `deserialize` argument is untrusted (non-literal) data instead of a `schemaDecode(schema, data)` call — insecure deserialization (pickle/readObject RCE, CWE-502) | `function`, `sink`, `reason` |
| **E0721** | a `net.fetch` scope uses the `http://` scheme to a non-loopback host — cleartext transmission of credentials/PII (CWE-319). Loopback is host-exact (`localhost`, `0.0.0.0`, a `127.0.0.0/8`, `::1` or `::ffff:127.x` address literal, userinfo/port/brackets stripped); `127.0.0.1.evil.com`, `127.0.0.1@evil.com` and an obfuscated spelling like `2130706433` are not loopback | `function`, `effect_arg`, `reason` |
| **E0722** | a `net.fetch` scope is pinned to the link-local range `169.254.0.0/16` in any spelling (dotted, decimal, hex, octal, short, IPv4-mapped IPv6, with userinfo/port), the AWS IPv6 IMDS `fd00:ec2::254`, or a cloud metadata name (`metadata.google.internal`, `metadata`, `instance-data`, Alibaba `100.100.100.200`) — server-side metadata request / IAM-credential theft (CWE-918) | `function`, `effect_arg`, `reason` |
| **E0723** | a string literal matches a known provider-credential shape (AWS `AKIA…`, GitHub `ghp_…`, Google `AIza…`, Slack `xox…` / incoming-webhook URL, Stripe `sk_live_…`, OpenAI `sk-proj-…` / `sk-…`, Anthropic `sk-ant-…`, Hugging Face `hf_…`, Groq `gsk_…`, Google OAuth `ya29.…`, GitLab `glpat-…`, SendGrid `SG.….…`, npm `npm_…`, PyPI `pypi-…`, a PEM private key with a base64 body) — a hardcoded secret in source (CWE-798); positioned at the literal | `credential_kind` |
| **E0724** | an `Untrusted<...>`-marked value reaches a log sink (`print`) without `sanitizeLog(...)` — log injection / forging via embedded CR/LF (CWE-117) | `function`, `sink` |
| **E0725** | an `Untrusted<...>`-marked value reaches an HTML response (`htmlResponse`) without `htmlEscape(...)` — reflected cross-site scripting (CWE-79) | `function`, `sink` |
| **E0726** | an `Untrusted<...>`-marked value reaches a response header (`setHeader`) without `sanitizeHeader(...)` — HTTP response splitting / header injection (CWE-113) | `function`, `sink` |
| **E0727** | a `parseXml` argument is untrusted (non-literal) instead of a `parseXmlSafe(data)` call — XML external entity injection (file read / SSRF, CWE-611). On Python the text is per resolved callee (iteration 53, measured): `lxml.etree` — read local files through external entities by default before lxml 5.0 and under `resolve_entities=True`, a URL only with `no_network=False` as well; a parser bound in the same function with `resolve_entities=False` (and `no_network`/`load_dtd`/`dtd_validation` absent or at their safe value), passed positionally or as `parser=`, clears it. `xml.sax.parse`/`parseString` — build their own parser with external entities off (since Python 3.7.1) and take no parser argument, so no XXE through entities. `xml.dom.minidom`/`xml.dom.pulldom` — off by default, but a `parser=` built with `make_parser()` and `feature_external_ges` reads files and fetches URLs. `xml.etree.ElementTree`/`cElementTree` `parse`/`fromstring` — called without a parser argument, never expand external entities, on any Expat; a parser passed in (`parser=` or positionally) is used as given, and measured (BUG-031) an lxml `XMLParser(resolve_entities=True)` reads local files through them (and fetches URLs with `no_network=False`) and a `make_parser()` with `feature_external_ges` reads local files and fetches URLs. `xml.dom.expatbuilder` — takes no parser argument and never expands external entities, on any Expat. Every `parse()` spelling adds that its source string is itself opened as a local path (`xml.sax.parse`, `lxml.etree.parse`: or fetched as a URL), which no row judges. Every stdlib row adds the docs' hedged DoS clause (an older Expat, possibly the system copy, may be open to billion laughs / quadratic blowup below 2.4.1, large tokens below 2.6.0, disproportional memory use below 2.7.2) and names the `defusedxml` equivalent without a parser argument (`parser=` or positional), or else no parser argument plus a `pyexpat.version_info >= (2, 7, 2)` startup check (the check alone covers only the DoS clause). `defusedxml.minidom`/`pulldom` `parse`/`parseString` and `defusedxml.ElementTree.parse` handed a caller's `parser=` are the sink themselves (defusedxml defuses only the parser it builds; `parser` absent or `None` is clean) | `function`, `sink`, `reason`; on Python also `match` and `callee` |
| **E0728** | an `Untrusted<...>`-marked value reaches a CSV cell (`csvCell`) without `csvEscape(...)` — spreadsheet formula injection (CWE-1236) | `function`, `sink` |
| **E0729** | a `Secret<...>`/`PII<...>`/`Untrusted<...>`-marked value is passed to a user-function parameter not typed with that marker — the callee holds the value with the marker erased, blinding every downstream sink check (taint laundering). Sanctioned exits: the marker's unwrapper (`reveal`/`redact`/the per-sink sanitizers/`trusted`) at the call site, or a marker-typed parameter. Two crossings the row also refuses: (a) a call **through a function-typed parameter** (`f: function(String) returns Unit`, `grammar.ebnf` line 88) — the callee is chosen by the caller's caller and is unknown here, so no sanctioned crossing exists and only unwrapping at the call site clears it (`extra.via = "function_type"`); an alias of such a parameter (`let g = f`) is the same callee and `extra.param` names the parameter (BUG-025); (b) a crossing cleared by the **wrong sanitizer** — a sanitizer is sink-specific, so `sanitizeLog(u)` into a callee that feeds `htmlResponse` is still refused, naming what cleared it and what the reached sink demands. A parameter that reaches the sink only THROUGH that sink's own sanitizer (`htmlResponse(htmlEscape(s))`) does not reach it raw and is accepted (BUG-024); any other wrapper still leaks (`trusted(...)`, an explicit assertion rather than a sanitizer, still clears) | `function`, `callee`, `param`, `marker`; plus `via`, or `cleared_with`/`reaches_sink`/`needs` |
| **E0730** | a function returns a `Secret<...>`/`PII<...>`/`Untrusted<...>`-carrying value while its declared return type does not carry the marker — every caller receives the value with the marker washed off (return laundering, the dual of E0729). Sanctioned exits: declare the marker-typed return, or unwrap (`reveal`/`redact`/the per-sink sanitizers/`trusted`) at the return site | `function`, `marker`, `declared_return` |
| **E0731** | an `evalCode` source argument is not a fixed string literal (built by concatenation, from a parameter, or by another call) — an interpreter fed attacker-authored source is arbitrary code execution (code injection, CWE-94/95). On Python: `exec`/`eval`/`compile` on a non-literal | `function`, `sink`, `reason` |

E0701 comes from the B.3 default-on capability pass. E0702/E0703/E0704
come from the D.3 module-validation pass — also default-on, opt out
with `--no-module-check`. Programs without any module declaration
retain an implicit all-grant; the module pass is a no-op for them.

E0705/E0706 come from the H.E.3 import-resolution pass
(`passes/imports.py`), which resolves each `import` to a sibling
`.aeth` file and refuses a cycle instead of recursing. Both were live
and tested from the day they shipped but documented nowhere until
2026-07-25: they are constructed as `_diag("E07xx", …)`, passing the
code POSITIONALLY, and the catalog scanner only recognised the keyword
and dict forms. See `docs/adr/0002-diagnostics-md-stays-hand-written.md`
and `tools/diagnostic_codes.py`.

E0710 comes from the broad-scope pass — default-on, opt out with
`--no-scope-check`. It refuses the *promise* itself when a fetch scope
is broad enough to be steered inward, closing the SSRF precondition
that E0801/E0701 (which a wildcard scope satisfies) cannot see.
Path/query wildcards (`https://api.x/charge/*`) and subdomain pins
(`https://*.corp.example/*`) keep the host bounded and pass untouched.

E0711 is the filesystem sibling from the same reach-scope pass (also
default-on, same `--no-scope-check` opt-out). A `readFile`/`writeFile`
path that is a fixed literal, or is built with the `safeJoin` stdlib
sanitizer (which strips `..` and absolute roots), is safe; any other
path expression is steerable by untrusted input and is refused —
closing the path-traversal / Zip-Slip precondition.

E0712 is the taint sibling in the same reach-scope pass. `Secret<T>` is
a compile-time-only marker type (erased at runtime); taint originates at
`Secret`-typed parameters and propagates through straight-line bindings.
A value still carrying the marker cannot reach `print` nor the contents
of `writeFile` (persisting a credential to disk is the same leak as
logging it); `reveal(...)` is the sanctioned, auditable disclosure that
clears it. `classify(x)` wraps a value as `Secret<T>`. Same
`--no-scope-check` opt-out.

Since iteration 39, taint for the confidentiality markers (`Secret<T>`,
`PII<T>`, `Untrusted<T>`) ALSO originates at calls to functions whose
declared return type carries the marker — the stdlib constructors
(`classify`/`classifyPII`/`classifyUntrusted`) and any user function
declared `returns Secret<...>` etc. This is signature-level
interprocedural seeding: declared types are trusted, bodies are not
analyzed. An argument consumed by a marker-typed parameter of a
user-declared callee is a sanctioned crossing (the callee's own body is
checked; what escapes is its return, covered by the same seeding). The
dual guard is **E0729**: a marked value passed to a parameter NOT typed
with the marker is refused as laundering. `Authorized<T>` (E0716/E0717)
keeps its own machinery and is deliberately outside both rules — it is a
proof marker, and widening acceptance there would relax, not tighten.
Iteration 40 closes the remaining direction with **E0730**: a body that
returns a marker-carrying value under a plain declared return type is
refused, so declared signatures are enforced on the way out as well as
trusted on the way in.
Iteration 41 fixed a false accept in the shared dataflow: `match`-arm
pattern bindings destructured from a tainted scrutinee are now tainted
(every arm, every binding — conservative), so wrapping a marked value
in `Some(...)`/`Ok(...)` and unwrapping it via `match` no longer washes
the marker.
Iteration 42 resolved function ALIASES (`let f = logIt; f(secret)`)
across every boundary mechanism, conservatively: an alias joins the
taint-source set and E0729 checks every function it may name, but an
aliased unwrapper (`let r = reveal`) never clears taint — recognizing
sanctioned exits by name at the call site is the audit contract, and
the alias over-flag is deliberate.
A marker also travels inside the two containers Aether has: a generic type
argument (`List<PII<String>>`, `Option<Secret<T>>`) and a record field
(`record User do email: PII<String> end`). Reading a marker-typed field is
a taint source; constructing the record with a marked value into that field
is a sanctioned crossing, so it raises neither E0729 nor E0730. Putting a
marked value into a PLAIN field still launders the marker and is refused.
Record fields are matched by NAME, not by resolved record type — an
over-flag, not inference.

E0713 is the injection sibling in the same reach-scope pass. The
`sqlQuery` sink (effect `db.query`) must receive a fixed string literal
or a `sqlBind(template, value)` parameterized query (which escapes the
value so it cannot break out of the string). A raw `+` concatenation or
any other dynamic query expression is refused. Same `--no-scope-check`
opt-out; same sink+sanitizer+literal shape as E0711/`safeJoin`.

E0714 is the command sibling of E0713 (the OpenSSL `c_rehash`
CVE-2022-1292 shape: a filename concatenated into a shell command line).
The `shellExec` sink (effect `exec.run`, capability `exec`) must receive
a fixed string literal or a `shellArg(template, value)` result (which
quotes the value as a single argument so it cannot inject `;`/`|`/`$( )`
shell syntax). A raw `+` concatenation or any other dynamic command
expression is refused. Same `--no-scope-check` opt-out.

E0715 is the PII-egress sibling of E0712 in the same reach-scope pass:
same taint machinery, distinct marker `PII<T>` and distinct sanctioned
exit `redact(...)` (which masks the value — emails keep first char +
domain). A PII value must not reach `print` (logs) or the contents
argument of `writeFile` (disk) in the clear. `classifyPII(x)` wraps a
value as `PII<T>`. This is the data-residency / GDPR-leak class. Same
`--no-scope-check` opt-out. (Network-body egress is deferred until a
body-carrying stdlib net sink exists.)

E0716 inverts the taint polarity of E0712/E0715 in the same reach-scope
pass: instead of "a marked value must not reach a sink", a mutating
sink REQUIRES a marked value in its dataflow. `sqlExec(stmt, auth)` —
a data-mutating statement (effect `db.exec`, capability `db`) — must
receive as `auth` a proof of authorization: a direct
`authorize(principal, action)` guard call, an `Authorized<T>`-typed
parameter (the caller authorized; the proof crosses the call boundary),
or a name bound only to those. Omitting the argument or passing
anything unproven is refused — the missing-authorization class
(CWE-862/863; the Ivanti EPMM CVE-2023-35078 shape: a mutating API
path reachable with no auth check on it). Conservative direction: a
proof the checker cannot see is refused (over-flag, never miss).
`sqlExec`'s query argument is additionally covered by E0713. Same
`--no-scope-check` opt-out.

E0717 is the resource-binding extension of E0716 in the same reach-scope
pass. E0716 proves *an* authorization happened on the dataflow — but not
that it named the SAME resource being mutated, so an authorized caller
can still reach ANOTHER tenant's row (broken object-level authorization
/ IDOR, CWE-639, OWASP API1). The resource-scoped sink
`sqlByOwner(stmt, resourceId, proof)` (effect `db.exec`, capability
`db`) requires its `proof` to be an `authorizeResource(principal,
action, resourceId)` result — a direct call or a name bound exactly once
to one — whose id expression resolves to the same identity as the sink's
`resourceId`: an identical literal, or the same *stable* name (a
parameter or a name bound exactly once, so it denotes one value for the
whole body). Anything the checker cannot relate — a computed id, a
rebound name, a proof carried across a call boundary as a plain
`Authorized<T>` parameter — is refused (over-flag, never miss).
`sqlByOwner`'s statement argument is additionally covered by E0713.
Same `--no-scope-check` opt-out.

E0718 is the open-redirect sibling of E0711 in the same reach-scope pass
(CWE-601). The `redirect` sink (effect `net.redirect`, capability `net`)
must receive a fixed literal target or a `safeRedirect(host, path)`
result, which strips any scheme/authority and leading slashes from
`path` so the target can only ever stay on `host` (defeating both
absolute-url and protocol-relative `//evil.com` redirects). A bare
parameter, a concatenation, or any other dynamic target is refused.
Same `--no-scope-check` opt-out.

E0719 is the template-injection sibling of E0713 in the same reach-scope
pass (CWE-94, the Jinja2/Flask/Handlebars SSTI shape). `renderTemplate`'s
first argument — the template — must be a fixed string literal (or a name
bound only to literals). Untrusted input belongs in the second (data)
argument, which the engine escapes rather than evaluates; a template
built by concatenation or from a parameter lets user input steer template
syntax (arbitrary code execution) and is refused. No sanitizer — the fix
is a fixed template. Same `--no-scope-check` opt-out.

E0720 is the deserialization sibling in the same reach-scope pass
(CWE-502, the pickle / Java `readObject` / unsafe-YAML gadget class).
Feeding untrusted bytes to an unrestricted decoder that can instantiate
arbitrary types is remote code execution. Like SSTI there is no safe way
to `deserialize` untrusted input — the sanctioned form is
`schemaDecode(schema, data)`, a decoder pinned to a fixed schema that can
only produce the declared shape. `deserialize` on any non-literal
argument is refused; `schemaDecode(...)` on any data passes. Same
`--no-scope-check` opt-out.

E0721 is the cleartext-transmission sibling of E0710 in the same
reach-scope pass (CWE-319). E0710 checks that a `net.fetch` host is
*pinned*; E0721 checks the *scheme* — a pinned `http://` host satisfies
E0710 but still sends credentials and PII unencrypted, readable by any
passive network observer. Loopback hosts (`localhost`, `127.0.0.0/8`,
`::1`, `0.0.0.0`) are exempt — that traffic never leaves the machine. The
exemption is host-exact: the host is what remains after userinfo, port
and IPv6 brackets are stripped, so `127.0.0.1@evil.com` is `evil.com`,
`127.0.0.1.evil.com` is a public name, and an obfuscated spelling
(`2130706433`) is not a sanctioned loopback. The fix is the `https://`
scheme. Same `--no-scope-check` opt-out.

E0722 is the metadata-fetch sibling of E0710 in the same reach-scope pass
(CWE-918). E0710 refuses an *unpinned* scope; E0722 refuses a scope
*pinned* to the link-local range `169.254.0.0/16`, which holds the cloud
metadata endpoint `169.254.169.254` (AWS/GCP/Azure IMDS) — a pinned
metadata host satisfies E0710/E0721 yet is the crown-jewel SSRF target for
IAM-credential theft. The host is canonicalised before the range test —
decimal, hex, octal and short IPv4 spellings, IPv4-mapped IPv6, userinfo
and port are all read as the address they resolve to — and the
provider names (`metadata.google.internal`, `metadata`, `instance-data`,
`100.100.100.200`) and the AWS IPv6 endpoint `fd00:ec2::254` are refused
by name. Application code should obtain credentials through the
SDK/credential provider, never a raw metadata request. Private RFC-1918
ranges are deliberately NOT flagged (legitimate in service meshes). Same
`--no-scope-check` opt-out.

E0723 is a new detector family — a **literal-content scan** (not effect
or dataflow): every string literal is matched against high-confidence
provider-credential shapes (AWS/GitHub/Google/Slack/Stripe/OpenAI/
Anthropic/Hugging Face/Groq/GitLab/SendGrid/npm/PyPI/PEM). A match is a
hardcoded secret (CWE-798) — committed to version control forever,
shipped in every build. The patterns are deliberately narrow so false
positives are near zero (a demo password like `"hunter2"` does not match;
a real `AKIA…` key does; a PEM header quoted in an error message without
a base64 body does not). Fix: load the secret at runtime from the
environment / a secret manager. Same `--no-scope-check` opt-out.

E0724 introduces the taint-SOURCE marker `Untrusted<T>` — the sound,
explicit dual of provenance inference. A value crossing a trust boundary
(a request field, an uploaded filename) is marked `Untrusted` there;
logging it raw lets embedded CR/LF forge fake log lines (audit-log
poisoning). It reuses the same taint machinery as E0712/E0715 (origin at
`Untrusted`-typed params, straight-line propagation); `sanitizeLog(...)`
strips the control characters and is the sanctioned exit. `classifyUntrusted(x)`
marks a value. Same `--no-scope-check` opt-out.

E0725 is the second sink for the `Untrusted<T>` marker (CWE-79, reflected
XSS): an untrusted value written into an HTML response (`htmlResponse`)
without escaping executes as markup in the victim's browser. The sanctioned
exit is `htmlEscape(...)` — and it is sink-SPECIFIC: `sanitizeLog` (which
clears E0724) does NOT clear E0725, because stripping CR/LF does not
neutralize `<script>`. This is the key property of per-sink sanitizers —
the right exit for one sink is not the right exit for another. Same
`--no-scope-check` opt-out.

E0726 is the third `Untrusted<T>` sink (CWE-113, response splitting): an
untrusted value in a response header whose embedded CR/LF injects headers
or a second response (cache poisoning, forged Set-Cookie). The sanctioned
exit is `sanitizeHeader(...)`. The three Untrusted sinks now cover the
common HTTP-output contexts — log (E0724), HTML body (E0725), header
(E0726) — each with its own context-correct sanitizer. Same
`--no-scope-check` opt-out.

E0727 is the XXE sibling of E0720 (CWE-611) — a parser-CONFIG class, not a
content-escaping one. `parseXml` (external entities enabled) reads local
files and reaches internal URLs from a crafted `<!ENTITY SYSTEM ...>`; it
is refused on untrusted (non-literal) input. `parseXmlSafe(data)` disables
entity resolution and is the sanctioned alternative. Same `--no-scope-check`
opt-out. On Python the mapped stdlib parsers are NOT that parser: "By
default, Expat itself does not access local files or create network
connections" (Python docs, `library/xml.html`, "XML security"), so a
stdlib callee's message says where the XXE read actually is (a `parser=`
SAX parser with `feature_external_ges` on minidom/pulldom; on ElementTree
a caller's parser, keyword or positional, which it uses as given — an lxml
`XMLParser(resolve_entities=True)` or that SAX parser reads the file,
BUG-031; nowhere on ElementTree without a parser argument, on expatbuilder,
which takes none, or on `xml.sax.parse`/`parseString`), hedges the
DoS clause the way the docs do, names the `defusedxml` equivalent, and on
a `parse()` spelling adds that the source string is itself opened as a
path or URL — a hazard no row judges; lxml's keeps the file-read wording,
stated as conditional (the default before 5.0, `resolve_entities=True` on
any version, a URL only with `no_network=False`; lxml 6.1.1's default
parser read nothing) and names the parser binding, which the
frontend clears in either slot. The sink set and the argument rule are
identical for every callee; only the text differs
(`LiteralOrWrapperSpec.callee_text`, iteration 53). Every Python-translated
finding of a literal-or-wrapper row (E0711/E0713/E0714/E0718/E0719/E0720/
E0727/E0731) also carries `match` (how the frontend named the sink,
`transpiler/aether/confidence.py`) and `callee` (the spelling the frontend
resolved: a dotted import path on a `qualified`/`guard`/`argv` match, the
builtin name on `builtin`/`builtin_compile`; on a `method` match, the bare
method name when the receiver is a plain variable — `execute` for
`cur.execute(...)` — the attribute path as written when it is chained —
`self.conn.execute` — and the resolved dotted path when the receiver is
an imported name). Only these rows carry `callee` on Python; `E0723`,
`E0701` and the sink rows on Aether source do not.

E0728 is the fourth `Untrusted<T>` sink (CWE-1236) and the first in a
NON-HTTP context — proving the marker generalizes past web output. A CSV
cell of exported data that begins with `=` `+` `-` `@` is interpreted as a
formula when opened in Excel / Google Sheets (`=WEBSERVICE(...)` exfil,
DDE → code execution). `csvEscape(...)` neutralizes a leading trigger and
is the sanctioned exit. Same `--no-scope-check` opt-out.

E0731 is the code-injection sibling of E0719 in the same reach-scope
pass (CWE-94/95, the agent-framework "run the code the model wrote"
shape: `exec(tool_code)`, `eval(expr)`, `compile(src, ...)`). `evalCode`'s
argument — the source an interpreter will run — must be a fixed string
literal (or a name bound only to literals). A source built by
concatenation, taken from a parameter, or produced by any other call is
refused: whatever authored it decides what runs, with the process's full
privileges. Like SSTI there is no sanitizer — there is no way to escape
attacker-authored code into something safe to run — so the sanctioned
form is the fixed literal and `trusted(...)` is the auditable escape
hatch for a source the program vouches for (a script bundled with the
application). On Python, `exec`/`eval`/`compile` map to this sink;
`ast.literal_eval` does not (literals only), and a local `def exec(...)`
is not the builtin. Same `--no-scope-check` opt-out.

E0719, E0720 and E0731 also accept an explicit `trusted(...)` argument —
the auditable trust boundary (the dual of `reveal`/`redact`) for a vetted
dynamic source (a config bundle, a template from a trusted store). It is
deliberately narrow: only these three no-sanitizer sinks honor it, and it
only relaxes the check, so it is strictly non-breaking. Wrapping
attacker-controlled input in `trusted()` is the one misuse — visible in
review by construction.

## Effect — static (E08xx)

| Code | Description | `extra` keys |
|------|-------------|--------------|
| **E0801** | callee's effects not covered by caller's declared set (B.1 + B.2). A function passed as a **value** counts as a callee: its effects run under the call it is handed to, so `apply(logIt, s)` from a `pure` caller is refused (`extra.via = "function_value"`). A pure function value adds nothing — `map(double, xs)` stays clean. The name is resolved as a function only when nothing local shadows it: a `String` parameter or a `let` named after a function is a VALUE (BUG-024). A local alias binding still counts — `let g = logIt  apply(g, s)` reports `logIt` with `g` named in the message | `caller`, `callee`, `caller_effects`, `missing_effect`, optional `via` |

Default-on. Opt out per-file with `aether check --no-static-effects`.
Glob-matching on effect args (B.2) is part of this code.

## Internal / harness (E9xxx)

These are emitted by `bench/harness.py` only, when something below the
Aether layer fails. They don't indicate user-code bugs; they indicate
toolchain/sandbox/etc. issues.

| Code | Description |
|------|-------------|
| **E9001** | emit error (Python `compile()` rejected the emitted source) |
| **E9002** | internal error (parser/emitter raised something other than `AetherError`) |
| **E9003** | Python runtime error inside the candidate (e.g. divide-by-zero with no precondition) |

## SMT contract proving — E09xx (default-on when z3 is installed)

Emitted by `transpiler/aether/passes/smt.py`. The pass runs by default on
`aether check` whenever the optional `z3-solver` dependency is importable
(`pip install 'aether-lang[smt]'`); `--no-prove` disables it, `--prove`
forces it (and errors with an install hint when z3 is missing). On
z3-less installs the pass is skipped silently — the core stays
zero-dependency.

| Code | Description | `extra` fields |
|------|-------------|----------------|
| **E0901** | SMT-refuted `ensures` clause: the solver found concrete inputs that satisfy every `requires` clause and every param refinement predicate but violate the postcondition | `function`, `clause_kind="ensures"`, `clause_index` (0-based), `counterexample` |
| **E0902** | SMT solver returned `unknown` (usually the per-obligation timeout, default 5000 ms, `--prove-timeout-ms`); warning — the clause keeps its runtime check | `function`, `clause_kind`, `clause_index`, `timeout_ms` |

E0901's `counterexample` maps param names (plus `result`) to the
violating values, so a fix-loop can re-prompt with them.

The pass only analyzes a restricted fragment (Int/Bool params,
single-`return` bodies, linear arithmetic without `/` and `%`);
everything else is counted `skipped` in the `prove:` summary and keeps
runtime checks. A function whose `requires` clauses or param
refinements do not translate is skipped entirely — dropping an
assumption would fabricate spurious counterexamples.

---

## Risk ratings (the triage axis)

Every code carries a second, orthogonal rating in
`transpiler/aether/risk.py`: a **risk** of `critical`, `high`, `medium`,
`low` or `info`.

- **`severity`** (on the `Diagnostic` itself) answers *does the run
  fail?* — `error` refuses the program, `warning` does not.
- **`risk`** answers *what does a reviewer read first?* — it ranks a
  finding against the other findings in a scan.

The two are independent: a parse error is `severity: error` (the
compiler refuses it) and `risk: info` (it is not a security finding).

A rating is a **triage heuristic about the class**, fixed per code — the
blast radius a violation of that class typically carries. It is not
CVSS, is not computed per finding, and must not be presented as a
measurement of a specific bug's impact.

Ratings are consumed by `tools/scan.py`:

- findings sort worst-first, then by line;
- `--min-risk <rating>` reports only findings at or above a floor, and is
  refused together with `--expect` (exit 2) since a filtered-out
  declared code would otherwise read as a regressed detector;
- SARIF maps `critical`/`high` → `level: error`, `medium` → `warning`,
  `low`/`info` → `note`, and sets each rule's `security-severity`
  property (critical 9.0, high 7.0, medium 5.0, low 3.0, info 1.0) so
  GitHub Code Scanning ranks them.

`tests/test_risk.py` fails if any emitted code lacks a rating, or if the
table rates a code the tree never emits.
