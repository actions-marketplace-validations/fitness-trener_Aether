---
type: question_page
question_id: q1
status: answered
confidence: high
last_updated: 2026-09-03
tags: [effect-system, capability-model, diagnostics]
---

# What is the soundness boundary of the taint-marker passes (E0712, E0715, E0716, E0717)?

## Short Answer

The taint passes are **syntactic and intraprocedural**, and deliberately
**over-flag rather than miss**. Taint originates only at marker-typed
*parameters* (`Secret<T>`, `PII<T>`, `Authorized<T>`) and propagates only
through *straight-line let/assign bindings* inside one function body
`[source: diagnostics, section: E0712]`. There is no interprocedural
flow, no flow through collections/records, and no value-equality — id
matching in E0717 is by identical literal or same never-rebound name
only. The design contract across every pass is **conservative**: a value
whose provenance cannot be proven safe is refused, so a false *accept*
(a real leak that slips through) is the bug that must never happen; a
false *reject* (over-strict) is acceptable and repaired by the sanctioned
exit (`reveal`/`redact`/`authorize`). This is sound in the "no missed
violation within the modeled surface" sense, **not** in the
whole-program dataflow sense. *Updated iter 39:* function-boundary flow
for the three confidentiality markers is now handled at **signature
level** — taint also seeds from calls to functions whose *declared
return type* carries the marker, and a marked value crossing into an
un-marked parameter is refused as laundering (E0729), with marker-typed
parameters as the sanctioned crossing. Declared signatures are the trust
boundary; bodies are still not analyzed across calls.

## Evidence

| Finding | Evidence | Confidence |
|---|---|---|
| Taint starts at marker-typed params only | `_marked_tainted_names` seeds from `params` with `_is_marker_type` `[source: diagnostics, section: E0712]` | high |
| Propagation is straight-line let/assign fixpoint | shared helper collects `Let`/`Assign` binds, no call-return modeling | high |
| Over-flag, never miss (the contract) | every pass' residual-limit note says "over-flag, not miss" (LOOP_LOG iters 3,6,7,8) | high |
| E0717 id identity is syntactic | iter-8 residual: identical literal or same stable name; differently-named aliases refused | high |
| A marker crossing a function boundary is refused, not tracked | E0717 refuses a bare `Authorized<String>` param carrying no resource id | high |
| Sink *coverage* per marker is a per-pass list, extensible cheaply | iter-11: E0712 sink set widened `{print}` → `{print, writeFile-contents}` via a sink-spec dict, mirroring E0715; the marker/dataflow core was untouched | high |
| The trusted-dynamic over-flag has an explicit-boundary escape, not a full provenance pass | iter-13: `trusted(x)` clears E0719/E0720 (the two no-sanitizer sinks) — the dual of `reveal`/`redact`. It relaxes only, so it is non-breaking, but it is an *assertion*, not *inference*: real source-taint (auto-mark `readFile`/network reads) remains unbuilt | high |
| Taint now seeds from marker-typed RETURN signatures | iter-39: `_marker_source_fns` (stdlib `classify`/`classifyPII`/`classifyUntrusted` + user `returns Secret<...>` decls) feeds the shared fixpoint for E0712/E0715/E0724/E0725/E0726/E0728; signature-level only — a body that returns a tainted local under a plain declared return type still launders (residual: body-level return-taint inference unbuilt) | high |
| Marker→unmarked-param crossings are refused, not tracked | iter-39: E0729 flags Secret/PII/Untrusted into a plain param of a user-declared callee; marker-typed params are the sanctioned crossing (arg pruned in the leak walk — the callee owns the value, its return is covered by seeding). Residuals: stdlib transforms (`trim(secret)`) out of scope; HOF/function-typed callees skipped; `Authorized<T>` deliberately excluded (proof marker — seeding/laundering rules there would RELAX acceptance, the wrong direction) | high |
| Body-level return laundering CLOSED | iter-40: E0730 refuses a marker-carrying `Return` value under a plain declared return type. With seeding + E0729 + E0730 the declared signature is enforced in BOTH directions — "signature-level" no longer means "signature-trusted". Sanctioned exits mirror E0729 (declare the marker-typed return, or unwrap at the return site) | high |
| Match-destructure MISS found & CLOSED | iter-41 (BUGS.md BUG-001, fixed 8d928d9): arm bindings over a tainted scrutinee were fresh untainted names — a genuine FALSE ACCEPT inside the modeled surface, the contract-breach class. Fixed by conservative all-arm propagation in `_marked_tainted_names`; regression ratchet-locked via the fixed-bugs layer | high |
| CORRECTION: "stdlib transform propagation" residual was PHANTOM | iter-41 probe: `print(trim(pw))` and `let t = trim(pw); print(t)` both already fire E0712 — the leak walk's generic recursion into unmodeled calls over-flags stdlib transforms at sinks, bindings, and returns. The iter-40 residual note was written without a probe. **Lesson: residuals enter the backlog only probe-confirmed, exactly like gaps** | high |
| Function-alias laundering MISS found & CLOSED | iter-42 (BUGS.md BUG-002, fixed f6b8bf3): callee/source resolution was by declared name only — `let f = logIt; f(secret)` bypassed E0729 and `let f = getToken; f()` defeated seeding, both exit 0. Fixed by per-function alias resolution (`_fn_aliases`) applied flag-more only; single-target aliases extend the sanctioned-crossing mask; aliased unwrappers deliberately NOT honored (documented, test-pinned over-flag) | high |
| The 13 sink detectors are TWO shapes, and collapsing them moved the boundary nowhere | candidate 02: 6 marker-flow + 7 literal-or-wrapper rows now drive off `passes/detector_specs.py`; `(code, line, message, suggestion)` is byte-identical across the 83-file corpus, all 427 in-tree `.aeth`, and a 67-row synthetic probe covering every reason branch. The marker→unwrapper map E0729/E0730 read is now DERIVED from the marker-flow rows, so a new row extends both without editing them | high |
| E0711's safe-name pass is single-pass, not a fixpoint — latent, not live | candidate-02 probe across all 427 in-tree `.aeth`: single-pass and fixpoint resolution of `_safe_names` agree on every file. A fixpoint would prove a superset of names safe (relax direction). Recorded as a precision knob, NOT a residual — probe found no live difference, per the iter-41 lesson | high |
| Container-carried markers CLOSED — generic args and record fields | iter-44: `_is_marker_type` matched a marker only at the TOP of a type node, so `List<PII<String>>` params and `record User do email: PII<String> end` field reads were both **exit 0** (probe-confirmed on `f98fdce`) — a genuine FALSE ACCEPT inside the modeled surface, the contract-breach class. Fixed by `_type_carries_marker` (whole type tree) + record masks in `_marker_param_mask` + `_marker_field_names`. Symmetric FALSE POSITIVES fixed in the same change: construction into a marker-typed field, and returning such a record, no longer raise E0729/E0730 — a marker-typed FIELD is a sanctioned crossing, the dual of a marker-typed param. Without that half the safe shape was unwritable, which is *why* the unsafe shape went unnoticed `[source: diagnostics, section: E0729/E0730, key: laundering]` | high |
| `Authorized<T>` deliberately NOT widened to containers | iter-44: `_is_marker_type` keeps its top-level-only rule at the six `_AUTH_MARKER` sites. `Authorized<T>` is a PROOF marker: counting `List<Authorized<T>>` as a proof would RELAX acceptance and could silence E0716/E0717. Test-pinned (`test_nested_authorized_still_unproven`) `[source: diagnostics, section: E0716, key: Authorized]` | high |
| NEW residual: record fields are matched by NAME, not by resolved record type | iter-44: the `Field` node holds only the field name and a base expression; resolving the base's record type needs inference this pass does not have. A plain `email` field on an unrelated record over-flags. Accepted direction (over-flag, never miss); the type-directed upgrade would reuse the param/`let`-annotation resolution `check_exhaustiveness` uses for union scrutinees. **Probe for a live over-flag on the corpus before building it** (iter-41 lesson: residuals enter the backlog only probe-confirmed) `[source: types, section: Records, key: record]` | high |
| CORRECTION: the grammar DOES have function types — the iter-42 "no HOFs" row was WRONG | iter-51 (BUGS.md BUG-022, probe-confirmed on `3986d38`). Iter-42 recorded "`grammar.ebnf` has no function types … nothing HOF-shaped remains in the language" and on that basis closed the whole surface. `grammar/grammar.ebnf` line 88 says otherwise: `type_atom = IDENT \| "function" "(" [ type_expr {"," type_expr} ] ")" "returns" type_expr ;`, and `transpiler/aether/parser.py:369` emits `{"kind": "FunctionType", …}`. **How it was found:** not by re-reading the vault but by writing the shape and running it — `apply(f: function(String) returns Unit, x: Secret<String>) … f(x)` with `apply(print, pw)` was exit 0, and so was the effect twin (`apply(logLine, s)` from a `pure` main). The iter-42 row was a grammar claim written without grepping the grammar; the iter-41 lesson (probe before recording) applies to CLOSING an item, not only to opening one `[source: grammar, section: type_expr, key: function]` | high |
| Function-typed-parameter laundering CLOSED, both axes | iter-51 (BUG-022): E0729 now fires when a call's callee name is a function-typed PARAMETER and an argument leaks the marker (`extra.via = "function_type"`) — the callee is chosen by the caller's caller, so it is strictly less visible than the plain-param case E0729 already refused. E0801 now counts a function passed as a VALUE as a callee: its declared effects join the caller's obligation (`extra.via = "function_value"`), so `apply(logLine, s)` from a `pure` caller is refused while `map(double, xs)` stays clean. Deliberately NO sanctioned crossing at a function-typed parameter: a function type's argument types are never checked against what arrives, so `function(Secret<String>) returns Unit` would be an exit that proves nothing — unwrap at the call site instead. Corpus impact 0 (9 function-value argument sites, all pure; 0 function-typed params) | high |
| NEW residual: a function type carries no effects clause | iter-51: the grammar's function type is `function(T,…) returns T` — no `effects` part (`grammar.ebnf` line 88). So a function that merely DECLARES a function-typed parameter may claim any effects clause it likes, and nothing can check a callee's own declaration against what arrives: `apply(f: function(String) returns Unit, x: String) effects pure do f(x) end` is accepted, and only the CALL SITE that supplies the function value is judged (E0801 there). Closing this needs effect-polymorphic function types — a language change, not a detector change. No effects syntax for function types is invented here `[source: grammar, section: type_expr, key: function]` | high |
| Boundary-sanitizer coarseness CLOSED at the call site | iter-51 (BUG-023, probe-confirmed on `3986d38`): `render(sanitizeLog(u))` into a `render` that feeds `htmlResponse` was exit 0, while the inline `htmlResponse(sanitizeLog(u))` fires E0725 whose own hint reads "sanitizeLog does NOT protect here". `boundary_markers()` flattens every row's sanitizer into one set per marker, so any member cleared any crossing. `param_sink_reach()` now summarises which marker-flow sinks each callee PARAMETER reaches (same `Sink.arg_indices` rule as `marker_flow`, aliased sinks included), `marker_sink_sanitizers()` derives (marker, sink) → sanitizer from `MARKER_FLOW_SPECS`, and E0729 accepts a cleared crossing only when the unwrapper that cleared it is right for every reached sink — else it reports the mismatch (`cleared_with`/`reaches_sink`/`needs`). `trusted(...)` is nobody's row sanitizer — an explicit assertion, not inference — and still clears. Empty reached-sink set = pre-fix behaviour, so corpus impact 0 `[source: diagnostics, section: E0729, key: laundering]` | high |
| NEW residual: the sink summary is ONE LEVEL and by direct Ident | iter-51: `param_sink_reach` walks one callee body and matches the parameter's Ident in the sink's checked argument positions. A callee that rebinds the parameter before the sink (`let t = s; htmlResponse(t)`), or hands it to a THIRD function, contributes no sinks — the crossing then falls back to the old marker-wide rule and is accepted. E0730 (return laundering) is untouched by the fix: a return has no callee parameter to summarise, so the coarseness stands there. Both are the ACCEPT direction, i.e. genuine remaining misses, not over-flags — stated plainly rather than described as sound | high |
| `var` and `x = …` were never bindings — FOUR false accepts CLOSED | iter-49 (BUGS.md BUG-013..016, fixed b30d7f1): the parser emits `Let` (name), `Var` (name) and `Assign` (target); every binding walker read `Let`/`Assign` by `name`, so `var x = password; print(x)` was exit 0, a literal-then-reassigned path/query proved literal-only, and E0717's stable-name proof missed a rebinding between guard and sink. One shared walker (`_walk_binds`, `_mutable_names`) now feeds the taint fixpoint, the safe-name pass, `_fn_aliases` and the E0716/E0717 proofs. Same iteration: `for x in markedList` and match-EXPRESSION arms taint (BUG-001 had the statement form only); an aliased STDLIB sink (`let run = sqlQuery`) is the sink for every row and for E0801/E0701 — an aliased sanitizer is still never honoured; a record whose field carries a marker is a CARRIER (`print(u)` leaks; `u.name` does not; record-typed params are the sanctioned crossing, plain params E0729, plain returns E0730). `Authorized<T>` untouched `[source: diagnostics, section: E0712, key: taint]` | high |
| A wrapper's PINNING argument is judged (BUG-020); `safeJoin`'s base deliberately is not | iter-50 (fixed c35b3f3): `sqlBind(tmpl, v)` / `shellArg(tmpl, v)` / `safeRedirect(host, p)` with a parameter in the first slot laundered the very text the row refuses — the wrapper was accepted on its NAME. `ArgRule.pin` requires `args[0]` to be a literal or literal-bound name. `safeJoin(base, rel)` is exempt on purpose: the base directory arriving as a parameter is the idiom (7 corpus sites, both zip-slip demos' `fixed.aeth`) and the untrusted half is `rel`; a Python-frontend wrapper call (`"py": True`) has no template slot and is exempt too. **Residual (over-flag direction is NOT available here — this is an accepted MISS):** a `safeJoin` whose base is attacker-controlled is not refused; the language has no way to say "this parameter is a trusted directory" short of a literal | high |
| Remaining probe-confirmed Aether-side miss: boundary-sanitizer coarseness | survey 2026-09-03 candidate AEDET-09: `render(sanitizeLog(u))` clears the E0729 boundary while the callee feeds `htmlResponse` — any per-sink sanitizer clears the generic crossing. **CLOSED at the call site in iter-51 (BUG-023)** — see the row above; what survives is the one-level/direct-Ident residual and E0730. Record-field resolution by TYPE (AEDET-16) stays a precision item | high |

## Recommended Actions

- Any new taint-style pass MUST inherit the "over-flag, never miss"
  contract and state its residual limit explicitly (as every prior
  iteration did). See [[q3-what-makes-a-good-backlog-target]].
- The highest-leverage soundness upgrade was **interprocedural flow** —
  SHIPPED at signature level across iters 39–40 (return-type seeding,
  E0729 param-crossing refusal, E0730 return-crossing refusal; see
  Evidence — the signature is now enforced both directions; iter-41
  closed the match-destructure false accept; iter-42 closed
  function-alias laundering and re-framed the HOF item out of
  existence). Iter-44 adds the CONTAINER axis to that story: the
  signature is now enforced in both directions AND through the two
  containers the language has (generic arguments, record fields), so
  "signature-level" no longer means "top-level-type-only"; what remains
  on that axis is the type-directed field resolution in Evidence.
  What remains: **value-equality / copy-alias reasoning for
  E0717's resource ids** — now PROBE-CONFIRMED (iter-42,
  `probe_e0717_alias.aeth`: `let id2 = docId` + proof on `docId` is
  refused — over-flag precision target, RELAX direction, must keep the
  E0716/E0717 wall green). **Boundary-sanitizer coarseness is now
  CLOSED at the call site** (iter-51, BUG-023): the probe asked for
  found the MISS, so it was backlog and not doctrine; E0729 judges which
  sanitizer cleared a crossing against the sinks the callee's parameter
  reaches. Its residual (one level, direct Ident; E0730 untouched) is in
  Evidence. The former "stdlib transform propagation" item is REMOVED —
  proven phantom by the iter-41 probe (see Evidence); probe residuals
  before backlog entry.
- **A closed item is a claim, and claims expire.** Iter-42 closed the
  HOF axis on a grammar reading that was simply wrong, and the vault
  carried "nothing HOF-shaped remains in the language" for nine
  iterations until iter-51 wrote the shape and ran it. Re-probe a
  *closure* the same way you probe a gap: the language, not the page, is
  the authority. What is open on that axis now is effect-polymorphic
  function types, and it is a LANGUAGE change — do not invent an effects
  clause for function types to get around it.
- Never describe these passes as "sound" without the qualifier
  "within the intraprocedural, syntactic surface" — overstating is a
  Never-Do (vault manifest, runtime-vs-static honesty).

## Related
- [[../clusters/violation-taxonomy|Violation Taxonomy]]
- [[../clusters/effect-system|Effect System]]
- [[q3-what-makes-a-good-backlog-target]]
