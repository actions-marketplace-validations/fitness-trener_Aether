# Real-World Evidence Run 2: `packaging` ordering, JWT proof-tokens, CVE replay

**Date:** 2026-07-05
**Follows:** `REALWORLD_HUMANIZE.md` (run 1). Same discipline: real targets with
real users, faithful ports, machine-checked results, every claim carries a
qualifier + metric, and gaps are surfaced, not hidden.

**Headline results:**

1. **`packaging` (PEP 440 ordering) — the dependency `pip` uses.** Ported PEP 440
   version parse + comparison to Aether; differential-tested **10,732,176 ordered
   pairs** across 3,276 canonical versions against `packaging` 26.2. **100.000000%
   agreement, full-corpus sort identical, zero divergence.** This is the "one
   ordering bug = a resolver picks the wrong package" surface, and the port matches
   the reference exactly.
2. **JWT auth-bypass class (CVE-2022-29217 precedent).** The naive missing-verify
   composition is refused by the shipped `E0716`. Adversarial testing then found a
   **real soundness gap** — `Authorized<T>` was a per-function allowlist, so the
   proof was forgeable through one indirection — which was **subsequently closed**
   (commit `9decaa7`, "E0716 authorization-provenance pass (nominal Authorized<T>)"):
   the forgery repro now emits `E0716`. Found, reported, and fixed — see the
   Resolution subsection in Part 3.
3. **CVE replay corpus.** Five **verified, named** CVEs in real Python packages,
   one per shipped E-code: every vulnerable port is refused with the exact expected
   diagnostic; every fixed port checks clean. **5/5 PASS.**

---

## Part 1 — `packaging` PEP 440 ordering (blast radius: all of PyPI)

### Why this target

`packaging` is the library `pip` and the wider Python ecosystem use to parse and
order version numbers. Version ordering decides which release a resolver selects.
A single ordering disagreement — `A < B` where the reference says `A > B` — means a
resolver built on the faulty logic can install a different artifact than `pip`
does: a supply-chain-scale failure mode, and exactly the class a security team pays
to rule out.

### What was built

`bench/realworld_packaging/`:

| File | Purpose |
|---|---|
| `pep440.aeth` | Aether port of PEP 440 parse + compare, matching `packaging` 26.2's `_cmpkey` (epoch, release with trailing-zero trim, flat 6-int pre/post/dev suffix) |
| `differential.py` | Generates a canonical-version corpus; compares Aether's `versionCompare` to `packaging.Version` ordering on **every ordered pair**; also checks full-corpus sort agreement and reflexivity |

Scope (stated plainly): the port covers the **ordering semantics** over canonical
PEP 440 forms `[N!]R(.R)*[{a|b|rc}N][.postN][.devN]` — the grammar
`str(Version(x))` emits. Local version segments (`+local`) and the input-
normalization front-end (v-prefix, alt spellings `alpha`/`beta`/`c`/`preview`,
separator variants, implicit `-N` post) are `packaging`'s regex layer and are out
of scope; the corpus is normalized through `packaging` so both sides compare the
identical canonical string. Ordering is the part that decides resolution, and it is
what this run exercises.

### Result

```
packaging version under test: 26.2
python: 3.13.7
corpus: 3276 distinct canonical versions
ordered pairs: 10732176

pairwise ordering: 10732176/10732176 match (100.000000%)
full-corpus sort agrees with packaging: True
reflexive cmp(a,a)==0 failures: 0

PASS
```

10.7M pairwise comparisons, zero disagreement, and sorting the whole corpus with
the Aether key reproduces `packaging`'s total order exactly. The eight spot checks
in `pep440.aeth`'s `main` cover the semantic edge cases the plan named — trailing
zeros (`1.0.0 == 1`), dev-only sorts first, pre before final, post after final,
`a < b < rc`, epoch dominance, numeric-not-lexical (`2.0 < 10.0`) — all correct.

Reproduce:

```
pip install --target <dir> packaging==26.2
PACKAGING_PYLIBS=<dir> python bench/realworld_packaging/differential.py
python -m transpiler.aether.cli run bench/realworld_packaging/pep440.aeth
```

### What this evidences

Aether's small, contract-typed subset carried a piece of **critical
infrastructure** logic — the thing `pip` resolves versions with — and matched the
reference across 10.7M comparisons with no divergence. Unlike run 1 (humanize),
this port found **no** reference bug; the value here is the inverse and equally
important for selling: a demonstrated **exact-match on the highest-stakes ordering
surface in the ecosystem**, which is the precondition for the pitch "you can trust
a resolver/verifier written in this."

---

## Part 2 — JWT verification as a proof-token flow (and a real gap found)

### The class and its precedent

JWT algorithm-confusion / `alg=none` (named precedent **CVE-2022-29217**, PyJWT) is
an authentication bypass: a protected action runs off token claims that never
passed a genuine signature verification. This is the bug class where
willingness-to-pay is already proven — bounties for exactly this run $10k–$100k+.

**Anchored against the real library.** `bench/realworld_jwt/pyjwt_repro.py`,
against installed **pyjwt 2.13.0** (current), reproducibly shows the core fact the
Aether demo addresses: an unverified decode returns full attacker claims —

```
UNVERIFIED DECODE RETURNS CLAIMS: {'sub': 'attacker', 'role': 'admin'}
```

i.e. claims in hand with zero authentication — the `alg=none` shape. (The
HS/RS-confusion forgery is guarded in current pyjwt via encode key-type checks and
required `algorithms`; CVE-2022-29217 stands as the named historical precedent for
the class, and the reproducible-today fact is the unverified-claims return.)

### The mapping and what holds

`bench/realworld_jwt/`:

| File | Result |
|---|---|
| `vulnerable.aeth` | protected `DELETE` off unverified decoded claims → **refused, E0716** |
| `fixed.aeth` | `verifyToken` pins the algorithm and mints an `Authorized<String>` proof; the mutation requires it → **OK, runs** |

The naive composition — a handler that acts on decoded claims with no verification
proof in its dataflow — **is refused**. That part of the pitch holds and is
demonstrated:

```
vulnerable.aeth  ->  [E0716] performs a data mutation via 'sqlExec' without an
                     authorization proof ... (CWE-862)
fixed.aeth       ->  OK
```

### The gap (found by adversarial testing, reported in full)

The stronger claim — "an `alg=none` / forged path *cannot* reach the sink" — **does
not hold as shipped.** `Authorized<T>` is not a nominal type. The `E0716` pass
(`transpiler/aether/passes/effects.py`, `_authorized_names`) trusts **any**
parameter declared `Authorized<T>` as proven, and the type checker does **not**
reject a `String` bound into an `Authorized<T>` slot. Two confirmed bypasses:

- `bench/realworld_jwt/e0716_bypass_FINDING.aeth` — interpose a helper
  `applyDelete(subject, auth: Authorized<String>)` and call it with a raw string:
  `applyDelete(subject, subject)`. **Type-checks OK; the `DELETE` emits.**
- `bench/realworld_jwt/e0716_coercion_probe.aeth` — `let p: Authorized<String> =
  raw` (a plain `String`). **Accepted, no error.**

Root cause: `E0716` is an **intra-function** dataflow check. Proof provenance does
not cross the call boundary, so the obligation is discharged locally inside whatever
function holds the sink; one indirection launders a non-proof into an `Authorized`
slot. The same laundering likely affects `E0717` (resource-scoped, IDOR) and the
shipped `demos/case_studies/missing_authorization` + `idor_cross_tenant` "fixed"
examples.

**Honest consequence for selling:** E0716 catches the *common naive* missing-auth
composition (real value — that is how most of these ship). It does **not** yet make
a forged proof inexpressible. Fix direction (v2): make `Authorized<T>` provenance
nominal + interprocedural — reject any value in an `Authorized` slot not sourced
from `authorize()`/`authorizeResource()` (or an `Authorized` param transitively fed
a real proof at every call site), and reject `String -> Authorized<T>` coercion.
A background task chip was filed for this fix.

This finding is the artifact working as intended: adversarial porting of a real bug
class surfaced a genuine soundness gap in the security machinery being pitched. A
partner would rather hear it from you with the repro than find it themselves.

### Resolution (2026-07-06): the gap is closed

`Authorized<T>` is now nominal. The `E0716` pass enforces four companion
obligations that make trusting an `Authorized<T>` parameter sound:

1. **Call-site proof** — an argument bound to an `Authorized<...>` parameter of a
   user function must itself be a proof; the laundering repro is refused at the
   call site (`e0716_bypass_FINDING.aeth` → **E0716**).
2. **Annotation cannot mint** — `let/var/const x: Authorized<...> = raw` is
   refused even with no sink in scope (`e0716_coercion_probe.aeth` → **E0716**).
3. **No first-class escape** — a function taking `Authorized<...>` cannot be used
   as a value (an indirect call would bypass obligation 1).
4. **Return types are promises** — a function declared to return
   `Authorized<...>` (or `Result`/`Option` of it) has every return site checked,
   which is what lets `verifyToken`-style minters and `match ... case Ok(proof)`
   destructuring stay clean without reopening the hole.

Also fixed while closing it: `Assign` bindings now demote a proven name
(`tok = raw` disqualifies `tok`; the collector previously matched `Let` only, so
rebinding was invisible), `var`-bound proofs are recognized (previously a false
positive), and `authorizeResource(...)` counts as an `Authorized<T>` proof for
E0716 (its id-binding remains E0717's job). E0717 itself was audited against the
same laundering shape and was already sound: it never trusts a proof across a
call boundary — only a direct `authorizeResource(...)` call or a stable name
bound to one in the same body.

Verified: both bypass repros now refused; `vulnerable.aeth` still refused;
`fixed.aeth`, `missing_authorization/fixed.aeth`, `idor_cross_tenant/fixed.aeth`
all still clean; 41/41 tests in `tests/test_effect_scope.py` (9 new regression
tests cover the four obligations, demotion, `var` proofs, fake minters, and
unproven-`Result` matches).

---

## Part 3 — CVE replay corpus (the fundable slide)

Five **verified, named** CVEs in real Python packages, each ported to Aether and
each refused at check time by an E-code that shipped before this run. Vulnerable
port → expected diagnostic; fixed port → clean.

`bench/realworld_cve/run_corpus.py` output:

```
CVE             package                   class                     E-code  vuln:refused  fixed:OK
-------------------------------------------------------------------------------------------------
CVE-2007-4559   CPython tarfile           path traversal            E0711   E0711         OK
CVE-2026-1312   Django order_by()         SQL injection             E0713   E0713         OK
CVE-2025-58763  Tautulli                  command injection         E0714   E0714         OK
CVE-2018-14574  Django CommonMiddleware   open redirect             E0718   E0718         OK
CVE-2026-54711  PGHoard                   secret in logs (CWE-532)  E0712   E0712         OK

PASS
```

Each CVE is real and independently verifiable:

| CVE | Package (ecosystem) | Primary reference |
|---|---|---|
| CVE-2007-4559 | CPython `tarfile` | [Red Hat bugzilla 263261](https://bugzilla.redhat.com/show_bug.cgi?id=263261), [python.org discussion](https://discuss.python.org/t/policies-for-tarfile-extractall-a-k-a-fixing-cve-2007-4559/23149) |
| CVE-2026-1312 | Django `QuerySet.order_by()` | [django/django fix commit](https://github.com/django/django/commit/90f5b10784ba5bf369caed87640e2b4394ea3314) |
| CVE-2025-58763 | Tautulli | [GHSA-jrm9-r57q-6cvf](https://github.com/Tautulli/Tautulli/security/advisories/GHSA-jrm9-r57q-6cvf) |
| CVE-2018-14574 | Django `CommonMiddleware` | [django/django fix commit](https://github.com/django/django/commit/d6eaee092709aad477a9894598496c6deec532ff) |
| CVE-2026-54711 | PGHoard | [GHSA-mpx4-jmpr-vm8v](https://github.com/advisories/GHSA-mpx4-jmpr-vm8v) |

The claim demonstrated: **these named, real-package vulnerabilities cannot be
written in Aether without the compiler refusing the composition** — the injection
sink refuses raw-concatenated input (E0713/E0714), the write refuses an uncontained
dynamic path (E0711), the redirect refuses an unpinned target (E0718), and a
`Secret<T>` value cannot reach a log sink (E0712). Each fix is the sanctioned repair
the same E-code accepts (`sqlBind`, `shellArg`, `safeJoin`, `safeRedirect`, drop the
secret / `reveal`).

**Honest scope:** these five are injection/containment/taint classes, which are
Aether's designed wedge and which it enforces at the sink regardless of call depth
(unlike the E0716 authorization proof in Part 2, whose provenance is intra-function
— the IDOR/authorization class shares that limitation and is **not** in this five).
Each port reproduces the *shape* of the CVE (the exact upstream code differs); the
value is that the vulnerable shape is unwriteable, verified by the E-code, not
asserted.

Reproduce:

```
python bench/realworld_cve/run_corpus.py     # -> PASS
```

---

## What the two runs together evidence for selling potential

Qualifier + metric, per the discipline:

1. **Faithful on critical infra (measured):** PEP 440 ordering, the logic `pip`
   resolves with, matched `packaging` 26.2 across **10,732,176 comparisons, 0
   divergence**. Precondition for "trust a resolver/verifier written in this."
2. **Finds real bugs and real gaps (demonstrated):** run 1 found a live
   `humanize` 4.16.0 regression; run 2's adversarial JWT test found a **soundness
   gap in Aether's own E0716**. The method surfaces defects on both sides of the
   fence — which is the credibility case, not against it.
3. **Named-CVE inexpressibility for the wedge classes (5/5):** five verified,
   real-package CVEs across five shipped E-codes, each refused at check time. This
   is the "these $10k–$100k-bounty bugs cannot be written here" slide, grounded in
   CVEs a partner can look up.
4. **Security is where willingness-to-pay is already proven** — and Part 3 lands
   squarely in it, with the honest caveat (Part 2) that the authorization-proof
   class needs a nominal-type fix before it carries the same weight as the
   injection classes.

What these runs do **not** prove: willingness to pay, fit on large multi-module
codebases, or that the found gaps are commercially decisive. The strongest use is
the CVE corpus as the fundable slide, the packaging exact-match as the trust proof,
and the E0716 finding as evidence the team tests its own claims adversarially.

## Sources

- packaging: https://github.com/pypa/packaging , https://pypi.org/project/packaging/ , PEP 440 https://peps.python.org/pep-0440/
- packaging ~600M downloads/month context and pip dependency: https://pypi.org/project/packaging/
- PyJWT CVE-2022-29217: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24
- CVE-2007-4559: https://bugzilla.redhat.com/show_bug.cgi?id=263261
- CVE-2026-1312: https://github.com/django/django/commit/90f5b10784ba5bf369caed87640e2b4394ea3314
- CVE-2025-58763: https://github.com/Tautulli/Tautulli/security/advisories/GHSA-jrm9-r57q-6cvf
- CVE-2018-14574: https://github.com/django/django/commit/d6eaee092709aad477a9894598496c6deec532ff
- CVE-2026-54711: https://github.com/advisories/GHSA-mpx4-jmpr-vm8v
