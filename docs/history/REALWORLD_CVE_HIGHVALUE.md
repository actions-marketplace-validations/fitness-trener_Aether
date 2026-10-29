# Real-World Evidence Run 4: the harsh, high-bounty bug classes

**Date:** 2026-07-06
**Follows:** runs 1–3 (`REALWORLD_HUMANIZE.md`, `REALWORLD_SECURITY_PACKAGING.md`,
`REALWORLD_TIER2.md`). Directive for this run: focus on the bug classes with
*proven, market-scale willingness to pay* — the ones bug-bounty programs pay
$10k–100k+ for — and demonstrate that Aether refuses them at compile time using
the security E-codes it already ships.

**Headline result:** the CVE replay corpus now covers **8 real, named CVEs, one per
security E-code**, and every vulnerable port is refused with the exact expected
diagnostic while every fixed port checks clean — **8/8 PASS.** This run added the
three highest-bounty classes that were missing: **SSRF (E0710), missing
authorization / auth bypass (E0716), and IDOR / broken object-level authorization
(E0717).**

```
CVE             package                   class                        E-code  vuln:refused  fixed:OK
CVE-2007-4559   CPython tarfile           path traversal               E0711   E0711         OK
CVE-2026-1312   Django order_by()         SQL injection                E0713   E0713         OK
CVE-2025-58763  Tautulli                  command injection            E0714   E0714         OK
CVE-2018-14574  Django CommonMiddleware   open redirect                E0718   E0718         OK
CVE-2026-54711  PGHoard                   secret in logs (CWE-532)      E0712   E0712         OK
CVE-2026-53754  crawl4ai                  SSRF unpinned host (CWE-918)   E0710   E0710         OK   *new
CVE-2023-35078  Ivanti EPMM               missing authz (CWE-862)       E0716   E0716         OK   *new
CVE-2025-13526  OneClick Chat to Order    IDOR / BOLA (CWE-639)         E0717   E0717         OK   *new
PASS
```

Reproduce: `python bench/realworld_cve/run_corpus.py` (uses `aether --json check`,
so the diagnostic code is machine-read, not eyeballed).

---

## Why these three classes

Security is the one class where willingness-to-pay is already proven at market
scale — bounties, not hypotheticals. Of the OWASP/CWE catalogue, three classes
dominate both payout tables and breach post-mortems, and all three were the gaps in
the prior corpus:

| Class | Why it pays | E-code |
|---|---|---|
| **Broken access control / IDOR (BOLA)** | OWASP A01 (#1 risk, 2021 & 2025). TikTok, Instagram, KubeSphere IDOR bounties. A single missing ownership check exposes every tenant's data. | E0717 |
| **Missing authorization / auth bypass** | CWE-862/863. Ivanti EPMM (below) was exploited in the wild against government systems and is on the CISA KEV list. | E0716 |
| **SSRF** | CWE-918, OWASP A10. The cloud-metadata pivot (`169.254.169.254` → IAM credentials) turns one unvalidated URL into full account takeover. | E0710 |

The pitch is not "we found a formatting bug." It is: **these named,
$50k-bounty-class vulnerabilities cannot be written in this language** — the
composition is a compile error, not a code-review miss.

---

## The three new replays

Each is a real, named CVE. The Aether port reproduces the vulnerable *composition*
(the exact shape the CVE exploited), and the compiler refuses it; the fixed port is
the sanctioned repair and checks clean. Files in `bench/realworld_cve/`.

### E0710 — SSRF, CVE-2026-53754 (crawl4ai)

crawl4ai (a widely-used Python crawler/scraper) validated fetch targets with an
**incomplete CIDR blocklist**, so a crafted URL bypassed the filter and reached
internal resources including the cloud metadata endpoint. Fixed in 0.8.8 by host
**allowlisting**.

Aether inverts the default: a `net.fetch` effect must **pin its host**. The
vulnerable port declares `effects net.fetch("*")` — the unpinned scope that is the
CVE's precondition — and the compiler refuses it:

```
[E0710] function 'fetchTarget' declares effect 'net.fetch('*')' with an unpinned
host (bare '*' - admits any host); pin the host so the scope cannot be steered to
an internal endpoint
```

The fixed port pins the host (`net.fetch("https://fetch.crawl-service.example/v1/get/*")`);
`169.254.169.254` is unreachable by construction, not by a blocklist that might have
a gap. This is the architectural point: the broad *promise itself* is the error,
before any request is made.

### E0716 — missing authorization, CVE-2023-35078 (Ivanti EPMM / MobileIron Core)

A mutating API path was reachable with **no authorization check on it** — an
unauthenticated remote attacker could read PII and change server configuration.
Exploited in the wild; on the CISA Known Exploited Vulnerabilities list.

The port's handler is locally perfect — input parameterized (no injection), effects
declared — and still an open door, because nothing on the path from request to the
`sqlExec` mutation proves authorization:

```
[E0716] function 'setDeviceConfig' performs a data mutation via 'sqlExec' without
an authorization proof (no authorization argument given); a mutation reachable
without an auth check is the missing-authorization class (CWE-862)
```

The fix threads an `authorize(caller, "devices:admin")` proof into the sink. An
unauthenticated request cannot produce the token, so the mutating path is closed —
not by remembering to add a decorator on one more route.

### E0717 — IDOR / BOLA, CVE-2025-13526 (OneClick "Chat to Order")

Textbook IDOR: an order-mutating endpoint trusted a client-supplied `order_id` and
never checked that the caller owns that order, so any authenticated user could act
on any order by changing the id.

E0716 is not enough here — the caller **is** authenticated and may act on their own
orders. The lie is that the id the caller is authorized for and the id the `UPDATE`
mutates are **different**. `sqlByOwner(stmt, resourceId, proof)` requires the proof
to be bound to the same id it mutates:

```
[E0717] function 'updateOrder' mutates a resource via 'sqlByOwner' whose
authorization is not bound to the same resource id (the proof authorizes resource
name 'myOrderId' but the sink mutates resource name 'targetOrderId'); an authorized
caller reaching ANOTHER tenant's row is the IDOR / cross-tenant class (CWE-639)
```

The fix authorizes the **same** id the sink writes. A proof for a different order is
refused by construction.

---

## Honest limits (carried forward, not buried)

- **E0716's earlier forgery gap is closed (from run 2).** Adversarial testing in
  `REALWORLD_SECURITY_PACKAGING.md` found that `Authorized<T>` was a per-function
  allowlist, forgeable by laundering a raw value into an `Authorized<...>` parameter
  through one indirection. That gap was **fixed** by commit `9decaa7` (the E0716
  authorization-provenance pass, making `Authorized<T>` nominal): the forgery repro
  (`bench/realworld_jwt/e0716_bypass_FINDING.aeth`) and the coercion probe now both
  emit `E0716`, verified this session. The corpus entries above use the direct
  sanctioned pattern; the indirection path is now refused too.
- **These are class/pattern replays, not upstream re-discoveries.** The corpus
  proves "this vulnerable composition is a compile error in Aether," on faithful
  ports of real named CVEs. It does not re-find the CVE in the upstream codebase
  (those are C/PHP/Python across frameworks Aether does not parse). CVE-2025-13526's
  upstream is a PHP plugin; it is ported as the canonical IDOR shape because the
  E-code refuses the *pattern*, independent of source language. This is stated so a
  partner clicking the link is not misled.
- **E0715 (PII-to-log) is demonstrated by the case study, not a new CVE here.** The
  corpus covers 8 of the 9 security E-codes; E0715's PII-egress pass is exercised by
  `demos/case_studies/pii_egress/`. Real named CWE-532 precedents exist (Apache
  Airflow CVE-2025-68675, Directus GHSA-8vg2-wf3q-mwv7) but log *credentials*
  (E0712's class), so a faithful *PII*-specific named CVE was not forced in.
- **Runtime/static split.** E0710/E0716/E0717 are static checks (compile-time
  refusal), verified via `aether --json check`. No runtime execution or SMT proof is
  claimed for these.

---

## What this run adds to the selling case

Qualifier + metric:

1. **The three highest-willingness-to-pay classes are now demonstrated
   (measured):** SSRF, missing-authz, and IDOR each refuse a real, named CVE with
   the exact expected diagnostic — 8/8 corpus PASS, machine-checked.
2. **The claim is the strong one, scoped honestly:** the vulnerable *composition*
   of each CVE is a compile error, not a review miss — with the class-replay (not
   upstream-rediscovery) caveat stated in place, and the earlier E0716 forgery gap
   now closed (commit `9decaa7`).
3. **This is the fundable slide.** Runs 1–3 proved expressiveness and bug-finding on
   real library logic; this run maps Aether's shipped E-codes directly onto the CVE
   classes security budgets already exist for. The natural next step is a design
   partner replaying their *own* last five access-control findings through the
   corpus harness.

## Sources

- CVE-2026-53754 (crawl4ai SSRF): https://github.com/unclecode/crawl4ai — cloud-metadata SSRF class, CWE-918
- CVE-2023-35078 (Ivanti EPMM): https://nvd.nist.gov/vuln/detail/CVE-2023-35078 , CISA KEV
- CVE-2025-13526 (OneClick Chat to Order IDOR): https://www.penligent.ai/hackinglabs/idor-in-the-wild-what-cve-2025-13526-really-teaches-security-engineers/
- CVE-2024-22513 (djangorestframework-simplejwt BOLA, related): https://nvd.nist.gov/vuln/detail/CVE-2024-22513
- Open WebUI SSRF (CVE-2025-65958, related): https://github.com/open-webui/open-webui/security/advisories/GHSA-c6xv-rcvw-v685
- OWASP A01 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-918 SSRF: https://cwe.mitre.org/data/definitions/918.html
- CWE-639 IDOR: https://cwe.mitre.org/data/definitions/639.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
