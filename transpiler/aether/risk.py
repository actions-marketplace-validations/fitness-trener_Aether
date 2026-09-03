"""Security risk ratings for diagnostic codes — the triage axis.

Aether already has a `severity` on every `Diagnostic` (`error` /
`warning` / `info`). That axis answers "does the run fail?" — it is a
GATE decision, and `passes/__init__.py` depends on its current values.

This module adds the second axis a scanner needs: "of the 4,000 findings
in this corpus, which do I read first?". The ratings borrow nuclei's
five-level vocabulary (info/low/medium/high/critical) because SARIF
consumers, GitHub Code Scanning and every security dashboard already
speak it.

A rating is a TRIAGE HEURISTIC, not a measurement. It is a fixed
judgement about the class the code names — the blast radius a violation
of that class typically has — not about the specific finding. It is not
CVSS and must never be presented as one; two E0713 findings can differ
by orders of magnitude in real impact.

Non-security codes (lex, parse, harness, SMT timeout) rate `info`. That
is not a claim that a parse error is unimportant — the compiler refuses
it regardless, via `severity`. It means a parse error is not a finding a
security reviewer triages.

The table is read only by output layers (`tools/scan.py`). No detector
imports it and no `Diagnostic` construction site changes, which is why
adding it moves no existing behaviour.
"""

from __future__ import annotations

ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# GitHub Code Scanning ranks SARIF rules by a `security-severity`
# property on a 0.0-10.0 scale and buckets it as
# critical >= 9.0 > high >= 7.0 > medium >= 4.0 > low.
SECURITY_SEVERITY = {
    "critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0,
}

RISK = {
    # --- lex (E01xx): a malformed program, not a security finding ----
    "E0101": "info", "E0102": "info", "E0103": "info",
    "E0104": "info", "E0105": "info", "E0106": "info",

    # --- parse / structure (E02xx) ----------------------------------
    "E0201": "info",       # parse error — the compiler refuses it anyway
    "E0202": "medium",     # non-exhaustive match — an unhandled variant
                           # is a live crash on a real input
    "E0203": "low",        # unreachable arm — dead code, not a crash
    "E0204": "low",        # dead code after terminator
    "E0205": "low",        # unused let / dead store
    "E0206": "medium",     # ignored Result (CWE-252) — the silently
                           # dropped write, a real data-loss path
    "E0207": "medium",     # unsatisfiable refinement — the type is
                           # uninhabitable, so the call can never succeed

    # --- contract / refinement (E03xx) ------------------------------
    "E0301": "low", "E0303": "low", "E0304": "low",
    "E0302": "medium",     # refinement boundary violated
    "E0305": "medium",

    # --- runtime effect (E05xx) -------------------------------------
    # medium, not high like their static sibling E0801: these fire during
    # execution and can never reach a tools/scan.py report; E0801 is the
    # static face that a scan can actually surface.
    "E0501": "medium", "E0502": "medium",

    # --- harness timeout (E06xx) ------------------------------------
    "E0601": "info",

    # --- capability (E07xx, structural) -----------------------------
    "E0701": "high",       # capability overrun — the module reaches
                           # further than any grant allows
    "E0702": "low", "E0703": "low", "E0704": "low",
    "E0705": "low", "E0706": "low",

    # --- security detectors (E071x-E073x) ---------------------------
    "E0710": "high",       # SSRF, unpinned fetch scope (CWE-918)
    "E0711": "high",       # path traversal / Zip-Slip (CWE-22) — not
                           # critical: the read half dominates in
                           # practice; the write half (writeFile,
                           # attacker-steerable arbitrary write) is why
                           # it is not medium either
    "E0712": "high",       # secret exfil to log/disk (CWE-532)
    "E0713": "critical",   # SQL injection (CWE-89)
    "E0714": "critical",   # command injection -> RCE (CWE-78)
    "E0715": "medium",     # PII egress (GDPR/residency, not RCE)
    "E0716": "high",       # missing authorization (CWE-862/863)
    "E0717": "high",       # cross-tenant access / IDOR (CWE-639)
    "E0718": "medium",     # open redirect (CWE-601) — phishing pivot
    "E0719": "critical",   # SSTI -> RCE (CWE-94)
    "E0720": "critical",   # insecure deserialization -> RCE (CWE-502)
    "E0721": "medium",     # cleartext transmission (CWE-319) — a
                           # scheme/config signal on the effect
                           # annotation (channel is cleartext), not proof
                           # anything sensitive crosses it, unlike
                           # E0710/E0722's reachable attacker-steerable
                           # target; deliberate, not an oversight
    "E0722": "critical",   # SSRF to IMDS -> IAM credential theft
    "E0723": "critical",   # hardcoded credential (CWE-798)
    "E0724": "medium",     # log injection / forging (CWE-117)
    "E0725": "high",       # reflected XSS (CWE-79)
    "E0726": "medium",     # HTTP response splitting (CWE-113)
    "E0727": "high",       # XXE (CWE-611) — file read / SSRF
    "E0728": "medium",     # CSV / formula injection (CWE-1236)
    "E0729": "high",       # marker laundering at a boundary
    "E0730": "high",       # return laundering / lying signature
    "E0731": "critical",   # code injection -> RCE (CWE-94/95)

    # --- static effect (E08xx) --------------------------------------
    "E0801": "high",       # effect leak — the Log4Shell shape

    # --- SMT (E09xx) -------------------------------------------------
    "E0901": "info", "E0902": "info",

    # --- internal / harness (E9xxx) ----------------------------------
    "E9001": "info", "E9002": "info", "E9003": "info",
}


def risk_of(code: str) -> str:
    """Rating for `code`; `info` for an unrated code.

    Degrading beats raising: an output layer must render a tree whose
    codes the table may briefly lag. `tests/test_risk.py` is what makes
    the lag impossible to ship.
    """
    return RISK.get(code, "info")


def rank(code: str) -> int:
    """Sortable rank; higher is worse."""
    return ORDER[risk_of(code)]


def at_or_above(code: str, floor: str) -> bool:
    """True when `code`'s rating is at least `floor`."""
    return rank(code) >= ORDER[floor]
