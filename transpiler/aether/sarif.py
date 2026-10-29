"""SARIF v2.1.0 rendering — ONE renderer, shared by every scan surface.

Two surfaces produce Code Scanning input: `tools/scan.py` over `.aeth`
corpora, and `aether check-py --sarif` over Python trees. They render the
same document from the same risk table, from here, on purpose. The scanner
already learned this lesson once about its detector list — it "used to keep
its own list, and drifted three detectors behind" (`tools/scan.py`) — and a
second SARIF renderer would be the same mistake in a place where the drift
is invisible, because a malformed or mis-ranked SARIF file is silently
dropped by GitHub rather than rejected.
"""
from __future__ import annotations

import os

from .risk import risk_of, SECURITY_SEVERITY


def sarif_level(risk: str) -> str:
    """SARIF has three levels; risk has five. critical/high are the ones
    that should break a Code Scanning gate, medium warns, the rest are
    notes."""
    return {"critical": "error", "high": "error",
            "medium": "warning"}.get(risk, "note")


def rel_uri(path: str, base: str) -> str:
    """Forward-slashed, relative to `base`.

    Code Scanning maps an alert onto a file by this URI, and it must be
    relative to the checkout root — a `../..` URI is not a valid SARIF
    `artifactLocation` and the result is dropped SILENTLY. For a target
    outside `base` there is no valid relative form, so the absolute path
    goes in: the finding then fails to attach to a file, which is visible,
    rather than vanishing.
    """
    r = os.path.relpath(path, base).replace(os.sep, "/")
    return r if not r.startswith("../") else path.replace(os.sep, "/")


# Where every code is described (the D.2 catalog test keeps it complete).
DIAGNOSTICS_DOC = ("https://github.com/fitness-trener/Aether/blob/main/"
                   "grammar/diagnostics.md")


def to_sarif(results: list, base: str, unreadable=(), crashed=()) -> dict:
    """Render findings as SARIF v2.1.0 — the format GitHub Code Scanning,
    VS Code, and most CI security dashboards ingest.

    `results` is `[{"path": str, "findings": [Diagnostic.to_dict()]}]` —
    the same rows `--json` prints (audit 2026-09-24 D6); `base` is the
    directory every path is reported relative to (the checkout root under
    CI). `unreadable` is `[(path, why)]` for files the scanner could not
    parse: each becomes a `toolExecutionNotification` on the run, so a
    tree the scanner could not read does not look green in Code Scanning.
    `crashed` is `[(path, error)]` for files the analyzer crashed on: an
    error notification each, and `executionSuccessful: false`.
    """
    rule_ids = sorted({f["code"] for r in results for f in r["findings"]})
    # A rule's description: the first finding of that code, in output
    # order (worst-first, deterministic). Its message names the class and
    # its suggestion the repair; there is no separate per-code title table
    # in the package to drift from grammar/diagnostics.md, which `helpUri`
    # links to (TC-08).
    first = {}
    for r in results:
        for f in r["findings"]:
            first.setdefault(f["code"], f)
    sarif_results = []
    for r in results:
        for f in r["findings"]:
            pos = f["position"]
            region = {"startLine": max(1, pos["line"])}
            if pos.get("column"):
                region["startColumn"] = max(1, pos["column"])
            res = {
                "ruleId": f["code"],
                "level": sarif_level(risk_of(f["code"])),
                "message": {"text": f["message"]},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": rel_uri(r["path"], base)},
                    "region": region,
                }}],
            }
            # The fix-loop reads `suggestion` and `extra` from the JSON;
            # Code Scanning shows `properties` on the alert, so the SARIF
            # carries the same two fields instead of dropping them.
            props = {}
            # How sure the ANALYSIS is that this call is the sink it
            # says (`aether/confidence.py`) — per FINDING, unlike the
            # rule's `security-severity`, which is per class. A rule
            # property could not carry it.
            if f.get("confidence") is not None:
                props["confidence"] = f["confidence"]
            if f.get("suggestion"):
                props["suggestion"] = f["suggestion"]
            if f.get("extra"):
                props["aether"] = f["extra"]
            if f.get("stage"):
                props["stage"] = f["stage"]
            if props:
                res["properties"] = props
            sarif_results.append(res)
    notifications = [{
        "level": "warning",
        "message": {"text": f"could not parse: {why}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": rel_uri(p, base)}}}],
    } for p, why in unreadable] + [{
        "level": "error",
        "message": {"text": f"analyzer error (a bug in Aether): {err}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": rel_uri(p, base)}}}],
    } for p, err in crashed]
    rules = []
    for rid in rule_ids:
        risk = risk_of(rid)
        rule = {
            "id": rid,
            "shortDescription": {"text": rid},
            "fullDescription": {"text": first[rid]["message"]},
            "helpUri": DIAGNOSTICS_DOC,
            "properties": {
                # Code Scanning parses this as a string, and ranks
                # >=9.0 critical, >=7.0 high, >=4.0 medium.
                "security-severity": str(SECURITY_SEVERITY[risk]),
                "tags": (["security"] if risk != "info" else []) + ["aether", risk],
            },
        }
        if first[rid].get("suggestion"):
            rule["help"] = {"text": first[rid]["suggestion"]}
        rules.append(rule)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "aether-scan",
                "informationUri": "https://github.com/fitness-trener/Aether",
                "rules": rules,
            }},
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": not crashed,
                "toolExecutionNotifications": notifications,
            }],
        }],
    }
