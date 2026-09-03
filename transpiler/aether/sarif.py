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


def to_sarif(results: list, base: str, unreadable=()) -> dict:
    """Render findings as SARIF v2.1.0 — the format GitHub Code Scanning,
    VS Code, and most CI security dashboards ingest.

    `results` is `[{"path": str, "findings": [{"code", "message", "line",
    "risk", "column"?, "suggestion"?, "extra"?}]}]`; `base` is the
    directory every path is reported relative to (the checkout root under
    CI). `unreadable` is `[(path, why)]` for files the scanner could not
    parse: each becomes a `toolExecutionNotification` on the run, so a
    tree the scanner could not read does not look green in Code Scanning.
    """
    rule_ids = sorted({f["code"] for r in results for f in r["findings"]})
    sarif_results = []
    for r in results:
        for f in r["findings"]:
            region = {"startLine": max(1, f["line"])}
            if f.get("column"):
                region["startColumn"] = max(1, f["column"])
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
            if f.get("suggestion"):
                props["suggestion"] = f["suggestion"]
            if f.get("extra"):
                props["aether"] = f["extra"]
            if props:
                res["properties"] = props
            sarif_results.append(res)
    notifications = [{
        "level": "warning",
        "message": {"text": f"could not parse: {why}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": rel_uri(p, base)}}}],
    } for p, why in unreadable]
    rules = []
    for rid in rule_ids:
        risk = risk_of(rid)
        rules.append({
            "id": rid,
            "shortDescription": {"text": rid},
            "properties": {
                # Code Scanning parses this as a string, and ranks
                # >=9.0 critical, >=7.0 high, >=4.0 medium.
                "security-severity": str(SECURITY_SEVERITY[risk]),
                "tags": (["security"] if risk != "info" else []) + ["aether", risk],
            },
        })
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
                "executionSuccessful": True,
                "toolExecutionNotifications": notifications,
            }],
        }],
    }
