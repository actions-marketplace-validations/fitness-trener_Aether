"""tools/scan.py — the reusable corpus scanner.

Verifies the scanner (the product-shape of Aether's phase-2 story: point it
at a directory of AI-generated code, get a findings report) reports clean
code as clean and flags a known vulnerability.

Run: python3 tests/test_scan.py   (exit 0 = pass)
"""
from __future__ import annotations
import io
import json
import os
import sys
from collections import Counter
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools import scan  # noqa: E402
from tools.expectations import CORPUS_ROOTS  # noqa: E402


def test_clean_file_no_findings():
    p = os.path.join(ROOT, "reference", "01_hello", "program.aeth")
    r = scan.scan_file(p)
    assert r["findings"] == [], f"clean file should have no findings: {r}"
    assert "parse_error" not in r, r
    print("scan: clean reference file reports no findings")


def test_vulnerable_file_flagged():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    r = scan.scan_file(p)
    codes = {f["code"] for f in r["findings"]}
    assert "E0713" in codes, f"SQL-injection demo should flag E0713: {codes}"
    print("scan: vulnerable file flags E0713")


def test_fixed_file_clean():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "fixed.aeth")
    r = scan.scan_file(p)
    assert r["findings"] == [], f"fixed form should be clean: {r}"
    print("scan: fixed file reports no findings")


def test_sarif_output_wellformed():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    doc = scan.to_sarif([scan.scan_file(p)])
    assert doc["version"] == "2.1.0", doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "aether-scan"
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "E0713" in ids, ids
    res = run["results"][0]
    assert res["ruleId"] == "E0713"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("vulnerable.aeth")
    assert loc["region"]["startLine"] >= 1
    print("scan: SARIF output is well-formed (GitHub Code Scanning-ready)")


def test_expect_mode_gates_on_the_difference():
    """`--expect` is what makes the aether-scan workflow able to pass at
    all: this repo deliberately contains vulnerable files, so "fail on any
    finding" is red by construction. Both directions of the difference
    must fail — a finding nobody declared, and a declared finding that
    stopped firing (a detector regression, which the old gate could never
    see because it only ever counted findings upward)."""
    vuln = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                        "aether", "vulnerable.aeth")
    base = scan.scan_file(vuln)
    assert {f["code"] for f in base["findings"]} == {"E0713"}, base

    declared = scan.diff_expected(base)
    assert declared["unexpected"] == [], declared
    assert declared["missing"] == [], declared

    # No header -> held to `clean`, so the finding is unexpected.
    undeclared = scan.diff_expected(dict(base, declared=None))
    assert [f["code"] for f in undeclared["unexpected"]] == ["E0713"], undeclared

    # Declares a code it does not produce -> the regression direction.
    overstated = scan.diff_expected({"path": vuln, "findings": [],
                                     "declared": Counter({"E0713": 1})})
    assert overstated["missing"] == [("E0713", 1)], overstated
    assert overstated["unexpected"] == [], overstated

    # Multiplicity is part of the claim: 2 sites declared, 1 reported.
    two = dict(base, declared=Counter({"E0713": 2}))
    assert scan.diff_expected(two)["missing"] == [("E0713", 1)], two
    print("scan: --expect gates on the difference, both directions")


def test_expect_mode_clean_over_the_corpus():
    """The end state the workflow depends on: every corpus file matches
    what it declares, so the gate is green and any drift turns it red."""
    argv = [os.path.join(ROOT, sub) for sub in CORPUS_ROOTS] + ["--expect"]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main(argv)
    assert rc == 0, ("corpus does not match its declared expectations:\n"
                     + buf.getvalue())
    print("scan: --expect is green over the whole expectation corpus")


def test_findings_carry_risk_and_sort_worst_first():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    r = scan.scan_file(p)
    assert r["findings"], "expected findings on the vulnerable demo"
    for f in r["findings"]:
        assert f["risk"] in ("critical", "high", "medium", "low", "info"), f
    ranks = [scan.rank(f["code"]) for f in r["findings"]]
    assert ranks == sorted(ranks, reverse=True), (
        f"findings must sort worst-first, got {ranks}")
    assert r["findings"][0]["risk"] == "critical", (
        f"E0713 is critical and must lead: {r['findings'][0]}")
    print("scan: findings carry risk and sort worst-first")


def test_min_risk_filters_out_lower_ratings():
    # E0718 (open redirect) is rated medium; E0713 (SQLi) is critical.
    # A `critical` floor must keep the second and drop the first.
    medium = os.path.join(ROOT, "demos", "case_studies", "open_redirect",
                          "aether", "vulnerable.aeth")
    critical = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                            "aether", "vulnerable.aeth")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([medium, critical, "--json", "--min-risk", "critical"])
    out = json.loads(buf.getvalue())
    codes = {f["code"] for r in out["results"] for f in r["findings"]}
    assert codes == {"E0713"}, (
        f"--min-risk critical should drop the medium E0718: {codes}")
    assert rc == 1, rc

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([medium, "--json", "--min-risk", "critical"])
    out = json.loads(buf.getvalue())
    assert out["files_with_findings"] == 0, out
    assert rc == 0, "no findings at or above the floor means exit 0"

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([medium, "--json", "--min-risk", "medium"])
    out = json.loads(buf.getvalue())
    codes = {f["code"] for r in out["results"] for f in r["findings"]}
    assert codes == {"E0718"}, f"a medium floor keeps a medium: {codes}"
    assert rc == 1, rc
    print("scan: --min-risk filters and gates on the floor")


def test_min_risk_equals_form_filters():
    # `--min-risk=critical` (the equals form) must filter exactly like
    # the two-token `--min-risk critical` form, not silently fall through
    # to an unfiltered scan.
    medium = os.path.join(ROOT, "demos", "case_studies", "open_redirect",
                          "aether", "vulnerable.aeth")
    critical = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                            "aether", "vulnerable.aeth")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([medium, critical, "--json", "--min-risk=critical"])
    out = json.loads(buf.getvalue())
    codes = {f["code"] for r in out["results"] for f in r["findings"]}
    assert codes == {"E0713"}, (
        f"--min-risk=critical should drop the medium E0718: {codes}")
    assert rc == 1, rc
    print("scan: --min-risk=critical (equals form) filters")


def test_bad_min_risk_is_a_usage_error():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([os.path.join(ROOT, "reference", "01_hello",
                                     "program.aeth"),
                        "--min-risk", "catastrophic"])
    assert rc == 2, f"unknown rating must be a usage error, got {rc}"
    print("scan: unknown --min-risk value is a usage error")


def test_min_risk_with_expect_is_a_usage_error():
    p = os.path.join(ROOT, "demos", "case_studies", "open_redirect",
                     "aether", "vulnerable.aeth")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([p, "--expect", "--min-risk", "high"])
    assert rc == 2, (
        f"--min-risk with --expect must be refused, got {rc}: a filtered "
        f"declared code would read as a regressed detector")
    # The default floor is not a filter, so --expect alone still works.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([p, "--expect", "--json"])
    assert rc in (0, 1), f"--expect alone must still run, got {rc}"
    print("scan: --min-risk with --expect is refused")


def test_sarif_carries_risk_metadata():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    doc = scan.to_sarif([scan.scan_file(p)])
    run = doc["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"]
                if r["id"] == "E0713")
    # GitHub Code Scanning reads security-severity as a STRING.
    assert rule["properties"]["security-severity"] == "9.0", rule
    assert "critical" in rule["properties"]["tags"], rule
    res = next(r for r in run["results"] if r["ruleId"] == "E0713")
    assert res["level"] == "error", res

    # An info-rated code (E0201 — parse error) must NOT be tagged
    # "security": GitHub only honours security-severity on rules tagged
    # security, and non-security codes must not land in Code Scanning.
    fake = [{"path": __file__,
             "findings": [{"code": "E0201", "message": "m", "line": 1,
                           "risk": "info"}]}]
    info_rule = scan.to_sarif(fake)["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security" not in info_rule["properties"]["tags"], info_rule
    assert info_rule["properties"]["tags"] == ["aether", "info"], info_rule
    print("scan: SARIF carries security-severity, tags and mapped level")


def test_findings_carry_confidence_and_sort_by_it_within_a_risk():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    r = scan.scan_file(p)
    assert r["findings"], "expected findings on the vulnerable demo"
    for f in r["findings"]:
        assert 0.0 <= f["confidence"] <= 1.0, f
        # An Aether-source finding guesses nothing about its sink.
        assert f["confidence"] == 1.0, f
    keys = [(-scan.rank(f["code"]), -f["confidence"]) for f in r["findings"]]
    assert keys == sorted(keys), (
        f"findings must sort worst-first then most-certain-first: {keys}")

    # A synthetic pair at the same risk: the more certain one leads.
    findings = [{"code": "E0713", "message": "less sure", "line": 9,
                 "confidence": 0.6},
                {"code": "E0713", "message": "sure", "line": 9,
                 "confidence": 0.95}]
    findings.sort(key=lambda x: (-scan.rank(x["code"]), -x["confidence"],
                                 x["line"], x["code"]))
    assert findings[0]["message"] == "sure", findings
    print("scan: findings carry confidence and sort most-certain-first")


def test_min_confidence_filters_and_refuses_expect():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    # Aether-source findings are 1.0, so no floor removes them...
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([p, "--json", "--min-confidence", "1.0"])
    assert rc == 1, rc
    assert json.loads(buf.getvalue())["results"], "1.0 must keep 1.0 findings"
    # ...and a floor above 1.0 is a usage error, not a silent empty scan.
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert scan.main([p, "--json", "--min-confidence", "1.5"]) == 2
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert scan.main([p, "--json", "--min-confidence", "high"]) == 2
    # Same reason --min-risk is refused: a declared code filtered out by
    # confidence is indistinguishable from a detector that regressed.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = scan.main([p, "--expect", "--min-confidence", "0.9"])
    assert rc == 2, (
        f"--min-confidence with --expect must be refused, got {rc}")
    print("scan: --min-confidence filters, validates, and refuses --expect")


def test_sarif_carries_per_finding_confidence():
    p = os.path.join(ROOT, "demos", "case_studies", "sql_injection",
                     "aether", "vulnerable.aeth")
    doc = scan.to_sarif([scan.scan_file(p)])
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["confidence"] == 1.0, res
    # Per FINDING, not per rule: the rule properties carry the class-level
    # security-severity and must not grow a confidence.
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "confidence" not in rule["properties"], rule
    print("scan: SARIF carries per-finding confidence under properties")


def test_sarif_level_maps_below_high_to_warning_and_note():
    assert scan._sarif_level("critical") == "error"
    assert scan._sarif_level("high") == "error"
    assert scan._sarif_level("medium") == "warning"
    assert scan._sarif_level("low") == "note"
    assert scan._sarif_level("info") == "note"
    print("scan: SARIF level mapping covers all five ratings")


if __name__ == "__main__":
    test_clean_file_no_findings()
    test_vulnerable_file_flagged()
    test_fixed_file_clean()
    test_sarif_output_wellformed()
    test_expect_mode_gates_on_the_difference()
    test_expect_mode_clean_over_the_corpus()
    test_findings_carry_risk_and_sort_worst_first()
    test_min_risk_filters_out_lower_ratings()
    test_min_risk_equals_form_filters()
    test_bad_min_risk_is_a_usage_error()
    test_min_risk_with_expect_is_a_usage_error()
    test_sarif_carries_risk_metadata()
    test_findings_carry_confidence_and_sort_by_it_within_a_risk()
    test_min_confidence_filters_and_refuses_expect()
    test_sarif_carries_per_finding_confidence()
    test_sarif_level_maps_below_high_to_warning_and_note()
    print("SCAN TOOL: all tests pass")
