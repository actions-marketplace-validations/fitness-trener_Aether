"""CVE replay corpus driver. For each named CVE, assert:
  - the vulnerable port is refused with the expected E-code
  - the fixed port checks clean (OK)

Uses the Aether CLI in --json mode so the diagnostic code is machine-read.
Exit 0 iff every expectation holds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

CASES = [
    ("CVE-2007-4559", "CPython tarfile", "path traversal", "E0711",
     "cve_2007_4559_tarfile_vulnerable.aeth", "cve_2007_4559_tarfile_fixed.aeth"),
    ("CVE-2026-1312", "Django order_by()", "SQL injection", "E0713",
     "cve_2026_1312_django_orderby_vulnerable.aeth",
     "cve_2026_1312_django_orderby_fixed.aeth"),
    ("CVE-2025-58763", "Tautulli", "command injection", "E0714",
     "cve_2025_58763_tautulli_cmd_vulnerable.aeth",
     "cve_2025_58763_tautulli_cmd_fixed.aeth"),
    ("CVE-2018-14574", "Django CommonMiddleware", "open redirect", "E0718",
     "cve_2018_14574_django_redirect_vulnerable.aeth",
     "cve_2018_14574_django_redirect_fixed.aeth"),
    ("CVE-2026-54711", "PGHoard", "secret in logs (CWE-532)", "E0712",
     "cve_2026_54711_pghoard_secretlog_vulnerable.aeth",
     "cve_2026_54711_pghoard_secretlog_fixed.aeth"),
    ("CVE-2026-53754", "crawl4ai", "SSRF unpinned host (CWE-918)", "E0710",
     "cve_2026_53754_crawl4ai_ssrf_vulnerable.aeth",
     "cve_2026_53754_crawl4ai_ssrf_fixed.aeth"),
    ("CVE-2023-35078", "Ivanti EPMM", "missing authz (CWE-862)", "E0716",
     "cve_2023_35078_ivanti_authz_vulnerable.aeth",
     "cve_2023_35078_ivanti_authz_fixed.aeth"),
    ("CVE-2025-13526", "OneClick Chat to Order", "IDOR / BOLA (CWE-639)", "E0717",
     "cve_2025_13526_oneclick_idor_vulnerable.aeth",
     "cve_2025_13526_oneclick_idor_fixed.aeth"),
]


def check(path: str) -> tuple[int, list[str]]:
    """Return (exit_code, list-of-diagnostic-codes)."""
    p = subprocess.run(
        [sys.executable, "-m", "transpiler.aether.cli", "--json", "check", path],
        cwd=ROOT, capture_output=True, text=True,
    )
    # One JSON document on stdout (0.5.0; it was JSONL on stderr).
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        doc = {}
    codes: list[str] = [d["code"] for d in doc.get("diagnostics", [])]
    return p.returncode, codes


def main() -> int:
    print(f"{'CVE':<16}{'package':<26}{'class':<26}{'E-code':<8}"
          f"{'vuln:refused':<14}{'fixed:OK':<9}")
    print("-" * 97)
    all_ok = True
    for cve, pkg, cls, ecode, vuln, fixed in CASES:
        vrc, vcodes = check(os.path.join(HERE, vuln))
        frc, fcodes = check(os.path.join(HERE, fixed))
        vuln_ok = vrc != 0 and ecode in vcodes
        fixed_ok = frc == 0 and not fcodes
        ok = vuln_ok and fixed_ok
        all_ok = all_ok and ok
        vmark = f"{ecode}" if vuln_ok else f"NO({vcodes})"
        fmark = "OK" if fixed_ok else f"NO({frc},{fcodes})"
        print(f"{cve:<16}{pkg:<26}{cls:<26}{ecode:<8}{vmark:<14}{fmark:<9}")
    print()
    print("PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
