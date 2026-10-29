"""Evidence harness for bench/EVIDENCE.md.

For each real, CVE-assigned case under demos/evidence/<CVE>/aether/, assert:
  - vulnerable.aeth is REFUSED  (exit != 0) with the expected E-code
  - fixed.aeth      CHECKS OK   (exit 0, no diagnostics)

The diagnostic code is machine-read from the CLI's --json output, not
eyeballed. Exit 0 iff every case behaves. One command reproduces the whole
board:

    python -B bench/evidence_run.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
EV = os.path.join(ROOT, "demos", "evidence")

# (CVE, package, class, expected E-code)
CASES = [
    ("CVE-2021-44228", "Apache Log4j 2",          "effect leak (log->net) / JNDI RCE", "E0801"),
    ("CVE-2007-4559",  "CPython tarfile",          "path traversal (CWE-22)",           "E0711"),
    ("CVE-2021-35042", "Django order_by()",        "SQL injection (CWE-89)",            "E0713"),
    ("CVE-2022-1292",  "OpenSSL c_rehash",         "command injection (CWE-78)",        "E0714"),
    ("CVE-2018-14574", "Django CommonMiddleware",  "open redirect (CWE-601)",           "E0718"),
    ("CVE-2026-53754", "crawl4ai",                 "SSRF unpinned host (CWE-918)",      "E0710"),
    ("CVE-2023-35078", "Ivanti EPMM",              "missing authz (CWE-862/863)",       "E0716"),
    ("CVE-2025-13526", "OneClick Chat to Order",   "IDOR / BOLA (CWE-639)",             "E0717"),
]


def check(path: str) -> tuple[int, list[str]]:
    """Return (exit_code, list-of-diagnostic-codes) for `aether --json check`."""
    p = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "--json", "check", path],
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
    print(f"{'CVE':<16}{'package':<26}{'class':<36}{'E-code':<8}"
          f"{'vuln:refused':<14}{'fixed:OK':<9}")
    print("-" * 109)
    all_ok = True
    for cve, pkg, cls, ecode in CASES:
        base = os.path.join(EV, cve, "aether")
        vrc, vcodes = check(os.path.join(base, "vulnerable.aeth"))
        frc, fcodes = check(os.path.join(base, "fixed.aeth"))
        vuln_ok = vrc != 0 and ecode in vcodes
        fixed_ok = frc == 0 and not fcodes
        ok = vuln_ok and fixed_ok
        all_ok = all_ok and ok
        vmark = ecode if vuln_ok else f"NO({vrc},{vcodes})"
        fmark = "OK" if fixed_ok else f"NO({frc},{fcodes})"
        print(f"{cve:<16}{pkg:<26}{cls:<36}{ecode:<8}{vmark:<14}{fmark:<9}")
    print()
    print("PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
