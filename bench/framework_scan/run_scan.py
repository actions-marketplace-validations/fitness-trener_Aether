"""Run `aether check-py` over published AI-agent framework wheels.

`bench/pypi_scan/` answers "what does the tool do on a large body of
third-party code nobody wrote for it" using whatever happens to be in
site-packages. This one picks the corpus on purpose: the frameworks that
generate and execute AI-written Python, which is the population Aether
claims to be for.

Nothing is imported or executed. Wheels are downloaded with
`pip download --only-binary` (so no sdist build step runs), unzipped as
data, and read as text by the CLI, which parses with `ast`.

The corpus is pinned: `frameworks.lock.txt` names each version and its
wheel sha256, and pip refuses a wheel whose hash differs. Unpinned, a
re-run months later scanned whatever was newest and could not reproduce
REPORT.md's numbers.

Run: python -B bench/framework_scan/run_scan.py            (summary)
     python -B bench/framework_scan/run_scan.py --json     (every finding)
     python -B bench/framework_scan/run_scan.py --skip-download
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(HERE, "_work")
WHEELS = os.path.join(WORK, "wheels")
SRC = os.path.join(WORK, "src")
LOCK = os.path.join(HERE, "frameworks.lock.txt")


def pins() -> dict:
    """{wheel dist name: version} from the lock file. The corpus, chosen
    for relevance rather than convenience: agent frameworks and the AI
    coding tools whose output Aether is aimed at."""
    out = {}
    with open(LOCK, encoding="utf-8") as f:
        for line in f:
            spec = line.split("#", 1)[0].split()
            if spec:
                name, ver = spec[0].split("==")
                out[name.replace("-", "_")] = ver
    return out


def download() -> None:
    os.makedirs(WHEELS, exist_ok=True)
    r = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps",
         "--only-binary", ":all:", "--require-hashes", "-q",
         "-d", WHEELS, "-r", LOCK],
        capture_output=True, text=True)
    print(f"  download {'ok' if r.returncode == 0 else 'FAILED'}")
    if r.returncode != 0:
        raise SystemExit(r.stderr)


def extract() -> dict:
    """Unzip exactly the pinned wheel of each dist. A `_work/src/<dist>`
    left by an earlier run of another version is refused, not scanned."""
    os.makedirs(SRC, exist_ok=True)
    dists = {}
    for d, ver in sorted(pins().items()):
        dest = os.path.join(SRC, d)
        if not os.path.isdir(dest):
            whl = [fn for fn in os.listdir(WHEELS)
                   if fn.startswith(f"{d}-{ver}-") and fn.endswith(".whl")]
            if not whl:
                raise SystemExit(f"no wheel for {d}=={ver} in {WHEELS}")
            with zipfile.ZipFile(os.path.join(WHEELS, whl[0])) as z:
                z.extractall(dest)
        if not os.path.isdir(os.path.join(dest, f"{d}-{ver}.dist-info")):
            raise SystemExit(f"{dest} is not {d}=={ver}; delete it and re-run")
        dists[d] = dest
    return dists


def scan(path: str):
    r = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "--json",
         "check-py", path], cwd=ROOT, capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def main() -> int:
    if "--skip-download" not in sys.argv:
        download()
    dists = extract()
    rows, stats = [], {}
    for d, path in sorted(dists.items()):
        res = scan(path)
        if res is None:
            print(f"  !! {d}: no JSON output")
            continue
        for f in res["files"]:
            rel = os.path.relpath(f["path"], path).replace("\\", "/")
            for diag in f["diagnostics"]:
                rows.append({"dist": d, "file": rel, "code": diag["code"],
                             "line": diag["position"]["line"],
                             "message": diag["message"][:150]})
        stats[d] = {"files": len(res["files"]),
                    "findings": sum(len(f["diagnostics"]) for f in res["files"]),
                    "unreadable": len(res["unreadable"]),
                    "errors": len(res["errors"])}
        for e in res["errors"]:
            print(f"  !! ANALYZER ERROR {d}: {e['error'][:160]}")

    if "--json" in sys.argv:
        json.dump({"stats": stats, "findings": rows}, sys.stdout, indent=1)
        return 0

    for d in sorted(stats):
        s = stats[d]
        print(f"  {d:<22} {s['files']:>5} files  {s['findings']:>4} findings"
              f"  {s['unreadable']} unparseable  {s['errors']} errors")
    by_code = collections.Counter(r["code"] for r in rows)
    print("\n" + "=" * 66)
    print(f"files            {sum(s['files'] for s in stats.values())}")
    print(f"findings         {len(rows)}")
    print(f"analyzer errors  {sum(s['errors'] for s in stats.values())}")
    print(f"unparseable      {sum(s['unreadable'] for s in stats.values())}")
    print("by code: " + ", ".join(f"{c}x{n}" for c, n in sorted(by_code.items())))
    print("\nSee REPORT.md §4 for what the remaining E0713 are: agent SQL "
          "toolkits that run dynamic queries by design, and statements "
          "assembled in helpers no intraprocedural rule can root.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
