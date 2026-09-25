"""Regressions for the real-world mining toolkit.
Run: python3 tests/test_mining.py
"""
from __future__ import annotations
import math, os, sys
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT,"transpiler")); sys.path.insert(0, ROOT)

from tools.diff_shape import classify_file_change, path_bucket, classify_changeset
from tools.rw_metrics import wilson, aggregate
from tools.breakeven import breakeven, rw_unprovable, from_metrics
from tools import runtime_oracle
from tools.runtime_oracle import check_against_aether


def test_path_filtering():
    assert path_bucket("vendor/x.py") == "vendored"
    assert path_bucket("app/migrations/0001.py") == "migration"
    assert path_bucket("poetry.lock") == "lockfile"
    assert path_bucket("pyproject.toml") == "dependency_manifest"
    assert path_bucket("svc/api.py") == "analyze"
    assert path_bucket("logo.png") == "binary"
    print("  [ok] §C path filtering buckets correctly")


def test_shape_classification():
    # new file -> ADD_NEW_FILE
    fr = classify_file_change("svc/new.py", "", "import requests\ndef f(u):\n    return requests.get(u)\n", "added")
    assert fr.regions and all(r.shape == "ADD_NEW_FILE" for r in fr.regions)
    # modify existing fn -> MODIFY_EXISTING
    fr2 = classify_file_change("svc/e.py",
        "import requests\ndef f(u):\n    return u\n",
        "import requests\ndef f(u):\n    return requests.get(u)\n", "modified")
    assert any(r.shape == "MODIFY_EXISTING" for r in fr2.regions)
    # deletion excluded
    fr3 = classify_file_change("svc/g.py", "def g():\n    return 1\n", "", "deleted")
    assert fr3.bucket == "deleted" and not fr3.regions
    print("  [ok] shapes: ADD_NEW_FILE / MODIFY_EXISTING / deletion-excluded")


def test_capability_relevance_flag():
    # a pure refactor region is NOT capability-relevant
    fr = classify_file_change("svc/p.py", "def t(x):\n    return x+1\n",
                              "def t(x):\n    return x+2\n", "modified")
    assert all(not r.capability_relevant for r in fr.regions) or not fr.regions
    print("  [ok] pure region flagged capability-irrelevant")


def test_wilson():
    ci = wilson(5, 10)
    assert ci["lo"] < 0.5 < ci["hi"] and 0 <= ci["lo"] <= ci["hi"] <= 1
    assert wilson(0, 0)["p"] is None
    # known value: wilson(50,100) center ~0.5, half-width ~0.098
    ci2 = wilson(50, 100)
    assert abs(ci2["lo"] - 0.404) < 0.01 and abs(ci2["hi"] - 0.596) < 0.01
    print("  [ok] Wilson CI matches known values")


def test_breakeven_math():
    # u_add=0.6, u_modify=0.2 -> B where (1-B)0.6+B0.2=0.5 -> B=0.25
    assert abs(breakeven(0.6, 0.2) - 0.25) < 1e-6
    assert abs(rw_unprovable(0.25, 0.6, 0.2) - 0.5) < 1e-6
    # if modify itself >0.5, no mix saves it (B>1)
    assert breakeven(0.8, 0.6) > 1.0
    print("  [ok] break-even solves the GATE 0 line correctly")


def test_decision_clear_fail_when_modify_path_bad():
    metrics = {
        "per_region_unprovable_by_shape": {
            "ADD_NEW_FILE": wilson(8, 10), "ADD_IN_EXISTING": wilson(0, 0),
            "MODIFY_EXISTING": wilson(7, 10)},   # modify itself 70% unprov
        "shape_mix_region_weighted": {
            "ADD_NEW_FILE": wilson(10, 20), "ADD_IN_EXISTING": wilson(0, 20),
            "MODIFY_EXISTING": wilson(10, 20)},
    }
    d = from_metrics(metrics)
    assert d["decision"] == "CLEAR_FAIL"
    print("  [ok] decision = CLEAR_FAIL when even modify path exceeds gate")


def test_runtime_oracle_catches_fn():
    if not runtime_oracle.available():
        # Off Linux the oracle must refuse, not report an empty observation
        # as "sound" — that vacuous pass is what this test was red on.
        try:
            check_against_aether("def f(x):\n    return x\n", "def f(x):\n    return x\n")
        except runtime_oracle.OracleUnavailable:
            print("  [skip] runtime oracle: no Linux strace here (refuses, as it must)")
            return
        raise AssertionError("oracle without Linux strace returned a verdict")
    # head Aether clears, but exercised entrypoint writes a file -> confirmed FN
    r = check_against_aether("def f(x):\n    return x\n", "def f(x):\n    return x+1\n",
                             entrypoint_src="open('/tmp/_t.out','w').write('z')\n")
    assert not r["soundness_ok"] and r["confirmed_false_negatives"]
    # honest pass: head writes a file, Aether says UNPROVABLE/INTRODUCES -> ok
    r2 = check_against_aether("def s(p,d):\n    return d\n",
                              "def s(p,d):\n    open(p,'w').write(d)\n    return d\n",
                              entrypoint_src="open('/tmp/_t2.out','w').write('z')\n")
    assert r2["soundness_ok"]
    print("  [ok] runtime oracle catches induced FN, passes honest case")


def main():
    tests = [test_path_filtering, test_shape_classification, test_capability_relevance_flag,
             test_wilson, test_breakeven_math, test_decision_clear_fail_when_modify_path_bad,
             test_runtime_oracle_catches_fn]
    fails = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            fails += 1; print(f"  [FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests)-fails}/{len(tests)} mining tests passed")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
