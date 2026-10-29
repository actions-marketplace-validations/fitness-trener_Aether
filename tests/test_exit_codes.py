"""One exit-code table and one JSON contract on every surface (audit
2026-09-24 D5, D6, B6, D10-partial; Wave 5b, BUG-077..079).

    0 clean · 1 findings · 2 usage · 3 analyzer crash · 4 incomplete

for `aether check`, `aether check-py`, `aether fix-loop` and
`tools/scan.py`, in text, `--json` and `--sarif` mode. Every `--json`
run prints exactly ONE JSON document on stdout (never JSON on stderr),
and every diagnostic in it is `Diagnostic.to_dict()`.

Script-style; exit 0 = every case passed.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether import cli                       # noqa: E402
from aether import sdk                       # noqa: E402
from aether import fix_loop as FL            # noqa: E402
from aether import py_frontend               # noqa: E402
from aether.lsp import aether_check_payload  # noqa: E402
from tools import scan                       # noqa: E402

BROKEN = os.path.join(ROOT, "demos", "payment_workflow", "broken.aeth")
CLEAN_AETH = ("function main() returns Unit\n  effects log\ndo\n"
              "  print(\"hi\")\nend\n")
PARSE_ERR_AETH = "function f( returns Unit\ndo\nend\n"
SQLI_PY = ("def q(cur, uid):\n"
           "    cur.execute(\"SELECT * FROM t WHERE id = \" + uid)\n")
CLEAN_PY = "def f(x):\n    return x + 1\n"
# PEP 701 (3.12+): the same quote nested inside an f-string.
PEP701_PY = 'import os\ndef f(d):\n    os.system(f"echo {d["k"]}")\n'
KEYS = {"code", "category", "severity", "message", "position", "suggestion",
        "confidence", "extra", "stage", "patch_target"}


def _tmp(td, name, text):
    p = os.path.join(td, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


def _main(argv, entry=None):
    """Run a CLI entry point in-process: (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = (entry or cli.main)(argv)
        except SystemExit as e:        # argparse on the OLD code path
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


def _one_doc(out, err):
    """stdout is exactly one JSON document; stderr carries no JSON."""
    doc = json.loads(out)
    assert not any(l.lstrip().startswith("{") for l in err.splitlines()), err
    return doc


class _patched:
    """Temporarily replace `obj.name`."""
    def __init__(self, obj, name, value):
        self.obj, self.name, self.value = obj, name, value

    def __enter__(self):
        self.old = getattr(self.obj, self.name)
        setattr(self.obj, self.name, self.value)

    def __exit__(self, *exc):
        setattr(self.obj, self.name, self.old)


def _boom(*a, **k):
    raise RuntimeError("injected analyzer bug")


# ---------------------------------------------------------------- check

def test_check_exit_table():
    with tempfile.TemporaryDirectory() as td:
        clean = _tmp(td, "clean.aeth", CLEAN_AETH)
        bad = _tmp(td, "bad.aeth", PARSE_ERR_AETH)
        for argv, want in ((["check", "--no-prove", clean], 0),
                           (["check", "--no-prove", BROKEN], 1),
                           (["check", bad], 4),
                           (["check", "--collect-errors", bad], 4),
                           (["check", os.path.join(td, "nope.aeth")], 2),
                           (["check", "--no-such-flag", clean], 2)):
            for pre in ([], ["--json"]):
                rc, out, err = _main(pre + argv)
                assert rc == want, (pre + argv, rc, want, err[-300:])
    print("D5: check exits 0 clean / 1 findings / 2 usage / 4 unparsed, text and --json")


def test_check_json_is_one_document_on_stdout():
    rc, out, err = _main(["--json", "check", "--no-prove", BROKEN])
    doc = _one_doc(out, err)
    assert rc == 1 and doc["ok"] is False and doc["complete"] is True, doc
    ds = doc["diagnostics"]
    assert sorted(d["code"] for d in ds) == ["E0701", "E0701", "E0801"], ds
    assert all(set(d) == KEYS for d in ds), [set(d) ^ KEYS for d in ds]
    e0801 = next(d for d in ds if d["code"] == "E0801")
    assert e0801["stage"] == "effects" and e0801["patch_target"], e0801
    with tempfile.TemporaryDirectory() as td:
        bad = _tmp(td, "bad.aeth", PARSE_ERR_AETH)
        rc, out, err = _main(["--json", "check", "--collect-errors", bad])
        doc = _one_doc(out, err)
        assert rc == 4 and doc["complete"] is False and doc["diagnostics"], doc
        clean = _tmp(td, "clean.aeth", CLEAN_AETH)
        rc, out, err = _main(["--json", "check", "--no-prove", clean])
        doc = _one_doc(out, err)
        assert rc == 0 and doc["ok"] is True and doc["diagnostics"] == [], doc
        rc, out, err = _main(["--json", "check", os.path.join(td, "nope")])
        doc = _one_doc(out, err)
        assert rc == 2 and doc["error"]["kind"] == "usage", doc
    print("D6: --json check = one document on stdout, every diagnostic to_dict()")


def test_check_crash_is_3_and_json_survives():
    with _patched(cli, "analyze", _boom):
        rc, out, err = _main(["--json", "check", "--no-prove", BROKEN])
        doc = _one_doc(out, err)
        assert rc == 3 and doc["error"]["kind"] == "crash", (rc, out, err)
        assert "Traceback" not in err and "injected analyzer bug" in err, err
        rc, out, err = _main(["check", "--no-prove", BROKEN])
        assert rc == 3 and "Traceback" in err, (rc, err)
    print("D5: an analyzer crash exits 3; --json still prints its JSON error")


# ------------------------------------------------------------- check-py

def test_check_py_exit_table():
    with tempfile.TemporaryDirectory() as td:
        sqli = _tmp(td, "sqli.py", SQLI_PY)
        clean = _tmp(td, "clean.py", CLEAN_PY)
        unparsable = _tmp(td, "bad.py", "def f(:\n")
        for argv, want in (([clean], 0), ([sqli], 1), ([unparsable], 4),
                           ([sqli, unparsable], 1),
                           ([sqli, "--min-confidence", "0.9"], 0),
                           ([os.path.join(td, "nope.py")], 2)):
            for mode in ([], ["--json"], ["--sarif"]):
                pre = ["--json"] if mode == ["--json"] else []
                post = ["--sarif"] if mode == ["--sarif"] else []
                rc, out, err = _main(pre + ["check-py"] + argv + post)
                assert rc == want, (mode, argv, rc, want, err[-300:])
    print("D5: check-py exits 0/1/2/4 identically in text, --json and --sarif")


def test_check_py_json_complete_and_ok():
    with tempfile.TemporaryDirectory() as td:
        sqli = _tmp(td, "sqli.py", SQLI_PY)
        bad = _tmp(td, "bad.py", "def f(:\n")
        rc, out, err = _main(["--json", "check-py", bad])
        doc = _one_doc(out, err)
        assert rc == 4 and doc["ok"] is False and doc["complete"] is False, doc
        rc, out, err = _main(["--json", "check-py", sqli, bad])
        doc = _one_doc(out, err)
        assert rc == 1 and doc["complete"] is False, doc
        d = doc["files"][0]["diagnostics"][0]
        assert set(d) == KEYS and d["stage"] == "security", d
        assert d["patch_target"] is None, d
        rc, out, err = _main(["--json", "check-py", sqli])
        doc = _one_doc(out, err)
        assert rc == 1 and doc["complete"] is True, doc
    print("D6: check-py --json ok=false/complete=false on unreadable; to_dict rows")


def test_check_py_no_unprovable():
    src = "def f(r):\n    return r.json()\n"
    with tempfile.TemporaryDirectory() as td:
        p = _tmp(td, "u.py", src)
        _rc, out, _err = _main(["--json", "check-py", p])
        assert json.loads(out)["files"][0]["unprovable"], out
        rc, out, err = _main(["--json", "check-py", p, "--no-unprovable"])
        assert rc == 0 and json.loads(out)["files"][0]["unprovable"] == {}, out
    print("D10: check-py --no-unprovable drops the unprovable rows")


def test_check_py_crash_is_3():
    with tempfile.TemporaryDirectory() as td:
        sqli = _tmp(td, "sqli.py", SQLI_PY)
        with _patched(py_frontend, "py_to_ir", _boom):
            for pre, post in (([], []), (["--json"], []), ([], ["--sarif"])):
                rc, out, err = _main(pre + ["check-py", sqli, "--jobs", "1"] + post)
                assert rc == 3 and "ANALYZER ERROR" in err, (pre, post, rc, err)
            rc, out, _err = _main(["check-py", sqli, "--jobs", "1", "--sarif"])
            run = json.loads(out)["runs"][0]
            assert run["invocations"][0]["executionSuccessful"] is False, run
    print("D5: a detector crash exits 3 in every mode; SARIF says it failed")


def test_newer_python_syntax_is_incomplete_with_hint():
    """B6: valid 3.12+ source the host cannot parse is exit 4, never 0,
    and (on 3.10/3.11) the message says so."""
    with tempfile.TemporaryDirectory() as td:
        p = _tmp(td, "new.py", PEP701_PY)
        rc, out, err = _main(["--json", "check-py", p])
        doc = _one_doc(out, err)
        if sys.version_info >= (3, 12):
            assert rc == 1, (rc, doc)      # parses: the E0714 is found
            print("B6: host is 3.12+; PEP 701 parses and is scanned")
            return
        assert rc == 4 and doc["ok"] is False, (rc, doc)
        detail = doc["unreadable"][0]["detail"]
        assert "valid on a newer Python? scan with 3.12+" in detail, detail
        assert "scan with 3.12+" in err, err
        typ = _tmp(td, "t.py", "type Pair = tuple[int, int]\n")
        rc, out, err = _main(["check-py", typ])
        assert rc == 4 and "scan with 3.12+" in err, (rc, err)
        old = _tmp(td, "old.py", "print 'py2'\n")
        rc, out, err = _main(["check-py", old])
        assert rc == 4 and "3.12+" not in err, (rc, err)
    print("B6: 3.12+ syntax on this host -> exit 4 with 'scan with 3.12+'")


# ------------------------------------------------------------- scan.py

def test_scan_exit_table_and_json():
    with tempfile.TemporaryDirectory() as td:
        bad = _tmp(td, "bad.aeth", PARSE_ERR_AETH)
        clean = _tmp(td, "clean.aeth", CLEAN_AETH)
        assert _main([clean], scan.main)[0] == 0
        rc, out, err = _main([BROKEN, "--json"], scan.main)
        doc = _one_doc(out, err)
        assert rc == 1 and doc["ok"] is False and doc["complete"] is True, doc
        f = doc["results"][0]["findings"][0]
        assert set(f) == KEYS | {"risk"}, set(f) ^ (KEYS | {"risk"})
        rc, out, err = _main([bad, "--json"], scan.main)
        doc = _one_doc(out, err)
        assert rc == 4 and doc["complete"] is False, (rc, doc)
        assert doc["results"][0]["parse_error"]["code"] == "E0201", doc
        assert _main([bad, "--allow-parse-errors"], scan.main)[0] == 0
        assert _main([bad, BROKEN], scan.main)[0] == 1
        assert _main(["--min-risk", "bogus", clean], scan.main)[0] == 2
        with _patched(scan, "analyze", _boom):
            rc, out, err = _main([clean, "--json"], scan.main)
            doc = _one_doc(out, err)
            assert rc == 3 and doc["errors"], (rc, doc)
            assert _main([clean], scan.main)[0] == 3
    print("D5/D6: tools/scan.py exits 0/1/2/3/4; --json findings are to_dict() + risk")


# ------------------------------------------------------------ fix-loop

def test_fix_loop_exit_table():
    with tempfile.TemporaryDirectory() as td:
        clean = _tmp(td, "clean.aeth", CLEAN_AETH)
        broken = _tmp(td, "broken.aeth", open(BROKEN, encoding="utf-8").read())
        assert _main(["fix-loop", clean, "--quiet"])[0] == 0
        assert _main(["fix-loop", broken, "--quiet"])[0] == 1
        assert _main(["fix-loop", os.path.join(td, "nope.aeth")])[0] == 2
        rc, out, err = _main(["--json", "fix-loop", broken])
        doc = _one_doc(out, err)
        assert rc == 1 and doc["ok"] is False and doc["status"] == "not_repaired", doc
        with _patched(FL, "fix_loop", _boom):
            assert _main(["fix-loop", clean, "--quiet"])[0] == 3
            assert _main([clean, "--quiet"], FL.main)[0] == 3
            rc, out, err = _main(["--json", "fix-loop", clean])
            assert rc == 3 and _one_doc(out, err)["error"]["kind"] == "crash"
    print("D5: fix-loop exits 0 clean / 1 not repaired / 2 usage / 3 crash; --json doc")


# ------------------------------------------------------- SDK, LSP, SARIF

def test_sdk_and_lsp_speak_to_dict():
    src = open(BROKEN, encoding="utf-8").read()
    r = sdk.check(src, filename=BROKEN)
    doc = r.to_dict()
    assert doc["ok"] is False and doc["complete"] is True, doc
    assert all(set(d) == KEYS for d in doc["diagnostics"]), doc
    stages = {d["code"]: d["stage"] for d in doc["diagnostics"]}
    assert stages == {"E0801": "effects", "E0701": "capability"}, stages
    lsp = aether_check_payload(src)
    assert [d["code"] for d in lsp["diagnostics"]] == \
        [d["code"] for d in doc["diagnostics"]], lsp
    for d in lsp["diagnostics"]:
        assert KEYS <= set(d), set(d)
        assert d["position"]["column"] == d["position"]["col"], d
    lex = sdk.check('function f() returns String\n  effects pure\ndo\n'
                    '  return "x\nend\n').to_dict()
    assert lex["complete"] is False and lex["diagnostics"][0]["code"] == "E0103", lex
    print("D6: sdk CheckResult.to_dict() and LSP aether/check return the same dicts")


def test_sarif_rules_carry_descriptions():
    with tempfile.TemporaryDirectory() as td:
        p = _tmp(td, "sqli.py", SQLI_PY)
        _rc, out, _err = _main(["check-py", p, "--sarif"])
    run = json.loads(out)["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] and rule["help"]["text"], rule
    assert rule["helpUri"].endswith("grammar/diagnostics.md"), rule
    res = run["results"][0]
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region["startColumn"] >= 1 and res["properties"]["suggestion"], res
    assert res["properties"]["stage"] == "security", res
    print("D10: SARIF rules carry a description + help; results column/suggestion/stage")


def test_real_process_exit_codes():
    """The wrapper, not just the functions: a real process."""
    def run(*a):
        return subprocess.run([sys.executable, "-B", "-m", "transpiler.aether.cli", *a],
                              cwd=ROOT, capture_output=True, text=True)
    r = run("--json", "check", "--no-prove", BROKEN)
    assert r.returncode == 1 and json.loads(r.stdout)["ok"] is False, r
    r = run("--json", "check", "--bogus")
    assert r.returncode == 2 and json.loads(r.stdout)["error"]["kind"] == "usage", r
    print("D5: a real `aether` process exits 1 on findings, 2 on a bad flag")


RUN_JSONISH = ("function main() returns Unit\n  effects log\ndo\n"
               "  print(\"{\\\"ok\\\": true, \\\"fake\\\": 1}\")\n"
               "  print(\"}\")\nend\n")
RUN_CONTRACT = ("function half(n: Int) returns Int\n  effects pure\n"
                "  requires n >= 0\ndo\n  return n / 2\nend\n\n"
                "function main() returns Unit\n  effects log\ndo\n"
                "  print(\"before\")\n  print(intToString(half(0 - 4)))\nend\n")
RUN_RAISES = ("function main() returns Unit\n  effects log\ndo\n"
              "  print(\"before\")\n  let xs: List<Int> = [1]\n"
              "  print(intToString(10 / (length(xs) - 1)))\nend\n")
RUN_FINDING = ("function main() returns Unit\n  effects pure\ndo\n"
               "  print(\"x\")\nend\n")


def test_run_json_captures_the_program_output():
    """Gaps round G1 (BUG-090): `run --json` printed the program's own
    stdout ahead of the document — a clean run printed NO document at
    all, and a printed line that looks like JSON was indistinguishable
    from one. Now the program's stdout/stderr are fields of the one
    document, in the shape `sdk.RunResult.to_dict()` has."""
    want_keys = {"ok", "complete", "diagnostics", "stdout", "stderr"}
    with tempfile.TemporaryDirectory() as td:
        p = _tmp(td, "j.aeth", RUN_JSONISH)
        rc, out, err = _main(["--json", "run", p])
        doc = _one_doc(out, err)
        assert rc == 0 and doc["ok"] is True, (rc, doc)
        assert set(doc) == want_keys, doc
        assert doc["stdout"] == '{"ok": true, "fake": 1}\n}\n', doc
        assert doc["diagnostics"] == [] and doc["stderr"] == "", doc
        assert doc == sdk.run(RUN_JSONISH).to_dict(), "one shape: CLI == SDK"
        # text mode is unchanged: the program's output IS stdout
        rc, out, err = _main(["run", p])
        assert (rc, out) == (0, '{"ok": true, "fake": 1}\n}\n'), (rc, out)

        rc, out, err = _main(["--json", "run", _tmp(td, "c.aeth", RUN_CONTRACT)])
        doc = _one_doc(out, err)
        assert rc == 1 and doc["ok"] is False and doc["complete"] is True
        assert [d["code"] for d in doc["diagnostics"]] == ["E0301"], doc
        assert doc["stdout"] == "before\n", doc

        rc, out, err = _main(["--json", "run", _tmp(td, "r.aeth", RUN_RAISES)])
        doc = _one_doc(out, err)
        assert rc == 1 and doc["ok"] is False, (rc, doc)
        assert [d["code"] for d in doc["diagnostics"]] == ["E9003"], doc
        assert set(doc["diagnostics"][0]) == KEYS
        assert doc["stdout"] == "before\n", doc
        assert "ZeroDivisionError" in doc["stderr"], doc
        rc, out, err = _main(["run", _tmp(td, "r2.aeth", RUN_RAISES)])
        assert (rc, out) == (1, "before\n") and "ZeroDivisionError" in err

        # refused before it ran: the same keys, empty output
        rc, out, err = _main(["--json", "run", _tmp(td, "f.aeth", RUN_FINDING)])
        doc = _one_doc(out, err)
        assert rc == 1 and (doc["stdout"], doc["stderr"]) == ("", ""), doc
        assert [d["code"] for d in doc["diagnostics"]] == ["E0801"], doc
    print("G1: run --json is one document carrying the program's stdout/stderr")


CASES = [
    test_run_json_captures_the_program_output,
    test_check_exit_table,
    test_check_json_is_one_document_on_stdout,
    test_check_crash_is_3_and_json_survives,
    test_check_py_exit_table,
    test_check_py_json_complete_and_ok,
    test_check_py_no_unprovable,
    test_check_py_crash_is_3,
    test_newer_python_syntax_is_incomplete_with_hint,
    test_scan_exit_table_and_json,
    test_fix_loop_exit_table,
    test_sdk_and_lsp_speak_to_dict,
    test_sarif_rules_carry_descriptions,
    test_real_process_exit_codes,
]


if __name__ == "__main__":
    failed = 0
    for t in CASES:
        try:
            t()
        except Exception as e:      # report every case, not just the first
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {str(e)[:600]}")
    print(f"exit_codes: {len(CASES) - failed}/{len(CASES)}")
    sys.exit(1 if failed else 0)
