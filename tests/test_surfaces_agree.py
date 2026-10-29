"""Audit 2026-09-24 Wave 3: every surface sees the same program.

Five surfaces load Aether source: `aether check` (CLI), `sdk.check`, the
LSP, `tools/scan.py` and the fix-loop. They used to disagree:

  D2  only the CLI resolved `import`s, so a cross-file E0801 and an
      unresolved-import E0705 were "clean" on the other four;
  D4  `--json check` stopped at the first non-empty stage (an E0801 hid
      an E0713) while SDK/LSP/scan reported every stage;
  D9  a lex error made `sdk.check` raise, and the LSP published nothing
      for the document — it showed clean;
  D3  `tools/scan.py` read a BOM as E0101, and exited 0 when every file
      failed to parse;
  D7  `fmt --write` dropped every comment, `// expect:` headers included.

Each case asserts exact codes on every surface. Script-style; exit 0 =
pass.
"""
from __future__ import annotations
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether import sdk                      # noqa: E402
from aether import fix_loop as FL           # noqa: E402
from aether.lsp import LspServer            # noqa: E402
from tools import scan                      # noqa: E402

LIB = '''// expect: clean
function exfil(s: String) returns Unit
  effects net.fetch("https://evil.example/*")
do
  let _n = length(s)
end
'''
PROG = '''import lib

function main() returns Unit
  effects log
do
  exfil("secret")
  print("x")
end
'''
UNRESOLVED = '''import nosuch.thing

function main() returns Unit
  effects log
do
  print("x")
end
'''
MIXED = '''module UserRepo
  requires capability db
  requires capability log
  exports findUser
end

function findUser(userId: String) returns String
  effects pure
do
  print("dbg")
  return sqlQuery("SELECT * FROM users WHERE id = " + userId)
end

function main() returns Unit
  effects log, db.query
do
  print(findUser("1 OR 1=1; DROP TABLE users"))
end
'''
LEX = 'function f() returns String\n  effects pure\ndo\n  return "unterminated\nend\n'


def _cli(*args):
    r = subprocess.run([sys.executable, "-B", "-m", "transpiler.aether.cli", *args],
                       cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def _cli_json_codes(path):
    # One JSON document on stdout since Wave 5b (D6); it was JSONL on stderr.
    rc, out, _err = _cli("--json", "check", "--no-prove", path)
    return rc, json.loads(out)["diagnostics"]


def _lsp_codes(path, text):
    """Publish diagnostics for a didOpen on a real file:// URI."""
    out = io.BytesIO()
    srv = LspServer(io.BytesIO(), out)
    uri = "file:///" + os.path.abspath(path).replace(os.sep, "/").lstrip("/")
    srv._update_document(uri, text)
    raw = out.getvalue().split(b"\r\n\r\n", 1)[1]
    msg = json.loads(raw)
    assert msg["method"] == "textDocument/publishDiagnostics", msg
    return [d["code"] for d in msg["params"]["diagnostics"]]


def _all_surfaces(path, text):
    rc, diags = _cli_json_codes(path)
    fixed, tr = FL.fix_loop(text, filename=path)
    return {
        "cli": [d["code"] for d in diags],
        "sdk": [d.code for d in sdk.check(text, filename=path).diagnostics],
        "lsp": _lsp_codes(path, text),
        "scan": sorted(f["code"] for f in scan.scan_file(path)["findings"]),
        "fix-loop": tr[-1].get("remaining_codes"),
    }, rc


def _write(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return p


def test_cross_file_E0801_on_every_surface():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "lib.aeth", LIB)
        prog = _write(d, "prog.aeth", PROG)
        got, rc = _all_surfaces(prog, PROG)
    want = ["E0801"]
    bad = {k: v for k, v in got.items() if sorted(v or []) != want}
    assert rc == 1 and not bad, (rc, got)      # 1 = findings (D5)
    print("D2: cross-file E0801 on cli, sdk, lsp, scan, fix-loop")


def test_unresolved_import_E0705_on_every_surface():
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "imp.aeth", UNRESOLVED)
        got, rc = _all_surfaces(p, UNRESOLVED)
    bad = {k: v for k, v in got.items() if v != ["E0705"]}
    assert rc == 4 and not bad, (rc, got)      # 4 = not fully loaded (D5)
    print("D2: unresolved import E0705 on cli, sdk, lsp, scan, fix-loop")


def test_json_check_reports_every_stage_tagged():
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "mix.aeth", MIXED)
        rc, diags = _cli_json_codes(p)
        got = [(x["code"], x["stage"]) for x in diags]
        assert rc == 1 and got == [("E0801", "effects"), ("E0801", "effects"),
                                   ("E0713", "security")], got
        assert [c for c, _ in got] == [x.code for x in sdk.check(MIXED, filename=p).diagnostics]
        assert sorted(c for c, _ in got) == sorted(_lsp_codes(p, MIXED)) == \
            sorted(f["code"] for f in scan.scan_file(p)["findings"])
        rc, _out, err = _cli("check", "--no-prove", p)
        assert rc == 1 and "E0713" not in err, err
        assert "1 more diagnostic(s) from later stages not shown: security 1" in err, err
    print("D4: --json check = every stage, tagged; text mode says what it held back")


def test_lex_error_is_a_diagnostic_on_sdk_and_lsp():
    r = sdk.check(LEX)
    assert [d.code for d in r.diagnostics] == ["E0103"] and r.ast is None, r
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "lex.aeth", LEX)
        assert _lsp_codes(p, LEX) == ["E0103"]
        assert _cli_json_codes(p)[1][0]["code"] == "E0103"
    print("D9: lex error returned by sdk.check and published by the LSP")


def test_scan_reads_bom_and_fails_on_parse_errors():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bom.aeth"), "w", encoding="utf-8-sig") as f:
            f.write("// expect: E0801\nfunction f() returns Unit\n  effects pure\n"
                    "do\n  print(\"x\")\nend\n")
        lex = _write(d, "lex.aeth", LEX)
        r = scan.scan_file(os.path.join(d, "bom.aeth"))
        assert "parse_error" not in r and [f["code"] for f in r["findings"]] == ["E0801"], r
        e = scan.scan_file(lex)
        assert e["parse_error"]["code"] == "E0103" and e["parse_error"]["position"]["line"] == 4, e
        assert "\\" not in e["path"], e["path"]
        # 4 = incomplete: a parse error, no findings (D5; was 1).
        for argv, want in (([lex], 4), ([lex, "--allow-parse-errors"], 0),
                           ([lex, "--expect"], 4), ([d, "--json"], 1)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = scan.main(argv)
            assert rc == want, (argv, rc, buf.getvalue()[-400:])
        sarif = scan.to_sarif([e])
        notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notes) == 1 and "E0103" in notes[0]["message"]["text"], notes
    print("D3: scan reads utf-8-sig; a parse error fails the run unless allowed")


def test_fmt_keeps_comments():
    src = ("// expect: E0801\n// second header line\n\nfunction f() returns Unit\n"
           "  effects pure\ndo\n  // above a statement\n  print(\"x\")\nend\n\n"
           "// between decls\nfunction g() returns Int\n  effects pure\ndo\n"
           "  return 1\nend\n\n// trailing\n")
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "c.aeth", src)
        rc, _o, err = _cli("fmt", "--check", p)
        assert rc == 0, err
        rc, _o, err = _cli("fmt", "--write", p)
        assert rc == 0 and open(p, encoding="utf-8").read() == src, err
    # A comment inside an expression is still lost (documented on `pretty`).
    print("D7: fmt keeps header, between-decl, above-statement and trailing comments")


def test_fmt_check_passes_on_commented_corpus_files():
    """Measured: of the parseable corpus, `fmt --check` passed on 58 files
    before (every comment dropped) and 112 after."""
    from aether.parser import parse
    from aether.pretty import pretty
    ok = total = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [x for x in dirnames if not x.startswith(".") and x != "_work"]
        for fn in filenames:
            if not fn.endswith(".aeth"):
                continue
            src = open(os.path.join(dirpath, fn), encoding="utf-8-sig").read()
            try:
                ast = parse(src, fn)
            except Exception:
                continue
            total += 1
            ok += pretty(ast, src) == src
    assert ok >= 110, (ok, total)
    print(f"D7: fmt --check passes on {ok}/{total} parseable .aeth files")


def test_fix_loop_keeps_expect_header_when_it_edits():
    src = ("// expect: E0801\nfunction f() returns Unit\n  effects pure\ndo\n"
           "  print(\"x\")\nend\n")
    fixed, tr = FL.fix_loop(src, allow_widen=True)
    assert tr[-1]["status"] == "widened" and fixed.startswith("// expect: E0801\n"), (fixed, tr)
    print("D7: the fix-loop keeps the `// expect:` header")


CASES = [
    test_cross_file_E0801_on_every_surface,
    test_unresolved_import_E0705_on_every_surface,
    test_json_check_reports_every_stage_tagged,
    test_lex_error_is_a_diagnostic_on_sdk_and_lsp,
    test_scan_reads_bom_and_fails_on_parse_errors,
    test_fmt_keeps_comments,
    test_fmt_check_passes_on_commented_corpus_files,
    test_fix_loop_keeps_expect_header_when_it_edits,
]


if __name__ == "__main__":
    failed = 0
    for t in CASES:
        try:
            t()
        except Exception as e:      # report every case, not just the first
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {str(e)[:600]}")
    print(f"surfaces_agree: {len(CASES) - failed}/{len(CASES)}")
    sys.exit(1 if failed else 0)
