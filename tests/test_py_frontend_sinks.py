"""Python frontend — expression translation and sink detection.

`tests/test_py_soundness.py` owns the capability-table soundness contract
(nothing here may weaken it). This file owns the other half: that a Python
function BODY reaches the Aether detectors as judgeable expression shapes,
and that the sink mapping fires the right existing detector.

Run: python -B tests/test_py_frontend_sinks.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.py_frontend import py_to_ir                    # noqa: E402
from aether.passes import analyze_flat                    # noqa: E402
from aether.passes.ast_walk import walk                   # noqa: E402
from aether.confidence import confidence_of          # noqa: E402


def _fn(src: str, name: str):
    ast_dict, _unp, _meta = py_to_ir(src)
    for d in ast_dict["decls"]:
        if d.get("kind") == "FunctionDecl" and d["name"] == name:
            return d
    raise AssertionError(f"no FunctionDecl named {name!r}")


# Stages that do not apply to Python, skipped here and by `check-py` —
# the one definition, with its rationale, is in py_frontend.py.
from aether.py_frontend import PY_SKIP_STAGES              # noqa: E402


def _codes(src: str):
    ast_dict, _unp, _meta = py_to_ir(src)
    return sorted(d.code for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES))


# --- expression translation ---------------------------------------------

def test_body_is_no_longer_discarded():
    d = _fn("def f(a):\n    x = a + 'b'\n    return x\n", "f")
    assert d["body"], "the function body must reach the IR, not be dropped"
    print("body: statements reach the IR")


def test_assign_becomes_let():
    d = _fn("def f(a):\n    x = 'lit'\n", "f")
    lets = [n for n in walk(d["body"], "Let")]
    assert len(lets) == 1 and lets[0]["name"] == "x", \
        "a single-target assignment must become a Let the safe-name pass can read"
    assert lets[0]["value"]["kind"] == "StringLit", "a str constant is a StringLit"
    print("Let: assignment translated with a StringLit value")


def test_concat_becomes_binop_plus():
    d = _fn("def f(a):\n    x = 'p/' + a\n", "f")
    lets = [n for n in walk(d["body"], "Let")]
    v = lets[0]["value"]
    assert v["kind"] == "BinOp" and v["op"] == "+", \
        "string concatenation must reach the rules as BinOp '+'"
    print("BinOp: '+' concatenation translated")


def test_fstring_becomes_concat():
    d = _fn("def f(uid):\n    x = f'id={uid}'\n", "f")
    v = [n for n in walk(d["body"], "Let")][0]["value"]
    assert v["kind"] == "BinOp" and v["op"] == "+", \
        "an f-string with an interpolation is a concatenation, not a literal"
    print("BinOp: f-string with interpolation translated as concat")


def test_constant_only_fstring_is_a_literal():
    d = _fn("def f():\n    x = f'no interpolation here'\n", "f")
    v = [n for n in walk(d["body"], "Let")][0]["value"]
    assert v["kind"] == "StringLit", \
        "an f-string with no FormattedValue is a fixed literal"
    print("StringLit: constant-only f-string translated as a literal")


def test_percent_format_becomes_concat():
    d = _fn("def f(a):\n    x = 'id=%s' % a\n", "f")
    v = [n for n in walk(d["body"], "Let")][0]["value"]
    assert v["kind"] == "BinOp" and v["op"] == "+", \
        "%-formatting builds a dynamic string - same shape as concat"
    print("BinOp: %-formatting translated as concat")


def test_unmodeled_expression_is_not_cleared():
    d = _fn("def f(xs):\n    x = [i for i in xs]\n", "f")
    v = [n for n in walk(d["body"], "Let")][0]["value"]
    assert v["kind"] == "PyExpr", \
        "an unmodeled expression must be opaque, never silently a literal"
    print("PyExpr: unmodeled expression stays opaque (flag-more direction)")


# --- sink mapping: the detectors fire on unmodified Python --------------

VULN_SRC = """
import os
import subprocess
import pickle


def get_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")


def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)


def read_upload(base, entry):
    return open(base + "/" + entry).read()


def load_session(blob):
    pickle.loads(blob)


def run_it(cmd):
    os.system("sh -c " + cmd)
"""


def test_the_five_vulnerabilities_are_found():
    codes = _codes(VULN_SRC)
    assert codes.count("E0713") == 1, f"SQL injection via concat must fire: {codes}"
    assert codes.count("E0714") == 2, f"both command injections must fire: {codes}"
    assert codes.count("E0711") == 1, f"path traversal via concat must fire: {codes}"
    assert codes.count("E0720") == 1, f"pickle.loads must fire: {codes}"
    print("sinks: all five vulnerabilities found on unmodified Python")


def test_fstring_sql_injection_found():
    src = "def q(cur, uid):\n    cur.execute(f'SELECT * FROM t WHERE id={uid}')\n"
    assert "E0713" in _codes(src), "an f-string query is a dynamic query"
    print("sinks: f-string SQL injection found")


def test_literal_query_is_clean():
    src = "def q(cur):\n    cur.execute('SELECT 1')\n"
    assert "E0713" not in _codes(src), "a fixed literal query is not an injection"
    print("sinks: literal query stays clean")


def test_shell_false_is_not_a_shell_sink():
    src = ("import subprocess\n"
           "def r(name):\n    subprocess.run(['convert', name])\n")
    assert "E0714" not in _codes(src), \
        "an argv list without shell=True never reaches a shell"
    print("sinks: subprocess without shell=True is not a shell sink")


def test_yaml_load_with_safe_loader_is_not_a_sink():
    src = ("import yaml\n"
           "def load(raw):\n    yaml.load(raw, Loader=yaml.SafeLoader)\n")
    assert "E0720" not in _codes(src), \
        "an explicit safe Loader is the documented safe form of yaml.load"
    print("sinks: yaml.load with SafeLoader is not a deserialization sink")


def test_chained_receiver_call_is_not_lost():
    """`conn.cursor().execute(sql)` — the sink is reached through a call
    used as a RECEIVER. Dropping receivers loses the finding entirely."""
    src = "def q(conn, name):\n    conn.cursor().execute('SELECT ' + name)\n"
    assert "E0713" in _codes(src), \
        "a sink called on the result of another call must still be seen"
    print("sinks: chained receiver call is translated")


def test_sink_tables_are_auditable():
    from aether.py_frontend import mapping_table
    t = mapping_table()
    for key in ("sink_by_qualified", "sink_by_method", "sink_by_builtin"):
        assert key in t and t[key], f"{key} must be exposed for audit"
    print("sinks: mapping tables exposed via mapping_table()")


# --- the fix must be silent ---------------------------------------------
# Each bench repro carries the vulnerable shape AND the documented fix.
# A checker that flags both is noise, not a checker.

import glob                                                      # noqa: E402

SINK_CODES = {"E0711", "E0713", "E0714", "E0718", "E0719", "E0720", "E0727"}


def _repro_files():
    return sorted(glob.glob(os.path.join(ROOT, "bench", "realworld_*", "*_repro.py")))


def test_repro_corpus_flags_the_bug():
    files = _repro_files()
    assert files, "bench repro corpus is empty - glob found nothing"
    hits = {}
    for path in files:
        with open(path, encoding="utf-8") as f:
            codes = set(_codes(f.read())) & SINK_CODES
        hits[os.path.basename(path)] = sorted(codes)
    # The four sink-family repros must each produce their code.
    assert "E0714" in hits.get("subprocess_repro.py", []), hits
    assert "E0720" in hits.get("pyyaml_repro.py", []), hits
    print("repro corpus: sink-family bugs found ->", hits)


def test_safe_functions_are_clean():
    """Per-function: the documented fix must produce no sink-family code."""
    import ast as pyast
    offenders = []
    for path in _repro_files():
        with open(path, encoding="utf-8") as f:
            src = f.read()
        for node in pyast.parse(src).body:
            if not isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
                continue
            if not node.name.endswith("_safe"):
                continue
            fn_src = pyast.get_source_segment(src, node) or ""
            header = "\n".join(l for l in src.splitlines()
                               if l.startswith("import ") or l.startswith("from "))
            codes = set(_codes(header + "\n\n" + fn_src)) & SINK_CODES
            if codes:
                offenders.append((os.path.basename(path), node.name, sorted(codes)))
    assert not offenders, \
        "the documented FIX must not be flagged - that is noise: " + repr(offenders)
    print("repro corpus: every *_safe function is clean")


def test_parameterized_query_is_the_sanctioned_exit():
    """DB-API parameter binding is Python's `sqlBind`: the driver binds
    the values, so the string is not the injection vector. It is a call
    SHAPE (a second argument), not a wrapper function."""
    src = ("def q(cur, uid):\n"
           "    cur.execute('SELECT * FROM t WHERE id = ?', (uid,))\n")
    assert "E0713" not in _codes(src), \
        "a parameterized query is the documented safe form"
    print("sinks: parameterized query passes clean")


def test_single_arg_dynamic_query_still_fires():
    src = ("def q(cur, uid):\n"
           "    cur.execute('SELECT * FROM t WHERE id = ' + uid)\n")
    assert "E0713" in _codes(src), \
        "one argument built by concatenation is the injection"
    print("sinks: single-argument dynamic query still fires")


def test_with_statement_open_is_seen():
    """`with open(path) as f:` is THE idiomatic Python file access.
    Missing it made the benign-corpus false-positive count look good for
    the wrong reason: most file opens were simply invisible."""
    src = ('def load(base, name):\n'
           '    with open(base + "/" + name) as f:\n'
           '        return f.read()\n')
    assert "E0711" in _codes(src), \
        "a with-statement open must reach the path rule"
    print("sinks: with-statement open is translated")


def test_string_literal_carries_a_position():
    """E0723 anchors on the literal itself. A finding with no line is
    useless to a fix-loop, so StringLit must carry `pos`."""
    src = 'def f():\n\n\n    k = "AKIAIOSFODNN7EXAMPLE"\n'
    ast_dict, _u, _m = py_to_ir(src)
    diags = [d for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES)
             if d.code == "E0723"]
    assert diags, "a hardcoded AWS key literal must be reported"
    assert diags[0].position.line == 4, \
        f"E0723 must anchor on the literal's real line, got {diags[0].position.line}"
    print("sinks: E0723 anchors on the literal's line")


def test_xxe_safe_parser_disarms_the_sink():
    src = ("from lxml import etree\n"
           "def load(raw):\n"
           "    parser = etree.XMLParser(resolve_entities=False)\n"
           "    etree.fromstring(raw, parser)\n")
    assert "E0727" not in _codes(src), \
        "resolve_entities=False is lxml's documented XXE fix"
    print("sinks: XML parser with entities off is not an XXE sink")


def test_xxe_default_parser_still_fires():
    src = ("from lxml import etree\n"
           "def load(raw):\n"
           "    parser = etree.XMLParser(resolve_entities=True)\n"
           "    etree.fromstring(raw, parser)\n")
    assert "E0727" in _codes(src), \
        "entity resolution left ON is the vulnerability"
    print("sinks: XML parser with entities on still fires")


_LXML_SAFE = "lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)"


def test_xxe_python_text_names_the_callee_and_a_python_fix():
    """E0727's text on a Python finding names the resolved callee and a
    fix that exists in Python — `parseXmlSafe` is an Aether function.
    Measured 2026-09-11 (LOOP_LOG iteration 53): by default no stdlib
    parser fetches an external entity, ElementTree never does without a
    parser argument (a caller's parser is used as given: BUG-031, measured
    2026-09-15), expatbuilder takes no parser and never does,
    xml.sax.parse/parseString cannot, minidom/pulldom do through a
    `parser=` built with `feature_external_ges`; a parse() spelling opens
    its source string as a path (xml.sax.parse and lxml.etree.parse also
    as a URL); lxml reads the file by default before 5.0 and under
    `resolve_entities=True`, a URL only with `no_network=False`.
    Detection is untouched on these shapes: same codes, same confidence."""
    src = ("import xml.etree.ElementTree as ET\n"
           "import xml.etree.cElementTree as CET\n"
           "from xml.dom import minidom, pulldom, expatbuilder\n"
           "import xml.sax\n"
           "from lxml import etree\n"
           "def a(raw):\n    return ET.fromstring(raw)\n"
           "def b(raw):\n    return minidom.parseString(raw)\n"
           "def c(raw):\n    return xml.sax.parseString(raw, None)\n"
           "def d(raw):\n    return pulldom.parseString(raw)\n"
           "def e(raw):\n    return etree.fromstring(raw)\n"
           "def f(raw):\n    return CET.fromstring(raw)\n"
           "def g(raw):\n    return expatbuilder.parseString(raw)\n"
           "def h(raw):\n    return ET.parse(raw)\n"
           "def i(raw):\n    return xml.sax.parse(raw, None)\n"
           "def j(raw):\n    return etree.parse(raw)\n"
           "def k(raw):\n    return minidom.parse(raw)\n")
    ast_dict, _, _ = py_to_ir(src)
    ds = {d.extra["function"]: d
          for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0727"}
    assert set(ds) == set("abcdefghijk"), sorted(ds)
    assert all(d.confidence == confidence_of("qualified") for d in ds.values()), \
        {k: d.confidence for k, d in ds.items()}
    for fn, callee, fix in [
        ("a", "xml.etree.ElementTree.fromstring", "defusedxml.ElementTree.fromstring"),
        ("b", "xml.dom.minidom.parseString", "defusedxml.minidom.parseString"),
        ("c", "xml.sax.parseString", "defusedxml.sax.parseString"),
        ("d", "xml.dom.pulldom.parseString", "defusedxml.pulldom.parseString"),
        # defusedxml.cElementTree is deprecated: the hint names ElementTree.
        ("f", "xml.etree.cElementTree.fromstring", "defusedxml.ElementTree.fromstring"),
        ("g", "xml.dom.expatbuilder.parseString", "defusedxml.expatbuilder.parseString"),
        ("h", "xml.etree.ElementTree.parse", "defusedxml.ElementTree.parse"),
        ("i", "xml.sax.parse", "defusedxml.sax.parse"),
        ("k", "xml.dom.minidom.parse", "defusedxml.minidom.parse"),
    ]:
        d = ds[fn]
        assert d.extra["callee"] == callee, d.extra
        assert callee in d.message and fix in d.suggestion, (d.message, d.suggestion)
        assert "cElementTree" not in d.suggestion, d.suggestion
        assert "parseXmlSafe" not in d.suggestion, d.suggestion
        # defusedxml defuses only the parser it builds: the hint says so.
        assert "no parser argument, parser= or positional" in d.suggestion \
            and "otherwise pass no parser argument and check" in d.suggestion, d.suggestion
        # The DoS clause is hedged and per issue, as the Python docs put
        # it; "large tokens" is not an entity-expansion attack.
        assert "may be open to" in d.message and "2.4.1" in d.message \
            and "2.6.0" in d.message and "2.7.2" in d.message, d.message
        assert "entity-expansion" not in d.message, d.message
        assert "pyexpat.version_info >= (2, 7, 2)" in d.suggestion, d.suggestion
    # ElementTree, cElementTree, expatbuilder: never an XXE read, any Expat
    # -- for ElementTree/cElementTree only without a parser argument.
    for fn in ("a", "f", "g", "h"):
        assert "never expands external entities" in ds[fn].message \
            and "on any Expat" in ds[fn].message, ds[fn].message
    for fn in ("a", "f", "h"):
        assert "called without a parser argument" in ds[fn].message \
            and "is used as given" in ds[fn].message, ds[fn].message
    assert "takes no parser argument and never expands" in ds["g"].message \
        and "used as given" not in ds["g"].message, ds["g"].message
    # xml.sax.parse/parseString build their own parser: the feature is
    # unreachable through them; the negation is scoped to entities.
    for fn in ("c", "i"):
        assert "takes no parser argument" in ds[fn].message \
            and "no XXE through entities" in ds[fn].message, ds[fn].message
        assert "feature_external_ges" not in ds[fn].message, ds[fn].message
        assert "not a file read" not in ds[fn].message, ds[fn].message
    # minidom / pulldom: a parser= built with feature_external_ges reads
    # files and reaches URLs (measured).
    for fn in ("b", "d", "k"):
        assert "parser= argument" in ds[fn].message \
            and "feature_external_ges" in ds[fn].message \
            and "reading local files and reaching internal URLs" in ds[fn].message, \
            ds[fn].message
    # The parse() spellings open their source; the string forms do not.
    for fn in ("h", "k"):
        assert "opened as a local path" in ds[fn].message, ds[fn].message
        assert "never pass an untrusted path" in ds[fn].suggestion, ds[fn].suggestion
    assert "urllib.request.urlopen()" in ds["i"].message, ds["i"].message
    assert "path or URL" in ds["i"].suggestion, ds["i"].suggestion
    assert "filename or URL lxml opens with any parser" in ds["j"].message, ds["j"].message
    for fn in "abcdefg":
        assert "source string" not in ds[fn].message, ds[fn].message
    # lxml: the file read is real; a URL only with no_network=False; the
    # fix is the exact binding the frontend clears, in either slot.
    for fn in ("e", "j"):
        e = ds[fn]
        assert e.extra["callee"] == "lxml.etree." + ("fromstring" if fn == "e" else "parse"), e.extra
        assert "5.0" in e.message and "resolve_entities=True" in e.message \
            and "no_network=False" in e.message and "reads local files" in e.message, e.message
        assert "reaches internal URLs" not in e.message, e.message
        assert _LXML_SAFE in e.suggestion and "as parser=" in e.suggestion \
            and "parseXmlSafe" not in e.suggestion, e.suggestion
    print("sinks: E0727 on Python names the callee and a Python fix")


def test_xxe_python_fix_shapes_are_clean():
    """Every fix an E0727 hint names is itself clean, in the same walk as
    shapes that must fire (the positive controls): the defusedxml
    equivalents without a parser, and the exact lxml parser binding the
    hint prescribes (`_LXML_SAFE`, the string the hint carries), passed
    positionally or as `parser=` — lxml's own spelling, which fired until
    iteration 53. Still firing: a parser that is not that binding in
    either slot, a `**kwargs` splat, a hardened parser under the WRONG
    keyword, a binding that re-enables DTD retrieval, the dead
    `make_parser(resolve_entities=False)` shape, and defusedxml handed a
    caller's parser — the shape its own hint would otherwise steer into."""
    src = ("import defusedxml.ElementTree as DET\n"
           "from defusedxml import minidom as dm\n"
           "import defusedxml.sax\n"
           "from lxml import etree\n"
           "import xml.sax\n"
           "from xml.dom import pulldom\n"
           "def a(raw):\n    return DET.fromstring(raw)\n"
           "def b(raw):\n    return dm.parseString(raw)\n"
           "def c(raw):\n    return defusedxml.sax.parseString(raw, None)\n"
           "def d(raw):\n"
           f"    parser = {_LXML_SAFE}\n"
           "    return etree.fromstring(raw, parser)\n"
           "def e(raw):\n"
           f"    parser = {_LXML_SAFE}\n"
           "    return etree.fromstring(raw, parser=parser)\n"
           "def f(raw):\n"
           f"    parser = {_LXML_SAFE}\n"
           "    return etree.parse(raw, parser=parser, base_url=None)\n"
           "def g(raw):\n    return dm.parseString(raw, parser=None)\n"
           "def s(raw, p):\n    return dm.parseString(raw, parser=p)\n"
           "def t(raw):\n    parser = etree.XMLParser(resolve_entities=False, load_dtd=True, no_network=False)\n"
           "    return etree.fromstring(raw, parser)\n"
           "def u(raw):\n    p = xml.sax.make_parser(resolve_entities=False)\n"
           "    return pulldom.parseString(raw, p)\n"
           "def v(raw):\n"
           f"    parser = {_LXML_SAFE}\n"
           "    return etree.fromstring(raw, base_url=parser)\n"
           "def w(raw, **kw):\n    return etree.fromstring(raw, **kw)\n"
           "def x(raw):\n    return etree.fromstring(raw)\n"
           "def y(raw):\n    parser = etree.XMLParser(resolve_entities=True)\n"
           "    return etree.fromstring(raw, parser=parser)\n"
           "def z(raw, parser):\n    return etree.fromstring(raw, parser=parser)\n")
    ast_dict, _, _ = py_to_ir(src)
    ds = {d.extra["function"]: d
          for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0727"}
    assert sorted(ds) == ["s", "t", "u", "v", "w", "x", "y", "z"], sorted(ds)
    assert ds["s"].extra["match"] == "guard" \
        and ds["s"].extra["callee"] == "defusedxml.minidom.parseString", ds["s"].extra
    assert "passes a caller's parser straight through" in ds["s"].message, ds["s"].message
    assert "drop the parser= argument" in ds["s"].suggestion, ds["s"].suggestion
    print("sinks: every E0727 hint's fix shape is clean; parser= clears like the positional slot")


def test_xxe_elementtree_text_is_scoped_to_calls_without_a_parser():
    """BUG-031. ElementTree/cElementTree parse(source, parser=None) and
    fromstring(text, parser=None) use a caller's parser as given, keyword
    or positional. Measured 2026-09-15 (CPython 3.11.15, Expat 2.7.4, lxml
    6.1.1, a local HTTP server): an lxml XMLParser(resolve_entities=True)
    returned a local file's contents through ET.fromstring/XML/parse (a
    URL request with no_network=False too), and a make_parser() with
    feature_external_ges delivered a file's contents to its handler and
    fetched a URL. The text said "never" unconditionally; it now scopes
    that to the no-parser call. expatbuilder takes no parser (its second
    positional is `namespaces`), so "never" stays exact there. Also: the
    lxml file read is conditional (lxml 6.1.1's default parser read
    nothing), and minidom/pulldom's text does not borrow the xml.sax
    3.7.1 date. Detection is unchanged: every shape fires as qualified."""
    src = ("import xml.etree.ElementTree as ET\n"
           "import xml.etree.cElementTree as CET\n"
           "from xml.dom import minidom, pulldom, expatbuilder\n"
           "from lxml import etree\n"
           "def a(raw, p):\n    return ET.fromstring(raw, parser=p)\n"
           "def b(raw, p):\n    return ET.parse(raw, p)\n"
           "def c(raw, p):\n    return CET.fromstring(raw, parser=p)\n"
           "def d(raw):\n    return CET.parse(raw)\n"
           "def e(raw):\n    return expatbuilder.parse(raw)\n"
           "def f(raw):\n    return etree.XML(raw)\n"
           "def g(raw):\n    return minidom.parseString(raw)\n"
           "def h(raw):\n    return pulldom.parse(raw)\n")
    ast_dict, _, _ = py_to_ir(src)
    ds = {d.extra["function"]: d
          for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0727"}
    assert sorted(ds) == list("abcdefgh"), sorted(ds)
    assert all(d.extra["match"] == "qualified" for d in ds.values()), \
        {k: d.extra for k, d in ds.items()}
    for fn, callee in [("a", "xml.etree.ElementTree.fromstring"),
                       ("b", "xml.etree.ElementTree.parse"),
                       ("c", "xml.etree.cElementTree.fromstring"),
                       ("d", "xml.etree.cElementTree.parse")]:
        m, s = ds[fn].message, ds[fn].suggestion
        assert ds[fn].extra["callee"] == callee, ds[fn].extra
        assert "called without a parser argument" in m \
            and "a parser passed in (parser= or positionally) is used as given" in m, m
        assert "XMLParser(resolve_entities=True) reads local files" in m \
            and "fetches URLs with no_network=False" in m \
            and "setFeature(feature_external_ges, True) reads local files and fetches URLs" in m, m
        assert "may be open to" in m and "2.7.2" in m, m
        # The version check alone does not cover a passed parser.
        assert "no parser argument, parser= or positional" in s \
            and "otherwise pass no parser argument and check" in s \
            and "cElementTree" not in s, s
    # cElementTree's parse row: the source-path clause and the
    # defusedxml.ElementTree.parse hint.
    assert "is itself opened as a local path" in ds["d"].message, ds["d"].message
    assert "defusedxml.ElementTree.parse" in ds["d"].suggestion \
        and "never pass an untrusted path" in ds["d"].suggestion, ds["d"].suggestion
    assert "source string" not in ds["c"].message, ds["c"].message
    # expatbuilder takes no parser: the unconditional "never" is exact.
    assert "takes no parser argument and never expands external entities" in ds["e"].message \
        and "used as given" not in ds["e"].message \
        and "opened as a local path" in ds["e"].message, ds["e"].message
    # lxml: the file read is conditional, not a default of every version.
    m = ds["f"].message
    assert "when lxml is older than 5.0" in m \
        and "or when the parser sets resolve_entities=True" in m \
        and "from 5.0 the default parser does not expand it" in m, m
    assert "so a crafted" not in m, m
    # minidom/pulldom: the 3.7.1 date is xml.sax's feature default.
    for fn in ("g", "h"):
        assert "3.7.1" not in ds[fn].message \
            and "external entities are off by default, but" in ds[fn].message, ds[fn].message
    # Every callee the frontend maps to parseXml has Python text: none
    # falls through to the Aether row's parseXmlSafe wording.
    from aether.py_frontend import SINK_BY_QUALIFIED, SINK_GUARDS
    from aether.passes.detector_specs import LITERAL_OR_WRAPPER_SPECS
    spec = next(r for r in LITERAL_OR_WRAPPER_SPECS if r.code == "E0727")
    mapped = [k for k, v in SINK_BY_QUALIFIED.items() if v == "parseXml"] \
        + [k for k, g in SINK_GUARDS.items() if g.sink_name == "parseXml"]
    assert len(mapped) >= 20, sorted(mapped)
    fallthrough = [k for k in mapped
                   if spec.text_for(k) == (spec.message, spec.suggestion)]
    assert not fallthrough, fallthrough
    print("BUG-031: E0727's ElementTree text says never only without a parser argument")


def test_xxe_guard_and_parser_binding_shapes():
    """Detection shapes the E0727 audit found untested, each run through
    check-py first: every defusedxml SINK_GUARDS row handed a caller's
    parser fires as `guard` (keyword and positional slot), a positional
    None is the defused path, and three lxml XMLParser bindings do NOT
    clear the sink: a `**kwargs` splat into the constructor, a
    dtd_validation=True binding, and a no_network value that is not a
    constant."""
    src = ("import defusedxml.minidom as dm\n"
           "import defusedxml.pulldom as dp\n"
           "import defusedxml.ElementTree as DET\n"
           "from lxml import etree\n"
           "def a(raw, p):\n    return dm.parse(raw, parser=p)\n"
           "def b(raw, p):\n    return dp.parse(raw, parser=p)\n"
           "def c(raw, p):\n    return dp.parseString(raw, parser=p)\n"
           "def d(raw, p):\n    return DET.parse(raw, parser=p)\n"
           "def e(raw, p):\n    return dm.parseString(raw, p)\n"
           "def f(raw):\n    return dm.parseString(raw, None)\n"
           "def s(raw, **kw):\n"
           "    parser = etree.XMLParser(resolve_entities=False, **kw)\n"
           "    return etree.fromstring(raw, parser=parser)\n"
           "def t(raw):\n"
           "    parser = etree.XMLParser(resolve_entities=False, dtd_validation=True)\n"
           "    return etree.fromstring(raw, parser)\n"
           "def u(raw, flag):\n"
           "    parser = etree.XMLParser(resolve_entities=False, no_network=flag)\n"
           "    return etree.fromstring(raw, parser)\n")
    ast_dict, _, _ = py_to_ir(src)
    ds = {d.extra["function"]: d
          for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0727"}
    assert sorted(ds) == ["a", "b", "c", "d", "e", "s", "t", "u"], sorted(ds)
    for fn, callee in [("a", "defusedxml.minidom.parse"),
                       ("b", "defusedxml.pulldom.parse"),
                       ("c", "defusedxml.pulldom.parseString"),
                       ("d", "defusedxml.ElementTree.parse"),
                       ("e", "defusedxml.minidom.parseString")]:
        assert ds[fn].extra["match"] == "guard" \
            and ds[fn].extra["callee"] == callee, ds[fn].extra
        assert "passes a caller's parser straight through" in ds[fn].message, ds[fn].message
    for fn in ("s", "t", "u"):
        assert ds[fn].extra["match"] == "qualified" \
            and ds[fn].extra["callee"] == "lxml.etree.fromstring", ds[fn].extra
    print("sinks: defusedxml with a caller's parser fires in either slot; "
          "splat, dtd_validation and non-constant no_network bindings do not clear lxml")


# --- guard-bound-elsewhere: an unresolved guard means SINK ---------------
# These gates decide safety from something other than the argument the
# rule judges. All three shipped defaulting the unknown case to "safe",
# which produced three false accepts (BUGS.md BUG-004). q5's rule applies
# to values exactly as it does to names: never clear on weak evidence.

def test_yaml_unsafe_loader_is_still_a_sink():
    """`Loader=yaml.Loader` is the RCE. Verified by execution on PyYAML
    6.0.3: yaml.Loader constructs !!python/object/apply. Adding Loader=
    to silence the deprecation warning is the commonest wrong fix."""
    src = "import yaml\ndef f(raw):\n    yaml.load(raw, Loader=yaml.Loader)\n"
    assert "E0720" in _codes(src), "yaml.Loader is the unsafe loader"
    print("guard: yaml.Loader still flagged")


def test_yaml_unsafe_loader_named_elsewhere_is_still_a_sink():
    src = ("import yaml\ndef f(raw):\n"
           "    loader = yaml.Loader\n"
           "    yaml.load(raw, Loader=loader)\n")
    assert "E0720" in _codes(src), \
        "a loader bound elsewhere must not clear the sink"
    print("guard: loader bound elsewhere still flagged")


def test_yaml_safe_loader_stays_clean():
    src = "import yaml\ndef f(raw):\n    yaml.load(raw, Loader=yaml.SafeLoader)\n"
    assert "E0720" not in _codes(src), "SafeLoader is the documented fix"
    print("guard: SafeLoader stays clean")


def test_yaml_full_loader_is_not_sanctioned():
    """FullLoader refused this plan's probe payload but has its own
    bypass CVEs (CVE-2020-1747, CVE-2020-14343). Over-flag."""
    src = "import yaml\ndef f(raw):\n    yaml.load(raw, Loader=yaml.FullLoader)\n"
    assert "E0720" in _codes(src), \
        "FullLoader is deliberately not sanctioned - it has bypass CVEs"
    print("guard: FullLoader deliberately not sanctioned")


def test_shell_true_bound_elsewhere_is_still_a_sink():
    src = ("import subprocess\ndef f(cmd):\n"
           "    sh = True\n"
           "    subprocess.run('x ' + cmd, shell=sh)\n")
    assert "E0714" in _codes(src), \
        "shell= whose value is not provably False must be treated as a shell"
    print("guard: shell bound elsewhere still flagged")


def test_concatenated_sql_with_params_is_still_a_sink():
    """A second argument does not launder a concatenated query. The
    parameterized form is already clean because argument 0 is a literal -
    the recognizer was unnecessary AND wrong."""
    src = ("def f(cur, name, extra):\n"
           "    cur.execute('SELECT * FROM t WHERE n=' + name, extra)\n")
    assert "E0713" in _codes(src), \
        "params do not save a query built by concatenation"
    print("guard: concatenated SQL with params still flagged")


def test_attribute_read_of_a_call_result_is_not_lost():
    """`subprocess.run(...).returncode` is an attribute READ of a call
    result — not a call, so the call inside it used to vanish. Found by
    the bench, not by a hand-written test: the same shape without
    `.returncode` was flagged, so the unit tests all passed."""
    src = ("import subprocess\ndef f(cmd):\n"
           "    return subprocess.run('x ' + cmd, shell=True).returncode\n")
    assert "E0714" in _codes(src), \
        "a sink call under an attribute read must still be seen"
    print("guard: attribute read of a call result is translated")


def test_safe_loader_bound_elsewhere_is_clean():
    src = ("import yaml\ndef f(raw):\n"
           "    loader = yaml.SafeLoader\n"
           "    yaml.load(raw, Loader=loader)\n")
    assert "E0720" not in _codes(src), \
        "a name bound once to a sanctioned loader is resolvable"
    print("guard: SafeLoader bound elsewhere resolves clean")


def test_rebound_loader_is_still_a_sink():
    src = ("import yaml\ndef f(raw, flag):\n"
           "    loader = yaml.SafeLoader\n"
           "    loader = yaml.Loader\n"
           "    yaml.load(raw, Loader=loader)\n")
    assert "E0720" in _codes(src), \
        "a name with disagreeing bindings must not resolve to safe"
    print("guard: rebound loader stays flagged")


def test_shell_false_bound_elsewhere_is_clean():
    src = ("import subprocess\ndef f(cmd):\n"
           "    sh = False\n"
           "    subprocess.run(['x', cmd], shell=sh)\n")
    assert "E0714" not in _codes(src), \
        "shell provably False is not a shell sink"
    print("guard: shell=False bound elsewhere resolves clean")


# --- recall gaps found by the bandit oracle (bench/pypi_scan/run_recall) ---
# Each of these was a confirmed MISS on real PyPI code: an independent
# tool flagged the shape and Aether said nothing. Table rows were added
# only for shapes the oracle actually flagged - no speculative entries.

def test_recall_gap_shapes_now_fire():
    src = ("import marshal\nimport pickle\n"
           "from xml.dom import pulldom\n"
           "from xml.etree import ElementTree as ET\n"
           "import xml.sax\n"
           "def a(f):\n    return marshal.load(f)\n"
           "def b(f):\n    return pickle.Unpickler(f).load()\n"
           "def c(s):\n    return pulldom.parseString(s)\n"
           "def d(s):\n    return ET.fromstring(s)\n"
           "def e(s):\n    return xml.sax.parseString(s, None)\n")
    codes = _codes(src)
    assert codes.count("E0720") == 2, f"marshal.load + Unpickler: {codes}"
    assert codes.count("E0727") == 3, f"pulldom + ET alias + xml.sax: {codes}"
    print("recall: all five oracle-confirmed misses now fire")


def test_chained_module_path_resolves():
    """`import xml.sax` + `xml.sax.parseString(...)` arrives as
    Attribute(Attribute(Name)). Resolving one level returned the bare
    method name, so the dotted table never matched - while the
    `from xml.dom import minidom` spelling of the same sink matched fine.

    Also pins the substitution bug found while fixing it: `import xml.sax`
    binds the ROOT name, so alias_to_path["xml"] is "xml.sax" and naive
    substitution produced "xml.sax.sax.parseString"."""
    from aether.py_frontend import _callee_spelling, _Imports
    import ast as pyast
    imp = _Imports()
    tree = pyast.parse("import xml.sax\nimport numpy as np\n"
                       "xml.sax.parseString(s)\nnp.linalg.norm(v)\n")
    for n in tree.body:
        if isinstance(n, pyast.Import):
            imp.add_import(n)
    calls = [n for n in pyast.walk(tree) if isinstance(n, pyast.Call)]
    assert _callee_spelling(calls[0].func, imp) == "xml.sax.parseString", \
        _callee_spelling(calls[0].func, imp)
    assert _callee_spelling(calls[1].func, imp) == "numpy.linalg.norm", \
        _callee_spelling(calls[1].func, imp)
    print("recall: chained module paths resolve, aliases still substitute")


def test_pypi_scan_row_set_matches_cli():
    """The PyPI scan claims to measure exactly what `check-py` prints. If
    the CLI's row set drifts, the scan's headline number silently stops
    describing the shipped tool."""
    import importlib.util
    from transpiler.aether import cli
    spec = importlib.util.spec_from_file_location(
        "pypi_scan", os.path.join(ROOT, "bench", "pypi_scan", "run_scan.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.SKIP_STRICT == cli._PY_SKIP_STAGES, \
        f"scan {m.SKIP_STRICT} vs cli {cli._PY_SKIP_STAGES}"
    assert m.SKIP_DEFAULT == cli._PY_SKIP_STAGES + ("capability",), \
        f"scan default stages drifted: {m.SKIP_DEFAULT}"
    assert m.STRICT_ONLY == cli._PY_STRICT_ONLY_CODES, \
        f"scan {m.STRICT_ONLY} vs cli {cli._PY_STRICT_ONLY_CODES}"
    print("scan: row set matches the CLI's")


def test_unmapped_call_cannot_collide_with_an_aether_sink_name():
    """An unmapped Python call keeps its spelling under a `py:` prefix, so
    a method merely SPELLED like an Aether sink cannot become one without
    passing through the mapping table. Found by the PyPI scan: before the
    prefix, `self.redirect(uri)` fired E0718 and `self.renderTemplate(x)`
    fired E0719 on the name collision alone."""
    src = ("class H:\n"
           "    def go(self, uri):\n"
           "        self.redirect(uri)\n"
           "    def w(self, x):\n"
           "        self.renderTemplate(x)\n"
           "    def d(self, b):\n"
           "        self.deserialize(b)\n")
    codes = _codes(src)
    assert codes == [], \
        f"a name collision must not create an unmapped sink: {codes}"
    print("sinks: unmapped calls cannot collide with Aether sink names")


def test_real_mapped_sinks_still_fire_after_prefixing():
    """The prefix must not cost a mapped sink. Control for the test above."""
    src = ("import os\nfrom flask import redirect\n"
           "def a(cmd):\n    os.system('sh ' + cmd)\n"
           "def b(nxt):\n    redirect(nxt)\n")
    codes = _codes(src)
    assert "E0714" in codes and "E0718" in codes, \
        f"mapped sinks must still fire: {codes}"
    print("sinks: mapped sinks unaffected by the py: prefix")


# --- CLI ----------------------------------------------------------------
# `_emit_error` writes diagnostics to STDERR and the summary to STDOUT,
# so these assert against the combined output.

def _run_check_py(src: str, *flags):
    import subprocess as sp
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "m.py")
        with open(p, "w", encoding="utf-8") as f:
            f.write(src)
        r = sp.run([sys.executable, "-B", "-m", "transpiler.aether.cli",
                    "check-py", p, *flags], cwd=ROOT,
                   capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


_OPEN_PARAM_SRC = 'def load(path):\n    with open(path) as f:\n        return f.read()\n'


def test_e0711_is_held_back_by_default():
    """Measured on 76 benign modules: E0711 fired 11 times, 8 of them
    `open(path_param)`. Real, but at a ratio that buries the other rows."""
    rc, out = _run_check_py(_OPEN_PARAM_SRC)
    # "[E0711]" is the diagnostic form; the banner mentions the bare code
    # when it explains what --strict adds, and that must not count.
    assert "[E0711]" not in out, f"E0711 must not be reported by default: {out}"
    assert rc == 0, f"default run on this shape must be clean: {out}"
    print("cli: E0711 held back by default")


def test_e0711_appears_under_strict():
    rc, out = _run_check_py(_OPEN_PARAM_SRC, "--strict")
    assert "[E0711]" in out, f"--strict must report E0711: {out}"
    assert rc == 2, "a finding must exit 2"
    print("cli: --strict reports E0711")


def test_check_py_cli_reports_and_exits_2():
    rc, out = _run_check_py("import subprocess\n"
                            "def r(host):\n"
                            "    subprocess.run('ping ' + host, shell=True)\n")
    assert rc == 2, f"a finding must exit 2, got {rc}: {out}"
    assert "E0714" in out, out
    assert "not checked" in out.lower(), \
        "the reduced guarantee set must be stated on the output, not implied"
    print("cli: check-py reports E0714 and states its limits")


def test_check_py_clean_exits_0():
    rc, out = _run_check_py("def add(a, b):\n    return a + b\n")
    assert rc == 0, f"clean file must exit 0: {out}"
    print("cli: check-py on a clean file exits 0")


# --- directory walk -----------------------------------------------------

_CMDI_SRC = ("import subprocess\n"
             "def r(h):\n"
             "    subprocess.run('ping ' + h, shell=True)\n")


def _run_check_py_tree(files, *flags, target="."):
    """Write `files` ({relative path: source-or-bytes}) into a temp tree and
    run `check-py` over `target` within it. Returns (rc, combined output)."""
    import subprocess as sp
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        for rel, src in files.items():
            p = os.path.join(d, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            mode, enc = ("wb", None) if isinstance(src, bytes) else ("w", "utf-8")
            with open(p, mode, encoding=enc) as f:
                f.write(src)
        r = sp.run([sys.executable, "-B", "-m", "transpiler.aether.cli",
                    "check-py", os.path.join(d, *target.split("/")), *flags],
                   cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def test_directory_walk_scans_every_file():
    rc, out = _run_check_py_tree({
        "app/a.py": _CMDI_SRC,
        "app/sub/b.py": "def f(cur, n):\n    cur.execute('SELECT ' + n)\n",
        "app/clean.py": "def add(a, b):\n    return a + b\n",
    })
    assert rc == 2, f"findings in a tree must exit 2: {out}"
    assert "E0714" in out and "E0713" in out, \
        f"both files' findings must be reported: {out}"
    assert "a.py" in out and "b.py" in out, \
        f"each finding must name its file: {out}"
    assert "scanned 3 file(s)" in out, f"summary must count every file: {out}"
    print("cli: check-py walks a directory and names each file")


def test_directory_walk_skips_vendored_trees():
    """A repo scan must not become a dependency scan. Findings the user
    cannot fix bury the ones they can."""
    rc, out = _run_check_py_tree({
        "app/mine.py": "def add(a, b):\n    return a + b\n",
        ".venv/lib/vendored.py": _CMDI_SRC,
        "node_modules/x/dep.py": _CMDI_SRC,
        "__pycache__/cached.py": _CMDI_SRC,
        "build/generated.py": _CMDI_SRC,
    })
    assert "E0714" not in out, f"vendored trees must not be walked: {out}"
    assert "scanned 1 file(s)" in out, f"only the user's file counts: {out}"
    assert rc == 0, f"no findings in the user's own code must exit 0: {out}"
    print("cli: check-py skips .venv/node_modules/__pycache__/build")


def test_unparseable_file_does_not_abort_the_walk():
    """py2 sources, templates and fixtures are normal in a real tree. They
    are counted, and the files after them are still scanned."""
    rc, out = _run_check_py_tree({
        "app/a_py2.py": "print 'hello'\n",       # sorts before b.py
        "app/b.py": _CMDI_SRC,
    })
    assert rc == 2, f"the finding after the bad file must still be found: {out}"
    assert "E0714" in out, out
    assert "1 unparseable" in out, f"the skip must be counted, not hidden: {out}"
    print("cli: an unparseable file does not abort the walk")


def test_utf8_bom_file_is_scanned_not_silently_skipped():
    """A UTF-8 BOM is common on Windows and Python's own tokenizer strips
    it. Read as plain utf-8 it survives as U+FEFF, every such file becomes
    a SyntaxError, and a tree walk counts it 'unparseable' — a SILENT
    false negative. Found by scanning a tree written by PowerShell."""
    rc, out = _run_check_py_tree({
        "app/bom.py": b"\xef\xbb\xbf" + _CMDI_SRC.encode("utf-8"),
    })
    assert "0 unparseable" in out, \
        f"a BOM must not make a file unreadable: {out}"
    assert "E0714" in out and rc == 2, \
        f"the finding in a BOM'd file must still be reported: {out}"
    print("cli: a UTF-8 BOM does not hide a file from the scanner")


def test_missing_path_is_a_usage_error():
    import subprocess as sp
    r = sp.run([sys.executable, "-B", "-m", "transpiler.aether.cli",
                "check-py", "no/such/path.py"], cwd=ROOT,
               capture_output=True, text=True)
    assert r.returncode == 2, f"a missing target must exit 2: {r.stderr}"
    assert "no such file or directory" in (r.stdout + r.stderr).lower()
    print("cli: a missing target is a usage error, not a traceback")


# --- BUG-010: a SQLAlchemy expression is a parameterized query --------
# 1,029 of 1,055 findings across 15 agent frameworks were E0713 on
# `conn.execute(select(t).where(...))` — the safest SQL in Python. The
# soundness line: `text(...)`/`literal_column(...)` are where raw strings
# re-enter, and a concatenation there must still fire, nested or not.

def test_sqlalchemy_expression_is_not_a_dynamic_query():
    src = ("from sqlalchemy import select, delete, insert\n"
           "def a(conn, t, cid):\n    return conn.execute(select(t).where(t.c.id == cid))\n"
           "def b(conn, t, now):\n    conn.execute(delete(t).where(t.c.x < now))\n"
           "def c(conn, t, n):\n    conn.execute(insert(t).values(name=n))\n")
    assert "E0713" not in _codes(src), _codes(src)
    print("sqla: select/delete/insert expressions are not dynamic queries")


def test_sqlalchemy_alias_and_chained_receiver_are_clean():
    src = ("import sqlalchemy as sa\n"
           "def a(conn, t, cid):\n"
           "    return conn.execute(sa.select(t.c.m).where(t.c.id == cid)).first()\n")
    assert "E0713" not in _codes(src), _codes(src)
    print("sqla: module alias resolves; call-as-receiver shape is clean")


def test_sqlalchemy_text_literal_clean_but_concat_fires():
    clean = ("from sqlalchemy import text\n"
             "def a(conn):\n    conn.execute(text('SELECT 1'))\n"
             "def b(conn, u):\n"
             "    conn.execute(text('SELECT * FROM t WHERE id = :id'), {'id': u})\n")
    bad = ("from sqlalchemy import text\n"
           "def a(conn, u):\n    conn.execute(text('SELECT 1 WHERE id=' + u))\n")
    assert "E0713" not in _codes(clean), _codes(clean)
    assert "E0713" in _codes(bad), "text() with a concatenation is an injection"
    print("sqla: text(literal) clean, text(concat) still fires")


def test_raw_string_nested_inside_a_safe_builder_still_fires():
    src = ("from sqlalchemy import select, text, literal_column\n"
           "def a(conn, t, n):\n"
           "    return conn.execute(select(t).where(text(\"name='\" + n + \"'\")))\n"
           "def b(conn, t, c):\n"
           "    return conn.execute(select(literal_column('id, ' + c)).select_from(t))\n")
    codes = _codes(src)
    assert codes.count("E0713") == 2, f"both nested raw strings must fire: {codes}"
    print("sqla: raw SQL nested in select() is not laundered by the builder")


def test_non_sqlalchemy_name_spelled_select_clears_nothing():
    """q5: a NAME may not clear a call. Only a root that resolves through
    imports into sqlalchemy/sqlmodel is a builder."""
    src = ("from mylib import select\n"
           "def a(conn, q):\n    return conn.execute(select('SELECT ' + q))\n")
    assert "E0713" in _codes(src), "a foreign `select` must stay a computed query"
    print("sqla: a foreign name spelled `select` is still a sink argument")


def test_sql_expression_bound_to_a_local_is_clean():
    src = ("from sqlalchemy import select\n"
           "def a(conn, t, cid):\n"
           "    stmt = select(t).where(t.c.id == cid)\n"
           "    return conn.execute(stmt)\n")
    assert "E0713" not in _codes(src), _codes(src)
    print("sqla: expression bound elsewhere resolves through _safe_names")


def test_statement_built_incrementally_is_clean():
    """The dominant real-world shape: bound to a builder, then rebound to
    methods on itself. Anchored, and closed under self-reference."""
    src = ("from sqlalchemy import select\n"
           "def a(conn, t, cid, lim):\n"
           "    stmt = select(t)\n"
           "    if cid:\n        stmt = stmt.where(t.c.id == cid)\n"
           "    stmt = stmt.limit(lim)\n"
           "    return conn.execute(stmt).fetchall()\n")
    assert "E0713" not in _codes(src), _codes(src)
    print("sqla: incrementally built statement is clean")


def test_one_raw_rebinding_disqualifies_the_name():
    src = ("from sqlalchemy import select, text\n"
           "def a(conn, t, n):\n"
           "    stmt = select(t)\n"
           "    stmt = stmt.where(text(\"name='\" + n + \"'\"))\n"
           "    return conn.execute(stmt)\n")
    assert "E0713" in _codes(src), "a raw rebinding must poison every use"
    print("sqla: one raw rebinding disqualifies the name")


def test_unanchored_self_chain_never_qualifies():
    """Two parameters rebound to methods on each other: no anchor. q5 —
    a name clears nothing, however the chain is spelled."""
    src = ("def a(conn, a, b):\n"
           "    a = b.where(True)\n    b = a.where(True)\n"
           "    return conn.execute(a)\n")
    assert "E0713" in _codes(src), "no builder anchor means no clearance"
    print("sqla: an unanchored self-referential chain stays a sink")


def test_table_method_form_argument_free_only():
    clean = ("def a(conn, t, rid):\n"
             "    conn.execute(t.delete().where(t.c.run_id == rid))\n"
             "    conn.execute(t.update().where(t.c.x == 1).values(d=True))\n")
    bad = ("def a(conn, qb, q):\n"
           "    return conn.execute(qb.select('SELECT * FROM t WHERE ' + q))\n")
    assert "E0713" not in _codes(clean), _codes(clean)
    assert "E0713" in _codes(bad), "a method root handed a string is not the Table form"
    print("sqla: Table-method form accepted only with no positional argument")


def test_text_of_literal_bound_name_clean_but_parameter_fires():
    clean = ("from sqlalchemy import text\n"
             "def a(conn, s):\n"
             "    q = 'SELECT 1 WHERE schema = :s'\n"
             "    return conn.execute(text(q), {'s': s})\n")
    bad = ("from sqlalchemy import text\n"
           "def a(conn, q):\n    return conn.execute(text(q))\n")
    assert "E0713" not in _codes(clean), _codes(clean)
    assert "E0713" in _codes(bad), "a parameter is unresolvable, so text(param) is a sink"
    print("sqla: text(literal-bound name) clean, text(parameter) fires")


# --- BUG-011: imports under try:/in functions were invisible -----------
# An unresolved qualified sink is SILENT, not over-flagged. Confirmed by
# execution before the fix: try-guarded yaml.load / pickle.loads produced
# no finding at all.

def test_try_guarded_import_sinks_are_seen():
    src = ("try:\n    import yaml\n    import pickle\nexcept ImportError:\n    raise\n"
           "def a(raw):\n    return yaml.load(raw)\n"
           "def b(blob):\n    return pickle.loads(blob)\n")
    codes = _codes(src)
    assert codes.count("E0720") == 2, f"both guarded sinks must fire: {codes}"
    print("imports: try-guarded yaml.load and pickle.loads are sinks")


def test_function_local_import_sink_is_seen():
    src = ("def a(raw):\n    import marshal\n    return marshal.loads(raw)\n")
    assert "E0720" in _codes(src), "a function-local import must resolve"
    print("imports: function-local import resolves to its sink")


def test_try_guarded_builder_import_clears_the_query():
    src = ("try:\n    from sqlalchemy.sql.expression import select\n"
           "except ImportError:\n    raise\n"
           "def q(conn, t, cid):\n    return conn.execute(select(t).where(t.c.id == cid))\n")
    assert "E0713" not in _codes(src), _codes(src)
    print("imports: try-guarded select resolves to a builder")


def test_ambiguous_import_clears_nothing_and_sinks_nothing_new():
    """Two imports bind `update` to different targets. It must not be a
    builder (would clear a query) — never pick a winner."""
    src = ("try:\n    from sqlalchemy import update\nexcept ImportError:\n"
           "    from mylib.compat import update\n"
           "def q(conn, t, cid):\n    return conn.execute(update(t).where(t.c.id == cid))\n")
    assert "E0713" in _codes(src), "an ambiguous alias must not clear a query"
    from aether.py_frontend import _Imports
    import ast as _ast
    imp = _Imports()
    for n in _ast.walk(_ast.parse(src)):
        if isinstance(n, _ast.ImportFrom):
            imp.add_importfrom(n)
    assert "update" in imp.ambiguous and imp.resolve_name("update") is None
    print("imports: an ambiguous alias resolves to nothing")


def test_sql_builder_tables_are_auditable():
    from aether.py_frontend import mapping_table
    t = mapping_table()["sql_expression_builders"]
    assert "sqlalchemy" in t["roots"] and "select" in t["builders"]
    assert "text" in t["raw_string_entry_points"]
    print("sqla: builder tables exposed via mapping_table()")


# --- BUG-012: the translator is total over positions and binding forms --

_SQLI = 'cur.execute("SELECT * FROM u WHERE id = " + uid)'


def test_await_wrapped_sink_is_seen():
    src = ("import pickle\n"
           "async def a(conn, uid):\n    await conn.execute('SELECT ' + uid)\n"
           "async def b(conn, uid):\n    rows = await conn.execute('SELECT ' + uid)\n    return rows\n"
           "async def c(raw):\n    return await pickle.loads(raw)\n")
    sinks = [c for c in _codes(src) if c in SINK_CODES]
    assert sinks == ["E0713", "E0713", "E0720"], _codes(src)
    print("BUG-012: a sink behind `await` is the call")


def test_sink_in_every_statement_position_is_seen():
    shapes = {
        "for": "def f(cur, uid):\n    for row in %s:\n        pass\n",
        "if": "def f(cur, uid):\n    if %s:\n        return 1\n",
        "while": "def f(cur, uid):\n    while %s:\n        break\n",
        "yield": "def f(cur, uid):\n    yield %s\n",
        "assert": "def f(cur, uid):\n    assert %s\n",
        "raise": "def f(cur, uid):\n    raise ValueError(%s)\n",
        "comprehension": "def f(cur, uid):\n    return [r for r in %s]\n",
        "keyword": "def f(cur, uid, g):\n    return g(rows=%s)\n",
        "boolop": "def f(cur, uid):\n    return %s or []\n",
        "compare": "def f(cur, uid):\n    return %s == 0\n",
        "subscript": "def f(cur, uid):\n    return %s[0]\n",
        "ifexp": "def f(cur, uid, c):\n    return %s if c else None\n",
        "lambda": "def f(cur, uid):\n    return lambda: %s\n",
        "list": "def f(cur, uid):\n    return [%s]\n",
        "dict": "def f(cur, uid):\n    return {'k': %s}\n",
        "tuple-return": "def f(cur, uid):\n    return %s, 1\n",
        "attr-target": "def f(self, cur, uid):\n    self.rows = %s\n",
        "subscript-target": "def f(out, cur, uid):\n    out['k'] = %s\n",
        "tuple-target": "def f(cur, uid):\n    a, b = %s, 1\n",
        "chained-assign": "def f(cur, uid):\n    a = b = %s\n",
        "augassign-value": "def f(cur, uid, n):\n    n += %s\n",
        "expr-subscript": "def f(cur, uid):\n    %s[0]\n",
        "default-arg": "def f(cur, uid, d=%s):\n    pass\n",
        "decorator": "def f(cur, uid):\n    @deco(%s)\n    def g():\n        pass\n",
        "match": "def f(cur, uid):\n    match %s:\n        case _:\n            pass\n",
        "walrus": "def f(cur, uid):\n    if (r := %s):\n        return r\n",
        "del-target": "def f(cur, uid, d):\n    del d[%s]\n",
        "augassign-target": "def f(cur, uid, d):\n    d[%s] += 1\n",
        "for-target": "def f(cur, uid, d, xs):\n    for d[%s] in xs:\n        pass\n",
        "with-target": "def f(cur, uid, d, cm):\n    with cm as d[%s]:\n        pass\n",
        "match-guard": "def f(cur, uid):\n    match uid:\n        case _ if %s:\n            pass\n",
        "except-type": "def f(cur, uid):\n    try:\n        pass\n    except %s:\n        pass\n",
    }
    silent = [k for k, s in shapes.items() if "E0713" not in _codes(s % _SQLI)]
    assert not silent, f"sink still invisible in: {silent}"
    doubled = [k for k, s in shapes.items() if _codes(s % _SQLI).count("E0713") != 1]
    assert not doubled, f"sink reported more than once in: {doubled}"
    print(f"BUG-012: sink seen exactly once in {len(shapes)} statement positions")


def test_def_at_any_statement_depth_is_analysed():
    src = ("import pickle\n"
           "try:\n    def load(raw):\n        return pickle.loads(raw)\nexcept Exception:\n    pass\n"
           "if True:\n    class K:\n        def m(self, raw):\n            return pickle.loads(raw)\n"
           "class Outer:\n    class Inner:\n        def m(self, raw):\n            return pickle.loads(raw)\n"
           "with ctx() as fh:\n    def w(raw):\n        return pickle.loads(raw)\n")
    ast_dict, _u, meta = py_to_ir(src)
    names = [d["name"] for d in ast_dict["decls"] if d["kind"] == "FunctionDecl"]
    for want in ("load", "K.m", "Outer.Inner.m", "w"):
        assert want in names, (want, names)
    assert meta["n_functions"] == 4, meta
    assert _codes(src).count("E0720") == 4, _codes(src)
    print("BUG-012: defs under try/if/with and in nested classes are analysed")


def test_module_and_class_body_code_is_analysed():
    src = ("import os, sys, pickle\n"
           "os.system(sys.argv[1])\n"
           "if __name__ == '__main__':\n    os.system(sys.argv[2])\n"
           "class K:\n    DEFAULT = pickle.loads(os.environ['BLOB'])\n"
           "    def m(self):\n        return 1\n")
    ast_dict, _u, meta = py_to_ir(src)
    names = [d["name"] for d in ast_dict["decls"] if d["kind"] == "FunctionDecl"]
    assert "<module>" in names and "K.<class>" in names, names
    assert meta["n_functions"] == 1 and meta["n_scopes"] == 2, meta
    codes = _codes(src)
    assert codes.count("E0714") == 2 and codes.count("E0720") == 1, codes
    _a, _u2, m2 = py_to_ir('"""doc"""\nX = 1\nY = 2\n')
    assert m2["n_scopes"] == 0, m2
    _a, _u3, m3 = py_to_ir("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert m3["n_scopes"] == 1, m3
    print("BUG-012: module-level and class-body code is analysed as its own scope")


def test_rebinding_forms_disqualify_a_literal_only_name():
    forms = {
        "augassign": "def f(cur, uid):\n    sql = 'SELECT '\n    sql += uid\n    cur.execute(sql)\n",
        "for-target": "def f(cur, qs):\n    sql = 'SELECT 1'\n    for sql in qs:\n        pass\n    cur.execute(sql)\n",
        "tuple-unpack": "def f(cur, pair):\n    sql = 'SELECT 1'\n    sql, other = pair\n    cur.execute(sql)\n",
        "walrus": "def f(cur, g):\n    sql = 'SELECT 1'\n    if (sql := g()):\n        pass\n    cur.execute(sql)\n",
        "except-as": "def f(cur):\n    sql = 'SELECT 1'\n    try:\n        pass\n    except Exception as sql:\n        pass\n    cur.execute(sql)\n",
        "param": "def f(cur, sql):\n    if sql is None:\n        sql = 'SELECT 1'\n    cur.execute(sql)\n",
        "nested-param": "def f(cur):\n    sql = 'SELECT 1'\n    def g(sql):\n        cur.execute(sql)\n    return g\n",
        "global": "def f(cur):\n    global sql\n    sql = 'SELECT 1'\n    cur.execute(sql)\n",
        "annassign-augassign": "def f(cur, uid):\n    sql: str = 'SELECT '\n    sql += uid\n    cur.execute(sql)\n",
    }
    silent = [k for k, s in forms.items() if "E0713" not in _codes(s)]
    assert not silent, f"literal-only proof survived a rebinding in: {silent}"
    assert "E0713" not in _codes("def f(cur):\n    sql = 'SELECT 1'\n    cur.execute(sql)\n")
    print(f"BUG-012: {len(forms)} rebinding forms disqualify a literal-only name")


def test_parameter_shadow_does_not_clear_a_guard():
    src = ("import yaml\n"
           "def load(raw, loader=None):\n    if loader is None:\n        loader = yaml.SafeLoader\n"
           "    return yaml.load(raw, Loader=loader)\n")
    assert "E0720" in _codes(src), _codes(src)
    safe = ("import yaml\ndef load(raw):\n    loader = yaml.SafeLoader\n"
            "    return yaml.load(raw, Loader=loader)\n")
    assert "E0720" not in _codes(safe), _codes(safe)
    print("BUG-012: a caller-supplied loader with a literal fallback stays a sink")


def test_xml_parser_rebound_to_unknown_is_a_sink():
    src = ("from lxml import etree\n"
           "def parse(raw, make):\n    parser = etree.XMLParser(resolve_entities=False)\n"
           "    parser = make()\n    return etree.fromstring(raw, parser)\n")
    assert "E0727" in _codes(src), _codes(src)
    print("BUG-012: a parser rebound to an unknown value no longer disarms XXE")


def test_splat_and_positional_guard_arguments_are_sinks():
    assert "E0714" in _codes("import subprocess\ndef f(cmd, **o):\n    subprocess.run(cmd, **o)\n")
    assert "E0714" in _codes("import subprocess\ndef f(cmd, *a):\n    subprocess.run(cmd, *a)\n")
    assert "E0714" in _codes("import subprocess\ndef f(cmd):\n"
                             "    subprocess.Popen(cmd, 0, None, None, None, None, None, False, True)\n")
    assert "E0714" not in _codes("import subprocess\ndef f(cmd):\n    subprocess.run(cmd, shell=False)\n")
    assert "E0720" in _codes("import yaml\ndef f(raw):\n    yaml.load(raw, yaml.Loader)\n")
    assert "E0720" not in _codes("import yaml\ndef f(raw):\n    yaml.load(raw, yaml.SafeLoader)\n")
    print("BUG-012: a splat is unresolvable (sink); positional shell=/Loader are read")


def test_getattr_and_bound_method_alias_reach_the_sink():
    assert "E0713" in _codes("def f(cur, uid):\n    getattr(cur, 'execute')('SELECT ' + uid)\n")
    assert "E0713" in _codes("def f(cur, uid):\n    ex = cur.execute\n    ex('SELECT ' + uid)\n")
    assert "E0714" in _codes("import subprocess\ndef f(cmd):\n    run = subprocess.run\n    run(cmd, shell=True)\n")
    assert "E0713" not in _codes("def f(cur, uid, m):\n    getattr(cur, m)('SELECT ' + uid)\n")
    print("BUG-012: getattr with a literal attribute and a bound-method alias spell the sink")


def test_exec_driver_sql_and_session_exec_are_sinks():
    assert "E0713" in _codes("def f(conn, t):\n    conn.exec_driver_sql(f'ALTER TABLE {t} ADD x INT')\n")
    assert "E0713" not in _codes("def f(conn):\n    conn.exec_driver_sql('SELECT 1')\n")
    src = ("from sqlalchemy import text, select\n"
           "def f(s, x, t):\n    s.exec(text('SELECT ' + x))\n    s.exec(select(t).where(t.c.id == x))\n")
    assert _codes(src).count("E0713") == 1, _codes(src)
    print("BUG-012: exec_driver_sql and Session.exec are query sinks")


def test_raw_sql_methods_disqualify_the_expression():
    hdr = "from sqlalchemy import select\n"
    bad = {
        "prefix_with": "def f(conn, t, h):\n    conn.execute(select(t).prefix_with('/*+ ' + h))\n",
        "suffix_with": "def f(conn, t, h):\n    conn.execute(select(t).suffix_with('FOR UPDATE ' + h))\n",
        "with_hint": "def f(conn, t, h):\n    conn.execute(select(t).with_hint(t, 'USE INDEX ' + h))\n",
        "with_statement_hint": "def f(conn, t, h):\n    conn.execute(select(t).with_statement_hint('OPTION ' + h))\n",
        "op": "def f(conn, t, o):\n    conn.execute(select(t).where(t.c.x.op(o)(1)))\n",
        "incremental": "def f(conn, t, h):\n    stmt = select(t)\n    stmt = stmt.suffix_with(h)\n    conn.execute(stmt)\n",
    }
    silent = [k for k, s in bad.items() if "E0713" not in _codes(hdr + s)]
    assert not silent, silent
    assert "E0713" not in _codes(hdr + "def f(conn, t):\n    conn.execute("
                                 "select(t).prefix_with('/*+ NO_INDEX */').with_hint(t, 'USE INDEX i'))\n")
    from aether.py_frontend import mapping_table
    assert "prefix_with" in mapping_table()["sql_expression_builders"]["raw_string_methods"]
    print("BUG-012: verbatim-splice methods get text()'s literal discipline")


def test_module_level_literal_constant_is_a_literal():
    assert "E0713" not in _codes("_Q = 'SELECT 1'\ndef f(conn):\n    conn.execute(_Q)\n")
    assert "E0713" not in _codes("from sqlalchemy import text\n_Q = 'SELECT 1'\n"
                                 "def f(conn):\n    conn.execute(text(_Q))\n")
    for name, src in {
        "rebound-via-global": "_Q = 'SELECT 1'\ndef g(x):\n    global _Q\n    _Q = x\n"
                              "def f(conn):\n    conn.execute(_Q)\n",
        "shadowed-by-param": "_Q = 'SELECT 1'\ndef f(conn, _Q):\n    conn.execute(_Q)\n",
        "bound-twice": "_Q = 'SELECT 1'\n_Q = 'SELECT 2'\ndef f(conn):\n    conn.execute(_Q)\n",
        "not-a-literal": "_Q = build()\ndef f(conn):\n    conn.execute(_Q)\n",
    }.items():
        assert "E0713" in _codes(src), (name, _codes(src))
    key = ("KEY = 'AKIAIOSFODNN7EXAMPLE'\ndef a():\n    return use(KEY)\n"
           "def b():\n    return use(KEY)\n")
    ast_dict, _u, _m = py_to_ir(key)
    diags = [d for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0723"]
    assert len(diags) == 1 and diags[0].position.line == 1, \
        [(d.code, d.position.line) for d in diags]
    print("BUG-012: a module constant bound once is its literal; reported once")


def test_none_sentinel_before_expression_is_clean():
    src = ("from sqlalchemy import select\n"
           "def f(conn, t, flag):\n    stmt = None\n    if flag:\n"
           "        stmt = select(t).where(t.c.x == 1)\n    return conn.execute(stmt)\n")
    assert "E0713" not in _codes(src), _codes(src)
    still = ("def f(conn, x, flag):\n    stmt = None\n    if flag:\n"
             "        stmt = 'SELECT ' + x\n    return conn.execute(stmt)\n")
    assert "E0713" in _codes(still)
    print("BUG-012: a None sentinel binds nothing")


def test_safe_loader_from_import_is_positively_identified():
    assert "E0720" not in _codes("import yaml\nfrom yaml import SafeLoader\n"
                                 "def f(raw):\n    return yaml.load(raw, Loader=SafeLoader)\n")
    amb = ("import yaml\ntry:\n    from yaml import CSafeLoader as SafeLoader\n"
           "except ImportError:\n    from yaml import SafeLoader\n"
           "def f(raw):\n    return yaml.load(raw, Loader=SafeLoader)\n")
    assert "E0720" in _codes(amb), _codes(amb)
    shadow = ("import yaml\nfrom yaml import SafeLoader\n"
              "def f(raw, make):\n    SafeLoader = make()\n"
              "    return yaml.load(raw, Loader=SafeLoader)\n")
    assert "E0720" in _codes(shadow), _codes(shadow)
    print("BUG-012: a from-imported SafeLoader resolves; ambiguous or rebound does not")


def test_pep263_cookie_file_is_scanned():
    import json as _json
    import subprocess as sp
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "m.py")
        with open(p, "wb") as f:
            f.write(b"# -*- coding: latin-1 -*-\n# caf\xe9\n"
                    b"def f(cur, uid):\n    cur.execute('SELECT ' + uid)\n")
        r = sp.run([sys.executable, "-B", "-m", "transpiler.aether.cli",
                    "--json", "check-py", p], cwd=ROOT, capture_output=True, text=True)
    out = _json.loads(r.stdout)
    assert r.returncode == 2 and not out["unreadable"], (r.returncode, out["unreadable"])
    assert [x["code"] for f in out["files"] for x in f["diagnostics"]] == ["E0713"]
    print("BUG-012: a PEP 263 coding cookie is honoured, not 'unreadable'")


def test_deep_expression_loses_one_scope_not_the_file():
    deep = ("def f(cur, uid):\n    cur.execute('SELECT ' + uid)\n"
            "def g(a):\n    return " + "+".join(["a"] * 800) + "\n")
    ast_dict, unp, _m = py_to_ir(deep)
    assert "E0713" in [d.code for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES)]
    assert any(u["reason"] == "too_deep" for u in unp.get("g", [])), list(unp)
    print("BUG-012: a too-deep expression costs one scope, not the file")


def test_keyword_only_sink_argument_is_judged():
    assert "E0720" in _codes("import yaml\ndef f(raw):\n    return yaml.load(stream=raw)\n")
    assert "E0720" not in _codes("import yaml\ndef f(raw):\n"
                                 "    return yaml.load(stream=raw, Loader=yaml.SafeLoader)\n")
    assert "E0713" in _codes("def f(cur, uid):\n    return cur.execute(query='SELECT ' + uid)\n")
    assert "E0713" not in _codes("def f(cur):\n    return cur.execute(query='SELECT 1')\n")
    assert "E0714" in _codes("import subprocess\ndef f(cmd):\n"
                             "    return subprocess.run(args=cmd, shell=True)\n")
    assert "E0714" not in _codes("import subprocess\ndef f(cmd):\n"
                                 "    return subprocess.run(args=cmd, shell=False)\n")
    assert "E0720" in _codes("import pickle\ndef f(blob):\n    return pickle.loads(data=blob)\n")
    print("BUG-012: a keyword-only sink argument takes the judged slot")


def test_let_count_is_unchanged_by_seeded_bindings():
    d = _fn("def f(a):\n    x = 'lit'\n", "f")
    assert len(list(walk(d["body"], "Let"))) == 1
    seeds = [n for n in walk(d["body"], "Assign") if n.get("name") == "a"]
    assert len(seeds) == 1 and seeds[0]["value"]["kind"] == "PyExpr", seeds
    print("BUG-012: parameters seed an opaque Assign, not a Let")


# --- E0731 and the slice-2 sink rows -------------------------------------

def test_code_injection_sinks_fire():
    for src in ("def f(code):\n    exec(code)\n",
                "def f(expr):\n    return eval(expr)\n",
                "def f(src):\n    return compile(src, '<s>', 'exec')\n",
                "def f(code, ns):\n    exec(code, ns)\n",
                "def f(x):\n    return eval(f'{x}+1')\n",
                "def f(code):\n    exec(source=code)\n",
                "async def f(code):\n    await run(exec(code))\n"):
        assert "E0731" in _codes(src), src
    for src in ("def f():\n    exec('print(1)')\n",
                "import ast\ndef f(x):\n    return ast.literal_eval(x)\n",
                "def exec(c):\n    return c\ndef f(code):\n    return exec(code)\n",
                "def f(s, x):\n    return s.exec(x)\n"):
        assert "E0731" not in _codes(src), src
    once = "def f(src):\n    exec(compile(src, '<s>', 'exec'))\n"
    assert _codes(once).count("E0731") == 1, _codes(once)
    print("E0731: exec/eval/compile on a non-literal fire once; literal, literal_eval, shadow, method clean")


def test_slice2_sink_rows_fire():
    shapes = {
        "torch.load": ("import torch\ndef f(p):\n    return torch.load(p)\n", "E0720"),
        "torch.load weights_only": ("import torch\ndef f(p):\n    return torch.load(p, weights_only=True)\n", None),
        "joblib": ("import joblib\ndef f(p):\n    return joblib.load(p)\n", "E0720"),
        "cloudpickle": ("import cloudpickle\ndef f(b):\n    return cloudpickle.loads(b)\n", "E0720"),
        "numpy allow_pickle": ("import numpy as np\ndef f(p):\n    return np.load(p, allow_pickle=True)\n", "E0720"),
        "numpy default": ("import numpy as np\ndef f(p):\n    return np.load(p)\n", None),
        "yaml load_all": ("import yaml\ndef f(s):\n    return list(yaml.load_all(s))\n", "E0720"),
        "getoutput": ("import subprocess\ndef f(c):\n    return subprocess.getoutput('ls ' + c)\n", "E0714"),
        "create_subprocess_shell": ("import asyncio\nasync def f(c):\n    return await asyncio.create_subprocess_shell('ls ' + c)\n", "E0714"),
        "argv -c": ("import subprocess\ndef f(c):\n    subprocess.run(['bash', '-c', 'ls ' + c])\n", "E0714"),
        "argv -c literal": ("import subprocess\ndef f():\n    subprocess.run(['bash', '-c', 'ls -l'])\n", None),
        "argv plain": ("import subprocess\ndef f(c):\n    subprocess.run(['ls', '-l', c])\n", None),
        "exec_command": ("def f(client, c):\n    return client.exec_command('ls ' + c)\n", "E0714"),
        "from_string": ("def f(env, t):\n    return env.from_string(t).render()\n", "E0719"),
        "mako": ("from mako.template import Template\ndef f(t):\n    return Template(t)\n", "E0719"),
        "fetchrow": ("async def f(conn, x):\n    return await conn.fetchrow('SELECT ' + x)\n", "E0713"),
        "read_sql": ("import pandas as pd\ndef f(con, q):\n    return pd.read_sql(q, con)\n", "E0713"),
        "RedirectResponse": ("from starlette.responses import RedirectResponse\ndef f(u):\n    return RedirectResponse(u)\n", "E0718"),
        "minidom.parse": ("from xml.dom import minidom\ndef f(fh):\n    return minidom.parse(fh)\n", "E0727"),
    }
    bad = []
    for k, (s, code) in shapes.items():
        got = [c for c in _codes(s) if c in SINK_CODES]
        if code is not None and code not in got:
            bad.append((k, "silent", got))
        if code is None and got:
            bad.append((k, "over-flag", got))
    assert not bad, bad
    from aether.py_frontend import mapping_table
    m = mapping_table()
    assert "torch.load" in m["sink_guards"] and "from_string" in m["sink_by_method"]
    print(f"slice 2: {len(shapes)} sink-row shapes behave; tables auditable")


def test_match_kind_reaches_extra_for_every_sink_match():
    """How the frontend named a sink is data on the finding.

    The confidence axis (`transpiler/aether/confidence.py`) rates the
    match kind, so a finding that does not carry one silently claims an
    Aether-source finding's certainty. `tests/test_confidence.py` owns
    the ratings; this owns the wiring from `_sink_match` to `extra`."""
    from aether.py_frontend import SINK_MATCH_KINDS
    shapes = {
        "qualified": ("import pickle\ndef f(b):\n    pickle.loads(b)\n", "E0720"),
        "guard": ("import subprocess\ndef f(c):\n    subprocess.run(c, shell=True)\n", "E0714"),
        "argv": ("import subprocess\ndef f(c):\n    subprocess.run(['bash', '-c', c])\n", "E0714"),
        "builtin": ("def f(s):\n    exec(s)\n", "E0731"),
        "builtin_compile": ("def f(s):\n    compile(s, '<s>', 'exec')\n", "E0731"),
        "method": ("def f(cur, x):\n    cur.execute('SELECT ' + x)\n", "E0713"),
    }
    assert sorted(shapes) == sorted(SINK_MATCH_KINDS), (
        f"every match kind the frontend publishes needs a shape here: "
        f"{sorted(set(shapes) ^ set(SINK_MATCH_KINDS))}")
    bad = []
    for kind, (src, code) in shapes.items():
        ast_dict, _u, _m = py_to_ir(src)
        ds = [d for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES)
              if d.code == code]
        if len(ds) != 1:
            bad.append((kind, "expected one finding", [d.code for d in ds]))
            continue
        if ds[0].extra.get("match") != kind:
            bad.append((kind, "wrong match in extra", ds[0].extra))
    assert not bad, bad
    # A wrapper call the frontend NAMED (shlex.quote as shellArg) matched
    # no sink, so it carries no match kind — there is nothing to be more
    # or less sure of.
    ast_dict, _u, _m = py_to_ir(
        "import shlex, subprocess\n"
        "def f(c):\n    subprocess.run('ls ' + shlex.quote(c), shell=True)\n")
    for call in walk(ast_dict, "Call"):
        if call["func"]["name"] == "shellArg":
            assert "match" not in call, call
            break
    else:
        raise AssertionError("shlex.quote did not become a shellArg call")
    print(f"match: all {len(shapes)} match kinds reach `extra`; "
          f"a wrapper carries none")


def test_unreadable_and_skipped_are_visible_in_every_mode():
    import json as _json
    import subprocess as sp
    import tempfile

    def run(files, *global_flags, target=".", sub=()):
        """`--json` is a GLOBAL option (before the subcommand); `--sarif`
        belongs to `check-py` itself (after the target)."""
        with tempfile.TemporaryDirectory() as d:
            for rel, src in files.items():
                p = os.path.join(d, *rel.split("/"))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(src)
            r = sp.run([sys.executable, "-B", "-m", "transpiler.aether.cli",
                        *global_flags, "check-py",
                        os.path.join(d, *target.split("/")), *sub],
                       cwd=ROOT, capture_output=True, text=True)
        return r.returncode, r.stdout, r.stderr

    files = {"app/bad.py": "def f(:\n", "app/ok.py": _CMDI_SRC,
             "build/gen.py": _CMDI_SRC}
    rc, out, err = run(files, "--json")
    js = _json.loads(out)
    assert rc == 2 and js["unreadable"] and js["unreadable"][0]["detail"], js["unreadable"]
    assert js["skipped_dirs"] == ["build"], js["skipped_dirs"]
    assert "could not parse" in err and "skipped as vendored/build output" in err, err
    rc, out, err = run(files, sub=("--sarif",))
    doc = _json.loads(out)
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 1 and "could not parse" in notes[0]["message"]["text"], notes
    res = doc["runs"][0]["results"][0]
    assert "startColumn" in res["locations"][0]["physicalLocation"]["region"]
    assert res["properties"]["suggestion"], res
    assert "could not parse" in err, err
    rc, out, err = run(files)
    assert rc == 2 and "could not parse" in err and "1 unparseable" in out \
        and "1 dir(s) skipped" in out, (out, err)
    # an unparseable file alone never fails the run, in any mode
    rc, out, err = run({"only.py": "def f(:\n"}, target="only.py")
    assert rc == 0 and "could not parse" in err, (rc, out, err)
    print("cli: unreadable files and skipped dirs reported in json/sarif/text; exit codes agree")


def test_exec_of_compile_rates_as_exec():
    def e0731(src):
        ast_dict, _u, _m = py_to_ir(src)
        return [d for d in analyze_flat(ast_dict, skip=PY_SKIP_STAGES) if d.code == "E0731"]
    ds = e0731("def f(src):\n    exec(compile(src, '<s>', 'exec'))\n")
    assert len(ds) == 1 and ds[0].extra.get("match") == "builtin", [d.extra for d in ds]
    ds = e0731("def f(src):\n    return compile(src, '<s>', 'exec')\n")
    assert [d.extra.get("match") for d in ds] == ["builtin_compile"], [d.extra for d in ds]
    ds = e0731("def exec(c, g=None):\n    return c\n"
               "def f(src):\n    exec(compile(src, '<s>', 'exec'))\n")
    assert [d.extra.get("match") for d in ds] == ["builtin_compile"], [d.extra for d in ds]
    print("BUG-030: exec(compile(src)) rates as exec; compile alone or under a local exec stays at the floor")


def test_file_too_deep_for_python_is_unparseable_not_a_crash():
    src = ("import os\ndef f(c):\n    os.system('ls ' + c)\n"
           "def g(a):\n    return " + "+".join(["a"] * 20000) + "\n")
    rc, out = _run_check_py_tree({"deep.py": src}, target="deep.py")
    assert "ANALYZER ERROR" not in out, out[-600:]
    assert rc == 0 or "E0714" in out, (rc, out[-600:])
    print("BUG-029: a file too deep for Python's own parser is unparseable, not an analyzer crash")


# --- Wave 0 (audits/audit_2026-09-24_plan.md): BUG-032..035 --------------

def _sinks(src: str):
    """`_codes` without E0701, the capability inventory `check-py` shows
    only under --strict."""
    return [c for c in _codes(src) if c != "E0701"]


def test_html_escapers_are_not_trusted():
    """BUG-032: an HTML escaper leaves `{{7*7}}` and `__import__('os')`
    intact. Mapped onto `trusted`, it cleared the template, code and
    deserialization rules, whose one exit that is."""
    for esc_imp, esc in (("import html", "html.escape"),
                         ("import markupsafe", "markupsafe.escape"),
                         ("import urllib.parse", "urllib.parse.quote"),
                         ("import urllib.parse", "urllib.parse.quote_plus")):
        for sink_imp, sink, code in (
                ("from flask import render_template_string", "render_template_string", "E0719"),
                ("import jinja2", "jinja2.Template", "E0719"),
                ("", "eval", "E0731"),
                ("", "exec", "E0731"),
                ("import pickle", "pickle.loads", "E0720")):
            src = f"{esc_imp}\n{sink_imp}\ndef f(x):\n    return {sink}({esc}(x))\n"
            assert _sinks(src) == [code], (esc, sink, _sinks(src))
    src = ("from flask import render_template, render_template_string\n"
           "def f(x):\n    return render_template_string(render_template('a.html', n=x))\n")
    assert _sinks(src) == ["E0719"], _sinks(src)
    from aether.py_frontend import SANITIZER_BY_QUALIFIED
    assert "trusted" not in SANITIZER_BY_QUALIFIED.values(), \
        "no Python call may map onto the trusted(...) assertion"
    print("BUG-032: HTML/URL escapers clear no template, code or deserialization sink")


def test_ambiguous_import_is_a_sink_if_any_candidate_is():
    """BUG-033: the py2/lxml fallback idiom bound a name two ways, it
    resolved to nothing, and every sink behind it was silent."""
    cases = [
        ("try:\n    import cPickle as pickle\nexcept ImportError:\n    import pickle\n",
         "pickle.loads(b)", "E0720"),
        ("try:\n    from lxml import etree\nexcept ImportError:\n"
         "    import xml.etree.ElementTree as etree\n", "etree.fromstring(b)", "E0727"),
        ("try:\n    import subprocess32 as subprocess\nexcept ImportError:\n"
         "    import subprocess\n", "subprocess.call(b, shell=True)", "E0714"),
        ("try:\n    from flask import redirect\nexcept ImportError:\n"
         "    from werkzeug.utils import redirect\n", "redirect(b)", "E0718"),
        # a function-local `import json as pickle` elsewhere in the file
        ("import pickle\ndef g():\n    import json as pickle\n    return pickle.dumps(1)\n",
         "pickle.loads(b)", "E0720"),
    ]
    for head, call, code in cases:
        src = f"{head}def f(b):\n    return {call}\n"
        assert _sinks(src) == [code], (head, call, _sinks(src))
    # all candidates safe or non-sinks: still nothing
    src = ("try:\n    import ujson as json\nexcept ImportError:\n    import json\n"
           "def f(s):\n    return json.loads(s)\n")
    assert _sinks(src) == [], _sinks(src)
    print("BUG-033: an ambiguous import is a sink if any candidate is one")


def test_whole_command_shlex_quote_is_not_the_exit():
    """BUG-034: `shlex.quote(cmd)` as the WHOLE shell command quotes it
    into one word; the input still chooses the program."""
    head = "import subprocess, shlex, os\n"
    for body in ("subprocess.run(shlex.quote(p), shell=True)",
                 "c = shlex.quote(p)\n    os.system(c)",
                 "subprocess.run(['bash', '-c', shlex.quote(p)])"):
        assert _sinks(f"{head}def f(p):\n    {body}\n") == ["E0714"], body
    assert _sinks(f"{head}def f(p):\n    subprocess.run(['ls', p])\n") == []
    print("BUG-034: a whole-command shlex.quote is not the shell exit")


def test_detector_value_error_is_a_crash_not_unreadable():
    """BUG-035: a ValueError raised inside a DETECTOR was caught with the
    parse errors, reported as 'could not parse', exit 0, findings lost."""
    import tempfile
    from aether import cli
    import aether.passes as passes
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "v.py")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("import os\ndef f(c):\n    os.system(c)\n")
        real = passes.analyze_flat

        def boom(*_a, **_k):
            raise ValueError("detector bug")
        passes.analyze_flat = boom
        try:
            res = cli._scan_one((p, PY_SKIP_STAGES, False))
        finally:
            passes.analyze_flat = real
    assert res[0] == "crashed" and "ValueError" in res[2], res
    print("BUG-035: a detector ValueError is an analyzer crash, not an unreadable file")


if __name__ == "__main__":
    test_body_is_no_longer_discarded()
    test_assign_becomes_let()
    test_concat_becomes_binop_plus()
    test_fstring_becomes_concat()
    test_constant_only_fstring_is_a_literal()
    test_percent_format_becomes_concat()
    test_unmodeled_expression_is_not_cleared()
    test_the_five_vulnerabilities_are_found()
    test_fstring_sql_injection_found()
    test_literal_query_is_clean()
    test_shell_false_is_not_a_shell_sink()
    test_yaml_load_with_safe_loader_is_not_a_sink()
    test_chained_receiver_call_is_not_lost()
    test_sink_tables_are_auditable()
    test_parameterized_query_is_the_sanctioned_exit()
    test_single_arg_dynamic_query_still_fires()
    test_with_statement_open_is_seen()
    test_string_literal_carries_a_position()
    test_xxe_safe_parser_disarms_the_sink()
    test_xxe_default_parser_still_fires()
    test_xxe_python_text_names_the_callee_and_a_python_fix()
    test_xxe_python_fix_shapes_are_clean()
    test_xxe_elementtree_text_is_scoped_to_calls_without_a_parser()
    test_xxe_guard_and_parser_binding_shapes()
    test_repro_corpus_flags_the_bug()
    test_safe_functions_are_clean()
    test_yaml_unsafe_loader_is_still_a_sink()
    test_yaml_unsafe_loader_named_elsewhere_is_still_a_sink()
    test_yaml_safe_loader_stays_clean()
    test_yaml_full_loader_is_not_sanctioned()
    test_shell_true_bound_elsewhere_is_still_a_sink()
    test_concatenated_sql_with_params_is_still_a_sink()
    test_attribute_read_of_a_call_result_is_not_lost()
    test_safe_loader_bound_elsewhere_is_clean()
    test_rebound_loader_is_still_a_sink()
    test_shell_false_bound_elsewhere_is_clean()
    test_recall_gap_shapes_now_fire()
    test_chained_module_path_resolves()
    test_pypi_scan_row_set_matches_cli()
    test_unmapped_call_cannot_collide_with_an_aether_sink_name()
    test_real_mapped_sinks_still_fire_after_prefixing()
    test_check_py_cli_reports_and_exits_2()
    test_check_py_clean_exits_0()
    test_e0711_is_held_back_by_default()
    test_e0711_appears_under_strict()
    test_directory_walk_scans_every_file()
    test_directory_walk_skips_vendored_trees()
    test_unparseable_file_does_not_abort_the_walk()
    test_utf8_bom_file_is_scanned_not_silently_skipped()
    test_missing_path_is_a_usage_error()
    test_sqlalchemy_expression_is_not_a_dynamic_query()
    test_sqlalchemy_alias_and_chained_receiver_are_clean()
    test_sqlalchemy_text_literal_clean_but_concat_fires()
    test_raw_string_nested_inside_a_safe_builder_still_fires()
    test_non_sqlalchemy_name_spelled_select_clears_nothing()
    test_sql_expression_bound_to_a_local_is_clean()
    test_statement_built_incrementally_is_clean()
    test_one_raw_rebinding_disqualifies_the_name()
    test_unanchored_self_chain_never_qualifies()
    test_table_method_form_argument_free_only()
    test_text_of_literal_bound_name_clean_but_parameter_fires()
    test_try_guarded_import_sinks_are_seen()
    test_function_local_import_sink_is_seen()
    test_try_guarded_builder_import_clears_the_query()
    test_ambiguous_import_clears_nothing_and_sinks_nothing_new()
    test_sql_builder_tables_are_auditable()
    test_await_wrapped_sink_is_seen()
    test_sink_in_every_statement_position_is_seen()
    test_def_at_any_statement_depth_is_analysed()
    test_module_and_class_body_code_is_analysed()
    test_rebinding_forms_disqualify_a_literal_only_name()
    test_parameter_shadow_does_not_clear_a_guard()
    test_xml_parser_rebound_to_unknown_is_a_sink()
    test_splat_and_positional_guard_arguments_are_sinks()
    test_getattr_and_bound_method_alias_reach_the_sink()
    test_exec_driver_sql_and_session_exec_are_sinks()
    test_raw_sql_methods_disqualify_the_expression()
    test_module_level_literal_constant_is_a_literal()
    test_none_sentinel_before_expression_is_clean()
    test_safe_loader_from_import_is_positively_identified()
    test_pep263_cookie_file_is_scanned()
    test_deep_expression_loses_one_scope_not_the_file()
    test_keyword_only_sink_argument_is_judged()
    test_let_count_is_unchanged_by_seeded_bindings()
    test_code_injection_sinks_fire()
    test_slice2_sink_rows_fire()
    test_match_kind_reaches_extra_for_every_sink_match()
    test_unreadable_and_skipped_are_visible_in_every_mode()
    test_exec_of_compile_rates_as_exec()
    test_file_too_deep_for_python_is_unparseable_not_a_crash()
    test_html_escapers_are_not_trusted()
    test_ambiguous_import_is_a_sink_if_any_candidate_is()
    test_whole_command_shlex_quote_is_not_the_exit()
    test_detector_value_error_is_a_crash_not_unreadable()
    print("PY FRONTEND: ALL TESTS PASS")
