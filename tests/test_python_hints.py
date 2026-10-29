"""Python findings speak Python — and the fix they name converges.

Audit 2026-09-24 C6 (Wave 5a): a Python finding used to name Aether
functions (`sqlBind`, `shellArg`, `safeRedirect`, `schemaDecode`,
`trusted`, `getEnv`) that do not exist in Python, and filed SQL injection
under `category: "capability"`. An agent handed such a finding has no
Python action to take.

This is the plan's LLM-free fix loop, one repro per default-on code
(plus E0711 under --strict): the finding's suggestion must name a Python
spelling, and that spelling, applied mechanically, must be CLEAN. A hint
whose own fix is flagged is a loop that cannot converge.

Run: python -B tests/test_python_hints.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether import py_frontend as pf                       # noqa: E402
from aether.parser import parse                            # noqa: E402
from aether.passes import analyze_flat                     # noqa: E402

_SKIP = pf.PY_SKIP_STAGES + ("capability",)
_KEY = "AKIA" + "IOSFODNN7EXAMPLE"      # split: a fixture, not a credential

# Aether spellings a Python user cannot call.
_AETHER_WORDS = ("sqlBind", "shellArg", "safeRedirect", "safeJoin", "schemaDecode",
                 "trusted(", "getEnv", "parseXmlSafe", "'sqlQuery'", "'shellExec'",
                 "'redirect'", "'renderTemplate'", "'deserialize'", "'evalCode'",
                 "'readFile'")

# code -> (vulnerable snippet, [(phrase the suggestion names, fixed snippet)])
LOOP = {
    "E0711": ("import os\nBASE = '/srv/up'\ndef f(name):\n    return open(os.path.join(BASE, name))\n",
              [("werkzeug.utils.safe_join(BASE_DIR, name)",
                "from werkzeug.utils import safe_join\nBASE = '/srv/up'\n"
                "def f(name):\n    return open(safe_join(BASE, name))\n"),
               ("os.path.join(BASE_DIR, secure_filename(name))",
                "import os\nfrom werkzeug.utils import secure_filename\nBASE = '/srv/up'\n"
                "def f(name):\n    return open(os.path.join(BASE, secure_filename(name)))\n")]),
    "E0713": ("def f(cur, value):\n    cur.execute('SELECT * FROM t WHERE id = ' + value)\n",
              [('cursor.execute("SELECT * FROM t WHERE id = %s", (value,))',
                "def f(cur, value):\n    cur.execute('SELECT * FROM t WHERE id = %s', (value,))\n"),
               ('text("SELECT * FROM t WHERE id = :id").bindparams(id=value)',
                "from sqlalchemy import text\ndef f(session, value):\n"
                "    session.execute(text('SELECT * FROM t WHERE id = :id').bindparams(id=value))\n"),
               ("sql.SQL(\"... {}\").format(sql.Identifier(name))",
                "from psycopg import sql\ndef f(cur, name):\n"
                "    cur.execute(sql.SQL('SELECT * FROM {}').format(sql.Identifier(name)))\n")]),
    "E0714": ("import os\ndef f(path):\n    os.system('ls -l ' + path)\n",
              [('subprocess.run(["ls", "-l", path])',
                "import subprocess\ndef f(path):\n    subprocess.run(['ls', '-l', path])\n"),
               ('"ls -l " + shlex.quote(path)',
                "import os, shlex\ndef f(path):\n    os.system('ls -l ' + shlex.quote(path))\n"),
               ("shlex.join(args)",
                "import os, shlex\ndef f(args):\n    os.system('ls -l ' + shlex.join(args))\n")]),
    "E0718": ("from flask import redirect, request\ndef x():\n    return redirect(request.args['next'])\n",
              [('flask.url_for("endpoint")',
                "from flask import redirect, url_for\ndef x():\n    return redirect(url_for('index'))\n"),
               ('django.urls.reverse("name")',
                "from django.shortcuts import redirect\nfrom django.urls import reverse\n"
                "def v(request):\n    return redirect(reverse('home'))\n"),
               ("if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}): "
                "target = \"/\"",
                "from django.shortcuts import redirect\n"
                "from django.utils.http import url_has_allowed_host_and_scheme\n"
                "def v(request):\n    target = request.GET.get('next')\n"
                "    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):\n"
                "        target = '/'\n    return redirect(target)\n")]),
    "E0719": ("from jinja2 import Template\ndef f(src, value):\n    return Template(src).render(name=value)\n",
              [('Template("Hello {{ name }}").render(name=value)',
                "from jinja2 import Template\ndef f(value):\n"
                "    return Template('Hello {{ name }}').render(name=value)\n"),
               ("jinja2.sandbox.SandboxedEnvironment().from_string(src)",
                "from jinja2.sandbox import SandboxedEnvironment\ndef f(src, value):\n"
                "    return SandboxedEnvironment().from_string(src).render(name=value)\n")]),
    "E0720": ("import pickle\ndef f(data):\n    return pickle.loads(data)\n",
              [("json.loads(data)", "import json\ndef f(data):\n    return json.loads(data)\n"),
               ("yaml.safe_load(data)", "import yaml\ndef f(data):\n    return yaml.safe_load(data)\n"),
               ("yaml.load(data, Loader=yaml.SafeLoader)",
                "import yaml\ndef f(data):\n    return yaml.load(data, Loader=yaml.SafeLoader)\n"),
               ("weights_only=True",
                "import torch\ndef f(data):\n    return torch.load(data, weights_only=True)\n")]),
    "E0723": (f"def f():\n    return make(key='{_KEY}')\n",
              [('os.environ["NAME"]',
                "import os\ndef f():\n    return make(key=os.environ['NAME'])\n")]),
    "E0727": ("import xml.etree.ElementTree as ET\ndef f(raw):\n    return ET.fromstring(raw)\n",
              [("defusedxml.ElementTree.fromstring",
                "import defusedxml.ElementTree\ndef f(raw):\n"
                "    return defusedxml.ElementTree.fromstring(raw)\n")]),
    "E0731": ("def f(text):\n    return eval(text)\n",
              [("ast.literal_eval(text)", "import ast\ndef f(text):\n    return ast.literal_eval(text)\n"),
               ("json.loads(text)", "import json\ndef f(text):\n    return json.loads(text)\n")]),
}


def _diags(src: str) -> list:
    ir, _u, _m = pf.py_to_ir(src)
    return [d for d in analyze_flat(ir, skip=_SKIP) if d.code != "E0701"]


def test_every_python_hint_converges():
    bad = []
    for code, (vuln, fixes) in LOOP.items():
        ds = [d for d in _diags(vuln) if d.code == code]
        if len(ds) != 1:
            bad.append(f"{code}: repro gives {[d.code for d in _diags(vuln)]}")
            continue
        d = ds[0]
        for phrase, fixed in fixes:
            if phrase not in d.suggestion:
                bad.append(f"{code}: suggestion does not name {phrase!r}: {d.suggestion}")
            if (left := [x.code for x in _diags(fixed)]):
                bad.append(f"{code}: the named fix {phrase!r} is still flagged {left}:\n{fixed}")
    assert not bad, "\n".join(bad)
    print(f"hints: {len(LOOP)} codes, each named Python fix applied mechanically is clean")


def test_python_findings_name_no_aether_function():
    bad = []
    for code, (vuln, _f) in LOOP.items():
        for d in _diags(vuln):
            text = d.message + " " + d.suggestion + " " + str(d.extra.get("reason", ""))
            hit = [w for w in _AETHER_WORDS if w in text]
            if hit:
                bad.append(f"{code}: names {hit}: {text}")
            if d.category != "security":
                bad.append(f"{code}: category {d.category!r}, want 'security'")
    assert not bad, "\n".join(bad)
    print("hints: Python findings name Python calls only, under category 'security'")


def test_aether_source_keeps_its_wording():
    """The Aether wording is right for Aether source, where `sqlBind`
    exists: only the Python text changed."""
    src = ('function lookup(name: String) returns String\n  effects db.query\ndo\n'
           '  return sqlQuery("SELECT * FROM t WHERE n = " + name)\nend\n')
    ds = [d for d in analyze_flat(parse(src, "x.aeth")) if d.code == "E0713"]
    assert ds, "the Aether E0713 repro must fire"
    assert all("sqlBind" in d.suggestion and d.category == "capability" for d in ds), \
        [(d.category, d.suggestion) for d in ds]
    print("hints: an Aether-source finding keeps the Aether fix (sqlBind)")


if __name__ == "__main__":
    test_every_python_hint_converges()
    test_python_findings_name_no_aether_function()
    test_aether_source_keeps_its_wording()
    print("PYTHON HINTS: ALL TESTS PASS")
