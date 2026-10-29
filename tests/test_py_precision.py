"""Python precision — the documented fix is clean, its near misses are not.

Audit 2026-09-24 §C (Wave 5a, LOOP_LOG iteration 60): the scanner flagged
the remediation — `"ls -l " + shlex.quote(p)`, `redirect(url_for(...))`,
module-level SQL constants, psycopg's `sql` composition, Jinja's sandbox —
at up to 0.95 confidence, so an agent fix-loop could not converge. Each
idiom below is pinned clean, and next to it the shapes that LOOK like it
but are still an injection are pinned to their code: over-flag, never
miss within the modeled surface.

Run: python -B tests/test_py_precision.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether import py_frontend as pf                       # noqa: E402
from aether.passes import analyze_flat                     # noqa: E402

# What `check-py --strict` reports, minus its E0701 inventory.
_SKIP = pf.PY_SKIP_STAGES + ("capability",)


def _diags(src: str) -> list:
    ir, _u, _m = pf.py_to_ir(src)
    return [d for d in analyze_flat(ir, skip=_SKIP) if d.code != "E0701"]


def _codes(src: str) -> list:
    return sorted(d.code for d in _diags(src))


def _check(cases) -> None:
    bad = [(want, got, src) for src, want in cases
           if (got := _codes(src)) != sorted(want)]
    assert not bad, "\n\n".join(f"want {w}, got {g}:\n{s}" for w, g, s in bad)


_SH = "import os, shlex, subprocess\n"


def test_c1_quoted_pieces_compose():
    """C1 + BUG-034: a command whose program is a literal and whose every
    other piece is a `shlex.quote`d word is clean — concatenation,
    f-string, `" ".join(<genexpr>)`, `shlex.join` as a piece or with a
    literal program. The whole command as one quoted word stays E0714."""
    _check([
        (_SH + "def f(p):\n    subprocess.run('ls -l ' + shlex.quote(p), shell=True)\n", []),
        (_SH + "def f(p):\n    subprocess.run(f'ls -l {shlex.quote(p)}', shell=True)\n", []),
        (_SH + "def f(p):\n    os.system('ls -l -- ' + shlex.quote(p) + ' | wc -l')\n", []),
        (_SH + "def f(files):\n    cmd = 'wc -l ' + ' '.join(shlex.quote(p) for p in files)\n"
               "    subprocess.run(cmd, shell=True)\n", []),
        (_SH + "def f(files):\n    cmd = 'tar czf out.tgz ' + ' '.join(shlex.quote(p) for p in files)\n"
               "    subprocess.run(cmd, shell=True)\n", ["E0714"]),
        (_SH + "def f(args):\n    os.system('du -sh ' + shlex.join(args))\n", []),
        (_SH + "def f(args):\n    subprocess.run(shlex.join(['du', '-sh', *args]), shell=True)\n", []),
        # git / tar / rsync / zip have options that run a command, and a
        # quoted word that starts with '-' is still an option (known-gaps
        # round, iteration 65): these were clean under iteration 60.
        (_SH + "def f(args):\n    os.system('git log ' + shlex.join(args))\n", ["E0714"]),
        (_SH + "def f(args):\n    subprocess.run(shlex.join(['git', 'log', *args]), shell=True)\n", ["E0714"]),
        (_SH + "import pipes\ndef f(p):\n    os.system('ls ' + pipes.quote(p))\n", []),
        # still an injection, or still the input choosing the program
        (_SH + "def f(p):\n    subprocess.run(shlex.quote(p), shell=True)\n", ["E0714"]),
        (_SH + "def f(args):\n    os.system(shlex.join(args))\n", ["E0714"]),
        (_SH + "def f(prog):\n    os.system(shlex.join([prog, '-l']))\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system(shlex.quote(p) + ' -l')\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system('ls' + shlex.quote(p))\n", ["E0714"]),
        (_SH + "def f(c):\n    os.system('sh -c ' + shlex.quote(c))\n", ["E0714"]),
        (_SH + "def f(c):\n    os.system('/bin/bash -c ' + shlex.quote(c))\n", ["E0714"]),
        (_SH + "def f(args):\n    subprocess.run(shlex.join(['bash', '-c', *args]), shell=True)\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system('sudo rm ' + shlex.quote(p))\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system(\"ls '\" + shlex.quote(p) + \"'\")\n", ["E0714"]),
        (_SH + "def f(p):\n    subprocess.run(f'echo \"{shlex.quote(p)}\"', shell=True)\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system('ls \\\\' + shlex.quote(p))\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system(f'ls {shlex.quote(p)!r}')\n", ["E0714"]),
        (_SH + "def f(p):\n    os.system('ls %r' % shlex.quote(p))\n", ["E0714"]),
        (_SH + "def f(args):\n    os.system('ls ' + ' '.join(p for p in args))\n", ["E0714"]),
        (_SH + "def f(a, b):\n    os.system('ls ' + ' '.join([shlex.quote(a), b]))\n", ["E0714"]),
        (_SH + "def f(p, x):\n    os.system('ls ' + shlex.quote(p) + '; ' + x)\n", ["E0714"]),
        # residual (q1): a quoted piece reached through a name is refused
        (_SH + "def f(p):\n    q = shlex.quote(p)\n    os.system('ls ' + q)\n", ["E0714"]),
    ])
    print("C1: quoted pieces compose; the whole-command and near-miss shapes still fire")


def test_c2_own_origin_redirects():
    """C2: `url_for` / `reverse` / an annotated `request.url_for`, and a
    redirect Django's own allow-list check dominates, are clean; a check
    that does not dominate, `resolve_url`, and an unresolved receiver are
    not."""
    dj = ("from django.shortcuts import redirect\n"
          "from django.utils.http import url_has_allowed_host_and_scheme\n")
    _check([
        ("from flask import redirect, url_for\ndef x():\n    return redirect(url_for('index'))\n", []),
        ("from flask import redirect, request, url_for\ndef x():\n"
         "    return redirect(url_for('login', next=request.path))\n", []),
        ("from django.shortcuts import redirect\nfrom django.urls import reverse\n"
         "def v(request, pk):\n    return redirect(reverse('detail', args=[pk]))\n", []),
        ("from fastapi import Request\nfrom fastapi.responses import RedirectResponse\n"
         "def v(request: Request):\n    return RedirectResponse(request.url_for('home'))\n", []),
        ("from django.shortcuts import redirect\ndef v(request, pk):\n"
         "    return redirect('detail', pk=pk)\n", []),
        (dj + "def v(request):\n    n = request.GET.get('next')\n"
              "    if not url_has_allowed_host_and_scheme(n, allowed_hosts={request.get_host()}):\n"
              "        n = '/'\n    return redirect(n)\n", []),
        (dj + "def v(request):\n    n = request.GET.get('next')\n"
              "    if url_has_allowed_host_and_scheme(n, allowed_hosts=None):\n"
              "        return redirect(n)\n    return redirect('/')\n", []),
        (dj + "def v(request):\n    n = request.GET.get('next')\n"
              "    if not url_has_allowed_host_and_scheme(n, allowed_hosts=None):\n"
              "        print('bad')\n    return redirect(n)\n", ["E0718"]),
        (dj + "def v(request):\n    n = request.GET.get('next')\n"
              "    if not url_has_allowed_host_and_scheme(n, allowed_hosts=None):\n"
              "        n = '/'\n    n = request.GET['x']\n    return redirect(n)\n", ["E0718"]),
        (dj + "def v(request, flag):\n    n = request.GET.get('next')\n    if flag:\n"
              "        if not url_has_allowed_host_and_scheme(n, allowed_hosts=None):\n"
              "            return None\n    return redirect(n)\n", ["E0718"]),
        (dj + "def v(request, m):\n    n = request.GET.get('next')\n"
              "    if url_has_allowed_host_and_scheme(m, allowed_hosts=None):\n"
              "        return redirect(n)\n", ["E0718"]),
        ("from django.shortcuts import redirect, resolve_url\ndef v(request, x):\n"
         "    return redirect(resolve_url(x))\n", ["E0718"]),
        ("from flask import redirect, url_for\ndef v(nxt):\n    return redirect(url_for('a') + nxt)\n",
         ["E0718"]),
        ("from starlette.responses import RedirectResponse\ndef v(request):\n"
         "    return RedirectResponse(url=request.url_for('home'), status_code=303)\n", ["E0718"]),
    ])
    # The unresolved receiver is not cleared, and rates at the floor (C5).
    ds = _diags("from starlette.responses import RedirectResponse\ndef v(request):\n"
                "    return RedirectResponse(request.url_for('home'))\n")
    assert [(d.code, d.confidence, d.extra.get("demoted")) for d in ds] == \
        [("E0718", 0.6, "argument_shape")], [(d.code, d.confidence, d.extra) for d in ds]
    print("C2: own-origin builders and a dominating Django check clear E0718; near misses fire")


def test_c3_sql_constants_and_composition():
    """C3: module/class literal constants, literal + literal, psycopg's
    `sql` composition, `self.table.delete()`, IN-list placeholders."""
    _check([
        ("TABLE = 'users'\ndef f(cur, x):\n"
         "    cur.execute('SELECT * FROM ' + TABLE + ' WHERE id = %s', (x,))\n", []),
        ("LIMIT = 10\ndef f(cur):\n    cur.execute(f'SELECT * FROM t LIMIT {LIMIT}')\n", []),
        ("def f(cur, x):\n    cur.execute('SELECT * FROM t ' + 'WHERE id = %s', (x,))\n", []),
        ("class Repo:\n    Q = 'SELECT * FROM t WHERE id = ?'\n"
         "    def get(self, cur, x):\n        cur.execute(self.Q, (x,))\n", []),
        ("from sqlalchemy import text\nQ = text('SELECT * FROM t WHERE id = :id')\n"
         "def f(session, x):\n    return session.execute(Q, {'id': x}).all()\n", []),
        ("from psycopg2 import sql\ndef f(cur, table, x):\n"
         "    q = sql.SQL('SELECT * FROM {} WHERE id = %s').format(sql.Identifier(table))\n"
         "    cur.execute(q, (x,))\n", []),
        ("from psycopg import sql\ndef f(cur, cols):\n"
         "    cur.execute(sql.SQL('SELECT {} FROM t').format(\n"
         "        sql.SQL(', ').join(sql.Identifier(c) for c in cols)))\n", []),
        ("def f(self, sess, cid):\n"
         "    sess.execute(self.table.delete().where(self.table.c.content_id == cid))\n", []),
        ("def f(self, sess, cid, uid):\n"
         "    stmt = self.table.delete().where(self.table.c.content_id == cid)\n"
         "    if uid is not None:\n        stmt = stmt.where(self.table.c.user_id == uid)\n"
         "    sess.execute(stmt)\n", []),
        ("def f(cur, ids):\n    ph = ','.join('?' * len(ids))\n"
         "    cur.execute(f'SELECT * FROM t WHERE id IN ({ph})', ids)\n", []),
        ("def f(cur, ids):\n    ph = ', '.join(['%s'] * len(ids))\n"
         "    cur.execute('SELECT * FROM t WHERE id IN (%s)' % ph, tuple(ids))\n", []),
        # not constants, not compositions
        ("from psycopg2 import sql\ndef f(cur, t):\n    cur.execute(sql.SQL('SELECT * FROM ' + t))\n",
         ["E0713"]),
        ("from psycopg2 import sql\ndef f(cur, t):\n"
         "    cur.execute(sql.SQL('SELECT {}').format(sql.SQL(t)))\n", ["E0713"]),
        ("from psycopg2 import sql\ndef f(cur, t):\n    cur.execute(sql.SQL('SELECT {}').format(t))\n",
         ["E0713"]),
        ("def f(cur, ids):\n    ph = ','.join(ids)\n"
         "    cur.execute(f'SELECT 1 WHERE id IN ({ph})')\n", ["E0713"]),
        ("def f(cur, x, n):\n    ph = ','.join([x] * n)\n"
         "    cur.execute(f'SELECT 1 WHERE id IN ({ph})')\n", ["E0713"]),
        ("class R:\n    Q = 'SELECT 1'\n    def g(self, cur):\n        cur.execute(self.Q)\n"
         "    def h(self, x):\n        self.Q = x\n", ["E0713"]),
        ("class R:\n    Q = 'SELECT 1'\n    def g(self, cur):\n        cur.execute(self.Q)\n"
         "class S(R):\n    Q = 'x'\n", ["E0713"]),
        # a lower-case class attribute is a placeholder a subclass fills in
        # (openhands' `MicroAgent.prompt = ''`), not a constant
        ("class R:\n    q = 'SELECT 1'\n    def g(self, cur):\n        cur.execute(self.q)\n",
         ["E0713"]),
        ("LIMIT = 10\ndef g(x):\n    global LIMIT\n    LIMIT = x\n"
         "def f(cur):\n    cur.execute(f'SELECT 1 LIMIT {LIMIT}')\n", ["E0713"]),
        ("from sqlalchemy import text\ndef f(self, s, x):\n"
         "    s.execute(self.table.delete().where(text(x)))\n", ["E0713"]),
        ("def f(cur, a):\n    cur.execute('SELECT ' + 'x' + a)\n", ["E0713"]),
    ])
    print("C3: constants, psycopg sql, attribute Tables and IN-lists clear E0713; raw text fires")


def test_c4_sandbox_and_own_from_string():
    """C4: Jinja's sandbox, and a class this file defines with its own
    `from_string`, are not the template row."""
    _check([
        ("from jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\n"
         "def f(tpl, ctx):\n    return env.from_string(tpl).render(**ctx)\n", []),
        ("from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
         "def f(tpl):\n    return ImmutableSandboxedEnvironment().from_string(tpl)\n", []),
        ("class Mode:\n    @classmethod\n    def from_string(cls, s):\n        return cls()\n"
         "def f(s):\n    return Mode.from_string(s)\n", []),
        ("from jinja2 import Environment\ndef f(x):\n    return Environment().from_string(x)\n",
         ["E0719"]),
        ("from jinja2 import Environment\nfrom jinja2.sandbox import SandboxedEnvironment\n"
         "def f(x, c):\n    env = SandboxedEnvironment()\n    if c:\n        env = Environment()\n"
         "    return env.from_string(x)\n", ["E0719"]),
        ("class M(Base):\n    pass\ndef f(x):\n    return M.from_string(x)\n", ["E0719"]),
        ("class M:\n    def from_string(self, s):\n        return s\n"
         "def f(x):\n    M = get()\n    return M.from_string(x)\n", ["E0719"]),
    ])
    print("C4: SandboxedEnvironment and a same-file from_string are not E0719")


def test_c7_compile_exec_xml_and_docstring():
    """C7: `compile(..., ast.PyCF_ONLY_AST)` is no sink; `code =
    compile(src); exec(code)` is ONE finding, rated as executed; a stdlib
    XML parse with no parser argument keeps its finding at the floor; an
    AWS key shape in a docstring keeps its finding at the floor."""
    _check([
        ("import ast\ndef f(src, fn):\n    return compile(src, fn, 'exec', ast.PyCF_ONLY_AST)\n", []),
        ("import ast\ndef f(src):\n    return compile(src, 'f', 'exec', flags=ast.PyCF_ONLY_AST | 1024)\n", []),
        ("def f(src):\n    return compile(src, 'f', 'exec', flags=0)\n", ["E0731"]),
        ("def f():\n    code = compile('x = 1', 'f', 'exec')\n    exec(code)\n", []),
        ("def f(src, c):\n    code = compile(src, 'f', 'exec')\n    if c:\n        code = other()\n"
         "    exec(code)\n", ["E0731", "E0731"]),
    ])
    ds = _diags("def f(path):\n    with open(path) as fh:\n"
                "        code = compile(fh.read(), path, 'exec')\n    exec(code, {})\n")
    e = [(d.code, d.position.line, d.confidence) for d in ds if d.code == "E0731"]
    assert e == [("E0731", 3, 0.9)], e
    ds = _diags("import xml.etree.ElementTree as ET\ndef f(s, p):\n"
                "    return ET.fromstring(s), ET.fromstring(s, p)\n")
    assert sorted((d.code, d.confidence) for d in ds) == [("E0727", 0.6), ("E0727", 0.95)], \
        [(d.code, d.confidence) for d in ds]
    key = "AKIA" + "IOSFODNN7EXAMPLE"      # split: a fixture, not a credential
    ds = _diags(f'def f():\n    """e.g. {key}"""\n    return "{key}"\n')
    assert sorted((d.code, d.position.line, d.confidence) for d in ds) == \
        [("E0723", 2, 0.6), ("E0723", 3, 1.0)], [(d.code, d.position, d.confidence) for d in ds]
    print("C7: ONLY_AST clean, bound compile/exec once, stdlib XML and docstring keys at the floor")


def test_bug039_secure_filename_join():
    """BUG-039: `os.path.join(<any>, <safeJoin row call>)` is the Werkzeug
    idiom and is clean under --strict; a plain join, or a sanitized part
    that is not the last one, is still E0711."""
    wz = "import os\nfrom werkzeug.utils import secure_filename, safe_join\n"
    _check([
        (wz + "def f(base, n):\n    return open(os.path.join(base, secure_filename(n)))\n", []),
        (wz + "def f(n):\n    return open(os.path.join('/srv/up', secure_filename(n)))\n", []),
        (wz + "def f(n):\n    return open(safe_join('/srv/up', n))\n", []),
        (wz + "def f(base, n):\n    return open(os.path.join(base, n))\n", ["E0711"]),
        (wz + "def f(base, n, e):\n    return open(os.path.join(base, secure_filename(n), e))\n",
         ["E0711"]),
    ])
    print("BUG-039: os.path.join(base, secure_filename(n)) is clean; a plain join is E0711")


def test_fp_probe_shapes_are_quiet_above_the_floor():
    """The precision auditor's probe shapes (audit §C) that stay flagged by
    design report at the 0.6 floor, never at 0.95: the whole command as
    one quoted word, and an unresolved `.url_for` receiver."""
    for src in (_SH + "def f(path):\n    subprocess.run(shlex.quote(path), shell=True)\n",
                "from starlette.responses import RedirectResponse\ndef v(request):\n"
                "    return RedirectResponse(url=request.url_for('home'), status_code=303)\n"):
        ds = _diags(src)
        assert ds and all(d.confidence == 0.6 for d in ds), [(d.code, d.confidence) for d in ds]
    print("probes: flagged-by-design fix shapes rate at the floor")


if __name__ == "__main__":
    test_c1_quoted_pieces_compose()
    test_c2_own_origin_redirects()
    test_c3_sql_constants_and_composition()
    test_c4_sandbox_and_own_from_string()
    test_c7_compile_exec_xml_and_docstring()
    test_bug039_secure_filename_join()
    test_fp_probe_shapes_are_quiet_above_the_floor()
    print("PY PRECISION: ALL TESTS PASS")
