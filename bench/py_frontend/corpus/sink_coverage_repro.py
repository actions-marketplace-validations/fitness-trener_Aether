# Sink-table coverage — callees that are the same hazard as a mapped row
# but were silent because their spelling was absent from the tables
# (slice 2, 2026-09-03). Each vulnerable shape has its documented fix.
#
# Every row here maps onto an EXISTING Aether sink string (deserialize,
# shellExec, renderTemplate, sqlQuery, redirect, parseXml), so no
# detector changed - only what the Python frontend recognises.

import asyncio
import subprocess
import cloudpickle
import dill
import joblib
import jsonpickle
import numpy as np
import pandas as pd
import torch
import yaml
import json
from jinja2 import Environment
from mako.template import Template
from starlette.responses import RedirectResponse
from django.http import HttpResponseRedirect
from django.db.models.expressions import RawSQL
from xml.dom import minidom
import defusedxml.minidom


# --- deserialize class (E0720) -------------------------------------------

def torch_load(path):
    # torch<2.6 defaults weights_only=False: a pickle load of the file.
    return torch.load(path)


def torch_load_explicit_unsafe(path):
    return torch.load(path, weights_only=False)


def torch_load_safe(path):
    return torch.load(path, weights_only=True)


def joblib_load(path):
    return joblib.load(path)


def dill_loads(blob):
    return dill.loads(blob)


def cloudpickle_loads(blob):
    return cloudpickle.loads(blob)


def pandas_read_pickle(path):
    return pd.read_pickle(path)


def jsonpickle_decode(s):
    # Instantiates arbitrary py/object classes - pickle-equivalent.
    return jsonpickle.decode(s)


def numpy_load_allow_pickle(path):
    return np.load(path, allow_pickle=True)


def numpy_load_safe(path):
    # allow_pickle defaults to False since numpy 1.16.3.
    return np.load(path)


def yaml_load_all(stream):
    return list(yaml.load_all(stream))


def yaml_load_all_safe(stream):
    return list(yaml.safe_load_all(stream))


def deserialize_safe(blob):
    return json.loads(blob)


# --- shell class (E0714) -------------------------------------------------

def getoutput(cmd):
    # Always runs through /bin/sh.
    return subprocess.getoutput("git " + cmd)


def getstatusoutput(cmd):
    return subprocess.getstatusoutput("git " + cmd)


async def create_subprocess_shell(cmd):
    return await asyncio.create_subprocess_shell("git " + cmd)


def paramiko_exec_command(client, cmd):
    return client.exec_command("ls " + cmd)


def argv_form_shell(cmd):
    # The argv exit, defeated: the third element IS a shell command line.
    return subprocess.run(["bash", "-c", cmd])


def argv_form_shell_popen(cmd):
    return subprocess.Popen(["/bin/sh", "-c", "git " + cmd])


def argv_form_shell_safe(cmd):
    # A real argv list - the program name and its arguments, no shell.
    return subprocess.run(["git", "status", cmd])


def argv_form_shell_literal_safe():
    return subprocess.run(["bash", "-c", "ls -la"])


def getoutput_safe():
    return subprocess.getoutput("git status")


# --- template class (E0719) ----------------------------------------------

def jinja_from_string(src, ctx):
    env = Environment()
    return env.from_string(src).render(**ctx)


def mako_template(src):
    return Template(src).render()


def jinja_from_string_safe(ctx):
    env = Environment()
    return env.from_string("Hello {{ name }}").render(**ctx)


# --- SQL class (E0713) ---------------------------------------------------

def asyncpg_fetchrow(conn, uid):
    return conn.fetchrow("SELECT * FROM u WHERE id = " + uid)


def databases_fetch_all(db, q):
    return db.fetch_all("SELECT 1 WHERE x = " + q)


def mogrify(cur, q):
    return cur.mogrify("SELECT * FROM t WHERE x = " + q)


def pandas_read_sql(con, q):
    return pd.read_sql("SELECT * FROM t WHERE x = " + q, con)


def django_rawsql(q):
    return RawSQL("SELECT 1 WHERE x = " + q, [])


def asyncpg_fetchrow_safe(conn, uid):
    return conn.fetchrow("SELECT * FROM u WHERE id = $1", uid)


def pandas_read_sql_safe(con):
    return pd.read_sql("SELECT * FROM t", con)


# --- redirect class (E0718) ----------------------------------------------

def starlette_redirect(u):
    return RedirectResponse(u)


def django_redirect(u):
    return HttpResponseRedirect(u)


def starlette_redirect_safe():
    return RedirectResponse("/dashboard")


# --- XXE class (E0727) ---------------------------------------------------

def minidom_parse(f):
    return minidom.parse(f)


def minidom_parse_safe(f):
    return defusedxml.minidom.parse(f)
