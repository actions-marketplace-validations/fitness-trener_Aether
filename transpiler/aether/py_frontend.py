"""Python -> Aether-IR translation frontend.

THIS FILE DOES NOT ANALYZE. It TRANSLATES Python source into the exact
dict-AST shape the existing Aether passes (`aether.passes.capability`,
`aether.passes.effects`) and the dashboard projection (`tools.alsp_surface`)
already consume, then lets those untouched passes do the proving.

The mapping from Python constructs to capability/effect signals is the
analysis surface, and it is intentionally explicit and auditable below:

    CAP_BY_MODULE      import name        -> capability        (whole module)
    CAP_BY_QUALIFIED   module.attr        -> capability        (specific call)
    CAP_BY_BUILTIN     builtin name       -> (capability,verb)
    DYNAMIC_BUILTINS   builtin name       -> reason            (UNPROVABLE)
    PURE_MODULES       import name        -> resolvable, no capability
    PURE_BUILTINS      builtin name       -> resolvable, no capability

SOUNDNESS DISCIPLINE (the whole point of the Python experiment):
  A call whose capability surface we CANNOT determine is NEVER assumed
  clean. It is emitted as an UNPROVABLE record. We only treat a call as
  capability-free when it is (a) a local function, (b) a known-pure
  builtin, or (c) a call into a known-pure module. Everything else —
  unmapped imports, methods on unknown objects, dynamic dispatch — is
  UNPROVABLE. This is why real Python may collapse to UNPROVABLE; the
  experiment is to measure exactly how much.

Output of `py_to_ir(source)`:
    (ast_dict, unprovable_map, meta)
  ast_dict       : {"kind":"Program","decls":[ModuleDecl, FunctionDecl...]}
  unprovable_map : { fn_name: [ {fn,line,granularity,callee/construct,
                                 reason,detail,needs}, ... ] }
  meta           : { "lang":"python", "module": name, "n_functions": int,
                     "pymap_version": str }
"""
from __future__ import annotations
import ast as _pyast
import re
from collections import deque
import shlex
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

PYMAP_VERSION = "py-cap-map/0.2"

# Stages and rows that do not apply to Python — defined ONCE here and
# imported by the CLI, both benches and the tests (they were four literal
# copies with one drift test between them).
#   effects  — E0801 compares a call site against a DECLARED effects
#              clause; Python has none, so there is nothing to compare.
#   semantic — E0202-E0207 check Aether language constructs (match
#              exhaustiveness, dead `let` stores, ignored Results). On
#              translated Python they describe the translation, not the
#              program: `cur = conn.cursor()` read as a dead store.
PY_SKIP_STAGES = ("effects", "semantic")
# Rows held back from the DEFAULT Python output by measurement, not taste
# (`bench/py_frontend/REPORT.md`, 76 benign modules): E0711 fired 11
# times, 8 of them `open(path_param)` — real, but at a ratio that buries
# the other rows. `--strict` adds it back. The rationale stays in cli.py.
PY_STRICT_ONLY_CODES = ("E0711",)

# ----------------------------------------------------------------------
# THE AUDITABLE CAPABILITY MAPPING TABLE
# ----------------------------------------------------------------------
# Whole-module imports that confer a capability on ANY call through them.
CAP_BY_MODULE: Dict[str, str] = {
    # network
    "socket": "net", "ssl": "net", "http": "net", "httplib": "net",
    "urllib": "net", "urllib2": "net", "requests": "net", "httpx": "net",
    "aiohttp": "net", "websocket": "net", "websockets": "net",
    "smtplib": "net", "ftplib": "net", "telnetlib": "net", "poplib": "net",
    "imaplib": "net", "xmlrpc": "net", "grpc": "net", "paramiko": "net",
    # filesystem
    "pathlib": "fs", "shutil": "fs", "tempfile": "fs", "glob": "fs",
    "fileinput": "fs", "csv": "fs", "configparser": "fs",
    # process / exec
    "subprocess": "process", "multiprocessing": "process", "pty": "process",
    "signal": "process",
    # database
    "sqlite3": "db", "psycopg2": "db", "psycopg": "db", "pymysql": "db",
    "mysql": "db", "sqlalchemy": "db", "pymongo": "db", "redis": "db",
    "asyncpg": "db", "aioredis": "db", "cassandra": "db", "elasticsearch": "db",
    # logging
    "logging": "log",
}

# Specific dotted calls that confer a capability (finer than whole-module).
CAP_BY_QUALIFIED: Dict[str, str] = {
    "os.system": "process", "os.popen": "process", "os.spawnv": "process",
    "os.spawnl": "process", "os.exec": "process", "os.execv": "process",
    "os.execl": "process", "os.fork": "process", "os.kill": "process",
    "os.remove": "fs", "os.unlink": "fs", "os.mkdir": "fs", "os.makedirs": "fs",
    "os.rmdir": "fs", "os.removedirs": "fs", "os.rename": "fs", "os.replace": "fs",
    "os.open": "fs", "os.read": "fs", "os.write": "fs", "os.listdir": "fs",
    "os.scandir": "fs", "os.walk": "fs", "os.chmod": "fs", "os.chown": "fs",
    "os.stat": "fs", "os.truncate": "fs", "os.link": "fs", "os.symlink": "fs",
    "os.getenv": "env", "os.putenv": "env", "os.unsetenv": "env",
    "os.urandom": "random",
    "time.time": "time", "time.sleep": "time", "time.monotonic": "time",
    "time.perf_counter": "time", "time.localtime": "time", "time.gmtime": "time",
    "time.process_time": "time",
    "datetime.now": "time", "datetime.today": "time", "datetime.utcnow": "time",
    "random.random": "random", "random.randint": "random", "random.choice": "random",
    "random.shuffle": "random", "random.uniform": "random", "random.seed": "random",
    "random.randrange": "random", "random.sample": "random", "random.getrandbits": "random",
    "secrets.token_bytes": "random", "secrets.token_hex": "random",
    "secrets.token_urlsafe": "random", "secrets.choice": "random",
    "secrets.randbelow": "random", "secrets.randbits": "random",
    "uuid.uuid1": "random", "uuid.uuid4": "random",
    # I/O-performing functions that previously hid inside PURE_MODULES.
    # Mapped to their real capability so the verdict is sound AND positively
    # identified rather than merely UNPROVABLE. See PURE_MODULES audit note.
    "pprint.pprint": "log", "pprint.pp": "log",   # write to stdout (a stream)
    "warnings.warn": "log",                          # writes to sys.stderr
    "codecs.open": "fs",                             # opens a file on disk
    # env via os.environ mapping object (the .get() method form; subscript form
    # os.environ['X'] is not a call and remains out of call-based analysis)
    "os.environ.get": "env", "os.environ.setdefault": "env",
    "os.environ.pop": "env",
    # pandas file readers (the module-level read_* functions perform fs I/O;
    # DataFrame .to_* writers are methods on an untyped frame -> UNPROVABLE)
    "pandas.read_csv": "fs", "pandas.read_parquet": "fs",
    "pandas.read_excel": "fs", "pandas.read_json": "fs", "pandas.read_table": "fs",
}

# Builtins that themselves confer a capability.
CAP_BY_BUILTIN: Dict[str, Tuple[str, str]] = {
    "open": ("fs", "open"),
    "print": ("log", "print"),
    "input": ("log", "input"),
}

# ----------------------------------------------------------------------
# THE AUDITABLE SINK MAPPING TABLE
# ----------------------------------------------------------------------
# Python call -> the Aether SINK NAME the existing detectors already know.
# Every value here must be a sink string that appears in
# `aether.passes.detector_specs.LITERAL_OR_WRAPPER_SPECS`; an unmapped
# string matches no row and would silently do nothing.
#
# WHY MATCHING BY METHOD NAME IS LEGITIMATE HERE, having been unsound for
# purity (see the PURE_METHODS note further down):
#   Clearing `obj.append()` as pure from the method NAME, with no proof of
#   the receiver's type, certified a capability-using module CLEAN — a
#   silent false negative, the contract-breach class (trap_04).
#   Treating `cursor.execute(...)` as a SQL sink from the method name,
#   with exactly the same absence of proof, can only produce a finding on
#   code that was not a sink — an over-flag.
#   One rule covers both: never assume clean from a name; freely assume
#   dangerous from a name. The asymmetry is not a double standard, it is
#   the direction of the error.

SINK_BY_QUALIFIED: Dict[str, str] = {
    "os.system": "shellExec", "os.popen": "shellExec",
    "pickle.loads": "deserialize", "pickle.load": "deserialize",
    "marshal.loads": "deserialize", "shelve.open": "deserialize",
    # Added after the bandit-oracle recall run (bench/pypi_scan/run_recall.py)
    # confirmed each of these as a MISS on real PyPI code. Only shapes the
    # oracle actually flagged were added - no speculative rows.
    "marshal.load": "deserialize",        # B302: .load, not just .loads
    "pickle.Unpickler": "deserialize",    # B301: the constructor form
    "xml.dom.pulldom.parse": "parseXml",      # B319
    "xml.dom.pulldom.parseString": "parseXml",
    "xml.sax.parse": "parseXml",              # B317
    "xml.sax.parseString": "parseXml",
    "xml.dom.expatbuilder.parse": "parseXml",         # B316
    "xml.dom.expatbuilder.parseString": "parseXml",
    "xml.etree.cElementTree.fromstring": "parseXml",  # B313
    "xml.etree.cElementTree.parse": "parseXml",
    "flask.render_template_string": "renderTemplate",
    "jinja2.Template": "renderTemplate",
    "django.template.Template": "renderTemplate",
    "flask.redirect": "redirect",
    "django.shortcuts.redirect": "redirect",
    "lxml.etree.fromstring": "parseXml", "lxml.etree.parse": "parseXml",
    "lxml.etree.XML": "parseXml",
    "xml.etree.ElementTree.fromstring": "parseXml",
    "xml.etree.ElementTree.parse": "parseXml",
    "xml.dom.minidom.parseString": "parseXml",
    # Slice 2 (2026-09-03): callees that are the same hazard as a mapped
    # row but were silent because their spelling was absent. Every value
    # is an existing sink string; prevalence per row is the AST census
    # over bench/framework_scan/_work/src (4,946 files).
    "xml.dom.minidom.parse": "parseXml",          # parse/parseString asymmetry
    # pickle-protocol loaders (E0720). joblib/dill/cloudpickle ARE pickle;
    # pandas.read_pickle unpickles; jsonpickle.decode instantiates
    # arbitrary py/object classes (over-flag direction). 1 site each for
    # joblib/dill/cloudpickle on the corpus, 0 for the pandas/jsonpickle.
    "joblib.load": "deserialize",
    "dill.load": "deserialize", "dill.loads": "deserialize",
    "cloudpickle.load": "deserialize", "cloudpickle.loads": "deserialize",
    "pandas.read_pickle": "deserialize",
    "jsonpickle.decode": "deserialize",
    # shell-always runners (E0714): each goes through /bin/sh whatever
    # the caller passes. 0 corpus sites; the shape is common in scripts.
    "subprocess.getoutput": "shellExec",
    "subprocess.getstatusoutput": "shellExec",
    "asyncio.create_subprocess_shell": "shellExec",
    "commands.getoutput": "shellExec",            # py2 legacy
    # template engines (E0719). jinja2's `Environment.from_string` is the
    # METHOD row below; mako's constructor takes the template text.
    "mako.template.Template": "renderTemplate",
    # SQL string executors (E0713). 0 corpus sites; pandas.read_sql is the
    # common LLM-generated analytics shape.
    "pandas.read_sql": "sqlQuery", "pandas.read_sql_query": "sqlQuery",
    "django.db.models.expressions.RawSQL": "sqlQuery",
    "django.db.models.RawSQL": "sqlQuery",
    # framework redirect constructors (E0718): 5 non-literal
    # RedirectResponse sites on the corpus (agno, mcp).
    "starlette.responses.RedirectResponse": "redirect",
    "fastapi.responses.RedirectResponse": "redirect",
    "django.http.HttpResponseRedirect": "redirect",
    "aiohttp.web.HTTPFound": "redirect",
    # Wave 4 (audit 2026-09-24 B9): spellings of classes the tables
    # already model, each probe-confirmed silent first. Corpus sites per
    # row are in audits/waves/wave4_record.md.
    "werkzeug.utils.redirect": "redirect",        # flask.redirect's own body
    "quart.redirect": "redirect",
    "django.http.HttpResponsePermanentRedirect": "redirect",
    "aiohttp.web.HTTPSeeOther": "redirect",
    "aiohttp.web.HTTPTemporaryRedirect": "redirect",
    "aiohttp.web.HTTPPermanentRedirect": "redirect",
    "aiohttp.web.HTTPMovedPermanently": "redirect",
    "duckdb.sql": "sqlQuery", "duckdb.execute": "sqlQuery",
    "duckdb.query": "sqlQuery",
    "_pickle.loads": "deserialize", "_pickle.load": "deserialize",
    "jinja2.nativetypes.NativeTemplate": "renderTemplate",
    "tornado.template.Template": "renderTemplate",
    # runpy executes the file / module the argument names: the caller
    # picks the CODE, which is E0731's class (CWE-94), not E0711's —
    # nothing is read back, the path is run. E0711 is also strict-only,
    # which would hide an RCE by default.
    "runpy.run_path": "evalCode", "runpy.run_module": "evalCode",
    # `code.InteractiveInterpreter().runsource(src)` compiles and runs
    # `src`. Spelled through the constructor (`_attr_spelling`): a
    # `runsource`/`push` METHOD row on an unresolved receiver would match
    # every queue's `.push(x)`.
    "code.InteractiveInterpreter.runsource": "evalCode",
    "code.InteractiveConsole.runsource": "evalCode",
    "code.InteractiveConsole.push": "evalCode",
}

# ----------------------------------------------------------------------
# SINK GUARDS — when safety lives somewhere other than the judged argument
# ----------------------------------------------------------------------
# q5 settled that a NAME may not clear a call. A VALUE may not either.
# Each guard answers "is this call safe?", and the answer is accepted only
# when the value is positively identified as one of the sanctioned forms.
# Unrecognized, computed, unresolvable, or absent all mean SINK.
#
# The ad-hoc gates this replaces defaulted the unknown case to "safe" and
# produced three false accepts (BUGS.md BUG-004), one of them an RCE
# written literally at the call site: `yaml.load(raw, Loader=yaml.Loader)`
# was silent, because the old rule read "any Loader= means safe".

class Guard:
    """One sink's safety condition.

    sink_name     — the Aether sink this call becomes when the guard says
                    SINK. Lives here because the guarded callables are not
                    in SINK_BY_QUALIFIED — the guard owns them entirely.
    keyword       — the keyword argument that decides, or None for a
                    positional slot (`arg_index`).
    safe_values   — dotted spellings that make the call SAFE. Empty means
                    no value is sanctioned; presence alone never is.
    sink_values   — dotted spellings that make it a SINK. Used where the
                    absent case is safe (`shell=` absent means no shell).
    absent_is_sink— verdict when the keyword is not present at all.
    on_receiver   — the keyword is read off the CONSTRUCTOR the method was
                    called on (`YAML(typ="unsafe").load(s)`), directly or
                    through a single-binding name; the call itself when
                    there is no such constructor.
    """
    def __init__(self, sink_name, keyword=None, arg_index=None,
                 safe_values=(), sink_values=(), absent_is_sink=True,
                 on_receiver=False):
        self.sink_name = sink_name
        self.keyword = keyword
        self.arg_index = arg_index
        self.safe_values = frozenset(safe_values)
        self.sink_values = frozenset(sink_values)
        self.absent_is_sink = absent_is_sink
        self.on_receiver = on_receiver


# Loader safety verified by EXECUTION on PyYAML 6.0.3 with the payload
# `!!python/object/apply:os.system [...]`:
#   yaml.Loader       -> CONSTRUCTED (unsafe)   yaml.UnsafeLoader -> CONSTRUCTED
#   yaml.FullLoader   -> refused                yaml.SafeLoader   -> refused
# FullLoader is deliberately NOT sanctioned: CVE-2020-1747 and
# CVE-2020-14343 are FullLoader bypasses. Over-flag direction.
_YAML_SAFE_LOADERS = ("yaml.SafeLoader", "yaml.CSafeLoader",
                      "yaml.BaseLoader", "yaml.CBaseLoader")

SINK_GUARDS: Dict[str, "Guard"] = {}
for _fn in ("yaml.load", "yaml.full_load", "yaml.unsafe_load",
            "yaml.load_all", "yaml.full_load_all", "yaml.unsafe_load_all"):
    # Absent Loader= is a sink (that is the classic yaml.load(x) RCE);
    # a SANCTIONED loader clears it; anything else does not.
    # `yaml.load(stream, Loader)`: the loader is also the second positional.
    # The `*_all` variants take the same Loader and were silent.
    SINK_GUARDS[_fn] = Guard("deserialize", keyword="Loader", arg_index=1,
                             safe_values=_YAML_SAFE_LOADERS,
                             absent_is_sink=True)
# torch.load is pickle. `weights_only=True` is the documented fix, and the
# default only from torch 2.6 — so, like lxml, the absent case is judged
# by the older default: SINK. (CVE-2025-32434: weights_only=True on
# torch<=2.5.1 is itself bypassable; the guard clears the documented fix,
# not the version.) 0 corpus sites; the dominant shape in ML repos.
SINK_GUARDS["torch.load"] = Guard("deserialize", keyword="weights_only",
                                  safe_values=("True",), absent_is_sink=True)
# numpy.load re-enables pickle by keyword: absent/False is safe (the
# default since numpy 1.16.3), a literal True is a sink, an unresolvable
# value is a sink — the same shape as the subprocess `shell=` row.
# 1 corpus site (langchain_community document_loaders/parsers/images.py).
SINK_GUARDS["numpy.load"] = Guard("deserialize", keyword="allow_pickle",
                                  sink_values=("True",), absent_is_sink=False)
for _fn in ("subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen"):
    # No shell= means no shell — the argv form, which IS the documented
    # fix — so absence is SAFE here. But a shell= we cannot resolve to a
    # literal False is treated as a shell. `shell` is the ninth
    # positional of every one of these (they share Popen's signature).
    SINK_GUARDS[_fn] = Guard("shellExec", keyword="shell", arg_index=8,
                             safe_values=("False",), absent_is_sink=False)

for _fn in ("defusedxml.minidom.parse", "defusedxml.minidom.parseString",
            "defusedxml.pulldom.parse", "defusedxml.pulldom.parseString",
            "defusedxml.ElementTree.parse"):
    # defusedxml defuses only the parser it builds itself: `parser=`
    # absent or None is the defused path, and a caller's parser is passed
    # straight through — one built with make_parser() and
    # feature_external_ges read the file through defusedxml.minidom
    # (measured, LOOP_LOG iteration 53). `parser` is the second
    # positional of every one of these. E0727's hint names defusedxml,
    # so the shape the hint would otherwise steer into must not be silent.
    SINK_GUARDS[_fn] = Guard("parseXml", keyword="parser", arg_index=1,
                             safe_values=("None",), absent_is_sink=False)

for _fn in ("ruamel.yaml.YAML.load", "ruamel.yaml.YAML.load_all"):
    # ruamel's default `typ` is round-trip (no arbitrary objects);
    # `typ="unsafe"` constructs `!!python/object` like yaml.Loader. The
    # keyword lives on the constructor, not on `.load` — `on_receiver`.
    # An unresolvable `typ` is a sink. 0 corpus sites.
    SINK_GUARDS[_fn] = Guard("deserialize", keyword="typ",
                             sink_values=("unsafe",), absent_is_sink=False,
                             on_receiver=True)
for _fn in ("langchain_core.prompts.PromptTemplate.from_template",
            "langchain_core.prompts.ChatPromptTemplate.from_template",
            "langchain.prompts.PromptTemplate.from_template",
            "langchain.prompts.ChatPromptTemplate.from_template"):
    # A LangChain prompt is an f-string template unless the caller asks
    # for jinja2, and a jinja2 template from input is SSTI (langchain's
    # own docstring warns against it). 0 corpus call sites.
    SINK_GUARDS[_fn] = Guard("renderTemplate", keyword="template_format",
                             sink_values=("jinja2",), absent_is_sink=False)

# Method name on a receiver of unresolved type -> sink (over-flag direction).
SINK_BY_METHOD: Dict[str, str] = {
    "execute": "sqlQuery", "executemany": "sqlQuery",
    "executescript": "sqlExec", "raw": "sqlQuery",
    # SQLAlchemy's raw DB-API pass-through, and sqlmodel's `Session.exec`
    # (which takes a SQL expression, so a real one clears as `sqlBind`).
    # 22 of 31 `exec_driver_sql` sites in bench/framework_scan were
    # f-strings and every one was silent (BUG-012 survey).
    "exec_driver_sql": "sqlQuery", "exec": "sqlQuery",
    # asyncpg / `databases` / aiopg query methods (slice 2). Unambiguous
    # DB names; bare `fetch` is deliberately NOT here — vector stores
    # (`index.fetch(ids)`) and HTTP clients (`client.fetch(url)`) spell it
    # too, so it stays a measured decision (q5 residual). fetch_all: 9
    # non-literal corpus sites (langchain_community; 5 cassandra, 4 HTTP
    # loaders that will over-flag — accepted direction).
    "fetchrow": "sqlQuery", "fetchval": "sqlQuery", "fetch_all": "sqlQuery",
    "fetch_one": "sqlQuery", "fetch_val": "sqlQuery",
    "mogrify": "sqlQuery",                        # psycopg's query renderer
    # jinja2 `Environment.from_string(src)` — the prompt-template SSTI
    # shape agent frameworks actually use: 24 non-literal corpus sites
    # (haystack PromptBuilder, semantic-kernel, langchain). A non-jinja
    # `.from_string` over-flags (q5 direction), except on a class this
    # file defines with its own `from_string` (`_own_class_method`). A
    # `jinja2.sandbox.SandboxedEnvironment` receiver is Jinja's documented
    # control for user-authored templates and clears it (audit C4); the
    # sandbox has had breakouts (CVE-2024-56326 among them, fixed in later
    # 3.1.x releases) — the row clears the documented control, not a
    # version, the q1 residual torch's `weights_only` also carries.
    "from_string": "renderTemplate",
    # paramiko `client.exec_command(cmd)` runs `cmd` through the remote
    # shell. 0 corpus sites.
    "exec_command": "shellExec",
    # Wave 4 (B9). peewee/ODPS `execute_sql` — 1 corpus site (max_compute).
    # `.sql(q)`: duckdb connections, pyspark, snowflake, rockset,
    # manticore — all 16 corpus `.sql(` calls are SQL executors. sqlglot's
    # `expr.sql(dialect=d)` renders instead and will over-flag (q5).
    "execute_sql": "sqlQuery", "sql": "sqlQuery",
    # Django `QuerySet.extra(select=, where=, tables=, order_by=)` splices
    # its strings verbatim. Only those strings are judged (`_extra_sql_arg`):
    # `extra(where=["a = %s"], params=[x])` is the parameterized form and
    # stays clean. 0 corpus sites.
    "extra": "sqlQuery",
}

# Builtins that are sinks. `exec`/`eval`/`compile` on a non-literal source
# is code injection (E0731, CWE-94/95) — THE hazard of agent frameworks
# (5 bare exec() + 9 compile() non-literal sites on the corpus). The
# capability side still files them as `dynamic_construct` UNPROVABLE
# notes; this row is what makes them a finding. `ast.literal_eval` is
# not here (literals only), and a name the module or function binds
# itself (`def exec(...)`) is not the builtin — see `_sink_name`.
SINK_BY_BUILTIN: Dict[str, str] = {
    "open": "readFile",
    "exec": "evalCode", "eval": "evalCode", "compile": "evalCode",
}

# How `_sink_match` named a sink. This is the vocabulary the per-finding
# confidence axis rates (`transpiler/aether/confidence.py`), published
# through `mapping_table()` like every other frontend table so the rating
# can be audited against what the frontend can actually emit.
SINK_MATCH_KINDS: Tuple[str, ...] = (
    "qualified",        # resolved through the imports to a dotted path
    "guard",            # a SINK_GUARDS path whose guard read as unsafe
    "builtin",          # a bare builtin name (open/exec/eval)
    "builtin_compile",  # `compile` — builds a code object, runs nothing
    "method",           # method name only, receiver unresolved (q5)
    "argv",             # literal ["bash", "-c", cmd]
    "stdlib_xml",       # stdlib XML parse with no parser argument: no XXE, DoS clause
)

# `["bash", "-c", cmd]` handed to a subprocess runner: the argv exit the
# `shell=` guard sanctions, carrying a shell command line in its third
# element. Literal program and flag only; a list built elsewhere stays
# the recorded residual (q1). 0 real corpus sites (one docstring).
_ARGV_SHELLS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash",
    "/usr/bin/sh", "/usr/bin/bash", "cmd", "cmd.exe", "powershell", "pwsh",
})
_ARGV_SHELL_FLAGS = frozenset({"-c", "/c"})

# Argument injection (CWE-88, gaps round G6): programs with an option
# that runs a command, or code, the caller names. Handed an argv whose
# non-literal word may itself be that option — a clone URL of
# `--upload-pack=touch /tmp/x` (GitPython CVE-2022-24439), an ssh host of
# `-oProxyCommand=...` (git CVE-2017-1000117) — the input picks the code
# with no shell involved, and quoting the word changes nothing. Each value
# lists the program's code-running options, for the record,
# `mapping_table()` and the pins; the rule does not read them, because a
# non-literal word can BE any of them: every non-literal word before a
# literal `--` is judged (E0714). git has the one corpus site (agno's
# `git *args` wrapper); the others are documented command-running options
# (GTFOBins) with 0 corpus sites.
_ARGV_CODE_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "git": ("-c", "--config", "--config-env", "--upload-pack", "-u",
            "--receive-pack", "--exec"),
    "ssh": ("-o", "-F", "<host>", "<command>"),
    "tar": ("--to-command", "--checkpoint-action", "--use-compress-program",
            "-I", "--info-script", "-F", "--new-volume-script", "--rsh-command"),
    "find": ("-exec", "-execdir", "-ok", "-okdir"),
    "rsync": ("-e", "--rsh", "--rsync-path"),
    "zip": ("-T", "-TT", "--unzip-command"),
}
# `--` does not end the danger here: ssh runs the words after the host as
# a remote shell command, and find reads every word as its expression.
_ARGV_NO_TERMINATOR = frozenset({"ssh", "find"})
# Exec-form runners whose positional arguments ARE the argv.
_ARGV_POSITIONAL_RUNNERS = frozenset({"asyncio.create_subprocess_exec"})

# Python's sanctioned exits, mapped onto Aether's wrapper names so a fixed
# call site reads as clean instead of as an unknown call.
SANITIZER_BY_QUALIFIED: Dict[str, str] = {
    "shlex.quote": "shellArg", "pipes.quote": "shellArg",
    # `shlex.join(args)` quotes every element — the argv list as one
    # command line. A PIECE of a command (`"git " + shlex.join(args)`);
    # as the whole command the input still picks the program (py_whole),
    # except a literal list display whose program is a literal, which
    # `_shlex_join_expr` spells element by element (audit C1).
    "shlex.join": "shellArg",
    "yaml.safe_load": "schemaDecode", "yaml.safe_load_all": "schemaDecode",
    "json.loads": "schemaDecode", "json.load": "schemaDecode",
    "werkzeug.utils.secure_filename": "safeJoin",
    # `safe_join(base, *parts)` returns None for a result outside `base`
    # (Werkzeug's docstring; `security.safe_join` is the pre-2.1
    # spelling), so what reaches `open` is under `base` or not a path.
    "werkzeug.utils.safe_join": "safeJoin", "werkzeug.security.safe_join": "safeJoin",
    # Own-origin URL builders (E0718, audit C2): each returns a URL of
    # the app's own routes — a path, or with `_external=True` the
    # request's own host — whatever the endpoint and values are, so it
    # cannot send the user off-site. `django.shortcuts.resolve_url` is
    # deliberately absent: it returns an absolute URL passed to it as is.
    "flask.url_for": "safeRedirect", "quart.url_for": "safeRedirect",
    "django.urls.reverse": "safeRedirect", "django.urls.reverse_lazy": "safeRedirect",
    # HTML escaping is HTML-context-specific: Aether's `htmlEscape`, which
    # clears only the HTML sink. No Python call maps onto `trusted` — that
    # is the one exit of the template, code and deserialization rules, and
    # an escaper leaves `{{7*7}}` and `__import__('os')` intact, so
    # `eval(html.escape(x))` was silent (BUG-032). `urllib.parse.quote`
    # and `flask.render_template` stay unmapped for the same reason.
    "html.escape": "htmlEscape", "markupsafe.escape": "htmlEscape",
}


# ----------------------------------------------------------------------
# SQL EXPRESSION BUILDERS — a query that is not a string (BUG-010)
# ----------------------------------------------------------------------
# `conn.execute(select(t).where(t.c.id == cid))` is the safest SQL in
# Python: SQLAlchemy compiles the expression with bound parameters, and no
# string is assembled anywhere. Two correct rules composed into refusing
# it anyway — `execute` is a sink by method name, and `_SQL_RULE` reads any
# non-literal argument as dynamic — at a rate of 1,029 findings across 15
# agent frameworks, 97% of everything reported (bench/framework_scan).
#
# A call rooted at one of these builders is named as the E0713 wrapper
# (`sqlBind`) so the untouched Aether rule clears it. Rooted means: walk
# `select(t).where(x).order_by(y)` down its receiver chain to `select(t)`.
# The root must resolve, through the file's imports, to one of these
# MODULES — a bare NAME spelled `select` from anywhere else clears
# nothing (q5).
_SQL_EXPR_ROOTS = frozenset({"sqlalchemy", "sqlmodel"})
_SQL_EXPR_BUILDERS = frozenset({"select", "insert", "update", "delete",
                                "text", "union", "union_all", "exists"})
# Where a RAW SQL STRING re-enters the expression language. These are the
# soundness line: `text("... " + uid)` is a real injection, nested inside
# a safe `select(...)` or not. Every such call anywhere in the expression
# must take a str literal as its first argument, or nothing is sanctioned.
# A name bound to a literal is NOT resolved here — over-flag direction.
_SQL_RAW_ENTRY = frozenset({"text", "literal_column", "column", "table"})
# The Table-object form: `table.delete().where(...)`, `t.select()`,
# `t.update().values(...)`. The receiver is a plain NAME, so no import can
# vouch for it — and q5 says a name clears nothing. What makes this form
# safe to accept is narrower than the name: the root call is accepted ONLY
# when it takes no positional argument at all. A homegrown builder that
# returns a raw string (`qb.select("SELECT " + x)`) has to be handed that
# string, so it can never match; `.values(...)` keywords are bound
# parameters. A receiver whose STATE is a raw string is outside any
# argument-shape rule, and is the recorded residual (q5).
_SQL_TABLE_METHODS = frozenset({"select", "insert", "update", "delete"})
# Methods that splice a raw string VERBATIM into the compiled SQL of an
# otherwise-parameterized expression: `select(t).prefix_with("/*+ " + h)`
# emits the string as written. They are `text()`'s siblings and get its
# discipline — every str argument must be a literal (or a literal-bound
# name), or the expression sanctions nothing. `with_hint(selectable,
# text)` carries its string in the SECOND positional slot.
_SQL_RAW_METHODS = frozenset({"prefix_with", "suffix_with", "with_hint",
                              "with_statement_hint", "op"})
# A raw SQL string is an injection WHEREVER it enters, executed in the
# same statement or not (audit 2026-09-24 B4/B5/PM-5/PM-7): a
# `Query.filter(text(f"..."))` runs at `.all()`, `session.scalars(...)`
# is no executor row, and `order = text(col)` is executed three lines
# later through `select(t).order_by(order)`. So the entry call ITSELF is
# the E0713 sink (`_raw_sql_entry`), and when it sits inside an
# executor's judged argument the executor's finding stands for both.
#   * `text` / `literal_column` resolved into sqlalchemy/sqlmodel;
#   * `.text(...)` on ANY receiver — Flask-SQLAlchemy's `db.text` is an
#     instance attribute no import resolves. Over-flag by name (q5): a
#     `.text(x)` that is not SQL (streamlit `st.text`, a canvas) fires;
#     a tuple/list/number argument (PIL's `draw.text((x, y), s)`) cannot
#     be SQL text and does not;
#   * a str-SHAPED argument (f-string, concat, `%`, `.format`, `.join`)
#     to `.where` / `.filter` / `.having` — SQLAlchemy 1.x coerced it to
#     `text()`, and LanceDB/sqlglot parse it as SQL.
_SQL_TEXT_ENTRY = frozenset({"text", "literal_column"})
_SQL_STR_ENTRY_METHODS = frozenset({"where", "filter", "having"})
# Inside a recognised builder chain a str-shaped argument to any of these
# sanctions nothing either (it is compiled verbatim), so the executor
# judges the chain as a raw query.
_SQL_STR_CLAUSE_METHODS = _SQL_STR_ENTRY_METHODS | {"order_by", "group_by", "select"}


class _FnScope:
    """Per-function facts the expression translator consults.

    Callable, so it stands wherever a plain `consts.get` resolver did:
    `_dotted_of` asks only for a name's single dotted binding. The two
    sets are what BUG-010's second measurement needed — names that hold a
    SQL expression (`stmt = select(t); stmt = stmt.where(...)`) and names
    bound only to a string literal (`text(sql_query)`).

    `local_names` is every name the function binds by ANY form
    (`_DefIndex.bindings`); a bare name not in it may be resolved through the
    module's imports, one in it may not — a local rebinding wins over
    an import, and an unresolvable local rebinding wins over both.
    `module_lits` maps a module-level name bound exactly once, to a str
    literal, nowhere else in the module, to that literal."""
    def __init__(self, consts: Dict[str, str], sql_names=(), lit_names=(),
                 local_names=(), module_lits: Optional[Dict[str, Tuple[str, int]]] = None,
                 local_fns=(), values: Optional[Dict[str, Any]] = None,
                 module: Optional["_ModuleFacts"] = None):
        self.consts = consts
        self.sql_names = frozenset(sql_names)
        self.lit_names = frozenset(lit_names)
        self.local_names = frozenset(local_names)
        self.module_lits: Dict[str, Tuple[str, int]] = module_lits or {}
        # Names that are NOT the builtin of the same spelling: bound in
        # this function, or a module-level `def`. `SINK_BY_BUILTIN` is
        # keyed by builtin name, so a local `def exec(...)` must win.
        self.shadowed = self.local_names | frozenset(local_fns)
        # name -> the one value expression bound to it (a name bound
        # once, by a form whose value is visible); `module` holds the
        # same for module-level names bound once in the whole module.
        self.values: Dict[str, Any] = values or {}
        self.module = module
        # Set by `translate` (audit 2026-09-24 §C): parameters annotated
        # as a framework Request (`_url_builder`), the redirect targets a
        # dominating Django check guards (`_redirect_guards`), and the
        # enclosing class's literal attributes (`self.Q`, `_class_lits`).
        self.request_params: frozenset = frozenset()
        self.redirect_guards: List[Tuple[str, int, int]] = []
        self.class_lits: Dict[str, Tuple[str, int]] = {}
        self.depth = 0            # current `_expr` nesting (see _MAX_EXPR_DEPTH)
        self.too_deep = False     # set when the cap was hit in this scope

    def __call__(self, name: str) -> Optional[str]:
        if name in self.local_names:
            return self.consts.get(name)
        # A module-level alias bound once in the whole module (`system =
        # os.system`) resolves like a function-local one (audit B8).
        return self.module.consts.get(name) if self.module else None

    def value_of(self, name: str) -> Optional[Any]:
        """The single value expression `name` is bound to here, or None.
        A local binding wins; an unbound name falls back to the module."""
        if name in self.local_names:
            return self.values.get(name)
        return self.module.values.get(name) if self.module else None


class _ModuleFacts:
    """Module-level names bound exactly ONCE in the whole module (any
    binding form, any depth — the bar `module_lits` uses), at module
    level, by a single-name assignment: `values` maps each to its value
    expression, `consts` to its dotted spelling where `_dotted_of` can
    name one."""
    def __init__(self, values: Dict[str, Any], consts: Dict[str, str],
                 class_methods: Optional[Dict[str, Set[str]]] = None):
        self.values = values
        self.consts = consts
        # class name -> its own `def` names, for top-level classes the
        # module binds once (`_own_class_method`).
        self.class_methods: Dict[str, Set[str]] = class_methods or {}


# ----------------------------------------------------------------------
# BINDING FORMS — every way a Python name acquires a value
# ----------------------------------------------------------------------
# The three per-function resolvers (`_local_constants`,
# `_safe_xml_parser_names`, `_sql_expression_names`) and the `Let` nodes
# the Aether safe-name pass reads all used to see ONE binding form: a
# single-Name `Assign`. Every other form — a parameter, `sql += uid`, a
# for-target, a tuple unpack, a walrus, an except-as, a `global` — was
# invisible, so a name whose only VISIBLE binding was a literal proved
# "literal-only" after it had been rebound to attacker input, and
# `if q is None: q = "SELECT 1"` made a caller-supplied query a constant
# (BUGS.md BUG-012). One walk, consumed by every resolver, so the
# discipline cannot drift again. A form whose value the translator can
# see yields it; every other form yields None, which every consumer
# reads as UNRESOLVED — the disqualifying case.

_PARAM_FIELDS = ("posonlyargs", "args", "kwonlyargs")
# Statement/expression fields that are binding SITES, not values.
_TARGET_FIELDS = frozenset({"target", "targets", "optional_vars"})
_PATTERN_BASE = getattr(_pyast, "pattern", ())


def _target_names(t: Any) -> List[str]:
    """Names bound by an assignment / for / with / comprehension target."""
    if isinstance(t, _pyast.Name):
        return [t.id]
    if isinstance(t, (_pyast.Tuple, _pyast.List)):
        return [n for e in t.elts for n in _target_names(e)]
    if isinstance(t, _pyast.Starred):
        return _target_names(t.value)
    return []      # Attribute / Subscript targets bind no local name


def _param_names(a: Any) -> List[str]:
    out = [x.arg for f in _PARAM_FIELDS for x in getattr(a, f, None) or []]
    for x in (a.vararg, a.kwarg):
        if x is not None:
            out.append(x.arg)
    return out


def _walk(node: Any) -> Iterator[Any]:
    """`ast.walk`, same breadth-first order, without its two generator
    layers per node (`iter_child_nodes` / `iter_fields`): the frontend's
    one walk per scope is its largest single cost."""
    AST = _pyast.AST
    todo = deque([node])
    pop, push = todo.popleft, todo.append
    while todo:
        n = pop()
        for f in n._fields:
            v = getattr(n, f, None)
            if isinstance(v, AST):
                push(v)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, AST):
                        push(x)
        yield n


# Every node kind `_binding_rows` reads; any other node binds nothing.
_BINDING_NODES = (_pyast.Assign, _pyast.AnnAssign, _pyast.AugAssign, _pyast.NamedExpr,
                  _pyast.For, _pyast.AsyncFor, _pyast.comprehension, _pyast.withitem,
                  _pyast.ExceptHandler, _pyast.Global, _pyast.Nonlocal,
                  _pyast.FunctionDef, _pyast.AsyncFunctionDef, _pyast.Lambda,
                  _pyast.ClassDef) + ((_PATTERN_BASE,) if _PATTERN_BASE else ())


def _binding_rows(s: Any, out: List[Tuple[str, Any, int]]) -> None:
    """Append the (name, value-or-None, line) bindings node `s` itself
    makes (not its children's) to `out`."""
    if not isinstance(s, _BINDING_NODES):
        return
    ln = getattr(s, "lineno", 0)
    if isinstance(s, _pyast.Assign):
        for t in s.targets:
            if isinstance(t, _pyast.Name):
                out.append((t.id, s.value, ln))
            else:
                out += [(n, None, ln) for n in _target_names(t)]
    elif isinstance(s, _pyast.AnnAssign):
        if s.value is not None and isinstance(s.target, _pyast.Name):
            out.append((s.target.id, s.value, ln))
    elif isinstance(s, _pyast.AugAssign):
        out += [(n, None, ln) for n in _target_names(s.target)]
    elif isinstance(s, _pyast.NamedExpr):
        out.append((s.target.id, s.value, ln))
    elif isinstance(s, (_pyast.For, _pyast.AsyncFor, _pyast.comprehension)):
        out += [(n, None, ln) for n in _target_names(s.target)]
    elif isinstance(s, _pyast.withitem):
        if isinstance(s.optional_vars, _pyast.Name):
            out.append((s.optional_vars.id, s.context_expr, ln))
        else:
            out += [(n, None, ln) for n in _target_names(s.optional_vars)]
    elif isinstance(s, _pyast.ExceptHandler) and s.name:
        out.append((s.name, None, ln))
    elif isinstance(s, (_pyast.Global, _pyast.Nonlocal)):
        out += [(n, None, ln) for n in s.names]
    elif isinstance(s, (_pyast.FunctionDef, _pyast.AsyncFunctionDef)):
        out.append((s.name, None, ln))
        out += [(n, None, ln) for n in _param_names(s.args)]
    elif isinstance(s, _pyast.Lambda):
        out += [(n, None, ln) for n in _param_names(s.args)]
    elif isinstance(s, _pyast.ClassDef):
        out.append((s.name, None, ln))
    elif _PATTERN_BASE and isinstance(s, _PATTERN_BASE):
        for attr in ("name", "rest"):
            if getattr(s, attr, None):
                out.append((getattr(s, attr), None, ln))


class _DefIndex:
    """Everything the per-def consumers read off one scope's Python AST,
    built by ONE walk (audit F5, gaps round G7). The consumers used to
    re-walk the same node each: the binding tables, the call pass, the
    statement pass and the walrus scan — ~7 walks of every file.

    * `bindings`: every (name, value-or-None, line) binding inside the
      node — its own parameters when it is a function, then every
      binding form in its body, nested functions and lambdas included
      (their bodies are translated into the enclosing function, so their
      names are its names). Over a Module: every binding in the file.
    * `calls` / `stmts`: every Call / statement node, the node itself
      included, in `ast.walk` (breadth-first) order — the order the two
      passes always visited them in, so the output order is unchanged.
    * `has_walrus`: any `:=` at all; without one, the per-expression
      walrus scan can find nothing and is skipped."""
    __slots__ = ("bindings", "calls", "stmts", "has_walrus")

    def __init__(self, node: Any):
        out: List[Tuple[str, Any, int]] = []
        if isinstance(node, (_pyast.FunctionDef, _pyast.AsyncFunctionDef, _pyast.Lambda)):
            out += [(n, None, getattr(node, "lineno", 0)) for n in _param_names(node.args)]
        calls: List[Any] = []
        stmts: List[Any] = []
        walrus = False
        for s in _walk(node):
            if isinstance(s, _pyast.Call):
                calls.append(s)
            elif isinstance(s, _pyast.stmt):
                stmts.append(s)
            elif isinstance(s, _pyast.NamedExpr):
                walrus = True
            if s is not node:
                _binding_rows(s, out)
        self.bindings, self.calls, self.stmts, self.has_walrus = out, calls, stmts, walrus


def _exprs_in(x: Any) -> Iterator[Any]:
    """Expression nodes directly held by `x` — descending through the
    helper nodes that are neither statements nor expressions
    (`arguments`, `keyword`, `withitem`, `match_case`, `comprehension`),
    never into a statement or a pattern. A binding target field
    contributes only what the target EVALUATES (`_target_loads`)."""
    if isinstance(x, _pyast.expr):
        yield x
    elif isinstance(x, list):
        for e in x:
            yield from _exprs_in(e)
    elif isinstance(x, _pyast.AST) and not isinstance(x, _pyast.stmt) \
            and not (_PATTERN_BASE and isinstance(x, _PATTERN_BASE)):
        for field, child in _pyast.iter_fields(x):
            if field in _TARGET_FIELDS:
                yield from _target_loads(child)
                continue
            yield from _exprs_in(child)


def _stmt_expr_children(stmt: Any) -> Iterator[Any]:
    """The value expressions a statement evaluates: `for`'s iterable,
    `if`/`while`'s test, `assert`'s operands, `raise`'s exception,
    `match`'s subject and guards, a handler's exception type, a nested
    `def`'s decorators and defaults, and whatever a target evaluates
    (`d` and `f(x)` in `del d[f(x)]`). Bodies are statements and are
    visited on their own."""
    for field, child in _pyast.iter_fields(stmt):
        if field in _TARGET_FIELDS:
            yield from _target_loads(child)
            continue
        yield from _exprs_in(child)


def _target_loads(t: Any) -> Iterator[Any]:
    """The expressions a binding TARGET evaluates. Only a bare name is
    purely a binding site: `d[f(x)] += 1`, `del d[f(x)]`,
    `for d[f(x)] in xs` and `with cm as d[f(x)]` all evaluate `d` and
    `f(x)` first, and a sink there was silent because the whole target
    field was skipped as "names, not values" (BUGS.md BUG-027)."""
    if isinstance(t, list):
        for e in t:
            yield from _target_loads(e)
    elif isinstance(t, (_pyast.Tuple, _pyast.List)):
        yield from _target_loads(t.elts)
    elif isinstance(t, _pyast.Starred):
        yield from _target_loads(t.value)
    elif isinstance(t, (_pyast.Subscript, _pyast.Attribute)):
        yield from _expr_children(t)


def _expr_children(node: Any) -> Iterator[Any]:
    """Expression children of an expression, through helper nodes."""
    for child in _pyast.iter_child_nodes(node):
        if isinstance(child, _pyast.expr):
            yield child
        elif not isinstance(child, _pyast.stmt):
            yield from _expr_children(child)


class _NameScope:
    """The resolver `_local_constants` uses while computing itself: it
    knows which names the function binds (so a Name bound locally is
    never resolved through an import) and resolves nothing else."""
    def __init__(self, local_names):
        self.local_names = frozenset(local_names)

    def __call__(self, name: str) -> Optional[str]:
        return None


def _scope_has_content(stripped: Any) -> bool:
    """A module or class body worth a scope of its own: it makes a call,
    or it binds a string literal that is not a docstring. The second
    half is E0723's: `API_KEY = "AKIA..."` at module level is THE
    hardcoded-credential shape, and before scopes existed it was never
    scanned at all. A docstring alone adds nothing."""
    for s in _pyast.walk(stripped):
        if isinstance(s, _pyast.Call):
            return True
        if isinstance(s, _pyast.Expr) and _const_str(s.value) is not None:
            continue                      # a docstring / bare string statement
        if isinstance(s, (_pyast.Assign, _pyast.AnnAssign)) \
                and any(_const_str(c) is not None
                        or (isinstance(c, _pyast.Constant) and isinstance(c.value, bytes))
                        for c in _pyast.walk(s.value or s)):
            return True
    return False


class _ScopeStripper(_pyast.NodeTransformer):
    """Remove every `def` / `class` from a (copied) tree, leaving the
    statements that run when the enclosing scope itself executes."""
    def visit_FunctionDef(self, node):
        return None
    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef


def _sql_builder_of(func: Any, imp: "_Imports") -> Optional[str]:
    """The builder's bare name if `func` resolves, via imports, into one of
    `_SQL_EXPR_ROOTS` (`sqlalchemy.select`, `sqlalchemy.sql.text`,
    `sa.delete` through an alias); else None."""
    dotted = _callee_spelling(func, imp)
    if not dotted or "." not in dotted:
        return None
    if _module_root(dotted) not in _SQL_EXPR_ROOTS:
        return None
    return dotted.rpartition(".")[2]


def _is_sql_expression(node: _pyast.Call, imp: "_Imports",
                       scope: Any = None, self_name: Optional[str] = None) -> bool:
    """True if `node` is a SQL expression that carries no raw SQL string
    anywhere inside it.

    Rooted means: walk `select(t).where(x).order_by(y)` down its receiver
    chain to the first call. That root is accepted if it resolves through
    imports to a builder, or is a method on a name already known to hold a
    SQL expression (`self_name` lets a rebinding `stmt = stmt.where(x)`
    refer to itself during the fixpoint), or is the argument-free Table
    form. Then every raw-string entry point inside the whole expression
    must take a str literal, or a name bound only to one."""
    sql_names = getattr(scope, "sql_names", frozenset())
    lit_names = getattr(scope, "lit_names", frozenset())
    root = node
    while isinstance(root.func, _pyast.Attribute) \
            and isinstance(root.func.value, _pyast.Call):
        root = root.func.value
    rf = root.func
    ok = _sql_builder_of(rf, imp) in _SQL_EXPR_BUILDERS
    if not ok and isinstance(rf, _pyast.Attribute) \
            and isinstance(rf.value, (_pyast.Name, _pyast.Attribute)):
        recv = rf.value.id if isinstance(rf.value, _pyast.Name) else None
        if recv is not None and (recv in sql_names or recv == self_name):
            ok = True
        elif rf.attr in _SQL_TABLE_METHODS and not root.args:
            # A Table held in an attribute (`self.table.delete()`) is the
            # same argument-free form (audit C3); the rule never read the
            # receiver's name, only the absence of a raw argument.
            ok = True
    if not ok:
        return False

    def _raw_ok(a: Any) -> bool:
        return _raw_literal(a, scope)

    for sub in _pyast.walk(node):
        if not isinstance(sub, _pyast.Call):
            continue
        if _raw_sql_entry(sub, imp, scope) is not None:
            return False
        if isinstance(sub.func, _pyast.Attribute) and sub.func.attr == "text" \
                and (sub.args or sub.keywords) \
                and not (sub.args and _raw_ok(sub.args[0])):
            return False           # `db.text(...)`, any signature: no name clears
        if _sql_builder_of(sub.func, imp) in _SQL_RAW_ENTRY:
            if not _raw_ok(sub.args[0] if sub.args else None):
                return False
        elif isinstance(sub.func, _pyast.Attribute) \
                and sub.func.attr in _SQL_RAW_METHODS:
            strs = sub.args[1:] if sub.func.attr == "with_hint" else sub.args
            if not all(_raw_ok(a) for a in strs):
                return False
        elif ((isinstance(sub.func, _pyast.Attribute)
               and sub.func.attr in _SQL_STR_CLAUSE_METHODS)
              or _sql_builder_of(sub.func, imp) == "select") \
                and any(_is_str_shaped(a) for a in sub.args):
            return False           # `select(t).order_by(f"{col} DESC")` (PM-7)
    return True


def _raw_literal(a: Any, scope: Any = None) -> bool:
    """A str literal, or a name bound only to str literals."""
    return _const_str(a) is not None or (
        isinstance(a, _pyast.Name) and a.id in getattr(scope, "lit_names", ()))


def _is_str_shaped(node: Any) -> bool:
    """A str BUILT at runtime: an f-string with an interpolation, a `+`
    chain with a str literal among non-literal parts, `"..." % x`,
    `"...".format(...)` / `"...".join(...)`. Shape only, no type
    inference: a bare name or a call result is not str-shaped."""
    if isinstance(node, _pyast.JoinedStr):
        return any(isinstance(v, _pyast.FormattedValue) for v in node.values)
    if isinstance(node, _pyast.BinOp) and isinstance(node.op, _pyast.Add):
        leaves: List[Any] = []
        stack = [node]
        while stack:
            x = stack.pop()
            if isinstance(x, _pyast.BinOp) and isinstance(x.op, _pyast.Add):
                stack += [x.left, x.right]
            else:
                leaves.append(x)
        return any(_const_str(x) is not None or isinstance(x, _pyast.JoinedStr)
                   for x in leaves) \
            and not all(_const_str(x) is not None for x in leaves)
    if isinstance(node, _pyast.BinOp) and isinstance(node.op, _pyast.Mod):
        return _const_str(node.left) is not None
    return isinstance(node, _pyast.Call) \
        and isinstance(node.func, _pyast.Attribute) \
        and node.func.attr in ("format", "join") \
        and _const_str(node.func.value) is not None


# One `%` conversion in a format literal (`%s`, `%(name)r`, `%-10d`, `%%`).
_PCT_CONV = re.compile(r"%(?:\([^)]*\))?[-#0 +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?[a-zA-Z%]")


# Argument shapes that cannot be SQL text: `draw.text((x, y), s)`.
_NOT_TEXT = (_pyast.Tuple, _pyast.List, _pyast.Set, _pyast.Dict)


def _raw_sql_entry(call: _pyast.Call, imp: "_Imports",
                   scope: Any = None) -> Optional[Tuple[Any, str]]:
    """`(judged argument, match kind)` when `call` enters a NON-literal
    raw SQL string (see `_SQL_TEXT_ENTRY`), else None."""
    func = call.func
    judged, kind = None, None
    if _sql_builder_of(func, imp) in _SQL_TEXT_ENTRY:
        kind = "qualified"
    elif isinstance(func, _pyast.Attribute) and func.attr == "text" \
            and len(call.args) + len(call.keywords or []) == 1:
        # SQLAlchemy's `text(text)` takes the one string and nothing else;
        # a `.text(x, y, c)` or `.text(q, max_results=n)` is some other
        # API's signature (a canvas, a search client: 3 corpus sites).
        # Residual: SQLAlchemy 1.x `db.text(sql, bindparams=...)` outside
        # an executor or builder chain (inside one it still sanctions
        # nothing — `_is_sql_expression`).
        kind = "method"
    if kind is not None:
        judged = call.args[0] if call.args else next(
            (kw.value for kw in call.keywords or [] if kw.arg == "text"), None)
        if judged is None or isinstance(judged, _NOT_TEXT) or (
                isinstance(judged, _pyast.Constant)
                and not isinstance(judged.value, str)):
            return None
    elif isinstance(func, _pyast.Attribute) and func.attr in _SQL_STR_ENTRY_METHODS:
        judged = next((a for a in call.args if _is_str_shaped(a)), None)
        kind = "method"
    if judged is None or _raw_literal(judged, scope):
        return None
    return judged, kind


def _assign_bindings(binds: List[Tuple[str, Any, int]]) -> Dict[str, List[Any]]:
    """name -> every value bound to it, by ANY binding form; None stands
    for a form whose value the translator cannot see (a parameter, an
    augmented assignment, a for-target ...) and disqualifies the name in
    every consumer."""
    out: Dict[str, List[Any]] = {}
    for name, value, _ln in binds:
        out.setdefault(name, []).append(value)
    return out


def _is_none_const(v: Any) -> bool:
    return isinstance(v, _pyast.Constant) and v.value is None


def _sql_expression_names(binds: List[Tuple[str, Any, int]], imp: "_Imports",
                          module_lits: Optional[Dict[str, Tuple[str, int]]] = None
                          ) -> Tuple[Set[str], Set[str]]:
    """(names holding a SQL expression, names bound only to a str literal).

    The first is a least fixpoint that ALLOWS self-reference but REQUIRES
    an anchor: a name qualifies when at least one binding is a SQL
    expression with no reference to the name, and every binding is one
    when the name may refer to itself. So `stmt = select(t)` followed by
    `stmt = stmt.where(x)` qualifies, and a parameter-only chain
    (`a = b.where(); b = a.where()`) never does — there is no anchor, and
    a name still clears nothing. A binding that fails the raw-string check
    disqualifies the name outright, in every later round.

    A `stmt = None` sentinel before the real binding is ignored: executing
    None is a TypeError, not a query. Every other non-call binding —
    including the unresolved forms `_DefIndex.bindings` reports as None —
    still disqualifies. A module-level literal constant the function
    never rebinds counts as a literal-bound name."""
    binds = _assign_bindings(binds)
    lit = {n for n, vs in binds.items()
           if vs and all(_const_str(v) is not None for v in vs)}
    lit |= {n for n in (module_lits or {}) if n not in binds}
    binds = {n: [v for v in vs if not _is_none_const(v)]
             for n, vs in binds.items()}
    sql: Set[str] = set()
    changed = True
    while changed:
        changed = False
        scope = _FnScope({}, sql, lit)
        for n, vs in binds.items():
            if n in sql or not vs \
                    or not all(isinstance(v, _pyast.Call) for v in vs):
                continue
            anchored = any(_is_sql_expression(v, imp, scope) for v in vs)
            closed = all(_is_sql_expression(v, imp, scope, self_name=n) for v in vs)
            if anchored and closed:
                sql.add(n)
                changed = True
    return sql, lit


# Builtins that DEFEAT sound static analysis -> always UNPROVABLE.
DYNAMIC_BUILTINS: Dict[str, str] = {
    "eval": "eval", "exec": "exec", "compile": "compile",
    "__import__": "dynamic_import",
    "globals": "reflection", "locals": "reflection", "vars": "reflection",
}
# getattr/setattr/delattr are dynamic ONLY when the attribute name is not a
# constant; handled specially in the visitor.
DYNAMIC_ATTR_BUILTINS = {"getattr", "setattr", "delattr"}

# Imports that are pure (CPU only, no capability) -> resolvable, no effect.
#
# SOUNDNESS AUDIT (P0.1): every entry below must perform NO I/O at module or
# call scope. Three former entries were removed because they CAN do I/O and
# were therefore unsound to trust wholesale:
#   * pprint   -> pprint.pprint/pp write to stdout  (now CAP_BY_QUALIFIED: log)
#   * warnings -> warnings.warn writes to stderr     (now CAP_BY_QUALIFIED: log)
#   * codecs   -> codecs.open opens a file           (now CAP_BY_QUALIFIED: fs)
# A bogus "dataclass" entry (not a real stdlib module; the module is
# "dataclasses") was also removed. Any *other* call into these modules now
# degrades to UNPROVABLE rather than being silently cleared.
#
# PURE_MODULE_CITATIONS gives the per-module justification (machine-readable
# provenance, surfaced via mapping_table()/the /pymap audit endpoint).
PURE_MODULE_CITATIONS: Dict[str, str] = {
    "math": "CPython Lib/math: pure C math, no I/O",
    "cmath": "complex math, no I/O",
    "json": "encode/decode in memory; file I/O happens on a caller-supplied fp (its own open() is gated)",
    "re": "regex compile/match over in-memory strings",
    "collections": "container datatypes, in-memory only",
    "itertools": "iterator algebra, in-memory only",
    "functools": "higher-order helpers (reduce/lru_cache), no I/O",
    "dataclasses": "class codegen at def time, no I/O",
    "typing": "type hints, erased at runtime, no I/O",
    "string": "string constants/templates/Formatter, no I/O",
    "decimal": "fixed-point arithmetic, no I/O",
    "fractions": "rational arithmetic, no I/O",
    "statistics": "numeric reductions over in-memory data",
    "operator": "operator functions, no I/O",
    "copy": "shallow/deep object copy, no I/O",
    "enum": "enumeration types, no I/O",
    "abc": "abstract base class machinery, no I/O",
    "numbers": "numeric tower ABCs, no I/O",
    "heapq": "heap algorithms over in-memory lists",
    "bisect": "binary search over in-memory sequences",
    "array": "typed array container; fromfile/tofile are object METHODS (UNPROVABLE), not module calls",
    "textwrap": "string wrapping/filling, no I/O",
    "base64": "byte<->ascii transforms in memory",
    "binascii": "binary/ascii conversions in memory",
    "hashlib": "cryptographic digests over in-memory bytes",
    "hmac": "keyed-hash MAC over in-memory bytes",
    "struct": "binary packing/unpacking in memory",
    "unicodedata": "Unicode database lookups, no I/O",
    "html": "HTML escaping/parsing of in-memory strings",
    "difflib": "sequence diffing in memory",
    "keyword": "Python keyword predicates, no I/O",
    "token": "tokenizer constants, no I/O",
    "graphlib": "topological sort over in-memory graph",
    "types": "dynamic type construction helpers, no I/O",
    "contextlib": "context-manager utilities; do not themselves perform I/O",
    "weakref": "weak references, no I/O",
}
PURE_MODULES: Set[str] = set(PURE_MODULE_CITATIONS)

# Pure builtins -> resolvable, no capability.
PURE_BUILTINS: Set[str] = {
    "len", "range", "str", "int", "float", "bool", "complex", "list", "dict",
    "set", "frozenset", "tuple", "bytes", "bytearray", "memoryview",
    "enumerate", "zip", "map", "filter", "sorted", "reversed", "sum", "min",
    "max", "abs", "round", "isinstance", "issubclass", "hasattr", "repr",
    "format", "ord", "chr", "hex", "oct", "bin", "divmod", "pow", "all",
    "any", "iter", "next", "type", "id", "hash", "callable", "slice",
    "object", "super", "property", "staticmethod", "classmethod", "ascii",
}

# NOTE (P0.2): the former PURE_METHODS allowlist (pragmatic mode) was DELETED.
# It cleared an unknown object's method call (e.g. `.append()`) as pure based on
# the method NAME alone, with no proof of the receiver's type. That is unsound:
# trap_04's `AuditLog.append()` opens a file and writes to disk, yet was being
# certified PROVEN_CLEAN. A method on an object of unresolved type is now ALWAYS
# UNPROVABLE. Soundness is the product; this allowlist is never coming back.


def _module_root(dotted: str) -> str:
    return dotted.split(".", 1)[0]


class _Imports:
    """Resolves a local name used in a Call back to a dotted module path or
    builtin, using the file's import statements."""
    def __init__(self):
        self.alias_to_path: Dict[str, str] = {}    # local name -> dotted path
        self.fromimport: Dict[str, str] = {}       # local name -> module.attr
        # A local name bound by two imports to DIFFERENT targets
        # (`try: import cPickle as pickle` / `except: import pickle`) is
        # ambiguous. It resolves to a candidate that is a SINK if any
        # candidate is one, and otherwise to nothing, so a builder or
        # sanitizer reached through it clears nothing: a sink if ANY
        # candidate is a sink, sanctioned only if ALL are. Resolving it to
        # nothing outright silenced every sink behind the py2/lxml
        # fallback idiom (BUG-033).
        self.ambiguous: Set[str] = set()
        # local name -> every (is_from_import, target) bound to it, in order
        self.candidates: Dict[str, List[Tuple[bool, str]]] = {}

    def _bind(self, table: Dict[str, str], local: str, target: str):
        prev = table.get(local)
        other = (self.fromimport if table is self.alias_to_path
                 else self.alias_to_path).get(local)
        if (prev is not None and prev != target) or other is not None:
            self.ambiguous.add(local)
        table[local] = target
        cand = (table is self.fromimport, target)
        seen = self.candidates.setdefault(local, [])
        if cand not in seen:
            seen.append(cand)

    @staticmethod
    def _first_sink(dotted: List[str]) -> Optional[str]:
        for d in dotted:
            if d in SINK_BY_QUALIFIED or d in SINK_GUARDS:
                return d
        return None

    def add_import(self, node: _pyast.Import):
        for a in node.names:
            self._bind(self.alias_to_path, a.asname or _module_root(a.name), a.name)

    def add_importfrom(self, node: _pyast.ImportFrom):
        mod = node.module or ""
        for a in node.names:
            self._bind(self.fromimport, a.asname or a.name,
                       (mod + "." + a.name) if mod else a.name)

    def resolve_attr(self, value_name: str, attr: str) -> Optional[str]:
        """`value_name.attr` -> dotted path using import aliases."""
        if value_name in self.ambiguous:
            return self._first_sink([t + "." + attr for _f, t
                                     in self.candidates[value_name]])
        base = self.alias_to_path.get(value_name)
        if base is not None:
            return base + "." + attr
        if value_name in self.fromimport:        # from x import y; y.attr
            return self.fromimport[value_name] + "." + attr
        return None

    def resolve_name(self, name: str) -> Optional[str]:
        """bare `name(...)` -> dotted path if it came from a `from` import."""
        if name in self.ambiguous:
            return self._first_sink([t for is_from, t
                                     in self.candidates[name] if is_from])
        return self.fromimport.get(name)


def _const_str(node: Any) -> Optional[str]:
    if isinstance(node, _pyast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _scalar_text(node: Any) -> Optional[str]:
    """The text a str/int/float literal renders as (`LIMIT = 10` is "10"
    in an f-string), or None. bytes and None are not text."""
    if isinstance(node, _pyast.Constant) and isinstance(node.value, (str, int, float)):
        return node.value if isinstance(node.value, str) else str(node.value)
    return None


# ----------------------------------------------------------------------
# EXPRESSION TRANSLATION
# ----------------------------------------------------------------------
# The detectors in `aether.passes.detector_specs` judge argument SHAPES:
# a fixed StringLit passes, a `+` concatenation is refused, a sanctioned
# wrapper call passes, an unknown expression is refused. Translating
# Python expressions into exactly those shapes is what lets the untouched
# Aether detectors run on Python.
#
# Anything not modeled becomes `PyExpr`, a kind no rule knows. `_arg_reason`
# falls through to `rule.default` for it — REFUSED, not cleared. That is the
# same direction as the UNPROVABLE discipline above: never assume clean.

def _pos(node: Any, fallback: int = 0) -> Dict[str, int]:
    return {"line": getattr(node, "lineno", fallback),
            "column": getattr(node, "col_offset", 0) + 1}


def _translated_calls(node: Any) -> Iterator[Dict[str, Any]]:
    """Every translated `Call` dict inside `node`, itself included."""
    stack = [node]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            if x.get("kind") == "Call":
                yield x
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)


def _demote_raw_entries(node: Any):
    """Un-name every raw-SQL-entry sink inside `node` (see `_call_expr`):
    an executor that judges the same value reports the flow once."""
    for c in _translated_calls(node):
        if c.pop("raw_entry", False):
            c["func"]["name"] = "py:" + str(c.pop("callee", "text"))
            c.pop("match", None)


def _fix_bound_flows(stmts: List[Dict[str, Any]]):
    """Two one-finding-per-flow fixes over a scope's translated statements,
    from ONE walk of them (the second set never names a call the first
    fix renames: a raw entry is never spelled `exec`/`eval`).

    `stmt = text(f"..."); session.execute(stmt)`: the executor judges
    `stmt` and fires (a name bound to a raw entry is never a safe name),
    so the entry in the binding is the same flow — one finding, at the
    executor, as before the entry became a sink itself.

    `code = compile(src, ...)` then `exec(code)`: `_sink_match` drops the
    exec (`_bound_compile`), so the compile() is the one finding — and its
    result IS executed, so it rates `builtin`, as `exec(compile(...))`
    does (BUG-030), not the floor of a compile() nobody runs."""
    executed: Set[str] = set()
    ran: Set[str] = set()
    for c in _translated_calls(stmts):
        fn = c["func"]["name"]
        if fn in ("sqlQuery", "sqlExec", "py:exec", "py:eval") and c.get("args") \
                and c["args"][0].get("kind") == "Ident":
            if fn in ("py:exec", "py:eval"):
                ran.add(c["args"][0]["name"])
            elif not c.get("raw_entry"):
                executed.add(c["args"][0]["name"])
    if not executed and not ran:
        return
    for s in stmts:
        if s.get("kind") == "Let" and s.get("name") in executed:
            _demote_raw_entries(s.get("value"))
    for s in stmts:
        if s.get("kind") == "Let" and s.get("name") in ran:
            v = s.get("value") or {}
            if v.get("kind") == "Call" and v.get("match") == "builtin_compile":
                v["match"] = "builtin"


def _concat(parts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Left-nested `+` tree over `parts` (>=1)."""
    out = parts[0]
    for p in parts[1:]:
        out = {"kind": "BinOp", "op": "+", "left": out, "right": p}
    return out


# Deepest expression the translator will nest. The detectors walk the IR
# recursively (two frames per level), so an expression the frontend CAN
# translate can still overflow a detector; capping here makes the limit
# the frontend's, deterministic, and reported — a scope that hits it gets
# an `unprovable` `too_deep` region and keeps every other finding.
_MAX_EXPR_DEPTH = 200


def _expr(node: Any, imp: "_Imports",
          safe_xml: Optional[Set[str]] = None,
          resolver: Optional[Any] = None) -> Dict[str, Any]:
    """One Python expression -> one Aether expression node. Total: always
    returns a dict, never None. Depth-capped through the scope's counter
    (see `_MAX_EXPR_DEPTH`); without a scope there is nothing to count."""
    if resolver is None or not hasattr(resolver, "depth"):
        return _expr_inner(node, imp, safe_xml, resolver)
    resolver.depth += 1
    try:
        if resolver.depth > _MAX_EXPR_DEPTH:
            resolver.too_deep = True
            return {"kind": "PyExpr", "py": "TooDeep"}
        return _expr_inner(node, imp, safe_xml, resolver)
    finally:
        resolver.depth -= 1


def _expr_inner(node: Any, imp: "_Imports",
                safe_xml: Optional[Set[str]] = None,
                resolver: Optional[Any] = None) -> Dict[str, Any]:
    if isinstance(node, _pyast.Constant):
        if isinstance(node.value, str):
            # `pos` is load-bearing: E0723 anchors on the literal itself,
            # and a finding with no line is useless to a fix-loop.
            return {"kind": "StringLit", "value": node.value, "pos": _pos(node)}
        if isinstance(node.value, bytes):
            # A bytes literal is not a str to any argument rule (it stays
            # an opaque PyExpr, judged as before), but a credential in
            # `b"AKIA..."` is as committed as one in a str (audit B9). The
            # decoded text rides along under `parts`, where only the
            # literal scan (E0723) walks; latin-1 maps every byte 1:1.
            return {"kind": "PyExpr", "py": "Constant",
                    "parts": [{"kind": "StringLit",
                               "value": node.value.decode("latin-1"),
                               "pos": _pos(node)}]}
        return {"kind": "PyExpr", "py": "Constant"}
    if isinstance(node, _pyast.Name):
        # A module-level constant bound exactly once, to a str literal,
        # and never rebound anywhere in the module IS that literal at
        # every read site (`conn.execute(_CREATE_TABLE)`). Inlined rather
        # than re-bound per function so the safe-name pass needs no
        # extra rule; `synthetic` tells E0723 the literal is not written
        # at this position (it is reported once, at its definition).
        lits = getattr(resolver, "module_lits", None)
        if lits and node.id in lits \
                and node.id not in getattr(resolver, "local_names", ()):
            return {"kind": "StringLit", "value": lits[node.id][0],
                    "pos": _pos(node), "synthetic": True}
        # The same for a module-level name bound once to a sanctioned
        # call — `Q = text("... :id")`, `Q = sql.SQL("...").format(...)`:
        # it reads as that wrapper, argument-free (audit C3). The call
        # itself is judged once, where it is written.
        mod = getattr(resolver, "module", None)
        if mod is not None and node.id in mod.values \
                and node.id not in getattr(resolver, "local_names", ()):
            w = _sanctioned_value(mod.values[node.id], imp)
            if w is not None:
                return _py_wrapper(w, [], node)
        return {"kind": "Ident", "name": node.id}
    if isinstance(node, _pyast.Await):
        # `await conn.execute(q)` IS the call — 603 sink calls in
        # bench/framework_scan sat behind an await and were invisible
        # because Await translated to an opaque leaf (BUG-012).
        return _expr(node.value, imp, safe_xml, resolver)
    if isinstance(node, (_pyast.Yield, _pyast.YieldFrom)):
        if node.value is None:
            return {"kind": "PyExpr", "py": "Yield"}
        return _expr(node.value, imp, safe_xml, resolver)
    if isinstance(node, _pyast.NamedExpr):
        # The binding is emitted as a `Let` by the statement walk
        # (`_FnVisitor._walrus_lets`), which carries the value once.
        return {"kind": "PyExpr", "py": "NamedExpr"}
    if isinstance(node, _pyast.BinOp):
        # `a + b` is concatenation; `"fmt" % x` builds a dynamic string and
        # is the same hazard, so it gets the same shape.
        if isinstance(node.op, _pyast.Add):
            return {"kind": "BinOp", "op": "+",
                    "left": _expr(node.left, imp, safe_xml, resolver), "right": _expr(node.right, imp, safe_xml, resolver)}
        if isinstance(node.op, _pyast.Mod) and _const_str(node.left) is not None:
            right = _expr(node.right, imp, safe_xml, resolver)
            if any(c not in ("%s", "%%") for c in _PCT_CONV.findall(node.left.value)):
                # `"ls %r" % shlex.quote(x)`: a conversion other than %s
                # re-renders the value (repr adds quotes the shell reads),
                # so it is not the value as a piece — opaque, carried.
                right = {"kind": "PyExpr", "py": "ModArg", "parts": [right]}
            return _concat([_expr(node.left, imp, safe_xml, resolver), right])
        return {"kind": "PyExpr", "py": "BinOp"}
    if isinstance(node, _pyast.JoinedStr):
        # f-string. With >=1 FormattedValue it is a dynamic string — the
        # dominant modern injection shape — so it reaches the rules as a
        # concatenation. With none it is just a literal.
        parts: List[Dict[str, Any]] = []
        dynamic = False
        for v in node.values:
            if isinstance(v, _pyast.FormattedValue):
                dynamic = True
                part = _expr(v.value, imp, safe_xml, resolver)
                if v.conversion != -1 or v.format_spec is not None:
                    # `{q!r}` / `{q:>10}` renders something other than the
                    # value itself (repr re-quotes it), so the value is not
                    # a piece a rule may accept — opaque, still carried.
                    part = {"kind": "PyExpr", "py": "FormattedValue", "parts": [part]}
                parts.append(part)
            elif isinstance(v, _pyast.Constant) and isinstance(v.value, str):
                # Positioned: E0723 inside an f-string reported line 0
                # (audit B10). Python < 3.12 gives each part the
                # f-string's own start; 3.12+ the part's.
                parts.append({"kind": "StringLit", "value": v.value,
                              "pos": _pos(v, getattr(node, "lineno", 0))})
            else:
                dynamic = True
                parts.append({"kind": "PyExpr", "py": "FormattedValue"})
        if not parts:
            return {"kind": "StringLit", "value": "", "pos": _pos(node)}
        if not dynamic:
            return {"kind": "StringLit", "pos": _pos(node),
                    "value": "".join(p.get("value", "") for p in parts)}
        return _concat(parts)
    if isinstance(node, _pyast.Call):
        return _call_expr(node, imp, safe_xml, resolver)
    if isinstance(node, _pyast.Attribute):
        # `self.Q` / `cls.Q` where the enclosing class binds `Q` once to a
        # literal and nothing in the file assigns an attribute `Q`: that
        # literal, like a module-level constant (audit C3).
        clits = getattr(resolver, "class_lits", None)
        if clits and isinstance(node.value, _pyast.Name) \
                and node.value.id in ("self", "cls") and node.attr in clits:
            return {"kind": "StringLit", "value": clits[node.attr][0],
                    "pos": _pos(node), "synthetic": True}
        # `subprocess.run(...).returncode`, `requests.get(u).text` — an
        # attribute READ of a call result. Not a call itself, so it used
        # to translate to a bare PyExpr and the call inside it vanished:
        # the bench's `run_shell_bound_elsewhere` went silent while the
        # same shape without `.returncode` was flagged. `walk` descends
        # dict values, so carrying the base is enough to find it again.
        return {"kind": "PyExpr", "py": "Attribute",
                "base": _expr(node.value, imp, safe_xml, resolver)}
    # Every other expression is opaque to the rules (`PyExpr` matches no
    # row, so an argument of this shape is REFUSED) — but its CHILDREN are
    # translated and carried, so a sink call inside `x or []`, `a == b`,
    # `not f()`, `c if t else e`, `f()[0]`, a list/dict/tuple display, a
    # lambda body or a comprehension is still found by `walk`. Parking
    # them under `parts` is enough: `_arg_reason` reads only `args[i]`,
    # so a carried call can never be mistaken for a wrapper argument.
    out: Dict[str, Any] = {"kind": "PyExpr", "py": type(node).__name__}
    parts = [_expr(c, imp, safe_xml, resolver) for c in _expr_children(node)]
    if parts:
        out["parts"] = parts
    return out


def _dotted_of(node: Any, imp: "_Imports",
               resolver: Optional[Any] = None) -> Optional[str]:
    """The dotted spelling of a VALUE expression, or None if it cannot be
    positively identified. `resolver` maps a local name to the single
    value bound to it; without one, a bare Name is unresolved — which,
    per the guard contract, means unsafe."""
    if isinstance(node, _pyast.Constant):
        return repr(node.value) if node.value is None else str(node.value)
    if isinstance(node, _pyast.Attribute) and isinstance(node.value, _pyast.Name):
        return imp.resolve_attr(node.value.id, node.attr) or \
            (node.value.id + "." + node.attr)
    if isinstance(node, _pyast.Name):
        if resolver is not None:
            d = resolver(node.id)
            if d is not None:
                return d
            if node.id in getattr(resolver, "local_names", ()):
                return None          # bound locally, not to one known value
        # `from yaml import SafeLoader` then `Loader=SafeLoader`: the same
        # import table the sink resolver trusts; a name two imports bind
        # differently is ambiguous there and resolves to nothing.
        return imp.resolve_name(node.id)
    return None


def _local_constants(binds: List[Tuple[str, Any, int]], imp: "_Imports") -> Dict[str, str]:
    """local name -> the single dotted value bound to it in this function.

    A name bound more than once to DIFFERENT values is omitted, and so is
    one whose value could not be identified: ambiguity must over-flag,
    never resolve. This only ever feeds `safe_values`, and a WRONG
    resolution to a safe value IS a false accept — which is the whole of
    BUG-004 — so the bar is a single unique binding, or nothing.

    Straight-line: no control flow is modeled, so a name assigned in one
    branch and read in another counts as one binding. That direction is
    safe here precisely because disagreement, not agreement, is what
    disqualifies a name. Every binding form counts (`_DefIndex.bindings`): a
    parameter, a for-target or a `+=` is a binding to an unknown value,
    so `if loader is None: loader = yaml.SafeLoader` no longer proves a
    caller-supplied loader safe (BUG-012)."""
    names = _NameScope(n for n, _v, _l in binds)
    seen: Dict[str, Set[str]] = {}
    for name, value, _ln in binds:
        val = _dotted_of(value, imp, names) if value is not None else None
        seen.setdefault(name, set()).add(val if val is not None
                                         else "<unresolved>")
    return {n: next(iter(vs)) for n, vs in seen.items()
            if len(vs) == 1 and "<unresolved>" not in vs}


def _guard_verdict(call: _pyast.Call, guard: "Guard", imp: "_Imports",
                   resolver: Optional[Any] = None) -> bool:
    """True if this call IS a sink under `guard`."""
    node = None
    # A `**kwargs` splat (or a `*args` splat that could reach the
    # positional slot) may carry the deciding keyword and cannot be
    # resolved; the guard contract says unresolvable means SINK, so
    # `subprocess.run(cmd, **opts)` is no longer read as "shell absent".
    splat = any(kw.arg is None for kw in call.keywords or []) or (
        guard.arg_index is not None
        and any(isinstance(a, _pyast.Starred) for a in call.args))
    for kw in call.keywords or []:
        if kw.arg == guard.keyword:
            node = kw.value
            break
    if node is None and guard.arg_index is not None \
            and len(call.args) > guard.arg_index:
        node = call.args[guard.arg_index]
    if node is None:
        return True if splat else guard.absent_is_sink
    dotted = _dotted_of(node, imp, resolver)
    if dotted is None:
        return True                      # unresolved -> sink, never safe
    if dotted in guard.safe_values:
        return False
    if guard.sink_values:
        return dotted in guard.sink_values
    return True                          # not positively sanctioned -> sink


# XML parser constructors whose keyword arguments carry the XXE guard.
# lxml only: `xml.sax.make_parser` was listed here until iteration 53, but
# it has no `resolve_entities` keyword (TypeError at runtime), so the only
# stdlib shape that cleared E0727 was one that cannot execute.
_XML_PARSER_CTORS = {"lxml.etree.XMLParser"}
# The keyword each hardening option must carry to count as OFF. Only
# `resolve_entities` is required; the others, when present, must be at
# their safe value — `XMLParser(resolve_entities=False, load_dtd=True,
# no_network=False)` still fetches an external DTD (measured, iteration
# 53), so it is not the sanctioned exit.
_XML_PARSER_SAFE_KWS = {"resolve_entities": False, "no_network": True,
                        "load_dtd": False, "dtd_validation": False}


def _safe_xml_parser_names(binds: List[Tuple[str, Any, int]], imp: "_Imports") -> Set[str]:
    """Names bound to an XML parser constructed with entity resolution
    OFF. Passing one of these disarms the XXE sink.

    This is the GUARD-BOUND-ELSEWHERE class: in `lxml_repro.py` the
    vulnerable and safe call sites are byte-identical
    (`etree.fromstring(raw, parser)`) and the safety lives in a DIFFERENT
    statement, in a keyword of the parser. E0727 inspects argument 0, so
    no argument-shape rule can ever see it — resolving it is the
    frontend's job, because the frontend is where the Python-specific
    knowledge belongs.

    Conservative: a name is safe only when EVERY binding to it in this
    function is an explicit `resolve_entities=False`. Rebound, computed,
    keyword absent, or constructor unknown — not safe.

    This is the parser-shaped instance of `_local_constants`' discipline:
    resolve a local name only when every binding agrees, and treat
    disagreement as unsafe. Kept separate because the value being
    resolved is a keyword INSIDE the bound call rather than the bound
    value itself; merging them would change what each one accepts, and a
    tidier guard that accepts more is a worse guard."""
    bound: Dict[str, List[bool]] = {}
    for name, value, _ln in binds:
        # EVERY binding of the name is recorded — a rebinding to anything
        # but a hardened constructor is False and disqualifies it. The
        # old loop skipped non-constructor bindings, so `parser = make()`
        # after the safe constructor still disarmed the sink (BUG-012).
        off = False
        if isinstance(value, _pyast.Call) \
                and _callee_spelling(value.func, imp) in _XML_PARSER_CTORS \
                and not any(kw.arg is None for kw in value.keywords or []):
            kws = {kw.arg: kw.value for kw in value.keywords or []}
            off = "resolve_entities" in kws and all(
                isinstance(kws[k], _pyast.Constant) and kws[k].value is want
                for k, want in _XML_PARSER_SAFE_KWS.items() if k in kws)
        bound.setdefault(name, []).append(off)
    return {n for n, flags in bound.items() if flags and all(flags)}


def _argv_shell_payload(call: _pyast.Call) -> Optional[Any]:
    """The third element of a literal `["bash", "-c", <cmd>]` argv — the
    string the shell parses, so the argument E0714 judges — or None."""
    if not call.args or not isinstance(call.args[0], (_pyast.List, _pyast.Tuple)):
        return None
    elts = call.args[0].elts
    if len(elts) < 3:
        return None
    if _const_str(elts[0]) in _ARGV_SHELLS and _const_str(elts[1]) in _ARGV_SHELL_FLAGS:
        return elts[2]
    return None


def _argv_display(node: Any, resolver: Any, hops: int = 0) -> Optional[List[Any]]:
    """The words of an argv value: a list/tuple display, a name bound once
    to one, or a `+` of those whose other operands are opaque words
    (`["git"] + args`). None when it cannot be read."""
    if isinstance(node, _pyast.Name) and hops < _MAX_ALIAS_HOPS:
        v = getattr(resolver, "value_of", lambda _n: None)(node.id)
        return _argv_display(v, resolver, hops + 1) if v is not None else None
    if isinstance(node, (_pyast.List, _pyast.Tuple)):
        return list(node.elts)
    if isinstance(node, _pyast.BinOp) and isinstance(node.op, _pyast.Add):
        left = _argv_display(node.left, resolver, hops)
        if left is None:
            return None
        return left + (_argv_display(node.right, resolver, hops) or [node.right])
    return None


def _argv_word(node: Any, resolver: Any) -> Optional[str]:
    """The literal text of one argv word, or None when it is not literal.
    A constant of any type is literal (`-n 5` cannot be an option); so is
    a name bound only to str literals, here or once at module level."""
    if isinstance(node, _pyast.Constant):
        return str(node.value)
    if not isinstance(node, _pyast.Name):
        return None
    if node.id in getattr(resolver, "local_names", ()):
        v = _const_str(getattr(resolver, "value_of", lambda _n: None)(node.id))
        if v is not None:
            return v
        return "" if node.id in getattr(resolver, "lit_names", ()) else None
    lits = getattr(resolver, "module_lits", None) or {}
    return lits[node.id][0] if node.id in lits else None


def _argv_option_payload(call: _pyast.Call, dotted: Optional[str],
                         resolver: Any) -> Optional[Any]:
    """The first non-literal argv word a code-option program receives
    before a literal `--` (`_ARGV_CODE_OPTIONS`) — the argument E0714
    judges — or None. The argv is a subprocess runner's first argument
    (or `args=`) or an exec-form runner's positional arguments."""
    if dotted in _ARGV_POSITIONAL_RUNNERS:
        words: Optional[List[Any]] = list(call.args)
    else:
        guard = SINK_GUARDS.get(dotted or "")
        if guard is None or guard.sink_name != "shellExec":
            return None
        a0 = call.args[0] if call.args else next(
            (k.value for k in call.keywords or [] if k.arg == "args"), None)
        words = _argv_display(a0, resolver) if a0 is not None else None
    if not words:
        return None
    prog = _argv_word(words[0], resolver)
    prog = re.split(r"[/\\]", prog)[-1] if prog else ""
    if prog.lower().endswith(".exe"):
        prog = prog[:-4]
    if prog not in _ARGV_CODE_OPTIONS:
        return None
    for w in words[1:]:
        text = _argv_word(w, resolver)
        if text == "--" and prog not in _ARGV_NO_TERMINATOR:
            return None
        if text is None:
            return w.value if isinstance(w, _pyast.Starred) else w
    return None


def _sink_name(call: _pyast.Call, imp: "_Imports",
               safe_xml: Optional[Set[str]] = None,
               resolver: Optional[Any] = None) -> Optional[str]:
    """The Aether sink name for this Python call, or None."""
    m = _sink_match(call, imp, safe_xml, resolver)
    return m[0] if m is not None else None


def _sink_match(call: _pyast.Call, imp: "_Imports",
                safe_xml: Optional[Set[str]] = None,
                resolver: Optional[Any] = None) -> Optional[Tuple[str, str]]:
    """`(sink name, how it was matched)` for this Python call, or None.

    The second element is one of `SINK_MATCH_KINDS`, and it is the whole
    evidence the confidence axis has: the ways this function names a
    sink are not equally certain (a dotted path resolved through the
    imports vs. a bare method name on an unresolved receiver — q5's
    sanctioned over-flag). It is decided HERE, where the branch is
    taken, rather than re-derived by the caller, which would be a second
    copy of this dispatch free to disagree with it.
    `transpiler/aether/confidence.py` rates the kinds; `mapping_table()`
    publishes the vocabulary."""
    dotted = _callee_spelling(call.func, imp, resolver)
    if dotted is None:
        return None
    guard = SINK_GUARDS.get(dotted)
    if guard is not None:
        judged_call = (_instance_ctor(call.func, resolver) if guard.on_receiver
                       else None) or call
        if _guard_verdict(judged_call, guard, imp, resolver):
            return guard.sink_name, "guard"
        # `subprocess.run(["bash", "-c", cmd])`: no shell= — the argv
        # exit — but the argv IS a shell invocation (BUGS.md BUG-021).
        # `_call_expr` puts the third element in the judged slot.
        if guard.sink_name == "shellExec" and _argv_shell_payload(call) is not None:
            return guard.sink_name, "argv"
        # `subprocess.run(["git", "clone", url])`: no shell, but a word the
        # input supplies can be an option that runs code (gaps round G6).
        if guard.sink_name == "shellExec" \
                and _argv_option_payload(call, dotted, resolver) is not None:
            return guard.sink_name, "argv"
        return None
    if dotted in _ARGV_POSITIONAL_RUNNERS:
        return (("shellExec", "argv")
                if _argv_option_payload(call, dotted, resolver) is not None else None)
    sink = SINK_BY_QUALIFIED.get(dotted)
    if sink == "parseXml":
        safe = safe_xml or set()
        # A parser bound with entity resolution OFF disarms the sink,
        # passed positionally (`fromstring(raw, parser)`) or, as lxml's
        # own docs spell it, as `parser=parser`. Same value, other slot;
        # the keyword form fired until iteration 53 while E0727's hint
        # promised the binding would clear it. The `parser` keyword only:
        # a hardened parser under another keyword (`base_url=parser`) is
        # not the parser the call uses, and a `**kwargs` splat is not a
        # named parser — neither clears.
        for a in call.args[1:]:
            if isinstance(a, _pyast.Name) and a.id in safe:
                return None      # entity resolution explicitly disabled
        for kw in call.keywords or []:
            if kw.arg == "parser" and isinstance(kw.value, _pyast.Name) \
                    and kw.value.id in safe:
                return None
        # A stdlib parser handed no parser argument never expands an
        # external entity (E0727's own callee text); what remains is the
        # Expat-version DoS clause, rated below lxml (audit C7).
        return sink, ("stdlib_xml" if _stdlib_xml_no_parser(dotted, call)
                      else "qualified")
    if sink is not None:
        return sink, "qualified"
    # A non-literal raw SQL string entering the expression language is the
    # sink itself, wherever it appears (audit B4/B5, `_SQL_TEXT_ENTRY`).
    raw = _raw_sql_entry(call, imp, resolver)
    if raw is not None:
        return "sqlQuery", raw[1]
    builtin = None
    if dotted.startswith("builtins.") and dotted[9:] in SINK_BY_BUILTIN:
        # `builtins.eval(x)`, `from builtins import exec as run`,
        # `getattr(builtins, "exec")`, `__builtins__["eval"]` — the module
        # spelled out, so no local binding can be what is called. Decided
        # BEFORE the by-method rows: `getattr(builtins, "exec")(src)` is
        # the builtin, not the SQL `exec` method (audit B10).
        builtin = dotted[9:]
    elif dotted in SINK_BY_BUILTIN and isinstance(call.func, _pyast.Name):
        # Bare names only: `_callee_spelling` falls back to the ATTRIBUTE
        # name for an unresolved receiver, and `session.exec(stmt)` is
        # not the builtin (it reported E0731 until this guard; the
        # by-name SQL row still judges it). An alias (`e = eval; e(x)`)
        # spells the builtin through `_alias_target`; then it is the
        # builtin's own name that must not be shadowed.
        if call.func.id in getattr(resolver, "shadowed", ()) \
                and call.func.id == dotted:
            return None          # a local def / binding, not the builtin
        if call.func.id != dotted and dotted in getattr(resolver, "shadowed", ()):
            return None
        builtin = dotted
    if builtin is not None:
        # `exec(compile(src, "<s>", "exec"))`: the source text enters at
        # compile(), which is judged on its own; the outer call runs a
        # code object, not text — one finding per line, not two.
        if builtin in ("exec", "eval") and call.args \
                and isinstance(call.args[0], _pyast.Call) \
                and _sink_name(call.args[0], imp, safe_xml, resolver) == "evalCode":
            return None
        # `code = compile(src, ...)` then `exec(code)`: the same flow bound
        # through a local name — reported once, at the compile(), which
        # `_fix_bound_flows` rates as executed (audit C7).
        if builtin in ("exec", "eval") and call.args \
                and _bound_compile(call.args[0], imp, safe_xml, resolver) is not None:
            return None
        # `compile(src, fn, "exec", ast.PyCF_ONLY_AST)` returns an AST, not
        # code — the same as `ast.parse`, which is no sink (audit C7).
        if builtin == "compile" and _only_ast(call):
            return None
        # `compile` gets its own kind: it builds a code object and runs
        # nothing, and 4 of the 8 measured corpus sites call it without
        # running the result — three syntax-checking linters and a
        # round-trip test (bench/framework_scan/REPORT.md §8). Wrapped in
        # exec/eval it is re-rated in `_call_expr` (BUG-030).
        return SINK_BY_BUILTIN[builtin], (
            "builtin_compile" if builtin == "compile" else "builtin")
    # Method on an unresolved receiver: over-flag by name (see doctrine note).
    #
    # No parameterized-query special case. `cur.execute("... id = ?", params)`
    # is ALREADY clean because argument 0 is a StringLit and `_SQL_RULE` has
    # no literal_bans — the rule clears it without help. The recognizer that
    # used to live here cleared ANY two-argument execute, so
    # `cur.execute("SELECT ... " + name, extra)` went silent: params do not
    # launder a concatenated query. BUGS.md BUG-004.
    attr = _method_name(call.func, resolver)
    if attr is not None and attr in SINK_BY_METHOD:
        if attr == "extra" and _extra_sql_arg(call, resolver) is None:
            return None          # every spliced string is a literal
        if _own_class_method(call.func, attr, resolver):
            return None          # this file's own class's method (audit C4)
        if attr == "from_string" and _sandboxed_env(call.func, imp, resolver):
            return None          # Jinja's documented control (audit C4)
        return SINK_BY_METHOD[attr], "method"
    return None


def _stdlib_xml_no_parser(dotted: str, call: _pyast.Call) -> bool:
    """A stdlib XML parse that CANNOT be handed a parser: `xml.sax.*` and
    `expatbuilder` take none; ElementTree, minidom and pulldom take one as
    the second positional or `parser=`, and have none here. A `*`/`**`
    splat may carry one, so it does not count as none."""
    if dotted.startswith(("xml.sax.", "xml.dom.expatbuilder.")):
        return True
    if not dotted.startswith(("xml.etree.", "xml.dom.minidom.", "xml.dom.pulldom.")):
        return False
    return len(call.args) < 2 \
        and not any(isinstance(a, _pyast.Starred) for a in call.args) \
        and not any(kw.arg in (None, "parser") for kw in call.keywords or [])


def _only_ast(call: _pyast.Call) -> bool:
    """`compile(...)` whose flags name `PyCF_ONLY_AST` (4th positional or
    `flags=`): whatever else is OR-ed in, the result is an AST."""
    flags = call.args[3] if len(call.args) > 3 else next(
        (kw.value for kw in call.keywords or [] if kw.arg == "flags"), None)
    return flags is not None and any(
        (isinstance(n, _pyast.Attribute) and n.attr == "PyCF_ONLY_AST")
        or (isinstance(n, _pyast.Name) and n.id == "PyCF_ONLY_AST")
        for n in _pyast.walk(flags))


def _bound_compile(arg: Any, imp: "_Imports", safe_xml: Optional[Set[str]],
                   resolver: Any) -> Optional[_pyast.Call]:
    """The `compile(...)` sink call a LOCAL name is bound to once, or None."""
    if not isinstance(arg, _pyast.Name) \
            or arg.id not in getattr(resolver, "local_names", ()):
        return None
    v = getattr(resolver, "value_of", lambda _n: None)(arg.id)
    if isinstance(v, _pyast.Call):
        m = _sink_match(v, imp, safe_xml, resolver)
        if m is not None and m[1] == "builtin_compile":
            return v
    return None


def _own_class_method(func: Any, attr: str, resolver: Any) -> bool:
    """`Cls.attr(...)` or `Cls(...).attr(...)` (directly or through a name
    bound once) where `Cls` is a class this file defines, once, with its
    own `def attr` — that method is the callee, and its body is judged
    where it is defined. Not `self.attr`: a subclass may override it."""
    if not isinstance(func, _pyast.Attribute):
        return False
    methods = getattr(getattr(resolver, "module", None), "class_methods", {})
    recv: Any = func.value
    if isinstance(recv, _pyast.Name) and recv.id in methods \
            and recv.id not in getattr(resolver, "local_names", ()):
        return attr in methods[recv.id]
    ctor = _instance_ctor(func, resolver)
    return ctor is not None and isinstance(ctor.func, _pyast.Name) \
        and ctor.func.id in methods \
        and ctor.func.id not in getattr(resolver, "local_names", ()) \
        and attr in methods[ctor.func.id]


# Jinja's sandbox (`jinja2.sandbox`): its documented way to render a
# template a user authored.
_SANDBOXED_ENVS = frozenset({"jinja2.sandbox.SandboxedEnvironment",
                             "jinja2.sandbox.ImmutableSandboxedEnvironment"})


def _sandboxed_env(func: Any, imp: "_Imports", resolver: Any) -> bool:
    """`.from_string` on a SandboxedEnvironment constructed right there or
    bound once to a name."""
    ctor = _instance_ctor(func, resolver)
    return ctor is not None and _callee_spelling(ctor.func, imp, resolver) in _SANDBOXED_ENVS


def _method_name(func: Any, resolver: Optional[Any] = None) -> Optional[str]:
    """The method a call spells, for the by-name sink rule: `x.execute`,
    `getattr(x, "execute")` with a literal attribute, or a bare name the
    function bound once to a bound method (`ex = cur.execute; ex(q)`).
    Lookups can only ADD a finding, so a wrong resolution over-flags."""
    if isinstance(func, _pyast.Attribute):
        return func.attr
    if isinstance(func, _pyast.Call) and isinstance(func.func, _pyast.Name) \
            and func.func.id == "getattr" and len(func.args) >= 2 \
            and _const_str(func.args[1]) is not None:
        return _const_str(func.args[1])
    if isinstance(func, _pyast.Name) and resolver is not None:
        d = resolver(func.id)
        if d and "." in d:
            return d.rpartition(".")[2]
    return None


def _call_expr(node: _pyast.Call, imp: "_Imports",
               safe_xml: Optional[Set[str]] = None,
               resolver: Optional[Any] = None) -> Dict[str, Any]:
    """A Python call as an Aether Call node, named so the existing
    detectors recognize it: the Aether SINK name when it maps to one, the
    Aether WRAPPER name when it is a sanctioned exit, otherwise its Python
    spelling under a `py:` prefix (which matches neither, so an argument
    that is one of these calls is refused — the flag-more direction).

    The prefix is load-bearing. Without it the raw Python spelling shares
    a namespace with Aether's sink names, and any method that happens to
    be spelled like one becomes a sink WITHOUT passing through the
    mapping table: `self.redirect(uri)` fired E0718 and
    `self.renderTemplate(x)` fired E0719 on that collision alone. Found
    by the PyPI scan (`bench/pypi_scan/`), where it accounted for most of
    tornado's and websockets' E0718 hits. It over-flags rather than
    misses, so it is not a soundness bug — but an unmapped, unaudited
    sink is invisible to `mapping_table()`, which is exactly what the
    auditable-surface design exists to prevent."""
    node = _unwrap_indirect(node, imp, resolver, safe_xml)
    dotted = _callee_spelling(node.func, imp, resolver)
    joined = _join_expr(node, dotted, imp, safe_xml, resolver)
    if joined is not None:
        return joined
    sink = _sink_match(node, imp, safe_xml, resolver)
    origin = _url_builder(node, dotted, resolver)
    name = ((sink[0] if sink else None)
            or SANITIZER_BY_QUALIFIED.get(dotted or "")
            # A SQLAlchemy expression is a parameterized query by
            # construction; naming it as E0713's wrapper is the same move
            # SANITIZER_BY_QUALIFIED makes for `shlex.quote` (BUG-010).
            # psycopg's `sql` composition is the same (audit C3).
            or ("sqlBind" if _is_sql_expression(node, imp, resolver)
                or _psycopg_composed(node, imp, resolver) else None)
            # `os.path.join(base, secure_filename(name))` (BUG-039).
            or ("safeJoin" if _sanitized_path_join(node, dotted, imp, resolver) else None)
            or ("safeRedirect" if origin == "resolved" else None)
            or ("py:" + dotted if dotted else "<expr>"))
    args = list(node.args)
    kws = list(node.keywords or [])
    if name == "shellExec":
        payload = _argv_shell_payload(node)
        if payload is None and sink is not None and sink[1] == "argv":
            # A code-option program's non-literal word (G6) is judged.
            payload = _argv_option_payload(node, dotted, resolver)
        if payload is not None:
            # `["bash", "-c", cmd]`: the shell parses `cmd`, so `cmd` is
            # the judged argument (BUG-021). The literal program name and
            # flag carry nothing worth keeping.
            args = [payload]
    raw = _raw_sql_entry(node, imp, resolver) if name == "sqlQuery" else None
    if raw is not None:
        # The raw string is the judged slot; the rest is carried.
        args = [raw[0]] + [a for a in args if a is not raw[0]]
    elif name == "sqlQuery" and _method_name(node.func, resolver) == "extra":
        args = [_extra_sql_arg(node, resolver)]
    carried: List[Any] = []
    if sink is not None and sink[1] == "guard" and not args and kws:
        # A guard's deciding keyword is not the payload: in keyword-only
        # `from_template(template_format="jinja2", template=t)` the
        # literal "jinja2" must not take the judged slot and clear it.
        # Still translated (carried), so nothing inside it goes unseen.
        g = SINK_GUARDS.get(dotted or "")
        if g is not None and g.keyword and any(k.arg != g.keyword for k in kws):
            carried = [k for k in kws if k.arg == g.keyword]
            kws = [k for k in kws if k.arg != g.keyword]
    if not args and kws:
        # A sink fed keyword-only — `yaml.load(stream=raw)`,
        # `cur.execute(query=q)`, `subprocess.run(args=cmd, shell=True)` —
        # has nothing in the positional slot the rules judge, so it was
        # silent. The keyword values take the positional slots, in
        # order. Flag-more: whatever lands in `args[0]` is refused unless
        # it is a literal or a sanctioned wrapper (BUG-012).
        args = [kw.value for kw in kws]
        kws = []
    # `py` marks a frontend-emitted Call. A wrapper call written in Aether
    # carries its pinning template/base/host in args[0] and `_arg_reason`
    # judges it (BUG-020); one the frontend named — `shlex.quote(x)` as
    # shellArg, a SQLAlchemy expression as sqlBind — has no such slot,
    # and the mark exempts it.
    out: Dict[str, Any] = {"kind": "Call",
                           "func": {"kind": "Ident", "name": name},
                           "args": [_expr(a, imp, safe_xml, resolver) for a in args],
                           "pos": _pos(node), "py": True}
    if origin == "unresolved":
        # `request.url_for(...)` on a receiver no import names: an own-
        # origin builder by its method name only. Not cleared (a name
        # clears nothing, q5); the confidence axis rates a finding whose
        # argument holds one at the floor (`argument_shape_demoted`).
        out["own_origin"] = True
    if name == "redirect" and args and isinstance(args[0], _pyast.Name) \
            and _redirect_guarded(resolver, args[0].id, getattr(node, "lineno", 0)):
        # Django's documented check dominates this redirect (audit C2).
        out["args"][0] = _py_wrapper("safeRedirect", [out["args"][0]], args[0])
    if sink is not None:
        # How this call was named a sink, for the confidence axis. Only
        # a sink carries it — a wrapper or a `py:` spelling matched
        # nothing, so there is nothing to be more or less sure about.
        out["match"] = sink[1]
        if dotted:
            # WHICH Python callee it was: the spelling `_callee_spelling`
            # resolved — a dotted import path on a `qualified`/`guard`/
            # `argv` match, the builtin name on `builtin`; on a `method`
            # match, the bare method name for a plain-variable receiver
            # (`execute` for `cur.execute`), the attribute path as written
            # for a chained one (`self.conn.execute`), and the resolved
            # dotted path for an imported receiver. The Aether
            # name is one sink for every spelling that maps to it, and
            # for E0727 the spellings are not one hazard: ElementTree
            # without a parser argument never expands an external entity
            # (a caller's parser is used as given, BUG-031), `lxml.etree`
            # before 5.0 did by default. The spec row picks its wording by this
            # (`LiteralOrWrapperSpec.callee_text`) and puts it in
            # `extra.callee`; detection never reads it.
            out["callee"] = dotted
    elif dotted in ("exec", "eval") and isinstance(node.func, _pyast.Name) \
            and node.func.id not in getattr(resolver, "shadowed", ()) \
            and out["args"] and out["args"][0].get("match") == "builtin_compile":
        # `exec(compile(src, ...))`: `_sink_match` reports this line once,
        # on the inner compile() that holds the source text. That source
        # IS executed, so the finding is as certain as a bare `exec(src)`,
        # not the floor rating of a compile() whose result nobody runs —
        # which hid real execution behind `--min-confidence 0.9`
        # (BUGS.md BUG-030).
        out["args"][0]["match"] = "builtin"
    # Keyword values are carried too, so `f(k=cur.execute(q))` is found by
    # `walk`; `_arg_reason` reads only `args[i]`, so nothing here is ever
    # judged as the sink's own argument (BUG-012).
    kw_vals = [_expr(kw.value, imp, safe_xml, resolver) for kw in kws + carried]
    if kw_vals:
        out["kwargs"] = kw_vals
    if raw is not None:
        out["raw_entry"] = True
    if name in ("sqlQuery", "sqlExec") and out["args"]:
        # One finding per flow: a raw-string entry inside this executor's
        # judged argument is what makes the executor fire (the argument is
        # then never a sanctioned expression), so the executor's finding
        # stands for it — `session.execute(text(f"..."))` reports once, at
        # the executor, exactly as before the entry became a sink itself.
        _demote_raw_entries(out["args"][0])
    # A call used as a RECEIVER is still a call: `open(p).read()`,
    # `conn.cursor().execute(sql)`, `requests.get(u).json()`. Chaining is
    # idiomatic Python, and dropping the receiver loses the sink entirely
    # (measured: `return open(base + name).read()` reported nothing).
    # `walk` descends dict values, so parking it under a key is enough for
    # every detector to find it; `_arg_reason` only ever reads `args[i]`,
    # so it cannot mistake a receiver for an argument.
    if isinstance(node.func, _pyast.Attribute) and \
            isinstance(node.func.value, _pyast.Call):
        out["recv"] = _call_expr(node.func.value, imp, safe_xml, resolver)
    return out


def _callee_spelling(func: Any, imp: "_Imports",
                     resolver: Optional[Any] = None) -> Optional[str]:
    """Dotted path for a call target, using the file's imports; falls back
    to the bare attribute/name as written. With a `resolver`, a bare name
    the function bound once to a dotted value (`run = subprocess.run`)
    spells that value; `getattr(obj, "m")(...)` with a literal attribute
    spells `obj.m`."""
    if isinstance(func, _pyast.Name):
        d = imp.resolve_name(func.id)
        if d is None and resolver is not None:
            d = resolver(func.id)
        if d is None:
            # `e = eval`, module-level `system = os.system`, `run =
            # importlib.import_module("os").system`: follow single-binding
            # aliases to the function they name (audit B8).
            t = _alias_target(func, imp, resolver)
            if t is not func:
                return (_callee_spelling(t, imp, resolver) if isinstance(t, _pyast.Attribute)
                        else imp.resolve_name(t.id) or t.id)
        return d or func.id
    if isinstance(func, _pyast.Subscript) and isinstance(func.value, _pyast.Name) \
            and func.value.id == "__builtins__" and _const_str(func.slice) is not None:
        return "builtins." + _const_str(func.slice)       # __builtins__["eval"]
    if isinstance(func, _pyast.Call) and isinstance(func.func, _pyast.Name) \
            and func.func.id == "getattr" and len(func.args) >= 2 \
            and _const_str(func.args[1]) is not None:
        return _callee_spelling(
            _pyast.Attribute(value=func.args[0], attr=_const_str(func.args[1]),
                             ctx=_pyast.Load()), imp, resolver)
    if isinstance(func, _pyast.Attribute):
        if isinstance(func.value, (_pyast.Name, _pyast.Call)):
            return _attr_spelling(func.value, func.attr, imp, resolver) or func.attr
        if isinstance(func.value, _pyast.Attribute):
            # Chained module path: `import xml.sax` + `xml.sax.parseString(...)`
            # arrives as Attribute(Attribute(Name)). Resolving only one level
            # returned the bare method name, so the dotted entry never
            # matched — `xml.sax.parseString` was a confirmed MISS in the
            # bandit-oracle run while the `from xml.dom import minidom` form
            # of the same sink matched fine. Mirrors _FnVisitor._flatten_attr,
            # which the capability side has always done.
            parts, cur = [], func
            while isinstance(cur, _pyast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, _pyast.Name):
                base = imp.alias_to_path.get(cur.id, cur.id)
                # `import xml.sax` binds the ROOT name: alias_to_path["xml"]
                # is "xml.sax". Substituting there would yield
                # "xml.sax.sax.parseString". Substitute only for a real
                # rename (`import numpy as np`), where the bound name is not
                # the path's own root.
                if _module_root(base) == cur.id:
                    base = cur.id
                parts.append(base)
                return ".".join(reversed(parts))
        return func.attr
    return None


# How many single-binding hops an alias / partial / dispatch lookup
# follows. `a = b; b = a` must terminate; real code uses one or two.
_MAX_ALIAS_HOPS = 5


def _alias_target(node: Any, imp: "_Imports", resolver: Any) -> Any:
    """Follow a Name through single-binding aliases (`e = eval`,
    `system = os.system`) to the Name or Attribute it finally names.
    Stops at an imported name, at a name with no single visible value,
    and at anything that is not itself a Name/Attribute (a call result
    is not the callee that produced it)."""
    cur = node
    value_of = getattr(resolver, "value_of", None)
    for _ in range(_MAX_ALIAS_HOPS):
        if value_of is None or not isinstance(cur, _pyast.Name) \
                or imp.resolve_name(cur.id) is not None \
                or cur.id in imp.alias_to_path:
            break
        v = value_of(cur.id)
        if isinstance(v, _pyast.Attribute) or (
                isinstance(v, _pyast.Name) and v.id != cur.id):
            cur = v
        else:
            break
    return cur


def _dynamic_import_target(call: Any, imp: "_Imports",
                           resolver: Any = None) -> Optional[str]:
    """The module `importlib.import_module("<lit>")` / `__import__("<lit>")`
    returns, or None. `__import__("a.b")` returns `a` unless a fromlist
    is given — the same package the statement form would bind."""
    if not isinstance(call, _pyast.Call) or not call.args \
            or _const_str(call.args[0]) is None:
        return None
    name = _const_str(call.args[0])
    if isinstance(call.func, _pyast.Name) and call.func.id == "__import__":
        has_fromlist = len(call.args) >= 4 or any(
            kw.arg == "fromlist" for kw in call.keywords or [])
        return name if has_fromlist else _module_root(name)
    if _callee_spelling(call.func, imp, resolver) == "importlib.import_module":
        return name
    return None


def _qualified_row(dotted: str) -> bool:
    return dotted in SINK_BY_QUALIFIED or dotted in SINK_GUARDS


def _attr_spelling(recv: Any, attr: str, imp: "_Imports", resolver: Any = None,
                   hops: int = 0) -> Optional[str]:
    """Dotted path of `<recv>.attr` when the receiver can be named: an
    import alias (the historical rule, checked first), `__builtins__`, a
    literal `import_module`/`__import__` call, a constructor call whose
    `Ctor.attr` is a table row (`code.InteractiveInterpreter().runsource`),
    or a name bound once to any of those (`m = importlib.import_module(
    "os")`, module-level `interp = code.InteractiveConsole()`)."""
    if hops > _MAX_ALIAS_HOPS:
        return None
    if isinstance(recv, _pyast.Name):
        d = imp.resolve_attr(recv.id, attr)
        if d is not None:
            return d
        if recv.id == "__builtins__":
            return "builtins." + attr
        v = getattr(resolver, "value_of", lambda _n: None)(recv.id)
        if v is not None:
            return _attr_spelling(v, attr, imp, resolver, hops + 1)
        return None
    if isinstance(recv, _pyast.Call):
        mod = _dynamic_import_target(recv, imp, resolver)
        if mod is not None:
            return mod + "." + attr
        ctor = _callee_spelling(recv.func, imp, resolver)
        if ctor and _qualified_row(ctor + "." + attr):
            return ctor + "." + attr
        return None
    if isinstance(recv, _pyast.Attribute):
        d = _callee_spelling(recv, imp, resolver)
        return (d + "." + attr) if d and "." in d else None
    return None


def _instance_ctor(func: Any, resolver: Any = None) -> Optional[_pyast.Call]:
    """The constructor call a method is invoked on: `Ctor(...).m` directly,
    or through a name bound once to it."""
    if not isinstance(func, _pyast.Attribute):
        return None
    recv = func.value
    for _ in range(_MAX_ALIAS_HOPS):
        if not isinstance(recv, _pyast.Name):
            break
        recv = getattr(resolver, "value_of", lambda _n: None)(recv.id)
    return recv if isinstance(recv, _pyast.Call) else None


def _synth_call(func: Any, args: List[Any], keywords: List[Any],
                at: _pyast.Call) -> _pyast.Call:
    return _pyast.copy_location(
        _pyast.Call(func=func, args=list(args), keywords=list(keywords)), at)


def _unwrap_indirect(call: _pyast.Call, imp: "_Imports", resolver: Any = None,
                     safe_xml: Optional[Set[str]] = None) -> _pyast.Call:
    """The call a callable VALUE stands for (audit B8):
      * `functools.partial(f, *a, **k)(*b, **j)` — directly, or through a
        name bound once to the partial — is `f(*a, *b, **k, **j)`;
      * `table[k](...)` where `table` is a dict/list/tuple display (or a
        name bound once to one) is the call of the entry a literal key
        selects, else of ANY entry that is a sink — over-flag: dispatch
        through a table that holds `os.system` may reach it.
    Anything else is returned unchanged. Synthesized calls carry the
    outer call's position, so a finding lands where the call is made."""
    value_of = getattr(resolver, "value_of", lambda _n: None)
    for _ in range(_MAX_ALIAS_HOPS):
        f = call.func
        target = value_of(f.id) if isinstance(f, _pyast.Name) else f
        if isinstance(target, _pyast.Call) and target.args \
                and _callee_spelling(target.func, imp, resolver) in (
                    "functools.partial", "functools.partialmethod"):
            call = _synth_call(target.args[0], target.args[1:] + call.args,
                               list(target.keywords or []) + list(call.keywords or []),
                               call)
            continue
        if isinstance(f, _pyast.Subscript):
            table = f.value
            if isinstance(table, _pyast.Name):
                table = value_of(table.id)
            cands: List[Any] = []
            key = f.slice
            if isinstance(table, _pyast.Dict):
                cands = [v for k, v in zip(table.keys, table.values)
                         if k is not None and isinstance(key, _pyast.Constant)
                         and isinstance(k, _pyast.Constant) and k.value == key.value] \
                    or [v for v in table.values if v is not None]
            elif isinstance(table, (_pyast.List, _pyast.Tuple)):
                cands = list(table.elts)
                if isinstance(key, _pyast.Constant) and isinstance(key.value, int) \
                        and -len(cands) <= key.value < len(cands):
                    cands = [cands[key.value]]
            for c in cands:
                s = _synth_call(c, call.args, call.keywords or [], call)
                if _sink_match(s, imp, safe_xml, resolver) is not None:
                    return s
        break
    return call


# Django `QuerySet.extra`: the keywords (and positional slots, in
# signature order) whose strings are spliced into the SQL verbatim.
_EXTRA_SQL_SLOTS = (("select", 0), ("where", 1), ("tables", 3), ("order_by", 4))


def _extra_sql_arg(call: _pyast.Call, scope: Any = None) -> Optional[Any]:
    """The first non-literal SQL string handed to `.extra(...)`: an
    element of `where=`/`tables=`/`order_by=`, a value of `select=`, or
    the slot itself when it is not a display. None when every string is
    a literal (`params=` is the parameterized form and is not judged)."""
    kws = {kw.arg: kw.value for kw in call.keywords or [] if kw.arg}
    for name, idx in _EXTRA_SQL_SLOTS:
        v = kws.get(name, call.args[idx] if len(call.args) > idx else None)
        if v is None or _is_none_const(v):
            continue
        if isinstance(v, _pyast.Dict):
            elems = v.values
        elif isinstance(v, (_pyast.List, _pyast.Tuple, _pyast.Set)):
            elems = v.elts
        else:
            elems = [v]
        for e in elems:
            if not _raw_literal(e, scope):
                return e
    # A splat may carry `where=`; unresolvable means judged.
    for kw in call.keywords or []:
        if kw.arg is None:
            return kw.value
    return next((a for a in call.args if isinstance(a, _pyast.Starred)), None)


# ----------------------------------------------------------------------
# COMPOSED SANITIZED VALUES — precision rows of audit 2026-09-24 §C
# ----------------------------------------------------------------------

def _py_wrapper(name: str, args: List[Dict[str, Any]], at: Any) -> Dict[str, Any]:
    """A frontend-emitted wrapper call (`py`), as `_call_expr` builds for
    a SANITIZER_BY_QUALIFIED row."""
    return {"kind": "Call", "func": {"kind": "Ident", "name": name},
            "args": args, "pos": _pos(at), "py": True}


def _join_elements(arg: Any) -> Optional[Tuple[List[Any], List[Any]]]:
    """`(elements, carried)` of the iterable a `sep.join(...)` joins, when
    its elements can be named: a list/tuple display, a comprehension's
    element expression (once — every element has its shape), or a display
    / str literal repeated by `*` (`["%s"] * n`, `"?" * len(ids)`). The
    iterables, conditions and repeat counts are `carried`: translated so a
    call inside them is still found, never judged. None for anything else."""
    if isinstance(arg, (_pyast.List, _pyast.Tuple)):
        if any(isinstance(e, _pyast.Starred) for e in arg.elts):
            return None
        return list(arg.elts), []
    if isinstance(arg, (_pyast.GeneratorExp, _pyast.ListComp, _pyast.SetComp)):
        carried = [x for g in arg.generators for x in [g.iter] + list(g.ifs)]
        return [arg.elt], carried
    if isinstance(arg, _pyast.BinOp) and isinstance(arg.op, _pyast.Mult):
        for rep, count in ((arg.left, arg.right), (arg.right, arg.left)):
            if _const_str(rep) is not None:
                return [rep], [count]     # joining a str joins its characters
            if isinstance(rep, (_pyast.List, _pyast.Tuple)) \
                    and not any(isinstance(e, _pyast.Starred) for e in rep.elts):
                return list(rep.elts), [count]
    return None


def _interleave(pieces: List[Dict[str, Any]], sep: str, at: Any) -> Dict[str, Any]:
    """`p0 + sep + p1 + ...` — what `sep.join([p0, p1, ...])` builds. The
    separator is written once in the source, so only its first copy is a
    literal E0723 reports; the rest are `synthetic`."""
    parts: List[Dict[str, Any]] = []
    for i, p in enumerate(pieces):
        if i:
            lit = {"kind": "StringLit", "value": sep, "pos": _pos(at)}
            if i > 1:
                lit["synthetic"] = True
            parts.append(lit)
        parts.append(p)
    return _concat(parts)


def _join_expr(node: _pyast.Call, dotted: Optional[str], imp: "_Imports",
               safe_xml: Optional[Set[str]], resolver: Any) -> Optional[Dict[str, Any]]:
    """A string JOIN spelled as the concatenation it builds, so the rules
    judge its parts (audit C1/C3):

      * `" ".join(shlex.quote(a) for a in args)` is one quoted piece
        (`shellArg`) — accepted inside a command, refused as a whole one;
      * `",".join("?" * len(ids))` / `", ".join(["%s"] * n)` is literal
        text, so the IN-list placeholder string is a literal;
      * `shlex.join([<lit>, ..., *args])` is each literal element quoted
        as written and each other element a quoted piece — so a literal
        program is visible to the command rule. Any other `shlex.join`
        argument stays the `shellArg` row.

    None: not one of these shapes, translated as an ordinary call."""
    if node.keywords or len(node.args) != 1 \
            or isinstance(node.args[0], _pyast.Starred):
        return None
    arg = node.args[0]

    def e(x):
        return _expr(x, imp, safe_xml, resolver)
    if dotted == "shlex.join":
        if not isinstance(arg, (_pyast.List, _pyast.Tuple)) or not arg.elts:
            return None
        pieces = []
        for el in arg.elts:
            s = _const_str(el)
            if s is not None:
                pieces.append({"kind": "StringLit", "value": shlex.quote(s),
                               "pos": _pos(el)})
            else:
                inner = el.value if isinstance(el, _pyast.Starred) else el
                pieces.append(_py_wrapper("shellArg", [e(inner)], el))
        return _interleave(pieces, " ", node)
    func = node.func
    if not (isinstance(func, _pyast.Attribute) and func.attr == "join"):
        return None
    sep = _const_str(func.value)
    found = _join_elements(arg) if sep is not None else None
    if found is None or not found[0]:
        return None
    elems, carried = found
    out = _interleave([e(x) for x in elems], sep, func.value)
    if carried:
        out["carried"] = [e(c) for c in carried]
    return out


def _sanitized_path_join(node: _pyast.Call, dotted: Optional[str],
                         imp: "_Imports", resolver: Any) -> bool:
    """`os.path.join(<any>..., <safeJoin row call>)`: the last component is
    already a single safe name (`secure_filename` strips separators and
    `..`), so the result stays under the base — BUG-039. The base is the
    program's, the same judgement `_PATH_RULE` makes for `safeJoin(base,
    rel)`. A plain `os.path.join(base, user)` is not this."""
    if dotted not in ("os.path.join", "posixpath.join", "ntpath.join") \
            or len(node.args) < 2 or node.keywords \
            or any(isinstance(a, _pyast.Starred) for a in node.args):
        return False
    last = node.args[-1]
    return isinstance(last, _pyast.Call) and SANITIZER_BY_QUALIFIED.get(
        _callee_spelling(last.func, imp, resolver) or "") == "safeJoin"


# `request.url_for(name)` builds a URL on the request's own origin
# (Starlette/FastAPI). Resolved only when the receiver is a parameter
# annotated with one of these classes, through the imports.
_REQUEST_TYPES = frozenset({"fastapi.Request", "fastapi.requests.Request",
                            "starlette.requests.Request"})
_URL_BUILDER_METHODS = frozenset({"url_for", "url_path_for"})


def _url_builder(node: _pyast.Call, dotted: Optional[str],
                 resolver: Any) -> Optional[str]:
    """"resolved" for `request.url_for(...)` on a parameter annotated as a
    framework Request; "unresolved" for any other `.url_for(...)` /
    `.url_path_for(...)`, or a bare `url_for(...)` no import names; else
    None. Only "resolved" clears (it is named `safeRedirect`)."""
    func = node.func
    if isinstance(func, _pyast.Attribute) and func.attr in _URL_BUILDER_METHODS:
        if func.attr == "url_for" and isinstance(func.value, _pyast.Name) \
                and func.value.id in getattr(resolver, "request_params", ()):
            return "resolved"
        return "unresolved"
    if isinstance(func, _pyast.Name) and dotted == "url_for":
        return "unresolved"
    return None


# Django's documented redirect check (django.utils.http). `is_safe_url`
# is its pre-4.0 name.
_REDIRECT_CHECKS = frozenset({"django.utils.http.url_has_allowed_host_and_scheme",
                              "django.utils.http.is_safe_url"})


def _redirect_guards(fn_node: Any, bindings: List[Tuple[str, Any, int]],
                     imp: "_Imports", resolver: Any) -> List[Tuple[str, int, int]]:
    """`(name, first line, last line)`: a redirect to `name` within those
    lines is dominated by Django's allow-list check on `name`. Two shapes,
    both at the function's own statement level:

      * `if url_has_allowed_host_and_scheme(x, ...): ... redirect(x)` —
        the body of the passing branch;
      * `if not url_has_allowed_host_and_scheme(x, ...):` whose body ends
        in `return` / `raise` / `abort(...)`, or rebinds `x` only to str
        literals — every statement after it.

    Either way `x` may not be rebound where it is guarded; a check that
    only an `elif`, a loop or a nested block reaches guards nothing."""
    body = getattr(fn_node, "body", None) or []
    binds = [(n, ln) for n, _v, ln in bindings]
    end = getattr(fn_node, "end_lineno", None) or 10 ** 9
    out: List[Tuple[str, int, int]] = []

    def checked(test: Any) -> Optional[str]:
        if not (isinstance(test, _pyast.Call)
                and _callee_spelling(test.func, imp, resolver) in _REDIRECT_CHECKS):
            return None
        target = test.args[0] if test.args else next(
            (k.value for k in test.keywords or [] if k.arg == "url"), None)
        return target.id if isinstance(target, _pyast.Name) else None

    def rebound(name: str, lo: int, hi: int, skip: Any = None) -> bool:
        lits = {getattr(s, "lineno", 0) for s in _pyast.walk(skip)
                if isinstance(s, _pyast.Assign) and _const_str(s.value) is not None} \
            if skip is not None else set()
        return any(n == name and lo <= ln <= hi and ln not in lits for n, ln in binds)

    for st in body:
        if not isinstance(st, _pyast.If) or not st.body:
            continue
        lo, hi = st.body[0].lineno, getattr(st.body[-1], "end_lineno", st.body[-1].lineno)
        name = checked(st.test)
        if name is not None and not rebound(name, lo, hi):
            out.append((name, lo, hi))
            continue
        neg = st.test.operand if isinstance(st.test, _pyast.UnaryOp) \
            and isinstance(st.test.op, _pyast.Not) else None
        name = checked(neg)
        if name is None:
            continue
        last = st.body[-1]
        exits = isinstance(last, (_pyast.Return, _pyast.Raise)) or (
            isinstance(last, _pyast.Expr) and isinstance(last.value, _pyast.Call)
            and (_callee_spelling(last.value.func, imp, resolver) or "")
            .rpartition(".")[2] == "abort")
        resets = any(isinstance(s, _pyast.Assign) and len(s.targets) == 1
                     and isinstance(s.targets[0], _pyast.Name)
                     and s.targets[0].id == name for s in st.body)
        after = getattr(st, "end_lineno", st.lineno) + 1
        if (exits or resets) and not rebound(name, st.lineno, end, skip=st):
            out.append((name, after, end))
    return out


def _annotation_of(args: Any, name: str, imp: "_Imports") -> Optional[str]:
    """The dotted spelling of parameter `name`'s annotation, or None."""
    for a in [x for f in _PARAM_FIELDS for x in getattr(args, f, None) or []]:
        if a.arg == name and a.annotation is not None:
            return _dotted_of(a.annotation, imp)
    return None


def _redirect_guarded(resolver: Any, name: str, line: int) -> bool:
    return any(n == name and lo <= line <= hi
               for n, lo, hi in getattr(resolver, "redirect_guards", ()))


# psycopg's `sql` module (psycopg 3 and psycopg2 alike): composable SQL
# whose only raw text is `sql.SQL(<literal>)`; identifiers and values are
# quoted by the driver (`Identifier`, `Literal`, `Placeholder`).
_PSYCOPG_SQL_MODULES = ("psycopg2.sql.", "psycopg.sql.")
_PSYCOPG_QUOTED = frozenset({"Identifier", "Literal", "Placeholder"})


def _psycopg_composed(node: Any, imp: "_Imports", resolver: Any = None) -> bool:
    """True if `node` is a psycopg `sql` composition carrying no raw
    string: `sql.SQL("... {} ...").format(sql.Identifier(t), ...)`,
    `sql.SQL(", ").join(sql.Identifier(c) for c in cols)`, or one of the
    quoting constructors. `sql.SQL(x)` with a non-literal `x` anywhere
    makes the whole thing raw, and a format argument that is not itself
    such a composition (a plain value, a name) sanctions nothing."""
    if not isinstance(node, _pyast.Call):
        return False
    spelled = _callee_spelling(node.func, imp, resolver) or ""
    if spelled.startswith(_PSYCOPG_SQL_MODULES):
        leaf = spelled.rpartition(".")[2]
        if leaf in _PSYCOPG_QUOTED:
            return True
        if leaf == "SQL":
            return len(node.args) == 1 and not node.keywords \
                and _raw_literal(node.args[0], resolver)
        if leaf == "Composed":
            return len(node.args) == 1 and _psycopg_parts(node.args[0], imp, resolver)
        return False
    func = node.func
    if isinstance(func, _pyast.Attribute) and func.attr in ("format", "join") \
            and _psycopg_composed(func.value, imp, resolver):
        if func.attr == "join":
            return len(node.args) == 1 and not node.keywords \
                and _psycopg_parts(node.args[0], imp, resolver)
        return all(_psycopg_composed(v, imp, resolver)
                   for v in list(node.args) + [k.value for k in node.keywords or []])
    return False


def _sanctioned_value(v: Any, imp: "_Imports") -> Optional[str]:
    """The wrapper a module-level VALUE stands for — a sanitizer row call,
    a SQLAlchemy expression or a psycopg composition, judged with no
    local names (a module-level expression has none) — or None."""
    if not isinstance(v, _pyast.Call):
        return None
    w = SANITIZER_BY_QUALIFIED.get(_callee_spelling(v.func, imp) or "")
    if w is not None:
        return w
    if _is_sql_expression(v, imp) or _psycopg_composed(v, imp):
        return "sqlBind"
    return None


def _psycopg_parts(arg: Any, imp: "_Imports", resolver: Any) -> bool:
    found = _join_elements(arg)
    return found is not None and bool(found[0]) \
        and all(_psycopg_composed(x, imp, resolver) for x in found[0])


def _classify_dotted(dotted: str) -> Optional[Tuple[str, str]]:
    """Return (capability, verb) for a dotted call path, or None if not a
    known capability. Checks exact qualified entry, then module root, then
    os.exec* prefix."""
    if dotted in CAP_BY_QUALIFIED:
        return (CAP_BY_QUALIFIED[dotted], dotted.split(".")[-1])
    root = _module_root(dotted)
    if root in CAP_BY_MODULE:
        return (CAP_BY_MODULE[root], dotted.split(".")[-1])
    if dotted.startswith("os.exec") or dotted.startswith("os.spawn"):
        return ("process", dotted.split(".")[-1])
    return None


class _FnVisitor:
    """Walk one function body and emit (effects, local_calls, unprovable)."""
    def __init__(self, imports: _Imports, local_fns: Set[str], fn_name: str,
                 fn_line: int, safe_xml: Optional[Set[str]] = None,
                 consts: Optional[Dict[str, str]] = None,
                 sql_names: Optional[Set[str]] = None,
                 lit_names: Optional[Set[str]] = None,
                 local_names: Optional[Set[str]] = None,
                 module_lits: Optional[Dict[str, Tuple[str, int]]] = None,
                 values: Optional[Dict[str, Any]] = None,
                 module: Optional[_ModuleFacts] = None):
        self.imp = imports
        # Names bound to an XML parser with entity resolution disabled —
        # the guard lives in a different statement than the parse call.
        self.safe_xml: Set[str] = safe_xml or set()
        # local name -> the single dotted value bound to it (Task 2).
        # Empty here means every bare Name is unresolved, which the guard
        # contract reads as SINK — the sound default.
        self.consts: Dict[str, str] = consts or {}
        # What the expression translator resolves against. Empty sets mean
        # no name holds a SQL expression or a literal — the sound default.
        self.scope = _FnScope(self.consts, sql_names or (), lit_names or (),
                              local_names or (), module_lits, local_fns,
                              values, module)
        self.local_fns = local_fns
        self.fn_name = fn_name
        self.fn_line = fn_line
        self.effects: List[Dict[str, Any]] = []
        self.local_calls: List[str] = []
        self.stmts: List[Dict[str, Any]] = []
        self.unprovable: List[Dict[str, Any]] = []
        self._eff_seen: Set[Tuple[str, str, Optional[str]]] = set()
        self._unp_seen: Set[str] = set()
        # False when the scope holds no `:=` anywhere (`_DefIndex`).
        self.has_walrus = True

    def _add_effect(self, cap: str, verb: str, arg: Optional[str]):
        key = (cap, verb, arg)
        if key in self._eff_seen:
            return
        self._eff_seen.add(key)
        eff: Dict[str, Any] = {"path": [cap, verb]}
        if arg is not None:
            eff["arg"] = {"kind": "StringLit", "value": arg}
        self.effects.append(eff)

    def _add_unprovable(self, reason: str, construct: str, detail: str,
                        line: int):
        key = reason + ":" + construct
        if key in self._unp_seen:
            return
        self._unp_seen.add(key)
        self.unprovable.append({
            "fn": self.fn_name, "line": self.fn_line, "granularity": "function",
            "callee": construct, "reason": reason, "detail": detail,
            "construct_line": line, "needs": "human review or a runtime check",
        })

    def _e(self, node: Any) -> Dict[str, Any]:
        return _expr(node, self.imp, self.safe_xml, self.scope)

    def seed_bindings(self, bindings: List[Tuple[str, Any, int]]):
        """One unresolved binding per name bound by a form whose value the
        translator cannot see — a parameter, `x += ...`, a for-target, a
        tuple unpack, an except-as, a `global` — emitted as an `Assign`
        (the kind the safe-name pass reads alongside `Let`) whose value
        is an opaque `PyExpr`. A name with such a binding can never prove
        literal-only, whatever else it is bound to (BUG-012)."""
        seen: Set[str] = set()
        for name, value, line in bindings:
            if value is None and name not in seen:
                seen.add(name)
                self.stmts.append({"kind": "Assign", "name": name,
                                   "value": {"kind": "PyExpr", "py": "Binding"},
                                   "pos": {"line": line, "column": 1}})

    def _walrus_lets(self, expr: Any):
        """`(q := build())` binds a name inside an expression; the binding
        is a `Let` carrying the value ONCE — `_expr` translates the
        NamedExpr itself to an opaque leaf."""
        if not self.has_walrus:
            return
        for sub in _pyast.walk(expr):
            if isinstance(sub, _pyast.NamedExpr):
                self.stmts.append({"kind": "Let", "name": sub.target.id,
                                   "value": self._e(sub.value),
                                   "pos": _pos(sub, self.fn_line)})

    def visit_stmt(self, stmt: Any):
        """Translate ONE statement into what the detectors read: `Let`
        nodes for the bindings the safe-name pass consumes, and every
        value expression the statement evaluates, in place.

        Total over statement kinds. The old walk translated four
        (`Assign`, `Expr(Call)`, `Return`, `With`) and dropped the rest,
        so a sink in a `for` iterable, an `if` test, a `yield`, an
        `assert`, a tuple-target assignment, an augmented assignment or
        a decorator was never seen — 89 sink calls on the framework
        corpus, plus 603 behind `await` (BUG-012). Control flow is still
        not modeled, exactly as in the Aether passes themselves; what
        changed is that no POSITION hides a value."""
        if isinstance(stmt, (_pyast.Assign, _pyast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, _pyast.Assign) else [stmt.target]
            if stmt.value is None:          # a bare annotation binds nothing
                return
            if _is_none_const(stmt.value):
                # `stmt = None` before `stmt = select(...)`: a None can
                # never reach a sink as a query, path or command
                # (executing it is a TypeError), so it is not a binding
                # the safe-name pass needs to see. Every other constant
                # kind still binds an opaque value.
                return
            self._walrus_lets(stmt.value)
            val = self._e(stmt.value)
            carried = False
            for t in targets:
                if isinstance(t, _pyast.Name):
                    # `a = b = f()`: the value travels with the first name;
                    # later names get an opaque binding (never a cleared one).
                    self.stmts.append({"kind": "Let", "name": t.id,
                                       "value": val if not carried
                                       else {"kind": "PyExpr", "py": "Assign"},
                                       "pos": _pos(stmt, self.fn_line)})
                    carried = True
                else:
                    # `self.x = ...`, `out[k] = ...`, `a, b = ...`: no local
                    # name proves anything, but the value is still a
                    # statement the rules must see. The index/base of the
                    # target can hold calls too.
                    for c in _target_loads(t):
                        self.stmts.append(self._e(c))
            if not carried:
                self.stmts.append(val)
            return
        if isinstance(stmt, _pyast.AugAssign):
            # The name's binding was seeded unresolved; the value is a
            # statement of its own (`out += subprocess.check_output(c)`).
            self._walrus_lets(stmt.value)
            self.stmts.append(self._e(stmt.value))
            for c in _target_loads(stmt.target):      # `d[f(x)] += 1` (BUG-027)
                self.stmts.append(self._e(c))
            return
        if isinstance(stmt, (_pyast.With, _pyast.AsyncWith)):
            # `with open(path) as f:` is THE idiomatic Python file access.
            # Measured: without this, `with open(base + name)` produced no
            # E0711 at all while the bare `open(base + name)` did — the
            # benign-corpus false-positive count looked good only because
            # most file opens were invisible.
            for item in stmt.items:
                self._walrus_lets(item.context_expr)
                val = self._e(item.context_expr)
                tgt = item.optional_vars
                if isinstance(tgt, _pyast.Name):
                    self.stmts.append({"kind": "Let", "name": tgt.id,
                                       "value": val,
                                       "pos": _pos(stmt, self.fn_line)})
                else:
                    self.stmts.append(val)
                    for c in _target_loads(tgt):      # `as d[f(x)]` (BUG-027)
                        self.stmts.append(self._e(c))
            return
        if isinstance(stmt, _pyast.Return):
            if stmt.value is not None:
                self._walrus_lets(stmt.value)
                self.stmts.append({"kind": "Return", "value": self._e(stmt.value),
                                   "pos": _pos(stmt, self.fn_line)})
            return
        if isinstance(stmt, _pyast.Expr) and _const_str(stmt.value) is not None:
            # A bare string statement — a docstring — is prose, never a
            # value the program uses. E0723 still reads it and rates a
            # credential shape there below one in code (audit C7).
            lit = self._e(stmt.value)
            lit["docstring"] = True
            self.stmts.append(lit)
            return
        # Every other statement — `Expr` (any value, not only a call),
        # `for`/`if`/`while` tests and iterables, `assert`, `raise`,
        # `match` subjects and guards, `del`, and the decorators, defaults
        # and annotations of a nested `def` or `class` — evaluates its
        # expression children in place. Bodies are statements and are
        # visited on their own; targets are binding sites, seeded above.
        for child in _stmt_expr_children(stmt):
            self._walrus_lets(child)
            self.stmts.append(self._e(child))

    def visit_call(self, call: _pyast.Call):
        func = call.func
        arg0 = _const_str(call.args[0]) if call.args else None
        line = getattr(call, "lineno", self.fn_line)

        # bare name(...)
        if isinstance(func, _pyast.Name):
            name = func.id
            if name in DYNAMIC_BUILTINS:
                self._add_unprovable("dynamic_construct", name,
                    f"`{name}(...)` executes or imports code chosen at runtime; "
                    f"its capability surface cannot be determined statically", line)
                return
            if name in DYNAMIC_ATTR_BUILTINS:
                # getattr/setattr/delattr — dynamic unless attr name constant
                if len(call.args) >= 2 and _const_str(call.args[1]) is None:
                    self._add_unprovable("dynamic_attr", name,
                        f"`{name}` with a computed attribute name dispatches to "
                        f"a target unknown at analysis time", line)
                return
            if name in CAP_BY_BUILTIN:
                cap, verb = CAP_BY_BUILTIN[name]
                self._add_effect(cap, verb, arg0); return
            if name in self.local_fns:
                self.local_calls.append(name); return
            if name in PURE_BUILTINS:
                return
            dotted = self.imp.resolve_name(name)   # from-import
            if dotted is not None:
                self._handle_dotted(dotted, arg0, line); return
            # Unknown bare callable -> cannot prove capability-free.
            self._add_unprovable("unresolved_call", name,
                f"callee `{name}` is not a local function, a known-pure builtin, "
                f"or a mapped import; its capability surface is unknown", line)
            return

        # value.attr(...)
        if isinstance(func, _pyast.Attribute):
            attr = func.attr
            val = func.value
            if isinstance(val, _pyast.Name):
                dotted = self.imp.resolve_attr(val.id, attr)
                if dotted is not None:
                    self._handle_dotted(dotted, arg0, line); return
                # method on a local variable / unknown object
                self._add_unprovable("unresolved_method", val.id + "." + attr,
                    f"method `{attr}` is called on `{val.id}`, whose type is not "
                    f"resolved here; its capability surface is unknown", line)
                return
            if isinstance(val, _pyast.Attribute):
                # a.b.c(...) — try to flatten to dotted import path
                dotted = self._flatten_attr(func)
                if dotted is not None:
                    cls = _classify_dotted(dotted)
                    if cls is not None:
                        self._add_effect(cls[0], cls[1], arg0); return
                    if _module_root(dotted) in PURE_MODULES:
                        return
                self._add_unprovable("unresolved_method", attr,
                    f"chained attribute call `...{attr}(...)` could not be "
                    f"resolved to a known module path", line)
                return
            # self.method(), obj().method(), subscript().method() ...
            self._add_unprovable("dynamic_dispatch", attr,
                f"call target `{attr}` is dispatched on a runtime value "
                f"(self/expression); its effects cannot be traced statically", line)
            return

        # eval()() , (lambda...)() , etc.
        self._add_unprovable("computed_callee", "<expr>",
            "the call target is an expression, not a named function", line)

    def _flatten_attr(self, node: _pyast.Attribute) -> Optional[str]:
        parts = []
        cur: Any = node
        while isinstance(cur, _pyast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, _pyast.Name):
            base = self.imp.alias_to_path.get(cur.id, cur.id)
            parts.append(base)
            return ".".join(reversed(parts))
        return None

    def _handle_dotted(self, dotted: str, arg0: Optional[str], line: int):
        if dotted == "importlib.import_module" or dotted.endswith(".import_module"):
            self._add_unprovable("dynamic_construct", dotted,
                "dynamic import selects a module at runtime; the imported "
                "capability surface is unknown", line); return
        cls = _classify_dotted(dotted)
        if cls is not None:
            self._add_effect(cls[0], cls[1], arg0); return
        root = _module_root(dotted)
        if root in PURE_MODULES:
            return
        if root == "os":
            # os.* not in the explicit table -> unknown, be honest.
            self._add_unprovable("unresolved_call", dotted,
                f"`{dotted}` is an os call not in the capability table; "
                f"treated as unknown rather than assumed safe", line); return
        # imported but unmapped module -> unknown capability surface.
        self._add_unprovable("unresolved_call", dotted,
            f"`{dotted}` comes from an unmapped import; its capability surface "
            f"is unknown and cannot be assumed empty", line)


def py_to_ir(source: str) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Translate Python source into Aether IR + an UNPROVABLE map.

    Single sound mode only. (The former `strict`/pragmatic split was removed in
    P0.2: pragmatic mode was unsound.)"""
    try:
        tree = _pyast.parse(source)
    except (RecursionError, MemoryError) as e:
        # CPython's own parser gave up on the nesting depth. Such a file
        # cannot be compiled or imported either, so it is unparseable
        # input, not a bug in Aether: 0.3.1 counted it that way, and
        # letting it reach the analyzer-crash path failed the whole run
        # with a message blaming Aether (BUGS.md BUG-029).
        raise SyntaxError(f"too deeply nested for Python's own parser "
                          f"({type(e).__name__})") from e

    imports = _Imports()
    func_nodes: List[Tuple[str, Any]] = []   # (qualname, node)

    # Every import anywhere in the module: under `try:` (the optional-
    # dependency guard every framework uses), inside functions, behind
    # `if TYPE_CHECKING:`. `collect` below used to read imports only as
    # direct children of the module and class bodies it walked, so a
    # try-guarded `import yaml` left `yaml.load(x)` unresolved — and an
    # unresolved qualified sink is SILENT, not over-flagged. Found by
    # bench/framework_scan (BUGS.md BUG-011); the same gap kept every
    # try-guarded `select` from resolving to a builder (BUG-010).
    # The same one walk collects every binding in the file (`mod_binds`
    # below) and every attribute name anything assigns (`attr_assigned`).
    mod_rows: List[Tuple[str, Any, int]] = []
    # Attribute names anything in the file assigns (`self.Q = ...`,
    # `obj.Q += 1`, `setattr(x, "Q", v)`): a class attribute of that name
    # is not a constant.
    attr_assigned: Set[str] = set()
    for n in _walk(tree):
        if isinstance(n, _pyast.Import):
            imports.add_import(n)
        elif isinstance(n, _pyast.ImportFrom):
            imports.add_importfrom(n)
        if n is not tree:
            _binding_rows(n, mod_rows)
        tgts = (n.targets if isinstance(n, _pyast.Assign)
                else [n.target] if isinstance(n, (_pyast.AugAssign, _pyast.AnnAssign))
                else [])
        for t in tgts:
            attr_assigned |= {a.attr for a in _pyast.walk(t)
                              if isinstance(a, _pyast.Attribute)}
        if isinstance(n, _pyast.Call) and isinstance(n.func, _pyast.Name) \
                and n.func.id in ("setattr", "delattr"):
            attr_assigned.add((_const_str(n.args[1]) if len(n.args) > 1 else None) or "*")

    # Every `def` at any STATEMENT depth outside a function body: under
    # `try:` (the optional-dependency fallback every framework writes),
    # under `if`, inside a `with`/`for`, in a class nested in a class.
    # `collect` used to read only direct children of the module and of
    # its top-level classes, so a `def` anywhere else was never analysed
    # at all — the function-shaped instance of BUG-011 (BUG-012). Nested
    # functions (a `def` inside a `def`) stay part of their enclosing
    # function: `_pyast.walk` already translates their bodies there.
    class_nodes: List[Tuple[str, Any]] = []

    def scope_stmts(stmts):
        """Statements of one scope, through `if`/`try`/`with`/`for`/
        `match` blocks, never into a `def` or `class` body."""
        for child in stmts:
            yield child
            if isinstance(child, (_pyast.FunctionDef, _pyast.AsyncFunctionDef,
                                  _pyast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                yield from scope_stmts(getattr(child, field, None) or [])
            for h in getattr(child, "handlers", None) or []:
                yield from scope_stmts(h.body)
            for c in getattr(child, "cases", None) or []:
                yield from scope_stmts(c.body)

    def collect(stmts, prefix=""):
        for child in scope_stmts(stmts):
            if isinstance(child, (_pyast.FunctionDef, _pyast.AsyncFunctionDef)):
                func_nodes.append((prefix + child.name, child))
            elif isinstance(child, _pyast.ClassDef):
                class_nodes.append((prefix + child.name, child))
                collect(child.body, prefix + child.name + ".")
    collect(tree.body)

    local_fn_names: Set[str] = set(q for q, _ in func_nodes)
    # local-call resolution uses simple names too (module-level helpers)
    simple_names: Set[str] = set(q.split(".")[-1] for q, _ in func_nodes if "." not in q)

    # Module-level literal constants: a name bound exactly ONCE in the
    # whole module, at module level, to a str literal — by any binding
    # form, in any function (a `global` declaration or a parameter of
    # the same name is a second binding and disqualifies it). Such a
    # name IS its literal at every read (`conn.execute(_CREATE_TABLE)`).
    mod_binds: Dict[str, int] = {}
    for n, _v, _l in mod_rows:
        mod_binds[n] = mod_binds.get(n, 0) + 1
    module_lits: Dict[str, Tuple[str, int]] = {}
    for s in scope_stmts(tree.body):
        if isinstance(s, _pyast.Assign) and len(s.targets) == 1 \
                and isinstance(s.targets[0], _pyast.Name) \
                and _scalar_text(s.value) is not None \
                and mod_binds.get(s.targets[0].id) == 1:
            module_lits[s.targets[0].id] = (_scalar_text(s.value),
                                            getattr(s, "lineno", 0))
    # Class-level literal constants (audit C3), per class: an UPPER_CASE
    # name (PEP 8's constant spelling) the class body binds exactly once,
    # to a literal, that no other class in the file binds (a subclass here
    # could override it) and no attribute assignment anywhere names.
    # `self.Q` / `cls.Q` in its methods reads it. The case rule is what
    # keeps a placeholder a subclass elsewhere fills in (`prompt = ''`,
    # openhands' MicroAgent, measured on the framework corpus) a name; a
    # subclass in another file overriding an UPPER_CASE constant with a
    # computed value is the residual (q1).
    class_binds: Dict[str, List[Tuple[str, Any, int]]] = {}
    body_names: Dict[str, int] = {}
    for q, c in class_nodes:
        rows = []
        for s in scope_stmts(c.body):
            if isinstance(s, (_pyast.Assign, _pyast.AnnAssign, _pyast.AugAssign)):
                for t in (s.targets if isinstance(s, _pyast.Assign) else [s.target]):
                    for nm in _target_names(t):
                        v = s.value if isinstance(s, (_pyast.Assign, _pyast.AnnAssign)) \
                            and isinstance(t, _pyast.Name) else None
                        rows.append((nm, v, getattr(s, "lineno", 0)))
            elif isinstance(s, (_pyast.FunctionDef, _pyast.AsyncFunctionDef, _pyast.ClassDef)):
                rows.append((s.name, None, getattr(s, "lineno", 0)))
        class_binds[q] = rows
        for nm in {r[0] for r in rows}:
            body_names[nm] = body_names.get(nm, 0) + 1
    class_lits: Dict[str, Dict[str, Tuple[str, int]]] = {}
    for q, rows in class_binds.items():
        per: Dict[str, Tuple[str, int]] = {}
        for nm in {r[0] for r in rows}:
            mine = [r for r in rows if r[0] == nm]
            if len(mine) == 1 and body_names[nm] == 1 and nm not in attr_assigned \
                    and nm.isupper() \
                    and _scalar_text(mine[0][1]) is not None:
                per[nm] = (_scalar_text(mine[0][1]), mine[0][2])
        class_lits[q] = per if "*" not in attr_assigned else {}
    # The same bar for any value, for aliases (audit B8): `system =
    # os.system`, `evaluate = eval`, `sh = functools.partial(...)`,
    # `HANDLERS = {"sh": os.system}`, `interp = code.InteractiveConsole()`.
    mod_values: Dict[str, Any] = {}
    for s in scope_stmts(tree.body):
        tgt = (s.targets[0] if isinstance(s, _pyast.Assign) and len(s.targets) == 1
               else s.target if isinstance(s, _pyast.AnnAssign) else None)
        if isinstance(tgt, _pyast.Name) and s.value is not None \
                and mod_binds.get(tgt.id) == 1:
            mod_values[tgt.id] = s.value
    mod_scope = _NameScope(mod_binds)
    module = _ModuleFacts(mod_values, {
        n: d for n, v in mod_values.items()
        if (d := _dotted_of(v, imports, mod_scope)) is not None},
        {q: {s.name for s in c.body
             if isinstance(s, (_pyast.FunctionDef, _pyast.AsyncFunctionDef))}
         for q, c in class_nodes if "." not in q and mod_binds.get(q) == 1})

    decls: List[Dict[str, Any]] = []
    unprovable_map: Dict[str, List[Dict[str, Any]]] = {}
    export_names: List[str] = []

    def translate(qual: str, node: Any, line: int):
        v = _FnVisitor(imports, simple_names, qual, line, module_lits=module_lits)
        try:
            ix = _DefIndex(node)
            binds = ix.bindings
            sql_names, lit_names = _sql_expression_names(binds, imports, module_lits)
            counts: Dict[str, int] = {}
            for n, _v, _l in binds:
                counts[n] = counts.get(n, 0) + 1
            v = _FnVisitor(imports, simple_names, qual, line,
                           _safe_xml_parser_names(binds, imports),
                           _local_constants(binds, imports),
                           sql_names, lit_names,
                           set(counts),
                           module_lits,
                           {n: val for n, val, _l in binds
                            if counts[n] == 1 and val is not None},
                           module)
            v.has_walrus = ix.has_walrus
            v.scope.class_lits = class_lits.get(qual.rpartition(".")[0], {})
            fargs = getattr(node, "args", None)
            v.scope.request_params = frozenset(
                n for n in (_param_names(fargs) if isinstance(fargs, _pyast.arguments) else [])
                if counts.get(n) == 1
                and _annotation_of(fargs, n, imports) in _REQUEST_TYPES)
            v.scope.redirect_guards = _redirect_guards(node, binds, imports, v.scope)
            # Two separate passes, deliberately (one walk collected both
            # lists). `visit_call` drives the untouched capability/
            # UNPROVABLE analysis over EVERY call anywhere in the function
            # (including inside comprehensions and nested calls);
            # `visit_stmt` builds the expression shapes the detectors
            # judge. Merging them would change what the capability pass
            # sees.
            for sub in ix.calls:
                v.visit_call(sub)
            v.seed_bindings(binds)
            # Statements only. A handler's exception type and a case's
            # guard are expression children of their Try / Match
            # statement and are translated there; visiting the handler
            # and the case as well reported a sink in either one twice
            # (BUGS.md BUG-028).
            for sub in ix.stmts:
                v.visit_stmt(sub)
            _fix_bound_flows(v.stmts)
            if v.scope.too_deep:
                v._add_unprovable("too_deep", qual,
                                  f"an expression in this scope is nested deeper "
                                  f"than {_MAX_EXPR_DEPTH} levels; the part below "
                                  f"the cap was not translated and its calls were "
                                  f"not judged", line)
        except RecursionError:
            # An expression deeper than the interpreter's stack. The old
            # behaviour let it escape and the CLI counted the WHOLE FILE
            # as unreadable — every other function's findings lost, exit
            # 0. Now this one scope reports an unprovable region and the
            # rest of the file is judged (BUG-012).
            v.stmts = []
            v._add_unprovable("too_deep", qual,
                              "an expression in this scope is nested deeper "
                              "than the analyzer can translate; its calls "
                              "were not judged", line)
        body_calls = [{"kind": "Call",
                       "func": {"kind": "Ident", "name": c},
                       "args": [], "pos": {"line": line, "column": 1},
                       "py": True}
                      for c in v.local_calls]
        decls.append({
            "kind": "FunctionDecl",
            "name": qual,
            "effects": v.effects,
            "body": v.stmts + body_calls,
            "pos": {"line": line, "column": 1},
        })
        export_names.append(qual)
        if v.unprovable:
            unprovable_map[qual] = v.unprovable

    for qual, node in func_nodes:
        translate(qual, node, getattr(node, "lineno", 0))

    # Code that runs when the module is imported — `os.system(sys.argv[1])`
    # at the top level, an `if __name__ == "__main__":` block, a class
    # attribute computed at class-creation time — was never analysed:
    # `n_functions: 0, ok: true` for a script whose whole body is a sink
    # (BUG-012). Each such scope becomes one synthetic decl, `<module>` or
    # `Class.<class>`, run through the identical machinery; a scope with
    # no call at all is omitted so a module of plain assignments adds
    # nothing to the output.
    n_scopes = 0
    # Stripped IN PLACE, after every `def` has been translated from its
    # own node: removing a `def` from its parent's list does not touch
    # the node. No copy — a deep copy of a deep expression is itself a
    # RecursionError. `generic_visit`, not `visit`, on a class: strip
    # its CHILDREN and keep the class node (`visit_ClassDef` deletes).
    stripper = _ScopeStripper()
    scopes = [(q + ".<class>", c, getattr(c, "lineno", 0)) for q, c in class_nodes]
    scopes.append(("<module>", tree, 1))
    for qual, node, line in scopes:
        try:
            stripped = stripper.generic_visit(node)
        except RecursionError:
            unprovable_map.setdefault(qual, []).append({
                "fn": qual, "line": line, "granularity": "function",
                "callee": qual, "reason": "too_deep",
                "detail": "an expression in this scope is nested deeper than "
                          "the analyzer can translate; its calls were not judged",
                "construct_line": line, "needs": "human review or a runtime check"})
            continue
        if not _scope_has_content(stripped):
            continue
        n_scopes += 1
        translate(qual, stripped, line)

    module_name = "PythonModule"
    decls.insert(0, {
        "kind": "ModuleDecl",
        "name": module_name,
        "capabilities": [],         # default boundary: nothing allowed (policy overrides)
        "exports": export_names,
        "pos": {"line": 1, "column": 1},
    })

    # `lang` lets a rule that is not a frontend call row (E0723's literal
    # scan) word its Python finding in Python.
    ast_dict = {"kind": "Program", "decls": decls, "lang": "python"}
    meta = {"lang": "python", "module": module_name,
            "n_functions": len(func_nodes), "n_scopes": n_scopes,
            "pymap_version": PYMAP_VERSION, "mode": "sound"}
    return ast_dict, unprovable_map, meta


def mapping_table() -> Dict[str, Any]:
    """Expose the capability mapping table for auditing (the /pymap endpoint)."""
    return {
        "pymap_version": PYMAP_VERSION,
        "cap_by_module": CAP_BY_MODULE,
        "cap_by_qualified": CAP_BY_QUALIFIED,
        "cap_by_builtin": {k: list(v) for k, v in CAP_BY_BUILTIN.items()},
        "dynamic_builtins": sorted(DYNAMIC_BUILTINS) + sorted(DYNAMIC_ATTR_BUILTINS),
        "pure_modules": sorted(PURE_MODULES),
        "pure_module_citations": PURE_MODULE_CITATIONS,
        "pure_builtins": sorted(PURE_BUILTINS),
        "sink_by_qualified": SINK_BY_QUALIFIED,
        "sink_by_method": SINK_BY_METHOD,
        "sink_by_builtin": SINK_BY_BUILTIN,
        "sink_match_kinds": list(SINK_MATCH_KINDS),
        "sink_guards": {
            name: {"sink": g.sink_name, "keyword": g.keyword,
                   "safe_values": sorted(g.safe_values),
                   "sink_values": sorted(g.sink_values),
                   "absent_is_sink": g.absent_is_sink}
            for name, g in sorted(SINK_GUARDS.items())},
        "sanitizer_by_qualified": SANITIZER_BY_QUALIFIED,
        "argv_shell_form": {"programs": sorted(_ARGV_SHELLS),
                            "flags": sorted(_ARGV_SHELL_FLAGS),
                            "judged_element": 2},
        "argv_option_programs": {
            "options": {k: list(v) for k, v in sorted(_ARGV_CODE_OPTIONS.items())},
            "no_terminator": sorted(_ARGV_NO_TERMINATOR),
            "positional_runners": sorted(_ARGV_POSITIONAL_RUNNERS),
            "judged_element": "first non-literal word before a literal --"},
        "sql_expression_builders": {
            "roots": sorted(_SQL_EXPR_ROOTS),
            "builders": sorted(_SQL_EXPR_BUILDERS),
            "table_methods_argument_free_only": sorted(_SQL_TABLE_METHODS),
            "raw_string_entry_points": sorted(_SQL_RAW_ENTRY),
            "raw_string_methods": sorted(_SQL_RAW_METHODS)},
        "mode": "sound",
    }
