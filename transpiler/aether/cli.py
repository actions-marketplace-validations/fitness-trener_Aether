"""Aether CLI — single entry point for the v0.1 toolchain.

Subcommands:
    aether parse  <file>           Lex + parse, print canonical AST as JSON
    aether emit   <file>           Emit Python source for the program
    aether check  <file>           Parse + emit (without running) — exit 0 if OK
    aether run    <file>           Parse, emit, exec; mirrors stdout/stderr
    aether test   <dir>            Run a reference-program directory: expects
                                   `program.aeth` and `expected_stdout.txt`

Global flag: --json — machine-readable output: exactly ONE JSON document
on stdout (stderr carries only human text). Every diagnostic in it is
`Diagnostic.to_dict()`. Exit codes are the one table in diagnostics.py
(0 clean, 1 findings, 2 usage, 3 crash, 4 incomplete) — see
docs/SCANNING.md, "Exit codes and the JSON contract".
"""

from __future__ import annotations
import argparse
import io
import json
import os
import re
import sys
import traceback
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from typing import Any, Dict

from .diagnostics import (AetherError, Diagnostic, EXIT_CLEAN, EXIT_CRASH,
                          EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_USAGE,
                          Position, error_doc, exit_code)
from .lexer import tokenize
from .parser import parse
from .emitter import emit
from .pretty import pretty
from .passes import analyze
from .passes.imports import load_program
from .runtime import build_namespace, set_effect_strict, set_deterministic


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _emit_error(diag: Diagnostic, as_json: bool = False):
    """One diagnostic, as human text on stderr. `--json` never comes here:
    it prints one document through `_report`/`_print_doc` (D6)."""
    sys.stderr.write(
        f"[{diag.code}] {diag.severity} ({diag.category}) "
        f"at line {diag.position.line}, col {diag.position.column}: "
        f"{diag.message}\n"
    )
    if diag.suggestion:
        sys.stderr.write(f"  hint: {diag.suggestion}\n")


def _print_doc(doc: dict) -> None:
    """THE `--json` output: one document, on stdout. It used to be JSONL
    on stderr for `check`, stdout AND stderr for `--collect-errors`, and a
    stdout object for `check-py` (audit 2026-09-24 D6)."""
    json.dump(doc, sys.stdout)   # ASCII-escaped: safe on any console codepage
    sys.stdout.write("\n")


def _report(args, diags, rc: int, *, ast=None, complete: bool = True,
            **extra) -> int:
    """Report `diags` for a run ending in `rc`: human lines on stderr, or
    under `--json` one document {ok, complete, diagnostics, ...extra}.
    Returns `rc` so a caller can `return _report(...)`."""
    if args.json:
        # `run` sets `run_output` so every one of its documents carries the
        # program's captured stdout/stderr (empty if it never started).
        extra = dict(getattr(args, "run_output", {}), **extra)
        _print_doc(dict({"ok": rc == EXIT_CLEAN, "complete": complete,
                         "diagnostics": [d.to_dict(ast) for d in diags]},
                        **extra))
    else:
        for d in diags:
            _emit_error(d)
    return rc


def _read(path: str) -> str:
    # `utf-8-sig`, not `utf-8`: a UTF-8 BOM is common in files written on
    # Windows, and Python's own tokenizer strips it. Read as plain utf-8 it
    # survives as U+FEFF and every such file becomes a syntax error — which
    # `check-py` over a tree would count as "unparseable" and skip SILENTLY.
    # A file the scanner cannot read is a missed finding, not a clean file.
    # On a file with no BOM this codec is identical to utf-8.
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


def _read_py(path: str) -> str:
    # Python source declares its own encoding (PEP 263): `tokenize.open`
    # honours a `# -*- coding: latin-1 -*-` cookie exactly as CPython
    # does, strips a BOM, and is byte-identical to utf-8-sig on a file
    # that has neither. Read as utf-8 a cookie'd file was a
    # UnicodeDecodeError, counted "unreadable" and skipped — valid
    # Python, findings lost. Kept apart from `_read`: `.aeth` has no
    # cookie grammar, and its behaviour must not move.
    import tokenize
    with tokenize.open(path) as f:
        return f.read()


def _load(src: str, source_path: str, args, collect: bool = False) -> tuple:
    """Parse + H.E.3 import resolution through `load_program`, the one
    loader the SDK, LSP, fix-loop and `tools/scan.py` also use (audit
    2026-09-24 D2). `--no-import-resolution` opts out. Reports every
    diagnostic and returns (ast, EXIT_INCOMPLETE) when the program did not
    load — it was not analysed — else (ast, 0)."""
    ast, parse_diags, import_diags = load_program(
        src, source_path, collect=collect,
        resolve=not getattr(args, "no_import_resolution", False))
    if parse_diags or import_diags:
        return ast, _report(args, parse_diags + import_diags,
                            EXIT_INCOMPLETE, complete=False)
    return ast, EXIT_CLEAN


# ----------------------------------------------------------------------
# Subcommands
# ----------------------------------------------------------------------

def cmd_parse(args) -> int:
    src = _read(args.file)
    ast = parse(src, args.file)
    print(json.dumps(ast, indent=2, default=str, ensure_ascii=False))
    return 0


def cmd_emit(args) -> int:
    src = _read(args.file)
    ast, rc = _load(src, args.file, args)
    if rc != 0:
        return rc
    py = emit(ast, release=getattr(args, "release", False))
    print(py)
    return 0


def cmd_pack(args) -> int:
    """Emit FILE as an importable Python package with a contract-checked
    boundary (formalizes the bench-harness interop pattern)."""
    from .runtime import mangle
    src = _read(args.file)
    ast, rc = _load(src, args.file, args)
    if rc != 0:
        return rc
    py = emit(ast)
    name = args.name or os.path.splitext(os.path.basename(args.file))[0]
    if not name.isidentifier():
        raise _UsageError(f"package name {name!r} is not a valid Python "
                          f"identifier (use --name)")
    pkg_dir = os.path.join(args.out, name)
    os.makedirs(pkg_dir, exist_ok=True)
    fns = [d["name"] for d in ast["decls"] if d.get("kind") == "FunctionDecl"]
    aliases = [(mangle(n)[len("_ae_"):], mangle(n)) for n in fns]
    header = (
        f"# Generated by `aether pack` from {os.path.basename(args.file)}"
        f" — do not edit.\n"
        "# Contract-checked boundary: every call below runs the declared\n"
        "# requires/ensures/refinement checks and raises\n"
        "# aether.diagnostics.AetherError on violation.\n"
        "try:\n"
        "    from transpiler.aether.runtime import build_namespace as _ae_bn\n"
        "except ImportError:\n"
        "    from aether.runtime import build_namespace as _ae_bn\n"
        "globals().update(_ae_bn())\n"
        "del _ae_bn\n\n")
    footer = ("\n\n# public aliases (clean names -> emitted functions)\n"
              + "".join(f"{clean} = {mangled}\n" for clean, mangled in aliases)
              + f"\n__all__ = {sorted(clean for clean, _ in aliases)!r}\n")
    out_path = os.path.join(pkg_dir, "__init__.py")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header + py + footer)
    print(out_path)
    return 0


def cmd_fmt(args) -> int:
    """C.4 formatter. Parse + canonical pretty-print.

    Defaults to writing the formatted source to stdout. With `--write`,
    overwrites the input file in place. With `--check`, exits 1 if the
    file is not already canonically formatted, exit 0 otherwise — for
    CI integration ("does this PR contain unformatted code?").
    """
    src = _read(args.file)
    ast = parse(src, args.file)
    # With the source, full-line comments survive — a `// expect:` header
    # among them (D7; what is still lost is listed on `pretty`).
    formatted = pretty(ast, src)
    if getattr(args, "check", False):
        ok = src == formatted
        if args.json:
            _print_doc({"ok": ok, "complete": True, "diagnostics": [],
                        "would_reformat": None if ok else args.file})
        elif not ok:
            sys.stderr.write(f"would reformat: {args.file}\n")
        return 0 if ok else 1
    if getattr(args, "write", False):
        with open(args.file, "w", encoding="utf-8", newline="\n") as f:
            f.write(formatted)
        if not args.json:
            print(f"formatted: {args.file}")
        return 0
    sys.stdout.write(formatted)
    return 0


# Which `--no-*` flag opts out of which registry stage. Stage membership
# itself lives in passes/STAGES and is never restated here.
_STAGE_OPT_OUT = {
    "effects":    "no_static_effects",      # B.1/B.2
    "security":   "no_scope_check",         # E0710-E0730
    "semantic":   "no_exhaustiveness_check",  # E0202-E0208
    "capability": "no_capability_check",    # B.3
    "modules":    "no_module_check",        # D.3
}


def _run_analysis(ast, args) -> int:
    """Run the static-analysis registry in stage order; EXIT_FINDINGS if
    any stage produced diagnostics, else 0.

    `--json` prints EVERY stage's diagnostics, each tagged with its
    `stage` — the same set `sdk.check`, the LSP and `tools/scan.py`
    report. It used to stop at the first non-empty stage, so an E0801
    hid an E0713 in the same file and an agent needed one round-trip per
    stage (audit 2026-09-24 D4). Text mode keeps the short-circuit for a
    human reader, and says what it held back."""
    skip = {stage for stage, flag in _STAGE_OPT_OUT.items()
            if getattr(args, flag, False)}
    found = [(stage, diags) for stage, diags in analyze(ast, skip=skip)
             if diags]
    for stage, diags in found:
        for d in diags:
            d.stage = stage
    if not found:
        return 0
    if args.json:
        return _report(args, [d for _s, diags in found for d in diags],
                       EXIT_FINDINGS, ast=ast, decls=len(ast["decls"]))
    for d in found[0][1]:
        _emit_error(d)
    if len(found) > 1:
        n = sum(len(diags) for _stage, diags in found[1:])
        sys.stderr.write(
            f"({n} more diagnostic(s) from later stages not shown: "
            + ", ".join(f"{stage} {len(diags)}" for stage, diags in found[1:])
            + "; run with --json to see every stage)\n")
    return EXIT_FINDINGS


def _run_smt_check(ast, timeout_ms):
    """SMT contract proving (default-on with z3; --prove forces it).
    Returns (rc, summary, diags). rc EXIT_FINDINGS iff a clause was
    refuted (E0901); E0902 timeouts are warnings and pass. z3 missing
    under --prove is a usage error: nothing was proved."""
    from .passes.smt import HAVE_Z3, check_contracts_smt
    if not HAVE_Z3:
        raise _UsageError("--prove requires the z3-solver package "
                          "(pip install 'aether-lang[smt]')")
    diags, summary = check_contracts_smt(ast, timeout_ms=timeout_ms)
    for d in diags:
        d.stage = "smt"
    rc = EXIT_FINDINGS if any(d.severity == "error" for d in diags) else 0
    return rc, summary, diags


# Stages that do not apply to Python source.
#   effects  — E0801 compares a call site against a DECLARED effects
#              clause; Python has none, so there is nothing to compare.
#   semantic — E0202-E0208 check Aether language constructs (match
#              exhaustiveness, dead `let` stores, ignored Results). On
#              translated Python they describe the translation rather
#              than the program.
# Defined once in py_frontend.py (with the strict-only codes below) and
# imported here, by both benches and by the tests.
from .py_frontend import PY_SKIP_STAGES as _PY_SKIP_STAGES  # noqa: E402

# Rows held back from the DEFAULT Python output, by measurement, not by
# taste. `bench/py_frontend/run_bench.py` over 76 benign modules
# (tools/py_corpus{,2}) counted:
#   E0711  11 findings — 1 clearly real (fa_04_upload writes to
#          "/data/uploads/" + file.filename, a textbook upload
#          traversal) and 8 of the form `open(path_param)`, where the
#          path is the function's own parameter and nothing in the
#          module constrains it. Those are provenance-UNKNOWN, not
#          proven safe; Aether's rule (a path must be a literal or
#          safeJoin'd) flags them because Python has no safeJoin
#          convention. Real, but at a ratio that would bury the other
#          rows, so it is opt-in rather than deleted.
#   E0713   1 finding, E0720  1 finding — both on genuinely suspicious
#          code (a migration runner executing SQL read from a file;
#          trap_05_pickle's `pickle.load(fh)`). Those rows stay default-on.
# The capability stage is opt-in for a different reason: on Python the
# module policy is empty by construction, so every I/O call yields
# E0701. That is an inventory, which `tools/py_surface.py` already
# reports properly — not a security verdict.
from .py_frontend import PY_STRICT_ONLY_CODES as _PY_STRICT_ONLY_CODES  # noqa: E402


# Directories that are never the user's own source. Walking `.venv` or
# `node_modules` turns a repo scan into a dependency scan — thousands of
# findings in code the user cannot fix, burying the ones they can.
_PY_SKIP_DIRS = frozenset((
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", ".venv", "venv", "env", "node_modules",
    "site-packages", "build", "dist", ".eggs",
))


def _py_files(target: str, skipped: list = None) -> list:
    """Every `.py` file under `target`, or `[target]` if it is a file.

    Sorted at every level so two runs over the same tree produce the same
    output in the same order (tests/test_deterministic.py's rule). A
    directory pruned by `_PY_SKIP_DIRS` is appended to `skipped` (its
    path relative to `target`) — a `build/` or `env/` that holds the
    user's own source used to vanish with no trace in any output."""
    if os.path.isfile(target):
        return [target]
    found = []
    for dirpath, dirnames, filenames in os.walk(target):
        if skipped is not None:
            for d in dirnames:
                if d in _PY_SKIP_DIRS or d.endswith(".egg-info"):
                    skipped.append(os.path.relpath(os.path.join(dirpath, d), target)
                                   .replace(os.sep, "/"))
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _PY_SKIP_DIRS
                             and not d.endswith(".egg-info"))
        found.extend(os.path.join(dirpath, f) for f in sorted(filenames)
                     if f.endswith(".py"))
    return found


# PEP 695 type parameters / `type` statements: what a 3.10/3.11 parser
# rejects on a line that 3.12 accepts.
_PEP695_LINE = re.compile(r"\s*(type\s+\w+\s*(\[.*\])?\s*=|(async\s+)?def\s+\w+\s*\[|"
                          r"class\s+\w+\s*\[)")


def _newer_syntax_hint(e) -> str:
    """B6, best effort: on a 3.10/3.11 host a SyntaxError that looks like
    3.12 syntax — a PEP 701 f-string (every 3.10/3.11 f-string error
    starts "f-string") or a PEP 695 type parameter — says so. A heuristic
    on the error, not a parse with a newer grammar, hence the question
    mark: a malformed f-string gets the same hint."""
    if sys.version_info >= (3, 12) or not isinstance(e, SyntaxError):
        return ""
    if str(e.msg or "").startswith("f-string") or \
            _PEP695_LINE.match(e.text or ""):
        return (" — valid on a newer Python? scan with 3.12+ (this is "
                f"Python {sys.version_info[0]}.{sys.version_info[1]})")
    return ""


def _scan_one(job):
    """Analyze ONE Python file. Everything `cmd_check_py`'s loop collects
    for a file, as one picklable tuple, so the loop can run in a worker
    process unchanged:

        ("ok", path, [Diagnostic], unprovable, meta)
      | ("unreadable", path, why, detail)
      | ("crashed", path, error_text)

    Module-level and self-contained on purpose: `ProcessPoolExecutor`
    pickles the callable by qualified name, and a closure over
    `cmd_check_py`'s locals would not survive. The per-file `except` walls
    stay INSIDE the worker — a detector that crashes must come back as
    this file's ANALYZER ERROR line, not as a BrokenProcessPool that
    loses the whole run.
    """
    path, skip, strict = job
    from . import py_frontend
    from .passes import analyze
    from .risk import rank
    try:
        src = _read_py(path)
    except (OSError, UnicodeDecodeError, SyntaxError) as e:
        # `tokenize.open` raises SyntaxError for an unknown cookie.
        return ("unreadable", path, type(e).__name__, str(e))
    try:
        # Only the frontend's parse can make a file "unreadable". A
        # ValueError raised by a detector is an analyzer crash; caught
        # here with the parse errors it was reported as "could not parse",
        # exit 0, its findings lost (BUG-035).
        try:
            ast, unprovable, meta = py_frontend.py_to_ir(src)
        except (SyntaxError, ValueError) as e:
            # py2 sources, templates and test fixtures are normal in a real
            # tree; they are counted, and the run exits 4 (incomplete) —
            # never 0, because what was not parsed was not checked (B6).
            return ("unreadable", path, type(e).__name__,
                    str(e) + _newer_syntax_hint(e))
        diags = []
        for stage, found in analyze(ast, skip=skip):
            for d in found:
                d.stage = stage
            diags += found
    except RecursionError as e:
        # The frontend catches this per scope and reports an `unprovable`
        # region; one that still escapes is the analyzer's limit, not the
        # input's — loud, like any crash, never a silently "unreadable"
        # file with exit 0.
        return ("crashed", path,
                f"RecursionError: expression too deep for the analyzer ({e})")
    except Exception as e:
        # An analyzer crash is a BUG in Aether, not a property of the
        # input. It must be loud and must fail the run — `passes/
        # __init__.py` deliberately does not swallow exceptions.
        return ("crashed", path, f"{type(e).__name__}: {e}")
    if not strict:
        diags = [d for d in diags if d.code not in _PY_STRICT_ONLY_CODES]
    # Worst-first, then most-certain-first: the top of a long scan is the
    # part worth reading, and of two equally-risky findings the one the
    # analysis is surest about leads. Line and code break ties so the
    # order stays deterministic (tests/test_deterministic.py).
    diags.sort(key=lambda d: (-rank(d.code), -d.confidence,
                              d.position.line, d.code))
    return ("ok", path, diags, unprovable, meta)


# Below this many files a worker pool costs more (process start-up, and
# pickling every Diagnostic back) than the parallelism buys. Measured on
# 8 logical cores: 300 files serially 23.6 s, 4 workers 9.4 s, 8 workers
# 9.2 s, identical findings — but a handful of files is dominated by the
# ~0.5 s of interpreter start-up per worker.
_JOBS_THRESHOLD = 32


def cmd_check_py(args) -> int:
    """Run the language-independent detectors over Python files.

    Takes any mix of files and directories; a directory is walked
    recursively for `.py` (see `_PY_SKIP_DIRS` for what is not walked).

    Python has no declared `effects` clause and no marker types, so the
    guarantee set is genuinely smaller than `check` on a .aeth file. That
    is printed, not implied: a tool that quietly offers less than it looks
    like it offers is worse than one that offers less out loud."""
    # The per-file work — and the frontend/pass imports it needs — lives
    # in `_scan_one`, which is also what a worker process runs.
    strict = getattr(args, "strict", False)
    skip = _PY_SKIP_STAGES if strict else _PY_SKIP_STAGES + ("capability",)

    targets = args.target
    missing = [t for t in targets if not os.path.exists(t)]
    if missing:
        raise _UsageError("; ".join(f"no such file or directory: {t}"
                                    for t in missing))
    if getattr(args, "sarif", False) and args.json:
        raise _UsageError("--sarif and --json are two different output "
                          "formats; pick one")
    min_conf = getattr(args, "min_confidence", 0.0) or 0.0
    if not 0.0 <= min_conf <= 1.0:
        raise _UsageError(f"--min-confidence must be in [0,1], got {min_conf}")
    # A usage error on our own flag must read like one. Unvalidated,
    # `--jobs 0` scanned serially with no message and `--jobs 999` died
    # with a raw ValueError traceback and exit 1 — Windows caps
    # ProcessPoolExecutor at 61 workers, which is a platform fact, not
    # something the caller should have to know.
    jobs_arg = getattr(args, "jobs", None)
    if jobs_arg is not None and jobs_arg < 1:
        raise _UsageError(f"--jobs must be >= 1, got {jobs_arg}")
    skipped_dirs: list = []
    paths = sorted({p for t in targets for p in _py_files(t, skipped_dirs)})
    skipped_dirs = sorted(set(skipped_dirs))
    # One explicit file keeps the original single-file output verbatim; a
    # directory (or several targets) prefixes each file's findings with
    # its path, because otherwise line numbers name nothing.
    show_paths = not (len(targets) == 1 and os.path.isfile(targets[0]))

    jobs = jobs_arg
    if jobs is None:
        jobs = (os.cpu_count() or 1) if (
            len(paths) > _JOBS_THRESHOLD and (os.cpu_count() or 1) > 1) else 1
    # Windows caps ProcessPoolExecutor at 61 workers. Asking for more is
    # not worth an error: clamp and scan, rather than refusing a run over
    # a number that only names how fast the caller wanted it.
    jobs = min(jobs, 61)
    work = [(p, skip, strict) for p in paths]
    if jobs > 1 and len(paths) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            # `map` over the ALREADY-SORTED paths: results come back in
            # submission order, so the output is byte-identical to the
            # serial loop's (tests/test_deterministic.py).
            outcomes = list(ex.map(_scan_one, work, chunksize=4))
    else:
        outcomes = [_scan_one(w) for w in work]

    results, unreadable, crashed = [], [], []
    for o in outcomes:
        if o[0] == "ok":
            results.append(o[1:])
        elif o[0] == "unreadable":
            unreadable.append(o[1:])
        else:
            crashed.append(o[1:])
    if min_conf > 0.0:
        # A filter on the OUTPUT, like `tools/scan.py`'s `--min-risk`: it
        # hides rows the analysis is less sure of, and changes nothing
        # about which findings the detectors produced.
        results = [(p, [d for d in ds if d.confidence >= min_conf], unp, m)
                   for p, ds, unp, m in results]

    n_find = sum(len(ds) for _, ds, _, _ in results)
    n_func = sum(m["n_functions"] for _, _, _, m in results)
    n_unp = sum(len(v) for _, _, unp, _ in results for v in unp.values())
    n_unp_fns = sum(len(unp) for _, _, unp, _ in results)

    # Crashes go to stderr in every output mode: SARIF and --json own
    # stdout, and a detector that crashed must not be invisible just
    # because the caller asked for machine-readable output.
    for p, err in crashed:
        sys.stderr.write(f"aether: ANALYZER ERROR on {p}: {err}\n"
                         f"  this is a bug in Aether, not in your code — "
                         f"please report it (see BUGS.md)\n")
    # A file the scanner could not read is a missed finding, not a clean
    # file. It is reported on stderr in EVERY output mode, and the exit
    # code says so in every mode: 4 (incomplete) when nothing was found,
    # 1 when something was — never 0. It used to be "unparseable input
    # never fails the run", which let a tree of 3.12 syntax scanned on
    # 3.11 exit 0 with `ok: true` and nothing analysed (audit B6). An
    # analyzer crash is 3, whatever else happened.
    rc = exit_code(n_find, incomplete=bool(unreadable), crashed=bool(crashed))
    for p, why, detail in unreadable:
        sys.stderr.write(f"aether: could not parse {p}: {why}: {detail}\n")
    if skipped_dirs:
        sys.stderr.write(f"aether: {len(skipped_dirs)} director"
                         f"{'y' if len(skipped_dirs) == 1 else 'ies'} skipped "
                         f"as vendored/build output: "
                         + ", ".join(skipped_dirs) + "\n")

    if getattr(args, "sarif", False):
        from .sarif import to_sarif
        # Relative to the working directory, which under CI is the
        # checkout root. Code Scanning silently drops a result whose
        # artifactLocation is not relative to it. Every finding is
        # `to_dict()`, the JSON's own rows, so the SARIF says what the
        # JSON says.
        print(json.dumps(to_sarif(
            [{"path": p, "findings": [d.to_dict() for d in ds]}
             for p, ds, _u, _m in results], base=os.getcwd(),
            unreadable=[(p, f"{why}: {detail}") for p, why, detail in unreadable],
            crashed=crashed),
            indent=2))
        return rc

    if args.json:
        no_unp = getattr(args, "no_unprovable", False)
        _print_doc({"ok": rc == EXIT_CLEAN,
                    "complete": not (unreadable or crashed),
                    "lang": "python",
                    "files": [{"path": p.replace(os.sep, "/"),
                               "diagnostics": [d.to_dict() for d in ds],
                               "unprovable": {} if no_unp else unp,
                               "meta": meta}
                              for p, ds, unp, meta in results],
                    "unreadable": [{"path": p.replace(os.sep, "/"),
                                    "reason": why, "detail": detail}
                                   for p, why, detail in unreadable],
                    "skipped_dirs": skipped_dirs,
                    "errors": [{"path": p.replace(os.sep, "/"), "error": e}
                               for p, e in crashed]})
        return rc

    for p, ds, _unp, _meta in results:
        if not ds:
            continue
        if show_paths:
            sys.stderr.write(f"{p.replace(os.sep, '/')}\n")
        for d in ds:
            _emit_error(d, False)

    print()
    if show_paths:
        by_code = {}
        for _, ds, _, _ in results:
            for d in ds:
                by_code[d.code] = by_code.get(d.code, 0) + 1
        print(f"scanned {len(results)} file(s) · "
              f"{sum(1 for _, ds, _, _ in results if ds)} with findings · "
              f"{len(unreadable)} unparseable · {len(crashed)} analyzer error(s)"
              + (f" · {len(skipped_dirs)} dir(s) skipped" if skipped_dirs else ""))
        if by_code:
            print("findings by code: " + ", ".join(
                f"{c}x{n}" for c, n in sorted(by_code.items())))
    print(f"{n_find} finding(s) in {n_func} function(s); "
          f"{n_unp} unprovable region(s) in {n_unp_fns} function(s).")
    # The net.fetch rows read effects the frontend synthesizes as
    # [capability, method name], so a mapped network call named `fetch`
    # does reach them; requests.get / urlopen do not (measured 2026-09-15).
    # E0716 is absent from the list: `executescript` maps to sqlExec, which
    # requires an authorization proof; no Python spelling tried supplies one
    # (an authorize(...) second argument, an Authorized annotation; measured).
    print("NOT checked on Python (no declared effects clause, no marker "
          "types): E0801 effect composition; the net.fetch scope rows "
          "(E0710/E0721/E0722), except on a network call named fetch; the "
          "marker rows (E0712/E0715/E0717/E0724/E0725/E0726/E0728/"
          "E0729/E0730); and the semantic family (E0202-E0208). E0716 "
          "fires on every .executescript method call; no Python spelling tried "
          "clears it.")
    if not strict:
        print("NOT checked by default (--strict adds both): E0711 dynamic "
              "filesystem paths, and the capability inventory (E0701). "
              "Held back by measurement, not taste - see "
              "bench/py_frontend/REPORT.md.")
    return rc


def cmd_check(args) -> int:
    src = _read(args.file)
    collect = getattr(args, "collect_errors", False)
    if collect:
        # C.6 multi-error parser recovery: surface every recoverable
        # parse error in one pass, instead of bailing on the first.
        _ast, parse_diags, _ = load_program(src, args.file, resolve=False)
        if parse_diags:
            return _report(args, parse_diags, EXIT_INCOMPLETE, complete=False)
    # H.E.3 multi-file resolution (default-on when ImportDecls present).
    ast, rc = _load(src, args.file, args, collect=collect)
    if rc != 0:
        return rc
    py = emit(ast)
    # Compile but don't execute.
    compile(py, args.file + ".py", "exec")
    # Every default-on static stage, in registry order. Each `--no-*` flag
    # in _STAGE_OPT_OUT drops its stage. (--capability-strict is kept as an
    # alias for the default behaviour for backward compat with v0.2 scripts.)
    rc = _run_analysis(ast, args)
    if rc != 0:
        return rc
    # SMT contract proving: default-on when z3-solver is installed
    # (wave 1 flip; was opt-in). --no-prove disables; --prove forces and
    # errors with an install hint when z3 is missing. E0901 refutations
    # fail the check; E0902 timeouts warn and pass.
    prove_summary, smt_diags = None, []
    if not getattr(args, "no_prove", False):
        from .passes.smt import HAVE_Z3
        if HAVE_Z3 or getattr(args, "prove", False):
            rc, prove_summary, smt_diags = _run_smt_check(
                ast, getattr(args, "prove_timeout_ms", 5000))
    extra = {"decls": len(ast["decls"])}
    if prove_summary is not None:
        extra["prove"] = prove_summary
    _report(args, smt_diags, rc, ast=ast, **extra)
    if not args.json:
        if prove_summary is not None:
            print("prove: {proved} proved, {refuted} refuted, "
                  "{timeout} timeout, {skipped} skipped".format(**prove_summary))
        if rc == EXIT_CLEAN:
            print(f"OK: {args.file} ({len(ast['decls'])} decls)")
    return rc


def cmd_run(args) -> int:
    if getattr(args, "release", False) and getattr(args, "effect_strict", False):
        raise _UsageError("--release and --effect-strict are mutually "
                          "exclusive (strict effect checking needs the "
                          "frames --release removes)")
    if args.effect_strict:
        set_effect_strict(True)
    # C.5 deterministic test mode: pin clock + random seed for reproducible runs.
    if getattr(args, "deterministic", False) or os.environ.get("AETHER_DETERMINISTIC"):
        seed = int(os.environ.get("AETHER_SEED", "0"))
        set_deterministic(seed)
    # `--json`: the program's own output is captured into the one stdout
    # document (`stdout`, `stderr` — the field names of `sdk.RunResult`)
    # instead of preceding it on stdout, where a printed line that looks
    # like JSON was indistinguishable from the document (gaps round G1).
    out = {"stdout": "", "stderr": ""}
    if args.json:
        args.run_output = out
    src = _read(args.file)
    # H.E.3 multi-file resolution (default-on when ImportDecls present).
    ast, rc = _load(src, args.file, args)
    if rc != 0:
        return rc
    # Default-on static analysis — the same registry `check` runs, so a
    # clean `check` now means something about what `run` verified.
    rc = _run_analysis(ast, args)
    if rc != 0:
        return rc
    py = emit(ast, release=getattr(args, "release", False))
    code = compile(py, args.file + ".py", "exec")
    g = build_namespace()
    g["__name__"] = "__main__"
    g["__file__"] = args.file + ".py"
    diags = []
    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with ExitStack() as stack:
            if args.json:
                stack.enter_context(redirect_stdout(buf_out))
                stack.enter_context(redirect_stderr(buf_err))
            try:
                exec(code, g)
            except AetherError:
                raise   # a contract/refinement violation: main reports it
            except Exception as e:
                # The PROGRAM raised, not Aether: print it as Python would
                # and exit 1, as Python does. Only an exception outside
                # the user's program is an analyzer crash (exit 3).
                traceback.print_exc()
                rc = EXIT_FINDINGS
                diags = [Diagnostic("E9003", "runtime", "error",
                                    f"{type(e).__name__}: {e}", Position(0, 0))]
    finally:
        out["stdout"], out["stderr"] = buf_out.getvalue(), buf_err.getvalue()
    if args.json:
        _report(args, diags, rc, ast=ast)
    return rc


def cmd_test(args) -> int:
    """Run a directory containing program.aeth + expected_stdout.txt.

    Exits 0 on match, 1 on mismatch, 2 on compile/runtime error — the
    fixture runner's own table, deliberately not the scan table in
    diagnostics.py: its callers (run_all.py, bench/harness.py) grade on it.

    Runs NO static passes, deliberately (ADR-0001). This is the fixture
    runner — `scripts/run_all.py` drives it over every `reference/` dir
    and `bench/harness.py` over `bench/tasks/`. Answering "does this
    program still behave" must stay decoupled from "does it still
    comply", or one new detector turns every fixture red at once and the
    gate stops being bisectable. Compliance is `check`'s job; the gate
    runs both.
    """
    pdir = args.dir
    src_path = os.path.join(pdir, "program.aeth")
    exp_path = os.path.join(pdir, "expected_stdout.txt")
    if not os.path.isfile(src_path):
        print(f"missing program.aeth in {pdir}", file=sys.stderr)
        return 2
    src = _read(src_path)
    expected = _read(exp_path) if os.path.isfile(exp_path) else ""
    try:
        # H.E.3 multi-file resolution (default-on when ImportDecls present).
        ast, rc = _load(src, src_path, args)
        if rc != 0:
            return 2
        py = emit(ast)
        code = compile(py, src_path + ".py", "exec")
        g = build_namespace()
        g["__name__"] = "__main__"
        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(code, g)
        actual = buf.getvalue()
    except AetherError as e:
        return _report(args, e.diagnostics, 2)
    except Exception as e:  # pragma: no cover
        sys.stderr.write(f"runtime error: {e}\n")
        if args.json:
            _print_doc({"ok": False, "complete": True, "diagnostics": [],
                        "expected": expected, "actual": None,
                        "runtime_error": f"{type(e).__name__}: {e}"})
        return 2
    ok = actual == expected
    if args.json:
        _print_doc({"ok": ok, "complete": True, "diagnostics": [],
                    "expected": expected, "actual": actual})
    elif ok:
        print(f"PASS  {pdir}")
    else:
        print(f"FAIL  {pdir}")
        print("--- expected ---")
        print(expected, end="")
        print("--- actual ---")
        print(actual, end="")
        print("--- end ---")
    return 0 if ok else 1


# ----------------------------------------------------------------------
# H.A.2 — fix-loop entry point
#
# `aether fix-loop <file>` dispatches to one of two paths:
#
#   default (deterministic)
#     Calls the deterministic reference implementation in the package,
#     `aether/fix_loop.py`. Handles E0801 (effect not
#     covered) and E0701 (capability not declared) — the codes whose
#     `extra` dict is sufficient for a mechanical AST rewrite. Used in
#     CI; produces an identical transcript on every invocation. NOT
#     "AI-driven."
#
#   --live
#     Calls Anthropic via the live LLM path used by
#     `demos/payment_workflow/llm_fix_demo.py` — source checkout only,
#     since demos/ is not in the wheel. Handles arbitrary
#     errors including logic errors that the deterministic path cannot
#     repair (E0301, E0302, E0304, E0305). Requires
#     ANTHROPIC_API_KEY. If the env var is missing, fails with a clear
#     message — does NOT silently fall back to deterministic.
#
# The two paths are documented for what they are. Never conflated.
# ----------------------------------------------------------------------

def cmd_fix_loop(args) -> int:
    """Dispatch to deterministic (default) or --live LLM path.
    Exit: 0 clean, 1 not repaired (not_repaired / stuck / widened under
    --allow-widen / rejected --live fix), 2 usage, 3 crash."""
    if not os.path.isfile(args.file):
        raise _UsageError(f"file not found: {args.file}")

    if args.live:
        # Live LLM path — calls Anthropic. Requires ANTHROPIC_API_KEY.
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.stderr.write(
                "aether fix-loop --live: ANTHROPIC_API_KEY not set.\n"
                "  The live path calls Anthropic for diagnostics the\n"
                "  deterministic path cannot mechanically repair.\n"
                "  Set ANTHROPIC_API_KEY, or omit --live for the\n"
                "  deterministic path (E0801 + E0701 only).\n"
            )
            return 2
        # The live path drives the demo in demos/payment_workflow/, which
        # the wheel does not ship: it runs from a source checkout only.
        here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(here))
        for d in (os.path.join(repo_root, "demos", "payment_workflow"), repo_root):
            if d not in sys.path:
                sys.path.insert(0, d)
        try:
            from llm_fix_demo import _do_live   # type: ignore
        except ImportError as e:
            sys.stderr.write(
                f"aether fix-loop --live: import failed: {e}\n"
                "  --live drives demos/payment_workflow/llm_fix_demo.py and\n"
                "  runs from a source checkout only. The deterministic path\n"
                "  (without --live) works in an installed copy.\n")
            return 2
        from pathlib import Path
        transcript = args.out_transcript or str(
            Path(args.file).with_suffix(".live.transcript.json"))
        if os.path.abspath(transcript) == os.path.abspath(args.file):
            sys.stderr.write("aether fix-loop --live: --out-transcript "
                             "must not be the input file\n")
            return 2
        rc = _do_live(args.file, transcript, label=f"cli ({args.file})")
        if rc != 0:
            return rc
        return _judge_live_fix(transcript, args)

    # Deterministic path (default) — part of the package, so it works in
    # a pip-installed copy. It used to be imported from demos/, which no
    # wheel has ever shipped (BUGS.md BUG-026).
    from . import fix_loop
    from pathlib import Path
    # The defaults are fix_loop.main's own; spelled here so `--json` can
    # name and read what was written.
    out_src = args.out_source or str(Path(args.file).with_suffix(".fixed.aeth"))
    out_tr = args.out_transcript or str(
        Path(args.file).with_suffix(".transcript.json"))
    argv = [args.file, "--out-source", out_src, "--out-transcript", out_tr]
    if args.quiet or args.json:
        argv += ["--quiet"]
    if args.allow_widen:
        argv += ["--allow-widen"]
    rc = fix_loop.main(argv)
    if args.json and rc in (EXIT_USAGE, EXIT_CRASH):
        _print_doc(error_doc("usage" if rc == EXIT_USAGE else "crash",
                             "fix-loop failed; the reason is on stderr"))
        return rc
    if args.json:
        with open(out_tr, encoding="utf-8") as f:
            transcript = json.load(f)
        _print_doc({"ok": rc == EXIT_CLEAN, "complete": True,
                    "diagnostics": [],
                    "status": transcript[-1].get("status"),
                    "final": transcript[-1],
                    "fixed_source": out_src.replace(os.sep, "/"),
                    "transcript": out_tr.replace(os.sep, "/")})
    return rc


def _judge_live_fix(transcript_path: str, args) -> int:
    """The live path's verdict used to be `sdk.check(fixed).ok` alone, so
    a model that "fixed" an E0801 by widening the effects clause passed
    (audit 2026-09-24 D1). Hold its output to the deterministic loop's
    rule: a fix that declares more effects/capabilities than the input is
    rejected (exit 1) and tagged `weakens_constraint` in the transcript;
    `--allow-widen` keeps it, with a warning, and still exits 1."""
    from .fix_loop import source_widening
    with open(transcript_path, encoding="utf-8") as f:
        tr = json.load(f)
    widen = source_widening(tr["input"]["source"], tr["fixed_source"],
                            args.file)
    if not widen:
        return 0
    tr["weakens_constraint"] = True
    tr["widens"] = widen
    if not args.allow_widen:
        tr["rejected"] = "the fix widens declared effects/capabilities"
    with open(transcript_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(tr, f, indent=2)
    verdict = ("WARNING: kept under --allow-widen" if args.allow_widen
               else "REJECTED")
    sys.stderr.write(
        f"aether fix-loop --live: {verdict}: the model's fix widens declared "
        f"effects/capabilities ({'; '.join(widen)}); remove or replace the "
        "offending call instead\n")
    return 1


# ----------------------------------------------------------------------
# argparse wiring
# ----------------------------------------------------------------------

class _UsageError(Exception):
    """A bad flag, value or path: exit 2, nothing was analysed."""


class _Parser(argparse.ArgumentParser):
    """argparse, but a usage error comes back to `main` instead of
    `sys.exit(2)`, so `--json` can still print its one document. Sub-
    parsers are built from the parent's class, so they inherit this."""

    def error(self, message):
        self.print_usage(sys.stderr)
        raise _UsageError(f"{self.prog}: error: {message}")


# How an AetherError that escaped a command ends the run: the source did
# not parse (4), Aether could not emit/run it (3: its limit, not yours),
# or the program violated a checked rule — a finding (1).
_ESCAPED_EXIT = {"lex": EXIT_INCOMPLETE, "parse": EXIT_INCOMPLETE,
                 "emit": EXIT_CRASH, "internal": EXIT_CRASH}


def main(argv=None) -> int:
    """Every exit goes through here, so every exit is one of the table's
    five codes and every `--json` run prints one JSON document, even when
    the run crashed (it used to be a raw traceback and exit 1)."""
    raw = sys.argv[1:] if argv is None else list(argv)
    as_json, debug = "--json" in raw, "--debug" in raw
    try:
        args = _build_parser().parse_args(raw)
    except _UsageError as e:
        return _fail(as_json, EXIT_USAGE, "usage", str(e))
    try:
        return _dispatch(args)
    except _UsageError as e:
        return _fail(as_json, EXIT_USAGE, "usage", f"aether: {e}")
    except AetherError as e:
        rc = _ESCAPED_EXIT.get(e.diag.category, EXIT_FINDINGS)
        return _report(args, e.diagnostics, rc, complete=rc == EXIT_FINDINGS)
    except FileNotFoundError as e:
        return _fail(as_json, EXIT_USAGE, "usage", f"file not found: {e}")
    except (UnicodeDecodeError, IsADirectoryError, PermissionError) as e:
        return _fail(as_json, EXIT_INCOMPLETE, "input",
                     f"aether: could not read the input: {type(e).__name__}: {e}")
    except Exception as e:
        # Aether itself failed: a bug in Aether, not in the input.
        if debug or not as_json:
            traceback.print_exc()
        return _fail(as_json, EXIT_CRASH, "crash",
                     f"aether: internal error: {type(e).__name__}: {e} — "
                     "this is a bug in Aether, not in your code; please "
                     "report it (see BUGS.md)")


def _fail(as_json: bool, rc: int, kind: str, message: str) -> int:
    sys.stderr.write(message.rstrip() + "\n")
    if as_json:
        _print_doc(error_doc(kind, message))
    return rc


def _dispatch(args) -> int:
    return {"parse": cmd_parse, "emit": cmd_emit, "pack": cmd_pack,
            "check": cmd_check, "check-py": cmd_check_py, "run": cmd_run,
            "test": cmd_test, "fmt": cmd_fmt,
            "fix-loop": cmd_fix_loop}[args.cmd](args)


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="aether", description="Aether toolchain")
    p.add_argument("--json", action="store_true",
                   help="print exactly one JSON document on stdout (every "
                        "diagnostic as Diagnostic.to_dict()); stderr keeps "
                        "only human text")
    p.add_argument("--debug", action="store_true",
                   help="print the traceback of an internal error even "
                        "under --json")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("parse", help="parse a file and print its AST")
    sp.add_argument("file")

    sp = sub.add_parser("emit", help="emit Python source for a file")
    sp.add_argument("file")
    sp.add_argument("--no-import-resolution", action="store_true",
                    help="opt out of default-on multi-file import resolution "
                         "(H.E.3); treat ImportDecls as opaque")
    sp.add_argument("--release", action="store_true",
                    help="elide effect frames and ensures asserts; keep "
                         "requires + refinement boundary checks")

    sp = sub.add_parser("pack",
                        help="emit FILE as an importable Python package "
                             "with a contract-checked boundary")
    sp.add_argument("file")
    sp.add_argument("--out", default="dist",
                    help="output directory (default: dist)")
    sp.add_argument("--name", default=None,
                    help="package name (default: the .aeth basename)")
    sp.add_argument("--no-import-resolution", action="store_true",
                    help="opt out of default-on multi-file import resolution")

    sp = sub.add_parser("check-py",
                        help="run the language-independent detectors over "
                             "Python files or directories (sinks + "
                             "capability; no effect composition, no marker "
                             "taint)")
    sp.add_argument("target", nargs="+", metavar="PATH",
                    help="Python file(s) and/or directory(ies); a directory "
                         "is walked recursively for .py, skipping .git, "
                         ".venv, node_modules, build and other vendored trees")
    sp.add_argument("--strict", action="store_true",
                    help="also report E0711 (dynamic filesystem paths) and "
                         "the capability inventory (E0701); both are held "
                         "back by default because they fire on ordinary "
                         "Python - see bench/py_frontend/REPORT.md")
    sp.add_argument("--sarif", action="store_true",
                    help="emit SARIF v2.1.0 on stdout for GitHub Code "
                         "Scanning; paths are relative to the working "
                         "directory, which under CI is the checkout root")
    sp.add_argument("--min-confidence", type=float, default=0.0,
                    metavar="FLOAT",
                    help="hide findings the analysis is less sure of, on a "
                         "0-1 scale (see transpiler/aether/confidence.py): "
                         "0.6 is a sink matched by method name on an "
                         "unresolved receiver, 0.95 one resolved through "
                         "the imports. A filter on the output; it changes "
                         "nothing about what the detectors found")
    sp.add_argument("--jobs", type=int, default=None, metavar="N",
                    help="analyze files in N worker processes. Default: a "
                         "pool only when it can pay for itself (more than "
                         f"{_JOBS_THRESHOLD} files on a multi-core machine), "
                         "else the serial loop — so single-file and "
                         "small-tree runs stay byte-identical. --jobs 1 "
                         "forces serial. Output order does not depend on it")
    sp.add_argument("--no-unprovable", action="store_true",
                    help="with --json, leave each file's `unprovable` rows "
                         "empty (they are most of the document on a real "
                         "tree); findings and the exit code are unchanged")

    sp = sub.add_parser("check", help="parse + emit (no execution)")
    sp.add_argument("file")
    sp.add_argument("--no-static-effects", action="store_true",
                    help="opt out of default-on static effect checking (B.1)")
    sp.add_argument("--no-scope-check", action="store_true",
                    help="opt out of default-on reach-scope checks (E0710 net host + E0711 fs path); "
                         "allows unpinned hosts + dynamic fs paths")
    sp.add_argument("--no-capability-check", action="store_true",
                    help="opt out of default-on capability check (B.3)")
    sp.add_argument("--no-exhaustiveness-check", action="store_true",
                    help="opt out of default-on match-exhaustiveness check (E0202)")
    sp.add_argument("--capability-strict", action="store_true",
                    help="(deprecated; capability check is now default-on, "
                         "this flag is a no-op alias kept for backward compat)")
    sp.add_argument("--collect-errors", action="store_true",
                    help="surface every recoverable parse error in one pass "
                         "(C.6); useful for agent fix-loops")
    sp.add_argument("--no-module-check", action="store_true",
                    help="opt out of default-on module-validation pass (D.3)")
    sp.add_argument("--no-import-resolution", action="store_true",
                    help="opt out of default-on multi-file import resolution "
                         "(H.E.3); treat ImportDecls as opaque")
    sp.add_argument("--prove", action="store_true",
                    help="force the SMT contract-proving pass; errors if "
                         "z3-solver is missing (pip install 'aether-lang[smt]'). "
                         "The pass already runs by default when z3 is installed")
    sp.add_argument("--no-prove", action="store_true",
                    help="disable the default-on SMT contract-proving pass")
    sp.add_argument("--prove-timeout-ms", type=int, default=5000,
                    help="per-obligation Z3 timeout in ms (default 5000)")

    sp = sub.add_parser("run", help="parse + emit + execute")
    sp.add_argument("file")
    sp.add_argument("--release", action="store_true",
                    help="elide effect frames and ensures asserts; keep "
                         "requires + refinement boundary checks")
    sp.add_argument("--effect-strict", action="store_true",
                    help="enforce that observed effects are subset of declared")
    sp.add_argument("--deterministic", action="store_true",
                    help="C.5: pin time + random seed for reproducible runs "
                         "(also activated by env var AETHER_DETERMINISTIC=1; "
                         "seed read from AETHER_SEED, default 0)")
    sp.add_argument("--no-static-effects", action="store_true",
                    help="opt out of default-on static effect checking (B.1)")
    sp.add_argument("--no-scope-check", action="store_true",
                    help="opt out of default-on reach-scope checks (E0710 net host + E0711 fs path); "
                         "allows unpinned hosts + dynamic fs paths")
    sp.add_argument("--no-capability-check", action="store_true",
                    help="opt out of default-on capability check (B.3)")
    sp.add_argument("--no-exhaustiveness-check", action="store_true",
                    help="opt out of default-on match-exhaustiveness check (E0202)")
    sp.add_argument("--capability-strict", action="store_true",
                    help="(deprecated; capability check is now default-on, "
                         "this flag is a no-op alias kept for backward compat)")
    sp.add_argument("--no-import-resolution", action="store_true",
                    help="opt out of default-on multi-file import resolution "
                         "(H.E.3); treat ImportDecls as opaque")

    sp = sub.add_parser("test", help="run a reference program directory")
    sp.add_argument("dir")
    sp.add_argument("--no-import-resolution", action="store_true",
                    help="opt out of default-on multi-file import resolution "
                         "(H.E.3); treat ImportDecls as opaque")

    sp = sub.add_parser("fmt", help="parse + canonical pretty-print (C.4)")
    sp.add_argument("file")
    sp.add_argument("--write", action="store_true",
                    help="overwrite the input file in place")
    sp.add_argument("--check", action="store_true",
                    help="exit 1 if the file is not canonically formatted "
                         "(useful for CI)")

    sp = sub.add_parser(
        "fix-loop",
        help="run the agent fix-loop against <file>",
        description=(
            "Aether agent fix-loop. "
            "Default (deterministic): reproducible AST rewrites for E0801 "
            "(effect not covered) and E0701 (capability not declared). Both "
            "repairs WIDEN a declaration, so by default they are not applied: "
            "the loop reports 'not_repaired' with the call to remove or "
            "replace, and exits non-zero (--allow-widen applies them). Used "
            "in CI. NOT 'AI-driven'. "
            "--live: calls Anthropic for arbitrary errors including logic "
            "errors (E0301/E0302/E0304/E0305). Requires ANTHROPIC_API_KEY. "
            "If unset, fails with a clear message. "
            "The two paths are documented separately and never conflated."
        ),
    )
    sp.add_argument("file", help="path to broken .aeth source")
    sp.add_argument("--live", action="store_true",
                    help="use the live LLM path (calls Anthropic; requires "
                         "ANTHROPIC_API_KEY). Default is the deterministic path.")
    sp.add_argument("--out-source", default=None,
                    help="where to write the fixed .aeth")
    sp.add_argument("--out-transcript", default=None,
                    help="where to write the fix transcript JSON")
    sp.add_argument("--allow-widen", action="store_true",
                    help="apply (or, with --live, keep) a repair that widens "
                         "a declared effects clause or module capability "
                         "list. Off by default: widening is what Aether "
                         "refuses. Each such step is tagged "
                         "weakens_constraint and the exit stays non-zero.")
    sp.add_argument("--quiet", action="store_true",
                    help="suppress progress output")

    return p


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
