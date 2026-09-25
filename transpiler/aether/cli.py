"""Aether CLI — single entry point for the v0.1 toolchain.

Subcommands:
    aether parse  <file>           Lex + parse, print canonical AST as JSON
    aether emit   <file>           Emit Python source for the program
    aether check  <file>           Parse + emit (without running) — exit 0 if OK
    aether run    <file>           Parse, emit, exec; mirrors stdout/stderr
    aether test   <dir>            Run a reference-program directory: expects
                                   `program.aeth` and `expected_stdout.txt`

Global flag: --json — emit machine-readable error output. The CLI prints a
single JSON object on stderr and exits non-zero on failure.
"""

from __future__ import annotations
import argparse
import io
import json
import os
import sys
from contextlib import redirect_stdout
from typing import Any, Dict

from .diagnostics import AetherError, Diagnostic
from .lexer import tokenize
from .parser import parse, parse_collect
from .emitter import emit
from .pretty import pretty
from .passes import analyze
from .passes.imports import resolve_imports
from .runtime import build_namespace, set_effect_strict, set_deterministic


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _emit_error(diag: Diagnostic, as_json: bool):
    if as_json:
        json.dump({"ok": False, "diagnostic": diag.to_dict()}, sys.stderr)
        sys.stderr.write("\n")
    else:
        sys.stderr.write(
            f"[{diag.code}] {diag.severity} ({diag.category}) "
            f"at line {diag.position.line}, col {diag.position.column}: "
            f"{diag.message}\n"
        )
        if diag.suggestion:
            sys.stderr.write(f"  hint: {diag.suggestion}\n")


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


def _has_imports(ast: Dict[str, Any]) -> bool:
    """True if the AST contains any top-level ImportDecl."""
    for d in ast.get("decls", []) or []:
        if d.get("kind") == "ImportDecl":
            return True
    return False


def _maybe_resolve_imports(ast: Dict[str, Any], source_path: str, args) -> tuple:
    """H.E.3 multi-file resolution gate.

    If the parsed AST contains at least one ImportDecl and the user has not
    opted out via --no-import-resolution, run resolve_imports and surface
    any diagnostics. Returns (combined_ast, exit_code). When exit_code != 0
    the caller should bail. When ImportDecls are absent or resolution is
    disabled, returns the original AST and exit_code=0.
    """
    if getattr(args, "no_import_resolution", False):
        return ast, 0
    if not _has_imports(ast):
        return ast, 0
    combined, diags = resolve_imports(ast, source_path)
    if diags:
        for d in diags:
            _emit_error(d, args.json)
        return combined, 2
    return combined, 0


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
    ast = parse(src, args.file)
    ast, rc = _maybe_resolve_imports(ast, args.file, args)
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
    ast = parse(src, args.file)
    ast, rc = _maybe_resolve_imports(ast, args.file, args)
    if rc != 0:
        return rc
    py = emit(ast)
    name = args.name or os.path.splitext(os.path.basename(args.file))[0]
    if not name.isidentifier():
        print(f"aether: package name {name!r} is not a valid Python "
              f"identifier (use --name)", file=sys.stderr)
        return 2
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
    formatted = pretty(ast)
    if getattr(args, "check", False):
        if src == formatted:
            return 0
        if not args.json:
            sys.stderr.write(f"would reformat: {args.file}\n")
        else:
            json.dump({"ok": False, "would_reformat": args.file}, sys.stderr)
            sys.stderr.write("\n")
        return 1
    if getattr(args, "write", False):
        with open(args.file, "w", encoding="utf-8") as f:
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
    "semantic":   "no_exhaustiveness_check",  # E0202-E0207
    "capability": "no_capability_check",    # B.3
    "modules":    "no_module_check",        # D.3
}


def _run_analysis(ast, args) -> int:
    """Run the static-analysis registry in stage order. Prints the first
    stage that produced diagnostics and returns 2; 0 if every stage is
    clean. Short-circuiting per stage is the pre-registry behaviour."""
    skip = {stage for stage, flag in _STAGE_OPT_OUT.items()
            if getattr(args, flag, False)}
    for _stage, diags in analyze(ast, skip=skip):
        if diags:
            for d in diags:
                _emit_error(d, args.json)
            return 2
    return 0


def _run_smt_check(ast, as_json, timeout_ms):
    """Opt-in SMT contract proving (--prove, v2 roadmap 1.1).
    Returns (rc, summary|None). rc 2 iff any clause was refuted."""
    from .passes.smt import HAVE_Z3, check_contracts_smt
    if not HAVE_Z3:
        msg = ("--prove requires the z3-solver package "
               "(pip install 'aether-lang[smt]')")
        if as_json:
            json.dump({"ok": False, "error": msg}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"aether: {msg}", file=sys.stderr)
        return 2, None
    diags, summary = check_contracts_smt(ast, timeout_ms=timeout_ms)
    for d in diags:
        _emit_error(d, as_json)
    if not as_json:
        print("prove: {proved} proved, {refuted} refuted, "
              "{timeout} timeout, {skipped} skipped".format(**summary))
    rc = 2 if any(d.severity == "error" for d in diags) else 0
    return rc, summary


# Stages that do not apply to Python source.
#   effects  — E0801 compares a call site against a DECLARED effects
#              clause; Python has none, so there is nothing to compare.
#   semantic — E0202-E0207 check Aether language constructs (match
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
    from .py_frontend import py_to_ir
    from .passes import analyze_flat
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
            ast, unprovable, meta = py_to_ir(src)
        except (SyntaxError, ValueError) as e:
            # py2 sources, templates and test fixtures are normal in a real
            # tree; they are counted, not fatal.
            return ("unreadable", path, type(e).__name__, str(e))
        diags = analyze_flat(ast, skip=skip)
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
        for t in missing:
            sys.stderr.write(f"aether: no such file or directory: {t}\n")
        return 2
    if getattr(args, "sarif", False) and args.json:
        sys.stderr.write("aether: --sarif and --json are two different "
                         "output formats; pick one\n")
        return 2
    min_conf = getattr(args, "min_confidence", 0.0) or 0.0
    if not 0.0 <= min_conf <= 1.0:
        sys.stderr.write(f"aether: --min-confidence must be in [0,1], "
                         f"got {min_conf}\n")
        return 2
    # A usage error on our own flag must read like one. Unvalidated,
    # `--jobs 0` scanned serially with no message and `--jobs 999` died
    # with a raw ValueError traceback and exit 1 — Windows caps
    # ProcessPoolExecutor at 61 workers, which is a platform fact, not
    # something the caller should have to know.
    jobs_arg = getattr(args, "jobs", None)
    if jobs_arg is not None and jobs_arg < 1:
        sys.stderr.write(f"aether: --jobs must be >= 1, got {jobs_arg}\n")
        return 2
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
    # file. It is reported on stderr in EVERY output mode — a `--sarif`
    # or `--json` run used to swallow it (the text mode said it for one
    # file only, and then failed the run for it while the other modes
    # did not). The rule, applied uniformly: unparseable input never
    # fails the run; an analyzer crash always does.
    for p, why, detail in unreadable:
        sys.stderr.write(f"aether: could not parse {p}: {why}: {detail}\n")
    if skipped_dirs:
        sys.stderr.write(f"aether: {len(skipped_dirs)} director"
                         f"{'y' if len(skipped_dirs) == 1 else 'ies'} skipped "
                         f"as vendored/build output: "
                         + ", ".join(skipped_dirs) + "\n")

    if getattr(args, "sarif", False):
        from .risk import risk_of
        from .sarif import to_sarif
        # Relative to the working directory, which under CI is the
        # checkout root. Code Scanning silently drops a result whose
        # artifactLocation is not relative to it. Column, suggestion and
        # `extra` ride along so the SARIF says what the JSON says.
        print(json.dumps(to_sarif(
            [{"path": p,
              "findings": [{"code": d.code, "message": d.message,
                            "line": d.position.line,
                            "column": d.position.column,
                            "risk": risk_of(d.code),
                            "confidence": d.confidence,
                            "suggestion": d.suggestion, "extra": d.extra}
                           for d in ds]}
             for p, ds, _u, _m in results], base=os.getcwd(),
            unreadable=[(p, f"{why}: {detail}") for p, why, detail in unreadable]),
            indent=2))
        return 2 if (n_find or crashed) else 0

    if args.json:
        json.dump({"ok": not n_find and not crashed, "lang": "python",
                   "files": [{"path": p.replace(os.sep, "/"),
                              "diagnostics": [d.to_dict() for d in ds],
                              "unprovable": unp, "meta": meta}
                             for p, ds, unp, meta in results],
                   "unreadable": [{"path": p.replace(os.sep, "/"),
                                   "reason": why, "detail": detail}
                                  for p, why, detail in unreadable],
                   "skipped_dirs": skipped_dirs,
                   "errors": [{"path": p.replace(os.sep, "/"), "error": e}
                              for p, e in crashed]}, sys.stdout)
        sys.stdout.write("\n")
        return 2 if (n_find or crashed) else 0

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
          "E0729/E0730); and the semantic family (E0202-E0207). E0716 "
          "fires on every .executescript method call; no Python spelling tried "
          "clears it.")
    if not strict:
        print("NOT checked by default (--strict adds both): E0711 dynamic "
              "filesystem paths, and the capability inventory (E0701). "
              "Held back by measurement, not taste - see "
              "bench/py_frontend/REPORT.md.")
    return 2 if (n_find or crashed) else 0


def cmd_check(args) -> int:
    src = _read(args.file)
    if getattr(args, "collect_errors", False):
        # C.6 multi-error parser recovery: surface every recoverable
        # parse error in one pass, instead of bailing on the first.
        ast, parse_diags = parse_collect(src, args.file)
        for d in parse_diags:
            _emit_error(d, args.json)
        if parse_diags:
            if args.json:
                json.dump({"ok": False, "diagnostics": [d.to_dict() for d in parse_diags]},
                          sys.stdout)
                sys.stdout.write("\n")
            return 2
    else:
        ast = parse(src, args.file)
    # H.E.3 multi-file resolution (default-on when ImportDecls present).
    ast, rc = _maybe_resolve_imports(ast, args.file, args)
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
    prove_summary = None
    if not getattr(args, "no_prove", False):
        from .passes.smt import HAVE_Z3
        if HAVE_Z3 or getattr(args, "prove", False):
            rc, prove_summary = _run_smt_check(
                ast, args.json, getattr(args, "prove_timeout_ms", 5000))
            if rc != 0:
                return rc
    if args.json:
        out = {"ok": True, "decls": len(ast["decls"])}
        if prove_summary is not None:
            out["prove"] = prove_summary
        json.dump(out, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"OK: {args.file} ({len(ast['decls'])} decls)")
    return 0


def cmd_run(args) -> int:
    if getattr(args, "release", False) and getattr(args, "effect_strict", False):
        print("aether: --release and --effect-strict are mutually exclusive "
              "(strict effect checking needs the frames --release removes)",
              file=sys.stderr)
        return 2
    if args.effect_strict:
        set_effect_strict(True)
    # C.5 deterministic test mode: pin clock + random seed for reproducible runs.
    if getattr(args, "deterministic", False) or os.environ.get("AETHER_DETERMINISTIC"):
        seed = int(os.environ.get("AETHER_SEED", "0"))
        set_deterministic(seed)
    src = _read(args.file)
    ast = parse(src, args.file)
    # H.E.3 multi-file resolution (default-on when ImportDecls present).
    ast, rc = _maybe_resolve_imports(ast, args.file, args)
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
    exec(code, g)
    return 0


def cmd_test(args) -> int:
    """Run a directory containing program.aeth + expected_stdout.txt.

    Exits 0 on match, 1 on mismatch, 2 on compile/runtime error.

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
        ast = parse(src, src_path)
        # H.E.3 multi-file resolution (default-on when ImportDecls present).
        if _has_imports(ast) and not getattr(args, "no_import_resolution", False):
            ast, diags = resolve_imports(ast, src_path)
            if diags:
                for d in diags:
                    _emit_error(d, args.json)
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
        _emit_error(e.diag, args.json)
        return 2
    except Exception as e:  # pragma: no cover
        sys.stderr.write(f"runtime error: {e}\n")
        return 2
    ok = actual == expected
    if args.json:
        json.dump({"ok": ok, "expected": expected, "actual": actual}, sys.stdout)
        sys.stdout.write("\n")
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
    """Dispatch to deterministic (default) or --live LLM path."""
    if not os.path.isfile(args.file):
        sys.stderr.write(f"file not found: {args.file}\n")
        return 2

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
        transcript = args.out_transcript or args.file.replace(
            ".aeth", ".live.transcript.json")
        return _do_live(args.file, transcript, label=f"cli ({args.file})")

    # Deterministic path (default) — part of the package, so it works in
    # a pip-installed copy. It used to be imported from demos/, which no
    # wheel has ever shipped (BUGS.md BUG-026).
    from .fix_loop import main as deterministic_main
    argv = [args.file]
    if args.out_source:
        argv += ["--out-source", args.out_source]
    if args.out_transcript:
        argv += ["--out-transcript", args.out_transcript]
    if args.quiet:
        argv += ["--quiet"]
    return deterministic_main(argv)


# ----------------------------------------------------------------------
# argparse wiring
# ----------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aether", description="Aether v0.1 toolchain")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON output for diagnostics")
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
            "(effect not covered) and E0701 (capability not declared). Used "
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
    sp.add_argument("--quiet", action="store_true",
                    help="suppress progress output")

    args = p.parse_args(argv)
    try:
        if args.cmd == "parse":    return cmd_parse(args)
        if args.cmd == "emit":     return cmd_emit(args)
        if args.cmd == "pack":     return cmd_pack(args)
        if args.cmd == "check":    return cmd_check(args)
        if args.cmd == "check-py": return cmd_check_py(args)
        if args.cmd == "run":      return cmd_run(args)
        if args.cmd == "test":     return cmd_test(args)
        if args.cmd == "fmt":      return cmd_fmt(args)
        if args.cmd == "fix-loop": return cmd_fix_loop(args)
    except AetherError as e:
        _emit_error(e.diag, args.json)
        return 2
    except FileNotFoundError as e:
        sys.stderr.write(f"file not found: {e}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
