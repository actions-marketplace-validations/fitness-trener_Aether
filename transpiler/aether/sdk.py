"""C.2 Agent SDK — the public Python surface for tool authors.

This is the "no other language has this" piece referenced in the YC
narrative: a single import gives an AI agent or build tool the entry
points it actually needs — parse, check, run, grade, edit — with
structured diagnostics shaped for fix-loops.

Public API (everything below is the supported surface):

    parse(source, filename="<sdk>")              -> ParseResult
    check(source_or_ast, filename="<sdk>")       -> CheckResult
    run(source, stdin="", timeout_ms=5000,
        deterministic=False)                     -> RunResult
    grade(source, expected_stdout, stdin="",
          timeout_ms=5000, deterministic=False)  -> GradeResult
    pretty(ast, source=None)                     -> str
    edit(source, transform)                      -> str

`source` is always a `str` containing Aether source. The SDK is
stateless — every call is a fresh pass through the toolchain. Use the
`Source` convenience class when you want to carry source + AST +
filename together.

Diagnostics returned by the SDK are the same `aether.diagnostics.Diagnostic`
dataclass used internally — `.code`, `.message`, `.position`, `.suggestion`,
`.extra` — so anything the compiler knows about a problem is reachable
without parsing strings. `CheckResult.to_dict()` is the document
`aether --json check` prints, every diagnostic as `Diagnostic.to_dict()`.

`TIMEOUT_ENFORCED` is part of this surface: False means this platform has
no POSIX SIGALRM, so `timeout_ms` is not enforced and a runaway program
hangs the caller. Each `RunResult.timeout_enforced` reports the same fact
per call.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import io
import sys
from contextlib import redirect_stdout, redirect_stderr

from .parser import parse as _parse_strict, parse_collect
from .emitter import emit as _emit
from .pretty import pretty as _pretty
from .runtime import build_namespace, set_deterministic
from .runner import compile_and_run as _compile_and_run, TIMEOUT_ENFORCED
from .passes import analyze
from .passes.imports import load_program
from .diagnostics import Diagnostic, Position, AetherError


# ----------------------------------------------------------------------
# Result types
# ----------------------------------------------------------------------

@dataclass
class ParseResult:
    """Outcome of parsing. `ast` may be a partial program if there were
    parse errors that the recovery pass could sync past."""
    ast: Optional[Dict[str, Any]]
    diagnostics: List[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diagnostics


@dataclass
class CheckResult:
    """Outcome of all static passes (parse + effects + capability).
    `complete` is False when some of the source did not parse or an
    import did not resolve — what was not loaded was not analysed."""
    ast: Optional[Dict[str, Any]]
    diagnostics: List[Diagnostic] = field(default_factory=list)
    complete: bool = True

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    def to_dict(self) -> Dict[str, Any]:
        """The same document `aether --json check` prints: {ok, complete,
        diagnostics: [Diagnostic.to_dict(ast)]} (audit 2026-09-24 D6)."""
        return {"ok": self.ok, "complete": self.complete,
                "diagnostics": [d.to_dict(self.ast) for d in self.diagnostics]}


@dataclass
class RunResult:
    """Outcome of executing a program."""
    ok: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed_ms: int = 0
    diagnostic: Optional[Diagnostic] = None
    #: Whether `timeout_ms` was actually armed for this run. False on a
    #: platform without POSIX SIGALRM, where a runaway program hangs the
    #: caller instead of returning exit_code=124 — so "no timeout fired"
    #: and "no timer exists here" are distinguishable.
    timeout_enforced: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """The keys `aether --json run` prints: {ok, complete, diagnostics,
        stdout, stderr}. `exit_code` stays an attribute: it is the
        runner's table (2 = AetherError), not the CLI's."""
        diag = [self.diagnostic] if self.diagnostic else []
        return {"ok": self.ok,
                "complete": not any(d.category in ("lex", "parse") for d in diag),
                "diagnostics": [d.to_dict() for d in diag],
                "stdout": self.stdout, "stderr": self.stderr}


@dataclass
class GradeResult:
    """Outcome of grading a candidate against expected stdout."""
    ok: bool
    expected: str = ""
    actual: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed_ms: int = 0
    diagnostic: Optional[Diagnostic] = None


# ----------------------------------------------------------------------
# Source convenience wrapper
# ----------------------------------------------------------------------

@dataclass
class Source:
    """Caches the text + lazily-parsed AST. Useful for fix-loops that
    re-check after each candidate edit."""
    text: str
    filename: str = "<sdk>"
    _ast_cache: Optional[Dict[str, Any]] = None
    _diags_cache: Optional[List[Diagnostic]] = None

    @classmethod
    def from_text(cls, text: str, filename: str = "<sdk>") -> "Source":
        return cls(text=text, filename=filename)

    @classmethod
    def from_path(cls, path: str) -> "Source":
        with open(path, "r", encoding="utf-8-sig") as f:
            return cls(text=f.read(), filename=path)

    def parse(self) -> ParseResult:
        if self._ast_cache is None:
            ast, diags = parse_collect(self.text, self.filename)
            self._ast_cache = ast
            self._diags_cache = list(diags)
        return ParseResult(ast=self._ast_cache,
                           diagnostics=list(self._diags_cache or []))


# ----------------------------------------------------------------------
# Public entry points
# ----------------------------------------------------------------------

def parse(source: str, filename: str = "<sdk>") -> ParseResult:
    """Lenient parse (uses C.6 multi-error recovery). The returned
    `ast` is a partial Program containing whichever top-level decls
    parsed cleanly; consult `diagnostics` for every parse error
    surfaced along the way."""
    ast, diags = parse_collect(source, filename)
    return ParseResult(ast=ast, diagnostics=list(diags))


def check(source_or_ast, filename: str = "<sdk>") -> CheckResult:
    """Parse + resolve imports + run every default-on static pass.

    Accepts either a source string or an already-parsed AST dict. Loading
    is `passes.imports.load_program`, the same loader `aether check`
    uses, so an `import` resolves here exactly as it does on the CLI
    (against the directory of `filename`; the working directory for a
    pseudo-name like `<sdk>`). Never raises for bad source: a lex error
    comes back as its diagnostic with `ast=None`.

    Returns the diagnostics of parse (C.6 recovery — a partial AST is
    still analysed) and of EVERY stage of the analysis registry, in stage
    order. That is what `aether --json check` prints; plain-text `check`
    prints only the first stage that has diagnostics (and says how many
    it held back). An import error (E0705/E0706, or a parse error in an
    imported file) stops before analysis, as it does on the CLI.
    """
    ast, all_diags, import_diags = load_program(source_or_ast, filename)
    complete = not (all_diags or import_diags)
    if import_diags:
        return CheckResult(ast=ast, diagnostics=all_diags + import_diags,
                           complete=False)
    if ast is not None and ast.get("decls"):
        for stage, diags in analyze(ast):
            for d in diags:
                d.stage = stage     # rides along in to_dict() (D6)
            all_diags.extend(diags)
    return CheckResult(ast=ast, diagnostics=all_diags, complete=complete)


def _rehydrate(d: Dict[str, Any]) -> Diagnostic:
    """Coerce one of `bench.harness`'s plain-dict diagnostics into the
    dataclass the rest of the SDK returns.

    The harness deliberately speaks dicts — it must stay importable
    without the transpiler package — and its dicts are partial: of the
    five `compile_and_run` can return, three (E9001 emit, E9002
    emit-compile, E9003 runtime) carry only code/category/message. The
    defaults below are `Diagnostic`'s own.

    Total by construction, which is why there is no `try` here. `position`
    is read field by field rather than splatted, so an unexpected key
    cannot raise, and every other field is a `.get` into a dataclass that
    does no validation. This coercion used to sit inside
    `except Exception: pass`: a shape change in the harness would have
    produced `diagnostic=None` on a run that DID fail, leaving `run()`
    reporting `ok=False` with no code for a fix-loop to dispatch on — the
    one thing the SDK exists to hand over.
    """
    pos = d.get("position")
    if not isinstance(pos, dict):
        pos = {}
    return Diagnostic(
        code=d.get("code", ""),
        category=d.get("category", ""),
        severity=d.get("severity", "error"),
        message=d.get("message", ""),
        position=Position(pos.get("line", 0), pos.get("column", 0)),
        suggestion=d.get("suggestion"),
        confidence=d.get("confidence", 0.0),
        extra=d.get("extra", {}),
    )


def run(source: str, stdin: str = "", timeout_ms: int = 5000,
        deterministic: bool = False, filename: str = "<sdk>") -> RunResult:
    """Compile + execute the program. Captures stdout, surfaces any
    `AetherError` as a structured diagnostic. Honours the C.5
    deterministic test mode when `deterministic=True`.

    `timeout_ms` is enforced with POSIX `SIGALRM`; on a platform without
    it (Windows) there is no enforcement and a runaway program hangs the
    calling process. `aether.sdk.TIMEOUT_ENFORCED` says which applies, and
    every `RunResult` carries `timeout_enforced` so a caller never has to
    infer it. This used to read "uses the bench helper where available",
    describing a fallback that did not exist: the helper lived in `bench/`,
    which is not in the wheel, so every installed copy took the except
    branch below and reported a working program as a failed run
    (BUGS.md BUG-008). The runner is now in the package.
    """
    import time
    t0 = time.time()
    try:
        if deterministic:
            set_deterministic(0)
        res = _compile_and_run(source, filename, stdin_text=stdin,
                               timeout_ms=timeout_ms)
        diag = _rehydrate(res["diagnostic"]) if res.get("diagnostic") else None
        return RunResult(
            ok=bool(res.get("ok")),
            stdout=res.get("actual", ""),
            stderr=res.get("stderr", ""),
            exit_code=int(res.get("exit_code", 0)),
            elapsed_ms=int(res.get("elapsed_ms", 0)),
            diagnostic=diag,
            timeout_enforced=bool(res.get("timeout_enforced", False)),
        )
    except Exception as e:
        return RunResult(
            ok=False,
            stderr=f"sdk.run error: {type(e).__name__}: {e}",
            exit_code=1,
            elapsed_ms=int((time.time() - t0) * 1000),
            timeout_enforced=TIMEOUT_ENFORCED,
        )


def grade(source: str, expected_stdout: str, stdin: str = "",
          timeout_ms: int = 5000, deterministic: bool = False,
          filename: str = "<sdk>") -> GradeResult:
    """Run + compare to expected stdout. Wraps `run()` with the
    bench-harness comparison contract: `ok=True` iff exit 0 AND stdout
    matches `expected_stdout` byte-for-byte. The bench harness's
    `grade-from-pair` is fine for files on disk; this is the same
    semantics for in-memory candidates."""
    r = run(source, stdin=stdin, timeout_ms=timeout_ms,
            deterministic=deterministic, filename=filename)
    ok = r.ok and r.stdout == expected_stdout
    return GradeResult(
        ok=ok,
        expected=expected_stdout,
        actual=r.stdout,
        stderr=r.stderr,
        exit_code=r.exit_code,
        elapsed_ms=r.elapsed_ms,
        diagnostic=r.diagnostic,
    )


def pretty(ast: Dict[str, Any], source: Optional[str] = None) -> str:
    """Re-export of the C.1 canonical pretty-printer. Pass `source` to
    keep its full-line comments."""
    return _pretty(ast, source)


def edit(source: str, transform: Callable[[Dict[str, Any]], Dict[str, Any]],
         filename: str = "<sdk>") -> str:
    """Structural edit: parse, hand the AST to `transform`, re-pretty.

    The transform receives a mutable AST dict (the Program node) and
    returns the new AST (the same node, mutated, or a fresh one).
    This is the primitive that lets a fix-loop apply an edit by
    operating on structure, not text — far less fragile than line
    diffs against an LLM-generated patch.
    """
    ast = _parse_strict(source, filename)
    new_ast = transform(ast)
    if new_ast is None:
        new_ast = ast       # transforms that mutate in place may return None
    # `source` keeps its full-line comments (a `// expect:` header among
    # them) — see `pretty`.
    return _pretty(new_ast, source)


__all__ = [
    "ParseResult", "CheckResult", "RunResult", "GradeResult", "Source",
    "parse", "check", "run", "grade", "pretty", "edit",
    "Diagnostic", "AetherError",
]
