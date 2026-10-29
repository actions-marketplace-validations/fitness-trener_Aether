"""Structured diagnostics. Every error has a code, a category, a position,
a human-readable message, and a machine-readable suggestion.

Also the ONE exit-code table and the ONE JSON serializer every surface
uses (`aether check`, `check-py`, `fix-loop`, `tools/scan.py`, the SDK,
the LSP's `aether/check`, SARIF). They used to be five shapes and a
different exit code per surface (audit 2026-09-24 D5/D6); the contract
is stated in docs/SCANNING.md, "Exit codes and the JSON contract".
"""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Optional, List


# Exit codes — identical for check, check-py, fix-loop and tools/scan.py,
# in text, --json and --sarif mode. Precedence when several apply:
# crash > findings > incomplete > clean. Usage errors stop before any
# analysis runs.
EXIT_CLEAN = 0        # everything was analysed; nothing found
EXIT_FINDINGS = 1     # at least one finding (fix-loop: not repaired)
EXIT_USAGE = 2        # bad flag, missing path — nothing was analysed
EXIT_CRASH = 3        # Aether itself failed: a bug in Aether, not your code
EXIT_INCOMPLETE = 4   # some input could not be read or parsed, no findings


def exit_code(findings, incomplete=False, crashed=False) -> int:
    """The table above, applied. `findings` is a count or a bool."""
    if crashed:
        return EXIT_CRASH
    if findings:
        return EXIT_FINDINGS
    if incomplete:
        return EXIT_INCOMPLETE
    return EXIT_CLEAN


def error_doc(kind: str, message: str) -> dict:
    """The `--json` document for a run that produced no analysis: `kind`
    is `usage` (exit 2), `crash` (exit 3) or `input` (exit 4)."""
    return {"ok": False, "complete": False, "diagnostics": [],
            "error": {"kind": kind, "message": message}}


@dataclass
class Position:
    line: int       # 1-based
    column: int     # 1-based

    def to_dict(self) -> dict:
        return {"line": self.line, "column": self.column}


@dataclass
class Diagnostic:
    code: str             # e.g. "E0101"
    # The categories emitted today (not renamed, only documented):
    #   lex, parse                      the source did not parse (E01xx/E0201)
    #   type, effect, capability,       static analysis (the STAGES registry;
    #   module, security                `capability` includes the E07xx
    #                                   security rows on Aether source;
    #                                   `security` is the same rows on a
    #                                   Python finding (check-py))
    #   contract, refinement, runtime,  runtime checks and SMT (E03xx, E09xx),
    #   timeout                         and the runner's E0601 / E9003
    #   emit, internal                  Aether could not emit or run the
    #                                   program (E9001/E9002): its limit or bug
    category: str
    severity: str         # one of: error|warning|info
    message: str
    position: Position
    suggestion: Optional[str] = None
    confidence: float = 0.0
    extra: dict = field(default_factory=dict)
    # Which analysis stage produced it (`passes.STAGES` names, or `smt`);
    # None for lex/parse/import/runtime diagnostics.
    stage: Optional[str] = None

    def to_dict(self, ast=None) -> dict:
        """THE serialized form, on every surface. Every key is always
        present. `patch_target` is the structural splice site in `ast`
        (`passes/patch_target.py`) when an AST is given and the code has
        one, else None — always None for a Python finding, whose IR is not
        the user's source."""
        patch_target = None
        if ast is not None:
            from .passes.patch_target import compute_patch_target
            patch_target = compute_patch_target(ast, self)
        return {
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "position": self.position.to_dict(),
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "extra": self.extra,
            "stage": self.stage,
            "patch_target": patch_target,
        }


class AetherError(Exception):
    """Wrapped diagnostic. Carries either a single Diagnostic (legacy
    single-error API) or a non-empty list of Diagnostics (multi-error
    parser-recovery API, C.6). The `.diag` attribute is the first
    diagnostic and remains stable for code that expected one error.

    The CLI catches these and emits structured JSON when --json is set."""

    def __init__(self, diag, diagnostics: Optional[List[Diagnostic]] = None):
        if diagnostics is None:
            diagnostics = [diag]
        if not diagnostics:
            raise ValueError("AetherError needs at least one Diagnostic")
        if diag is None:
            diag = diagnostics[0]
        n = len(diagnostics)
        head = (
            f"[{diag.code}] {diag.message} "
            f"at line {diag.position.line}, col {diag.position.column}"
        )
        if n > 1:
            head = f"{head} (+ {n - 1} more)"
        super().__init__(head)
        self.diag = diag
        self.diagnostics: List[Diagnostic] = list(diagnostics)
