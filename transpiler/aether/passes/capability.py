"""Capability-gating pass (Phase B.3 — transitive, default-on).

Walks the AST once, computes the effective effect set for every
FunctionDecl (declared direct effects ∪ transitive effects of every
function reachable through direct calls), and asserts each effect's
required capability is covered by some module's `requires capability`
declaration.

Default-on behaviour:
  - If at least one `module ... end` is declared in the program, the check
    is enforced strictly. Any uncovered capability emits E0701.
  - If no module is declared, the program is treated as living in an
    implicit "global" capability scope that grants all capabilities —
    the check silently passes. This is a pragmatic transition until
    Phase D.3 makes modules real composition units. Documented in
    SPEC_ISSUES; once D.3 ships, programs without modules will emit
    a warning by default.

Effect-to-capability mapping (B.3 keeps v0.2 mapping):

    pure                  → no capability required
    panic                 → no capability required (always available)
    mutate(_)             → no capability required (module-local mutation)
    log, random           → log, random respectively
    fs.<anything>         → fs
    net.<anything>        → net
    db.<anything>         → db
    exec.<anything>       → exec
    time.<anything>       → time
    other.<anything>      → first segment of the dotted path

Diagnostic codes:
  E0701  uncovered transitive effect — function's effective effect set
         contains a path whose required capability isn't declared by any
         module. The diagnostic always points at the *immediate* function
         declaring the effect (or the function up the call chain that
         introduces it via a transitive callee).
  E0702  reserved for cross-module capability violations once Phase D.3
         lands real module scoping.

Limits / known gaps (v1 scope):
  - "Transitive" here means "via direct function calls within this
     program file" — a single AST. Cross-file module composition is
     Phase D.3 work.
  - HOFs / function-typed parameters / let-bound function values are
    treated as pure for the call-graph build. Effect leakage through
    a HOF is caught by B.1 at the call site that passes the function in.
  - A program with no module declarations is treated as having an
    implicit all-capability grant. Surface this in the audit if a YC
    partner asks "what does this enforce on a script without a module?"
"""

from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple, Optional

from ..diagnostics import Diagnostic, Position
from .ast_walk import walk, callee_name
from .detector_specs import _fn_aliases


# Effects that require no capability.
_FREE_EFFECTS = {"pure", "panic"}


def effect_capability(effect_or_path: Any) -> str:
    """Return the capability name required by an effect, or '' if none.

    Accepts either an AST effect node `{"path": [...], "arg": ...}` or a
    plain `tuple[str, ...]` path (used by the transitive closure path).
    """
    if isinstance(effect_or_path, dict):
        path = effect_or_path.get("path", [])
    else:
        path = list(effect_or_path)
    if not path:
        return ""
    head = path[0]
    if head in _FREE_EFFECTS:
        return ""
    if head == "mutate":
        return ""
    return head


def collect_declared_capabilities(ast: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for d in ast.get("decls", []):
        if d.get("kind") == "ModuleDecl":
            out.update(d.get("capabilities", []))
    return out


# ----------------------------------------------------------------------
# Stdlib effects (paths only — capability mapping ignores args)
# ----------------------------------------------------------------------

_STDLIB_EFFECT_PATHS: Dict[str, Set[Tuple[str, ...]]] = {
    "print":      {("log",)},
    "readLine":   {("log",)},
    "readFile":   {("fs", "read")},
    "writeFile":  {("fs", "write")},
    "now":        {("time", "now")},
    "sqlQuery":   {("db", "query")},
    "sqlExec":    {("db", "exec")},
    "sqlByOwner": {("db", "exec")},
    "shellExec":  {("exec", "run")},
    "redirect":   {("net", "redirect")},
}


def _direct_effect_paths(fn_decl: Dict[str, Any]) -> Set[Tuple[str, ...]]:
    """Direct effect paths declared by a FunctionDecl (no args)."""
    out: Set[Tuple[str, ...]] = set()
    for eff in fn_decl.get("effects", []):
        path = tuple(eff.get("path", []))
        if not path or path == ("pure",):
            continue
        out.add(path)
    return out


def _transitive_effect_paths(
    name: str,
    direct_effects: Dict[str, Set[Tuple[str, ...]]],
    call_graph: Dict[str, Set[str]],
    visited: Optional[Set[str]] = None,
) -> Set[Tuple[str, ...]]:
    """Closure: name's direct effects ∪ closures of every direct callee.

    `visited` carries the recursion guard for mutually recursive functions.
    Stdlib callees contribute their stdlib effects. Unknown callees (HOFs,
    dynamic) contribute nothing — same skip-policy as B.1.
    """
    if visited is None:
        visited = set()
    if name in visited:
        return set()
    visited.add(name)
    out: Set[Tuple[str, ...]] = set(direct_effects.get(name, set()))
    for callee in call_graph.get(name, ()):
        if callee in direct_effects:
            out |= _transitive_effect_paths(callee, direct_effects, call_graph, visited)
        elif callee in _STDLIB_EFFECT_PATHS:
            out |= _STDLIB_EFFECT_PATHS[callee]
    return out


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

def check_capabilities(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0701 diagnostics for every function whose transitive
    effective effects contain a capability not declared by any module.

    Default-on contract: programs without a module declaration are
    treated as having an implicit all-capability grant and pass with
    zero diagnostics. Programs with at least one module are checked
    strictly. (This preserves the v0.2 reference-program corpus while
    enforcing the architectural-integrity claim wherever modules are
    actually used.)
    """
    has_modules = any(d.get("kind") == "ModuleDecl" for d in ast.get("decls", []))
    if not has_modules:
        return []

    declared = collect_declared_capabilities(ast)

    # Build direct effects + call graph in a single pass. A call through
    # a let-bound alias (`let sh = shellExec; sh(...)`) is an edge to the
    # target — resolution only ADDS edges (BUGS.md BUG-015).
    fn_names = frozenset(d["name"] for d in ast.get("decls", [])
                         if d.get("kind") == "FunctionDecl")
    alias_targets = fn_names | frozenset(_STDLIB_EFFECT_PATHS)
    direct_effects: Dict[str, Set[Tuple[str, ...]]] = {}
    call_graph: Dict[str, Set[str]] = {}
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        name = d["name"]
        direct_effects[name] = _direct_effect_paths(d)
        al = _fn_aliases(d, alias_targets)
        callees: Set[str] = set()
        for call in walk(d.get("body", []), "Call"):
            n = callee_name(call)
            if n is not None:
                callees.add(n)
                callees |= al.get(n, set())
        call_graph[name] = callees

    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn_name = d["name"]
        pos = d.get("pos") or {"line": 0, "column": 0}
        eff_paths = _transitive_effect_paths(fn_name, direct_effects, call_graph)
        for path in sorted(eff_paths):
            cap = effect_capability(path)
            if not cap or cap in declared:
                continue
            effname = ".".join(path)
            via_transitive = path not in direct_effects.get(fn_name, set())
            via = "transitively (through a callee)" if via_transitive else "directly"
            diags.append(Diagnostic(
                code="E0701",
                category="capability",
                severity="error",
                message=(
                    f"function {fn_name!r} {via} performs effect {effname!r} "
                    f"which requires capability {cap!r}, but no module in "
                    f"this program declares it"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"add `requires capability {cap}` to a `module` "
                    f"declaration, or change the function to be `effects pure`"
                ),
                confidence=1.0,
                extra={
                    "function": fn_name,
                    "effect": effname,
                    "required_capability": cap,
                    "declared_capabilities": sorted(declared),
                    "via_transitive": via_transitive,
                },
            ))
    return diags
