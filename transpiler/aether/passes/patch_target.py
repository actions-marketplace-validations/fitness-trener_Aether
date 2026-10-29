"""H.A.1.a — Patch-target resolution pass.

Given a parsed AST and a Diagnostic, walk the tree and return a
machine-readable path identifying the smallest enclosing node a fix-loop
should edit to repair the diagnostic.

Path representation
-------------------
A list of (field_name, index_or_None) tuples from the Program root
downward. For named fields without an index use `None`. For list fields
use the index. Example:

    [("decls", 2), ("body", 0), ("expr", None), ("args", 1)]

Path semantics by diagnostic code
---------------------------------
* E0801 (effect not covered) -> the offending Call inside the caller:
      [("decls", i), ("body", j), ..., ]
  Removing or replacing that call keeps the declared effects; adding the
  effect to the clause WIDENS it, and the fix-loop will not do that
  unless told to (`--allow-widen`). Falls back to
  [("decls", i), ("effects", None)] when the call cannot be located.
* E0701 (capability not declared) -> ModuleDecl's `capabilities` field:
      [("decls", i), ("capabilities", None)]
* E0301 (requires violation) -> the offending argument expression at the
  call site, located via the diagnostic's `extra.function` (function
  name being called) and `extra.args` (arg name->value dict that fired
  the violation). Path ends at:
      [("decls", i), ("body", j), ..., ("args", k)]
* E0302 (refinement boundary violation) -> same shape as E0301, located
  via `extra.binding` (parameter name) and `extra.type`.
* E0304 (ensures violation) -> the ReturnStmt's expression (or implicit
  fall-through) inside the function named by `extra.function`:
      [("decls", i), ("body", j), ("value", None)]
* E0305 (stdlib precondition violation) -> the offending argument at the
  call site of `extra.stdlib_function` (sqrt, tail, ...):
      [("decls", i), ("body", j), ..., ("args", k)]
* E0101, E0201 (lex/parse errors) -> return None.
* Any unknown code -> return None.

Field-name notes
----------------
The actual AST (see parser.py) doesn't have a separate `EffectsClause`
node — `effects` is a *field* on FunctionDecl carrying the parsed
effect list. Likewise the ModuleDecl's capability clause is the
`capabilities` field. The patch-target path therefore terminates at
those fields by name, which is what a structural fix-loop needs to
splice into. The corpus uses `patch_target_kind = "ModuleDecl"` for
E0701 because the resolved leaf is the parent decl node; E0801 resolves
to `"Call"`.

This pass is read-only and side-effect free.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

# Aliased: `callee_name` is already a parameter name in _patch_call_arg.
from .ast_walk import callee_name as _callee_name


PathElem = Tuple[str, Optional[int]]
Path = List[PathElem]


# ---------------------------------------------------------------------
# Helpers for locating decls
# ---------------------------------------------------------------------

def _find_decl_index(ast: Dict[str, Any], kind: str,
                     name: Optional[str] = None) -> Optional[int]:
    """Return the index of the first decl matching `kind` (and optionally
    `name`) in ast['decls'], or None if not found."""
    for i, d in enumerate(ast.get("decls", []) or []):
        if d.get("kind") != kind:
            continue
        if name is None or d.get("name") == name:
            return i
    return None


def _find_module_decl_index(ast: Dict[str, Any]) -> Optional[int]:
    return _find_decl_index(ast, "ModuleDecl")


# ---------------------------------------------------------------------
# Call-site walker — yields (path, call_node) for every Call inside a
# dict-shaped AST node. The recursion only ever crosses a field name
# AND its list index together, so the emitted path strictly alternates
# (field_name, idx_or_None) entries that can be replayed against the
# AST. Bare-list recursion roots are not entered — callers descend
# into the first field by name themselves.
# ---------------------------------------------------------------------

_SKIP_FIELDS = {"kind", "pos", "name", "op"}


def _walk_calls_with_path(node: Any, prefix: Path):
    if not isinstance(node, dict):
        return
    if node.get("kind") == "Call":
        yield list(prefix), node
    for k, v in node.items():
        if k in _SKIP_FIELDS:
            continue
        if isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    yield from _walk_calls_with_path(item, prefix + [(k, i)])
        elif isinstance(v, dict):
            yield from _walk_calls_with_path(v, prefix + [(k, None)])


# ---------------------------------------------------------------------
# Return-statement walker — yields (path, return_node).
# ---------------------------------------------------------------------

def _walk_returns_with_path(stmts: List[Any], prefix: Path):
    for j, stmt in enumerate(stmts or []):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("kind") == "Return":
            yield prefix + [("body", j)], stmt
        # Recurse into nested blocks.
        for k in ("then", "else", "body"):
            v = stmt.get(k)
            if isinstance(v, list):
                yield from _walk_returns_with_path(v, prefix + [("body", j), (k, None)])
        # if/match nested structures
        for arm_field in ("elifs", "arms"):
            v = stmt.get(arm_field)
            if isinstance(v, list):
                for ai, arm in enumerate(v):
                    body = arm.get("body") if isinstance(arm, dict) else None
                    if isinstance(body, list):
                        yield from _walk_returns_with_path(
                            body,
                            prefix + [("body", j), (arm_field, ai), ("body", None)],
                        )


# ---------------------------------------------------------------------
# Per-code resolvers
# ---------------------------------------------------------------------

def _patch_E0801(ast: Dict[str, Any], diag) -> Optional[Path]:
    """The offending CALL inside the caller: removing or replacing it is
    the repair that keeps the declared constraint. The declaration's
    `effects` field used to be the only target, which made widening the
    one mechanical repair on offer (audit 2026-09-24 D1).

    The diagnostic is positioned at the call (audit D10), so the call at
    that position is the target — the one whose callee is `callee` when a
    call chain shares that start. With no call at the position (an AST
    edited since the check, a call in a contract clause) it picks the
    caller's first call to `callee`, else the first call passing `callee`
    as a value (`extra.via == "function_value"`). Falls back to the
    effects clause when none is found (a call through an alias)."""
    extra = diag.extra or {}
    idx = _find_decl_index(ast, "FunctionDecl", extra.get("caller"))
    if idx is None:
        return None
    callee = extra.get("callee")
    # Body only: check_effects never reads the contract clauses.
    calls = [c for j, stmt in enumerate(ast["decls"][idx].get("body") or [])
             for c in _walk_calls_with_path(stmt, [("body", j)])]
    pos = getattr(diag, "position", None)
    at = [(path, call) for path, call in calls if pos is not None
          and (call.get("pos") or {}).get("line") == pos.line
          and (call.get("pos") or {}).get("column") == pos.column]
    named = [pc for pc in at if _callee_name(pc[1]) == callee]
    if at:
        return [("decls", idx)] + (named or at)[0][0]
    for path, call in calls:
        if _callee_name(call) == callee:
            return [("decls", idx)] + path
    for path, call in calls:
        if any(isinstance(a, dict) and a.get("kind") == "Ident"
               and a.get("name") == callee for a in call.get("args") or []):
            return [("decls", idx)] + path
    return [("decls", idx), ("effects", None)]


def _patch_E0701(ast: Dict[str, Any], diag) -> Optional[Path]:
    idx = _find_module_decl_index(ast)
    if idx is None:
        return None
    return [("decls", idx), ("capabilities", None)]


def _patch_call_arg(ast: Dict[str, Any], callee_name: Optional[str],
                    arg_position: Optional[int]) -> Optional[Path]:
    """Locate the first call to `callee_name` in any FunctionDecl body
    and return a path to its `arg_position`-th argument. If
    `arg_position` is None, return a path to the entire call node
    instead.

    Path always starts at ("decls", i). The walker descends into the
    FunctionDecl as the root dict, so the first emitted step is
    ("body", j) — body is a statement list, j is the statement index.
    """
    if callee_name is None:
        return None
    for di, d in enumerate(ast.get("decls", []) or []):
        if d.get("kind") != "FunctionDecl":
            continue
        for path, call in _walk_calls_with_path(d, []):
            if _callee_name(call) != callee_name:
                continue
            full = [("decls", di)] + path
            if arg_position is None:
                return full
            args = call.get("args") or []
            if 0 <= arg_position < len(args):
                return full + [("args", arg_position)]
            return full
    return None


def _patch_E0301(ast: Dict[str, Any], diag) -> Optional[Path]:
    """E0301: requires precondition violated. `extra.function` names the
    callee; `extra.args` is the dict of arg-name->value that fired.

    The runtime currently emits an empty `args` dict (emitter doesn't
    pass call-site values into `_ae_assert_contract`), so we fall back
    to targetting the first positional argument of the offending call.
    When `args` carries an explicit mapping, prefer that.
    """
    extra = diag.extra or {}
    callee = extra.get("function")
    args = extra.get("args") or {}
    if callee is None:
        return None
    # Resolve the parameter index from the callee's FunctionDecl when
    # `args` names a single field.
    arg_pos: int = 0
    if len(args) == 1:
        only = next(iter(args.keys()))
        idx = _find_decl_index(ast, "FunctionDecl", callee)
        if idx is not None:
            params = (ast["decls"][idx] or {}).get("params") or []
            for pi, p in enumerate(params):
                if p.get("name") == only:
                    arg_pos = pi
                    break
    return _patch_call_arg(ast, callee, arg_pos)


def _patch_E0302(ast: Dict[str, Any], diag) -> Optional[Path]:
    """E0302: refinement boundary violation. `extra.binding` names the
    parameter; the failing call's callee isn't in `extra` directly, but
    we can find the call by scanning for the first Call whose callee
    has a parameter named `binding` typed `extra.type`."""
    extra = diag.extra or {}
    binding = extra.get("binding")
    type_name = extra.get("type")
    if binding is None or type_name is None:
        return None
    # Find the FunctionDecl that has a parameter `binding` of type `type_name`.
    target_callee: Optional[str] = None
    arg_pos: Optional[int] = None
    for d in ast.get("decls", []) or []:
        if d.get("kind") != "FunctionDecl":
            continue
        for pi, p in enumerate(d.get("params") or []):
            if p.get("name") != binding:
                continue
            ty = p.get("type") or {}
            if ty.get("name") == type_name:
                target_callee = d.get("name")
                arg_pos = pi
                break
        if target_callee is not None:
            break
    if target_callee is None:
        return None
    return _patch_call_arg(ast, target_callee, arg_pos)


def _patch_E0304(ast: Dict[str, Any], diag) -> Optional[Path]:
    """E0304: ensures postcondition violated. `extra.function` names the
    function whose return value lies. Target the first Return inside it,
    or the function body itself when there's no explicit return."""
    extra = diag.extra or {}
    fn = extra.get("function")
    if fn is None:
        return None
    idx = _find_decl_index(ast, "FunctionDecl", fn)
    if idx is None:
        return None
    body = (ast["decls"][idx] or {}).get("body") or []
    for path, ret in _walk_returns_with_path(body, [("decls", idx)]):
        # path ends at [("decls", idx), ("body", j)]; target the Return's value.
        return path + [("value", None)]
    # No return statement at all — target the body itself.
    return [("decls", idx), ("body", None)]


def _patch_E0305(ast: Dict[str, Any], diag) -> Optional[Path]:
    """E0305: stdlib precondition violation. `extra.stdlib_function`
    names the stdlib call (sqrt, tail, ...)."""
    extra = diag.extra or {}
    fn = extra.get("stdlib_function")
    if fn is None:
        return None
    return _patch_call_arg(ast, fn, 0)


_RESOLVERS = {
    "E0801": _patch_E0801,
    "E0701": _patch_E0701,
    "E0301": _patch_E0301,
    "E0302": _patch_E0302,
    "E0304": _patch_E0304,
    "E0305": _patch_E0305,
}


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

def compute_patch_target(ast_root: Optional[Dict[str, Any]], diagnostic
                         ) -> Optional[List[List[Any]]]:
    """Return the patch-target path for `diagnostic` against `ast_root`,
    or None if the code doesn't have an AST anchor (lex/parse errors,
    unknown codes, missing AST)."""
    if ast_root is None:
        return None
    code = getattr(diagnostic, "code", None) or ""
    resolver = _RESOLVERS.get(code)
    if resolver is None:
        return None
    try:
        path = resolver(ast_root, diagnostic)
    except Exception:
        return None
    if path is None:
        return None
    # Serialise as list of lists for JSON-friendly output.
    return [[name, idx] for (name, idx) in path]


# ---------------------------------------------------------------------
# Path resolution helper (used by the corpus test to find the leaf
# node's class name).
# ---------------------------------------------------------------------

def resolve_path(ast_root: Dict[str, Any],
                 path: Optional[List[List[Any]]]) -> Optional[Any]:
    """Walk `path` against `ast_root` and return the resolved leaf node
    (or scalar value). Returns None if any step misses."""
    if path is None or ast_root is None:
        return None
    node: Any = ast_root
    for step in path:
        name, idx = step[0], step[1]
        if isinstance(node, dict):
            if name not in node:
                return None
            node = node[name]
        else:
            return None
        if idx is not None:
            if not isinstance(node, list) or idx < 0 or idx >= len(node):
                return None
            node = node[idx]
    return node


def resolve_path_kind(ast_root: Dict[str, Any],
                      path: Optional[List[List[Any]]]) -> Optional[str]:
    """Return the resolved leaf's AST kind (class name in our dict-AST
    representation), or a synthetic name for field anchors like
    `effects`/`capabilities` that don't have their own node class.

    For a path ending in a list field (effects/capabilities/body) with
    `idx=None`, returns the parent's `kind` (FunctionDecl / ModuleDecl)
    because the fix-loop's anchor IS the parent decl — the list field
    is just where the splice happens.
    """
    if path is None or ast_root is None:
        return None
    if not path:
        return ast_root.get("kind") if isinstance(ast_root, dict) else None
    # Walk to the parent of the final step so we can decide whether
    # the leaf is a node (use its `kind`) or a field anchor (use
    # parent's `kind`).
    node: Any = ast_root
    for step in path[:-1]:
        name, idx = step[0], step[1]
        if isinstance(node, dict):
            if name not in node:
                return None
            node = node[name]
        else:
            return None
        if idx is not None:
            if not isinstance(node, list) or idx < 0 or idx >= len(node):
                return None
            node = node[idx]
    last_name, last_idx = path[-1][0], path[-1][1]
    if isinstance(node, dict):
        leaf = node.get(last_name)
        if last_idx is None:
            # Field anchor: leaf is the field value. If it's a dict with
            # a `kind`, use that; otherwise return the parent's `kind`.
            if isinstance(leaf, dict) and "kind" in leaf:
                return leaf.get("kind")
            return node.get("kind")
        # Indexed list element.
        if isinstance(leaf, list) and 0 <= last_idx < len(leaf):
            elem = leaf[last_idx]
            if isinstance(elem, dict) and "kind" in elem:
                return elem.get("kind")
            return type(elem).__name__
    return None
