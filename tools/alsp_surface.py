"""Gate B / Dashboard projection layer — the capability SURFACE view.

This module is a *pure projection* over the Gate A engine. It runs NO new
analysis and makes NO new decidability claims. Everything it reports is
already proven (or already left unproven) by:

    aether.sdk.check        -> diagnostics (E0801 effect composition,
                               E0701 capability grant) + AST
    aether.passes.capability -> the transitive effect closure + call graph
    aether.passes.effects    -> the stdlib/user effect tables

What this layer adds is *exposition*, not inference:

  1. WITNESS EXTRACTION (approved Flag 1). The capability pass already
     walks `main -> log_formatter -> exfil -> net.fetch` to decide the
     E0701; it just discards the route. We re-walk the SAME call graph and
     retain the route so the dashboard can render it. Reconstructing the
     witness of an already-proven fact is not new analysis.

  2. UNPROVABLE ENUMERATION (approved Flag 2). The capability pass
     *silently skips* call sites whose callee it cannot resolve to a
     FunctionDecl or a known stdlib symbol (HOFs, function-valued params,
     let-bound function values). Those skips are exactly where the static
     proof has a hole. We enumerate them with exact line/col so the
     dashboard can say "these N lines still need a human." Naming the
     engine's own blind spot is honesty, not a new check.

  3. THREE-STATE ROLL-UP. Each ModuleDecl becomes a row whose state is the
     worst-of its exported functions: VIOLATION > UNPROVABLE > PROVEN_CLEAN.
     A PROVEN_CLEAN function carries its traced surface + which declared
     capability satisfies it (the "why it's proven" a scanner can't show).

CRITICAL FRAMING: Aether proves capability/effect boundaries ONLY. This
layer never emits the words bug/error/issue, never implies logic- or
design-flaw detection. The headline metric is review-surface REDUCTION.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.sdk import parse as _parse                       # noqa: E402
from aether.sdk import check as _sdk_check                    # noqa: E402
from aether.runtime import build_namespace as _runtime_ns    # noqa: E402
from aether.runtime import unmangle as _unmangle              # noqa: E402
from aether.passes.capability import (                       # noqa: E402
    effect_capability as _effect_capability,
    _STDLIB_EFFECT_PATHS,
)
from aether.passes.patch_target import (                     # noqa: E402
    compute_patch_target as _compute_patch_target,
)

# Effect paths a *stdlib* leaf introduces, keyed by the stdlib symbol name.
# Reused verbatim from passes.capability so the witness leaf matches the
# engine's own effect attribution.
_STDLIB_LEAF_EFFECTS: Dict[str, Set[Tuple[str, ...]]] = dict(_STDLIB_EFFECT_PATHS)

# Union/Result/Option constructors are resolvable (pure) callees.
_BUILTIN_CTORS = {"Some", "None", "Ok", "Err"}


def _stdlib_names() -> Set[str]:
    """Every Aether-visible stdlib symbol (length, print, sqrt, ...).
    Same derivation lsp.py uses for completion: `runtime.unmangle` (so
    `_ae_empty__q` is `empty?`). These are RESOLVABLE callees (known
    effects), so they are never UNPROVABLE."""
    out: Set[str] = set()
    for n in _runtime_ns():
        bare = _unmangle(n)
        if bare:
            out.add(bare)
    return out


_STDLIB_SYMBOLS = _stdlib_names()


# ---------------------------------------------------------------------
# AST helpers (mirror passes/capability.py + passes/patch_target.py so
# the projection sees exactly what the engine saw).
# ---------------------------------------------------------------------

def _callee_name(call_node: Dict[str, Any]) -> Optional[str]:
    func = call_node.get("func") or {}
    kind = func.get("kind")
    if kind == "Ident":
        return func.get("name")
    if kind == "Field":
        inner = func.get("value") or {}
        if inner.get("kind") == "Ident":
            return func.get("name")
    return None


def _iter_calls(node: Any):
    """Yield every Call node in a subtree."""
    if isinstance(node, dict):
        if node.get("kind") == "Call":
            yield node
        for v in node.values():
            yield from _iter_calls(v)
    elif isinstance(node, list):
        for x in node:
            yield from _iter_calls(x)


def _direct_effect_paths(fn_decl: Dict[str, Any]) -> Set[Tuple[str, ...]]:
    out: Set[Tuple[str, ...]] = set()
    for eff in fn_decl.get("effects", []) or []:
        path = tuple(eff.get("path", []))
        if not path or path == ("pure",):
            continue
        out.add(path)
    return out


def _decl_line(node: Dict[str, Any]) -> int:
    return int((node.get("pos") or {}).get("line", 0))


def _decl_col(node: Dict[str, Any]) -> int:
    return int((node.get("pos") or {}).get("column", 0))


# ---------------------------------------------------------------------
# Program model: collect functions, modules, call graph, effect tables.
# A re-derivation of the structures passes.capability builds; same shapes
# so our surface matches the engine's verdict.
# ---------------------------------------------------------------------

class _Model:
    def __init__(self, ast: Dict[str, Any]):
        self.ast = ast
        self.fn_decls: Dict[str, Dict[str, Any]] = {}
        self.fn_index: Dict[str, int] = {}
        self.modules: List[Dict[str, Any]] = []
        self.union_ctors: Set[str] = set()
        self.record_names: Set[str] = set()
        self.direct_effects: Dict[str, Set[Tuple[str, ...]]] = {}
        self.call_graph: Dict[str, Set[str]] = {}

        for i, d in enumerate(ast.get("decls", []) or []):
            k = d.get("kind")
            if k == "FunctionDecl":
                name = d.get("name")
                self.fn_decls[name] = d
                self.fn_index[name] = i
                self.direct_effects[name] = _direct_effect_paths(d)
            elif k == "ModuleDecl":
                self.modules.append(d)
            elif k == "UnionDecl":
                for c in d.get("cases", []) or []:
                    self.union_ctors.add(c.get("name"))
            elif k == "RecordDecl":
                self.record_names.add(d.get("name"))

        for name, d in self.fn_decls.items():
            callees: Set[str] = set()
            for call in _iter_calls(d.get("body", [])):
                cn = _callee_name(call)
                if cn:
                    callees.add(cn)
            self.call_graph[name] = {c for c in callees if c in self.fn_decls}

    def resolvable(self, callee: Optional[str]) -> bool:
        """A callee is resolvable (effects knowable) iff it is a user
        function, a stdlib symbol, or a union/record constructor. This is
        precisely the set passes.capability can trace; anything else it
        skips -> UNPROVABLE."""
        if callee is None:
            return False
        return (
            callee in self.fn_decls
            or callee in _STDLIB_SYMBOLS
            or callee in self.union_ctors
            or callee in self.record_names
            or callee in _BUILTIN_CTORS
        )


# ---------------------------------------------------------------------
# Witness extraction (Flag 1): rebuild the route the closure traverses.
# ---------------------------------------------------------------------

def _arg_to_str(arg: Any) -> Optional[str]:
    """Extract a readable literal from an effect arg AST node. Effects like
    net.fetch("http://...") carry a StringLit node; render its value, not
    the raw dict."""
    if arg is None:
        return None
    if isinstance(arg, dict):
        return str(arg["value"]) if "value" in arg else None
    return str(arg)


def _effect_to_str(fn_decl: Dict[str, Any], path: Tuple[str, ...]) -> str:
    """Render an effect path the way the engine's message does, including
    the arg when the declared effect carried one (e.g. net.fetch('...'))."""
    for eff in fn_decl.get("effects", []) or []:
        if tuple(eff.get("path", [])) == path:
            arg = _arg_to_str(eff.get("arg"))
            base = ".".join(path)
            return f"{base}({arg!r})" if arg is not None else base
    return ".".join(path)


def _find_chain(model: "_Model", start: str, target_path: Tuple[str, ...],
                _seen: Optional[Set[str]] = None) -> Optional[List[Dict[str, Any]]]:
    """Return a hop list [{fn,line}, ..., {fn,line,effect}] from `start`
    down to the function (or stdlib leaf call) that DIRECTLY introduces
    `target_path`. None if no such route."""
    if _seen is None:
        _seen = set()
    if start in _seen:
        return None
    _seen.add(start)
    d = model.fn_decls.get(start)
    if d is None:
        return None
    line = _decl_line(d)
    if target_path in model.direct_effects.get(start, set()):
        return [{"fn": start, "line": line, "effect": _effect_to_str(d, target_path)}]
    for call in _iter_calls(d.get("body", [])):
        cn = _callee_name(call)
        if cn in _STDLIB_LEAF_EFFECTS and target_path in _STDLIB_LEAF_EFFECTS[cn]:
            cpos = call.get("pos") or {}
            return [
                {"fn": start, "line": line},
                {"fn": cn, "line": int(cpos.get("line", line)),
                 "effect": ".".join(target_path), "stdlib": True},
            ]
    for callee in sorted(model.call_graph.get(start, ())):
        sub = _find_chain(model, callee, target_path, set(_seen))
        if sub is not None:
            return [{"fn": start, "line": line}] + sub
    return None


# ---------------------------------------------------------------------
# UNPROVABLE enumeration (Flag 2): the call sites the engine skips.
# ---------------------------------------------------------------------

def _unprovable_in_fn(model: "_Model", fn_name: str) -> List[Dict[str, Any]]:
    """Enumerate the untraceable call sites inside `fn_name`.

    The engine's AST does not attach a position to Call/expression nodes,
    so — exactly like every E0701/E0801 the engine emits — we report at
    FUNCTION granularity (the FunctionDecl line) and name the unresolved
    callee so a reviewer knows precisely what to inspect. We do NOT invent
    a call-site line we cannot derive."""
    d = model.fn_decls.get(fn_name)
    if d is None:
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for call in _iter_calls(d.get("body", [])):
        cn = _callee_name(call)
        if model.resolvable(cn):
            continue
        key = cn if cn is not None else "<computed>"
        if key in seen:
            continue
        seen.add(key)
        if cn is None:
            reason = "computed_callee"
            callee = None
            detail = ("a call target is an expression, not a named function; "
                      "its effects cannot be traced statically")
        else:
            reason = "indirect_call"
            callee = cn
            detail = (f"callee `{cn}` resolves to a parameter or local "
                      f"binding, not a declared function; its effects "
                      f"cannot be traced statically")
        out.append({
            "fn": fn_name,
            "line": _decl_line(d),
            "granularity": "function",
            "callee": callee,
            "reason": reason,
            "detail": detail,
            "needs": "human review or a runtime check",
        })
    return out


# ---------------------------------------------------------------------
# Diagnostic grouping.
# ---------------------------------------------------------------------

def _group_diagnostics(diags: List[Dict[str, Any]]):
    cap_grants: List[Dict[str, Any]] = []    # E0701
    compositions: List[Dict[str, Any]] = []  # E0801
    others: List[Dict[str, Any]] = []        # contract/lex/parse etc.
    for d in diags:
        code = d.get("code")
        if code == "E0701":
            cap_grants.append(d)
        elif code == "E0801":
            compositions.append(d)
        else:
            others.append(d)
    return cap_grants, compositions, others


# ---------------------------------------------------------------------
# Engine adapter — run the SAME default-on passes the LSP/HTTP /check
# path runs, but against an AST we may have policy-overridden first.
# Reuses aether.sdk.check + the patch_target pass verbatim; adds no
# analysis.
# ---------------------------------------------------------------------

def _raw_diags_for_ast(ast: Dict[str, Any]) -> List[Dict[str, Any]]:
    res = _sdk_check(ast)
    out: List[Dict[str, Any]] = []
    for d in res.diagnostics:
        out.append({
            "code": d.code,
            "message": d.message,
            "position": {"line": d.position.line, "col": d.position.column},
            "data": {
                "suggestion": d.suggestion,
                "extra": d.extra,
                "patch_target": _compute_patch_target(ast, d),
            },
        })
    return out


def _apply_policy(ast: Dict[str, Any], policy: Optional[Dict[str, Any]]) -> bool:
    """Override every ModuleDecl's declared capabilities with the buyer's
    policy `capabilities` list, in place. Returns True if applied. The
    engine then PROVES the program against the buyer's boundary instead of
    the source's own clause — the policy-editor workflow."""
    if not policy:
        return False
    allowed = policy.get("capabilities")
    if not isinstance(allowed, list):
        return False
    applied = False
    for d in ast.get("decls", []) or []:
        if d.get("kind") == "ModuleDecl":
            d["capabilities"] = list(allowed)
            applied = True
    return applied


# ---------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------

def build_surface(source: str,
                  policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Project the Gate A engine output into the dashboard surface model.

    Returns the /analyze response: headline + modules[] (three-state) +
    ungoverned + unprovable[] + raw_diagnostics[]. When `policy` is given
    (``{"capabilities": [...]}``) the program is re-proven against that
    boundary instead of its own `requires capability` clause."""
    parse_res = _parse(source)
    ast = parse_res.ast

    if ast is None or not ast.get("decls"):
        return {
            "ok": parse_res.ok,
            "headline": _empty_headline(source),
            "modules": [],
            "ungoverned": _ungoverned_stub(),
            "unprovable": [],
            "parse_ok": parse_res.ok,
            "policy_applied": False,
            "raw_diagnostics": [
                {"code": d.code, "message": d.message,
                 "position": {"line": d.position.line, "col": d.position.column},
                 "data": {"suggestion": d.suggestion, "extra": d.extra,
                          "patch_target": None}}
                for d in parse_res.diagnostics
            ],
        }

    policy_applied = _apply_policy(ast, policy)
    raw_diags = _raw_diags_for_ast(ast)

    model = _Model(ast)
    cap_grants, compositions, others = _group_diagnostics(raw_diags)

    fn_cap_viol: Dict[str, List[Dict[str, Any]]] = {}
    for d in cap_grants:
        extra = (d.get("data") or {}).get("extra") or {}
        fn = extra.get("function")
        cap = extra.get("required_capability")
        eff = extra.get("effect", "")
        target_path = tuple(eff.split(".")) if eff else ()
        chain = _find_chain(model, fn, target_path) if fn else None
        fn_cap_viol.setdefault(fn, []).append({
            "kind": "capability_not_granted",
            "code": "E0701",
            "capability": cap,
            "effect": eff,
            "call_chain": chain or [{"fn": fn,
                                     "line": (d.get("position") or {}).get("line", 0)}],
            "patch_target": (d.get("data") or {}).get("patch_target"),
            "suggestion": (d.get("data") or {}).get("suggestion"),
        })

    fn_comp_viol: Dict[str, List[Dict[str, Any]]] = {}
    for d in compositions:
        extra = (d.get("data") or {}).get("extra") or {}
        caller = extra.get("caller")
        callee = extra.get("callee")
        missing = extra.get("missing_effect")
        eff_str = _format_missing_effect(missing)
        fn_comp_viol.setdefault(caller, []).append({
            "kind": "effect_not_composed",
            "code": "E0801",
            "callee": callee,
            "effect": eff_str,
            "call_chain": [
                {"fn": caller, "line": (d.get("position") or {}).get("line", 0)},
                {"fn": callee, "line": _decl_line(model.fn_decls.get(callee, {})),
                 "effect": eff_str},
            ],
            "patch_target": (d.get("data") or {}).get("patch_target"),
            "suggestion": (d.get("data") or {}).get("suggestion"),
        })

    fn_unprovable: Dict[str, List[Dict[str, Any]]] = {}
    for name in model.fn_decls:
        ups = _unprovable_in_fn(model, name)
        if ups:
            fn_unprovable[name] = ups

    def fn_row(name: str) -> Dict[str, Any]:
        d = model.fn_decls[name]
        viols = list(fn_cap_viol.get(name, [])) + list(fn_comp_viol.get(name, []))
        ups = fn_unprovable.get(name, [])
        eff_caps = _effective_capabilities(model, name)
        if viols:
            state = "VIOLATION"
        elif ups:
            state = "UNPROVABLE"
        else:
            state = "PROVEN_CLEAN"
        row: Dict[str, Any] = {
            "name": name,
            "line": _decl_line(d),
            "state": state,
            "effective_capabilities": sorted(eff_caps),
            "violations": viols,
            "unprovable": ups,
        }
        if state == "PROVEN_CLEAN":
            row["proof"] = _proof_for(model, name, eff_caps)
        return row

    exported: Set[str] = set()
    modules_out: List[Dict[str, Any]] = []
    for m in model.modules:
        fns = [f for f in (m.get("exports") or []) if f in model.fn_decls]
        exported.update(fns)
        rows = [fn_row(f) for f in fns]
        modules_out.append(_roll_up_module(m, rows))

    free = [fn_row(f) for f in model.fn_decls if f not in exported]

    headline = _headline(source, modules_out, free, fn_unprovable,
                         fn_cap_viol, fn_comp_viol, model)

    return {
        "ok": not raw_diags,
        "headline": headline,
        "modules": modules_out,
        "ungoverned": _ungoverned(free, bool(model.modules)),
        "unprovable": [u for ups in fn_unprovable.values() for u in ups],
        "parse_ok": parse_res.ok,
        "policy_applied": policy_applied,
        "raw_diagnostics": raw_diags,
    }


def _format_missing_effect(missing: Any) -> str:
    """missing_effect is [[segments...], arg]. Render net.fetch('...')."""
    try:
        segs, arg = missing[0], missing[1]
        base = ".".join(segs)
        return f"{base}({arg!r})" if arg is not None else base
    except Exception:
        return str(missing)


def _effective_capabilities(model: "_Model", name: str,
                            _seen: Optional[Set[str]] = None) -> Set[str]:
    """Transitive capability set for a function — the same closure
    passes.capability computes, surfaced as capability names."""
    if _seen is None:
        _seen = set()
    if name in _seen:
        return set()
    _seen.add(name)
    caps: Set[str] = set()
    for path in model.direct_effects.get(name, set()):
        c = _effect_capability(path)
        if c:
            caps.add(c)
    d = model.fn_decls.get(name, {})
    for call in _iter_calls(d.get("body", [])):
        cn = _callee_name(call)
        if cn in model.fn_decls:
            caps |= _effective_capabilities(model, cn, _seen)
        elif cn in _STDLIB_LEAF_EFFECTS:
            for path in _STDLIB_LEAF_EFFECTS[cn]:
                c = _effect_capability(path)
                if c:
                    caps.add(c)
    return caps


def _proof_for(model: "_Model", name: str, eff_caps: Set[str]) -> Dict[str, Any]:
    """Why a clean function is clean: its traced surface and the declared
    capability that satisfies each effect. The proof a scanner can't show."""
    surface = []
    d = model.fn_decls[name]
    for path in sorted(model.direct_effects.get(name, set())):
        surface.append({"effect": ".".join(path),
                        "via": "directly",
                        "capability": _effect_capability(path) or "none"})
    for call in _iter_calls(d.get("body", [])):
        cn = _callee_name(call)
        if cn in _STDLIB_LEAF_EFFECTS:
            for path in _STDLIB_LEAF_EFFECTS[cn]:
                surface.append({"effect": ".".join(path),
                                "via": f"via {cn}()",
                                "capability": _effect_capability(path) or "none"})
    return {
        "traced_surface": surface,
        "effective_capabilities": sorted(eff_caps),
        "statement": (
            f"`{name}` holds exactly "
            f"{sorted(eff_caps) if eff_caps else 'no'} capability surface, "
            f"fully covered by the declared boundary."
        ),
    }


def _roll_up_module(m: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    order = {"VIOLATION": 3, "UNPROVABLE": 2, "PROVEN_CLEAN": 1}
    state = "PROVEN_CLEAN"
    if rows:
        state = max(rows, key=lambda r: order[r["state"]])["state"]
    return {
        "module": m.get("name"),
        "line": _decl_line(m),
        "state": state,
        "declared_capabilities": sorted(m.get("capabilities", []) or []),
        "exports": list(m.get("exports", []) or []),
        "functions": rows,
    }


def _ungoverned(free_rows: List[Dict[str, Any]], has_modules: bool) -> Dict[str, Any]:
    if not free_rows:
        return {"functions": [], "note": None}
    note = (
        "These functions are not exported by any module, so no capability "
        "boundary is declared over them. Under the default-on contract they "
        "run in an implicit all-capability grant — nothing is proven about "
        "their capability surface until a module governs them."
    )
    return {"functions": free_rows, "note": note}


def _ungoverned_stub() -> Dict[str, Any]:
    return {"functions": [], "note": None}


def _count_lines(source: str) -> int:
    return source.count("\n") + (0 if source.endswith("\n") else 1)


def _decl_spans(model: "_Model") -> Dict[int, Tuple[int, Optional[int]]]:
    """Approximate per-decl line span from declaration boundaries: a decl
    owns the lines from its own line up to (not including) the next decl.
    Sizes the review-surface metric only; never affects any verdict."""
    decls = []
    for d in model.ast.get("decls", []) or []:
        ln = int((d.get("pos") or {}).get("line", 0))
        if ln > 0:
            decls.append((ln, d))
    decls.sort(key=lambda t: t[0])
    spans: Dict[int, Tuple[int, Optional[int]]] = {}
    for i, (ln, d) in enumerate(decls):
        nxt = decls[i + 1][0] if i + 1 < len(decls) else None
        spans[id(d)] = (ln, nxt)
    return spans


def _span_len(span: Tuple[int, Optional[int]], total: int) -> int:
    ln, nxt = span
    end = (nxt - 1) if nxt is not None else total
    return max(0, end - ln + 1)


def _headline(source, modules_out, free_rows, fn_unprovable,
              fn_cap_viol, fn_comp_viol, model) -> Dict[str, Any]:
    total = _count_lines(source)
    proven_modules = sum(1 for m in modules_out if m["state"] == "PROVEN_CLEAN")
    has_modules = bool(model.modules)

    # Boundary violations: distinct breaches, deduped so one root cause
    # propagated up a call chain is not counted N times.
    cap_breaches = set()
    for vs in fn_cap_viol.values():
        for v in vs:
            cap_breaches.add(v.get("capability"))
    comp_breaches = set()
    for caller, vs in fn_comp_viol.items():
        for v in vs:
            comp_breaches.add((caller, v.get("callee")))
    boundary_violations = len(cap_breaches) + len(comp_breaches)

    # Review-surface reduction = lines POSITIVELY proven clean / total.
    # Only governed PROVEN_CLEAN functions are credited; ungoverned code,
    # violations and unprovable regions are not. An unmoduled program
    # therefore claims 0% reduction (it proves nothing).
    spans = _decl_spans(model)
    proven_lines = 0
    for m in modules_out:
        for f in m["functions"]:
            if f["state"] != "PROVEN_CLEAN":
                continue
            d = model.fn_decls.get(f["name"])
            if d is not None and id(d) in spans:
                proven_lines += _span_len(spans[id(d)], total)
    proven_lines = min(proven_lines, total)
    z = total - proven_lines
    reduction = round(100.0 * proven_lines / total) if total else 0

    if not has_modules:
        statement = (
            "No module declares a capability boundary, so nothing is proven "
            "about this program's capability surface. Add a `module` with a "
            "`requires capability` clause to start proving boundaries."
        )
    elif boundary_violations:
        statement = (
            f"{proven_modules} module(s) PROVEN clean, {boundary_violations} "
            f"boundary violation(s); {proven_lines} of {total} lines proven "
            f"clean, {z} still need human review."
        )
    else:
        statement = (
            f"{proven_modules} module(s) PROVEN clean, 0 boundary violations; "
            f"manual review surface reduced from {total} lines to {z}."
        )

    return {
        "modules_proven_clean": proven_modules,
        "modules_total": len(modules_out),
        "boundary_violations": boundary_violations,
        "capability_breaches": sorted(c for c in cap_breaches if c),
        "composition_rejections": len(comp_breaches),
        "unprovable_regions": sum(len(v) for v in fn_unprovable.values()),
        "lines_total": total,
        "lines_proven_clean": proven_lines,
        "lines_needing_review": z,
        "review_reduction_pct": reduction,
        "boundary_declared": has_modules,
        "statement": statement,
    }


def _empty_headline(source: str) -> Dict[str, Any]:
    total = _count_lines(source)
    return {
        "modules_proven_clean": 0,
        "modules_total": 0,
        "boundary_violations": 0,
        "capability_breaches": [],
        "composition_rejections": 0,
        "unprovable_regions": 0,
        "lines_total": total,
        "lines_proven_clean": 0,
        "lines_needing_review": total,
        "review_reduction_pct": 0,
        "boundary_declared": False,
        "statement": ("Source did not parse; no capability surface could be "
                      "projected. Nothing is proven."),
    }


# ---------------------------------------------------------------------
# Policy diff + signed manifest.
# ---------------------------------------------------------------------

def policy_diff(source: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    """Re-prove `source` against `policy` and return before/after surfaces
    plus a per-module state diff. Powers POST /policy."""
    before = build_surface(source)
    after = build_surface(source, policy=policy)
    before_state = {m["module"]: m["state"] for m in before["modules"]}
    after_state = {m["module"]: m["state"] for m in after["modules"]}
    changes = []
    for name in sorted(set(before_state) | set(after_state)):
        b = before_state.get(name)
        a = after_state.get(name)
        if b != a:
            changes.append({"module": name, "from": b, "to": a})
    return {
        "policy": policy,
        "before": before,
        "after": after,
        "changed_modules": changes,
        "summary": {
            "before_proven_clean": before["headline"]["modules_proven_clean"],
            "after_proven_clean": after["headline"]["modules_proven_clean"],
            "before_violations": before["headline"]["boundary_violations"],
            "after_violations": after["headline"]["boundary_violations"],
        },
    }


def build_manifest(source: str, secret: bytes) -> Dict[str, Any]:
    """Emit a signed capability manifest for the PROVEN_CLEAN modules of
    `source`. The signature is an HMAC-SHA256 integrity seal over the
    canonical manifest body — it attests "this exact surface was proven by
    this engine version", not a CA-backed identity. Non-PROVEN_CLEAN
    modules go in `withheld` and are never signed."""
    import datetime as _dt
    import hashlib
    import hmac

    surface = build_surface(source)
    certified = []
    withheld = []
    for m in surface["modules"]:
        if m["state"] == "PROVEN_CLEAN":
            certified.append({
                "module": m["module"],
                "declared_capabilities": m["declared_capabilities"],
                "exports": m["exports"],
                "proven_surface": [
                    {"function": f["name"],
                     "effective_capabilities": f["effective_capabilities"]}
                    for f in m["functions"]
                ],
            })
        else:
            withheld.append({"module": m["module"], "state": m["state"],
                             "reason": "not proven clean; not certified"})
    body = {
        "manifest_version": "1",
        "engine": "aether-alsp",
        "engine_property": "capability/effect boundaries (decidable)",
        "issued_at": _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0).isoformat(),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "certified_modules": certified,
        "withheld_modules": withheld,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    return {
        "manifest": body,
        "signature": {"alg": "HMAC-SHA256", "value": sig},
        "note": ("Integrity seal over the canonical manifest body. Verifies "
                 "the surface was emitted unaltered by this engine; it is "
                 "not a public-key identity certificate."),
    }
