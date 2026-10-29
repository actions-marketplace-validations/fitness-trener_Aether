"""E0208 — name resolution: a reference to a name nothing declares.

The emitter rewrites every identifier through `runtime.mangle()` and runs
the result in a namespace holding only the runtime's `_ae_*` exports and
the program's own definitions, so a name nothing binds is a Python
`NameError` at `run` — after `check` said nothing. Worse for a security
checker: a misspelt sink (`sqlQeury("SELECT " + u)`) is a call no taint
pass can name, so it produced no E0713 and exited 0 (iter-57 scope fact).

This is name RESOLUTION, not type checking: it proves each identifier
refers to some binding, never that the binding has the right type,
arity or kind (`grammar/types.md`, "What is checked, and when").

A name is visible where it is used if it is
  - a parameter of the enclosing function (`self` in a refinement
    predicate; `result` in an `ensures` clause),
  - bound earlier in the same block or an enclosing one (`let`, `var`,
    assignment, `for` variable, a `match` arm's pattern bindings — the
    binder kinds of `ast_walk.binders()`), block-scoped,
  - a top-level function, `const`, record constructor or union case of
    the program (imports already fused in by `load_program`) — inside a
    `const` initializer, which runs at module load, only one declared
    ABOVE it,
  - a runtime export: `runtime.unmangle()` over the runtime's globals,
    the set `build_namespace()` hands emitted code (so `Some`/`None`/
    `Ok`/`Err` too). Never a hand-kept list.
Not evaluated, so not resolved: the right side of `is` (a type name),
the qualifier of `Union.Case(...)`, patterns, type annotations, and
`effects` arguments.

Silent (no E0208 at all) when the program is not the whole program: a
partial AST from the lenient parser (the declaration that failed may
have bound the name), or an `import` that was not resolved
(`--no-import-resolution`, or a caller that parsed without
`load_program`) — the imported file may bind it.
"""

from __future__ import annotations
import difflib
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set

from .. import runtime
from ..diagnostics import Diagnostic, Position

# ponytail: derived once at import; the runtime's globals are fixed.
RUNTIME_NAMES: FrozenSet[str] = frozenset(
    n for n in map(runtime.unmangle, vars(runtime)) if n)


def _pattern_names(pat: Any) -> List[str]:
    out: List[str] = []
    stack = [pat]
    while stack:
        p = stack.pop()
        if isinstance(p, dict):
            if p.get("kind") in ("BindPat", "AsPat") and isinstance(p.get("name"), str):
                out.append(p["name"])
            stack.extend(p.values())
        elif isinstance(p, list):
            stack.extend(p)
    return out


class _Resolver:
    def __init__(self, globals_: Set[str], cases: Set[str], fn: str):
        self.globals = globals_
        self.cases = cases
        self.fn = fn
        self.diags: List[Diagnostic] = []
        self._seen: Set[tuple] = set()

    def _report(self, name: str, kind: str, scope: Iterable[str], pos) -> None:
        pos = pos or {"line": 0, "column": 0}
        key = (name, kind, pos.get("line", 0), pos.get("column", 0))
        if key in self._seen:
            return
        self._seen.add(key)
        known = set(scope) | self.globals | RUNTIME_NAMES
        close = difflib.get_close_matches(name, sorted(known), n=1)
        sugg = close[0] if close else None
        what = "calls" if kind == "call" else "reads"
        self.diags.append(Diagnostic(
            code="E0208", category="type", severity="error",
            message=(f"function {self.fn!r} {what} {name!r}, which is not "
                     f"declared anywhere: not a parameter, a local, a "
                     f"top-level declaration, an import or a stdlib "
                     f"function; it would fail at run time with NameError"),
            position=Position(pos.get("line", 0), pos.get("column", 0)),
            suggestion=(f"did you mean {sugg!r}?" if sugg else
                        f"declare {name!r}, or fix the spelling"),
            confidence=1.0,
            extra={"function": self.fn, "name": name, "kind": kind,
                   "suggestion": sugg},
        ))

    def _name(self, name: str, kind: str, scope: Set[str], pos) -> None:
        if name not in scope and name not in self.globals \
                and name not in RUNTIME_NAMES:
            self._report(name, kind, scope, pos)

    # --- expressions --------------------------------------------------
    def expr(self, e: Any, scope: Set[str], pos) -> None:
        if isinstance(e, list):
            for x in e:
                self.expr(x, scope, pos)
            return
        if not isinstance(e, dict):
            return
        pos = e.get("pos") or pos
        k = e.get("kind")
        if k == "Ident":
            self._name(e.get("name"), "value", scope, pos)
        elif k == "Call":
            f = e.get("func") or {}
            if f.get("kind") == "Ident":
                self._name(f.get("name"), "call", scope, pos)
            elif (f.get("kind") == "Field" and f.get("name") in self.cases
                  and (f.get("value") or {}).get("kind") == "Ident"):
                pass    # `Union.Case(...)`: the emitter calls the case
            else:
                self.expr(f, scope, pos)
            self.expr(e.get("args"), scope, pos)
        elif k == "BinOp" and e.get("op") == "is":
            self.expr(e.get("left"), scope, pos)    # right side is a type
        elif k == "MatchExpr":
            self.expr(e.get("scrutinee"), scope, pos)
            for arm in e.get("arms") or []:
                self.expr(arm.get("value"),
                          scope | set(_pattern_names(arm.get("pattern"))), pos)
        else:
            for v in e.values():
                if isinstance(v, (dict, list)):
                    self.expr(v, scope, pos)

    # --- statements ---------------------------------------------------
    def block(self, stmts: Any, scope: Set[str], pos=None) -> None:
        scope = set(scope)      # block scope: bindings end with the block
        for s in stmts or []:
            if not isinstance(s, dict):
                continue
            p = s.get("pos") or pos
            k = s.get("kind")
            if k in ("Let", "Var", "Assign"):
                self.expr(s.get("value"), scope, p)
                tgt = s.get("name") or s.get("target")
                if isinstance(tgt, str):
                    scope.add(tgt)
            elif k == "If":
                self.expr(s.get("cond"), scope, p)
                self.block(s.get("then"), scope, p)
                for el in s.get("elifs") or []:
                    self.expr(el.get("cond"), scope, p)
                    self.block(el.get("body"), scope, p)
                self.block(s.get("else"), scope, p)
            elif k == "While":
                self.expr(s.get("cond"), scope, p)
                self.block(s.get("body"), scope, p)
            elif k == "For":
                self.expr(s.get("iter"), scope, p)
                self.block(s.get("body"), scope | {s.get("var")}, p)
            elif k == "Match":
                self.expr(s.get("scrutinee"), scope, p)
                for arm in s.get("arms") or []:
                    self.block(arm.get("body"),
                               scope | set(_pattern_names(arm.get("pattern"))), p)
            else:       # Return, ExprStmt, Break, Continue
                self.expr({k2: v for k2, v in s.items() if k2 != "kind"},
                          scope, p)


def _complete(ast: Dict[str, Any]) -> bool:
    """False when names may be bound somewhere this AST does not show."""
    if ast.get("partial"):
        return False
    has_import = any(d.get("kind") == "ImportDecl" for d in ast.get("decls", []))
    return not has_import or bool(ast.get("imports_resolved"))


def check_name_resolution(ast: Dict[str, Any]) -> List[Diagnostic]:
    """E0208 for every identifier or callee no binding reaches."""
    if not _complete(ast):
        return []
    decls = ast.get("decls", [])
    cases = {c["name"] for d in decls if d.get("kind") == "UnionDecl"
             for c in d.get("cases") or []}
    globals_ = cases | {d["name"] for d in decls
                        if d.get("kind") in ("FunctionDecl", "ConstDecl",
                                             "RecordDecl")}
    # A `const` initializer runs at module load, in declaration order: it
    # sees only what is defined above it (`const A = B` before `const B`
    # was a NameError at load).
    earlier: Set[str] = set()
    diags: List[Diagnostic] = []
    for d in decls:
        k = d.get("kind")
        if k == "ConstDecl":
            r = _Resolver(earlier, cases, f"<const {d.get('name')}>")
            r.expr(d.get("value"), set(), d.get("pos"))
            diags.extend(r.diags)
        if k == "UnionDecl":
            earlier |= {c["name"] for c in d.get("cases") or []}
        elif k in ("FunctionDecl", "ConstDecl", "RecordDecl"):
            earlier.add(d["name"])
        pos: Optional[Dict[str, int]] = d.get("pos")
        if k == "FunctionDecl":
            r = _Resolver(globals_, cases, d["name"])
            params = {p["name"] for p in d.get("params") or []}
            r.expr(d.get("requires"), params, pos)
            r.expr(d.get("ensures"), params | {"result"}, pos)
            r.block(d.get("body"), params, pos)
        elif k == "TypeDecl" and d.get("refinement") is not None:
            r = _Resolver(globals_, cases, f"<type {d.get('name')} where>")
            r.expr(d["refinement"], {"self"}, pos)
        else:
            continue
        diags.extend(r.diags)
    return diags
