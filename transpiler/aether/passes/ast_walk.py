"""The recursive descent over the AST, written once.

Six generators across `passes/` were the same eleven lines with one
`kind` string changed, and a dozen more inlined the same recursion in a
local `collect()`. `walk(node, *kinds)` replaces them all: it yields
every dict node reachable from `node` — descending through dict values
and list elements — whose `"kind"` is in `kinds`. With no kinds it
yields every dict node.

Order is pre-order and follows dict insertion order, which is source
order for parser output. A matching node is yielded AND descended into,
so a Call nested in a Call yields both. Both properties are load-bearing:
`tests/test_corpus.py` pins the exact multiplicity every corpus program
reports, so a walk that visits a node twice or skips a branch fails the
gate rather than passing quietly.

`callee_name` lives here because every caller of `walk(node, "Call")`
immediately needs it, and it was the same clone in the same three files.

Deliberately NOT unified: `patch_target.py`'s `_walk_calls_with_path` /
`_walk_returns_with_path`. They thread a structural path prefix through
the descent and skip the `kind`/`pos`/`name`/`op` fields, to build the
anchor a fix-loop splices a patch against — a different traversal with a
different return type, pinned by `tests/test_alsp_corpus.py`'s H.A.1.b
anchor contract. Nor are the passes that PRUNE (`_expr_leaks_marked`,
`_escaped_gated_idents`): a walk that stops early is not this walk.
"""

from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple


# ----------------------------------------------------------------------
# The per-analysis index (audit 2026-09-24 F5)
# ----------------------------------------------------------------------
# Thirty detectors each re-walked every function for its binders, its
# calls and its contexts: ~5.4M `walk()` frames on the three slowest
# framework files, 77% of analysis time. Inside `shared_index()` (which
# `passes.analyze()` enters) each of those per-node results is computed
# once and handed to every detector. Outside it nothing is cached, so a
# detector called directly behaves exactly as before.
#
# Keyed by `id(node)`, with the node itself kept in the entry and compared
# by identity, so a recycled id can never alias. Sound only because no
# pass mutates the AST during analysis (the same property the walk's
# pre-order contract already relies on).
_INDEX: ContextVar[Optional[Dict[Tuple[str, int], Tuple[Any, Any]]]] = \
    ContextVar("aether_shared_index", default=None)


@contextmanager
def shared_index():
    """Share per-node walk results across every detector run inside."""
    token = _INDEX.set({})
    try:
        yield
    finally:
        _INDEX.reset(token)


def _indexed(tag: str, node: Any, compute: Callable[[], Any]) -> Any:
    memo = _INDEX.get()
    if memo is None:
        return compute()
    key = (tag, id(node))
    hit = memo.get(key)
    if hit is not None and hit[0] is node:
        return hit[1]
    value = compute()
    memo[key] = (node, value)
    return value


def walk(node: Any, *kinds: str) -> Iterator[Dict[str, Any]]:
    """Yield every dict node reachable from `node` whose `kind` is in
    `kinds` (every dict node if `kinds` is empty).

    Iterative (an explicit stack, children pushed in reverse so the order
    stays pre-order / insertion order): the recursive form hit Python's
    recursion limit on a 500-term `1 + 1 + ...` chain, which the parser
    accepts (audit 2026-09-24 A10)."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if not kinds or n.get("kind") in kinds:
                yield n
            stack.extend(reversed(list(n.values())))
        elif isinstance(n, list):
            stack.extend(reversed(n))


def fn_exprs(decl: Dict[str, Any]) -> List[Any]:
    """Everything a function EVALUATES: its body AND its `requires` /
    `ensures` clauses. Every pass that asks "what does this function do"
    walks this, never `decl["body"]` alone — a `requires
    isOk?(writeFile(...))` runs at call entry, so walking only the body
    let a `pure` function write files and a `requires shellExec("rm -rf "
    + n)` escape E0801 and E0714 together (audit 2026-09-24 A1)."""
    return [decl.get("body", []), decl.get("requires", []),
            decl.get("ensures", [])]


def contexts(ast: Dict[str, Any]) -> Tuple[Dict[str, Any], ...]:
    """`_contexts(ast)` as a tuple, built once per analysis: the
    synthetic contexts must be the SAME dicts for every detector, or the
    per-function index below would miss on them."""
    return _indexed("contexts", ast, lambda: tuple(_contexts(ast)))


def _contexts(ast: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    """Every evaluation context of a program, as function-shaped dicts:
    each `FunctionDecl`, plus one synthetic PURE context per refinement
    predicate (`type T = B where <pred>`, run at every boundary check,
    with `self` as its one parameter) and per `const` initializer (run
    once at module load). Neither declares effects, so any effect in
    them is E0801, and under a module E0701 (audit 2026-09-24 A1).

    The synthetic contexts carry `"synthetic"` and a `name` no user
    function can have (`<const X>` / `<type T where>`), so a pass that
    keys a SIGNATURE table by function name must keep reading real
    `FunctionDecl`s; only the per-body scans iterate this."""
    for d in ast.get("decls", []):
        k = d.get("kind")
        if k == "FunctionDecl":
            yield d
        elif k == "TypeDecl" and d.get("refinement") is not None:
            yield {"kind": "FunctionDecl", "synthetic": "refinement",
                   "name": f"<type {d.get('name')} where>",
                   "params": [{"name": "self", "type": d.get("base")}],
                   "effects": [], "body": [d["refinement"]],
                   "pos": d.get("pos")}
        elif k == "ConstDecl" and d.get("value") is not None:
            yield {"kind": "FunctionDecl", "synthetic": "const",
                   "name": f"<const {d.get('name')}>", "params": [],
                   "effects": [], "body": [d["value"]], "pos": d.get("pos")}


class Binder(NamedTuple):
    """One place a name gets a value inside a function.

    `value` is the bound expression, or None for a VALUE-LESS binder: a
    `for` loop variable or a `match` pattern binding, whose value is
    some element of `source` (the iterable / the scrutinee). A pass that
    PROVES something about a name (safe literal, stable id, authorized
    proof) must treat a value-less binder as disqualifying; a taint pass
    propagates through `source`."""
    name: str
    value: Optional[Dict[str, Any]]
    kind: str
    node: Dict[str, Any]
    source: Optional[Dict[str, Any]]


def binders(decl: Dict[str, Any]) -> Tuple[Binder, ...]:
    """`_binders(decl)` as a tuple, built once per analysis."""
    return _indexed("binders", decl, lambda: tuple(_binders(decl)))


def fn_calls(decl: Dict[str, Any]) -> Tuple[Dict[str, Any], ...]:
    """Every `Call` a function evaluates — `walk(fn_exprs(decl), "Call")`,
    in the same pre-order, built once per analysis."""
    return _indexed("calls", decl, lambda: tuple(walk(fn_exprs(decl), "Call")))


def all_nodes(node: Any) -> Tuple[Dict[str, Any], ...]:
    """`walk(node)` — every dict node, pre-order — built once per analysis."""
    return _indexed("nodes", node, lambda: tuple(walk(node)))


def names_in(node: Any) -> frozenset:
    """Every string `name` field anywhere under `node` (identifiers,
    callees, declarations, type names), built once per analysis."""
    return _indexed("names", node, lambda: frozenset(
        n["name"] for n in all_nodes(node) if isinstance(n.get("name"), str)))


def _binders(decl: Dict[str, Any]) -> Iterator[Binder]:
    """Every binding in a function: its parameters (kind `Param`, value
    None), then in body and contracts `let`, `var`, assignment, `for`
    loop variable, and each `BindPat` / `AsPat` name of every `match`
    statement AND match expression arm.

    The ONE binding iterator. Six fixpoints each walked their own subset
    and five of them knew only Let/Var/Assign, so `let s = "SELECT 1";
    for s in xs do sqlQuery(s) end` was proven a literal (audit
    2026-09-24 A5; the BUG-013/014 class, closed here at the root rather
    than walker by walker). `Let`/`Var` carry `name`, `Assign` carries
    `target` (the Python frontend's `Assign` carries `name`)."""
    for p in decl.get("params") or []:
        if isinstance(p.get("name"), str):
            # A parameter is a binder too: a value the body did not choose.
            # Without it `p = "lit"` after `readFile(p)` proved `p` a literal.
            yield Binder(p["name"], None, "Param", p, None)
    for n in walk(fn_exprs(decl)):
        k = n.get("kind")
        if k in ("Let", "Var", "Assign"):
            tgt = n.get("name") or n.get("target")
            if isinstance(tgt, str):
                yield Binder(tgt, n.get("value"), k, n, None)
        elif k == "For":
            if isinstance(n.get("var"), str):
                yield Binder(n["var"], None, k, n, n.get("iter"))
        elif k in ("Match", "MatchExpr"):
            for arm in n.get("arms") or []:
                for p in walk(arm.get("pattern"), "BindPat", "AsPat"):
                    if isinstance(p.get("name"), str):
                        yield Binder(p["name"], None, p["kind"], p,
                                     n.get("scrutinee"))


def callee_name(call_node: Dict[str, Any]) -> Optional[str]:
    """Extract a simple name from a Call's `func` if direct/named."""
    func = call_node.get("func") or {}
    kind = func.get("kind")
    if kind == "Ident":
        return func.get("name")
    if kind == "Field":
        inner = func.get("value") or {}
        if inner.get("kind") == "Ident":
            return func.get("name")
    return None
