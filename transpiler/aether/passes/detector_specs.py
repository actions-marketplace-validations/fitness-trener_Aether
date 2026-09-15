"""Declarative catalog of the two repeated detector shapes, and the two
drivers that read it.

Thirteen of `passes/effects.py`'s detectors were the same two shapes
written out thirteen times:

  * **marker-flow** (6 rows) — a value carrying a taint marker reaches a
    sink without passing through that marker's sanctioned exit.
  * **literal-or-wrapper** (8 rows) — an argument at a sink must be a
    fixed literal or the result of a sanctioned wrapper call. Anything
    else is reported with a short *reason* that lands in the message.

Both tables are data. `marker_flow(spec)` and `literal_or_wrapper(spec)`
turn one row into a `check_*(ast) -> [Diagnostic]` function, and
`effects.py` binds and re-exports the generated names, so every existing
import site (`tests/test_effect_scope.py`'s 26, `passes/__init__.py`'s
`STAGES`) is untouched.

Diagnostic prose is product surface: demo `REPORT.md` files quote it and
the fix-loop agent reads `suggestion` to repair code. Each row therefore
carries its message and suggestion as format templates, and the
per-sink wording (`Sink.where`) travels with the sink — so no driver
ever branches on a diagnostic code.

The marker taint machinery lives here too: it exists to serve these rows
plus E0729/E0730, and putting it beside the drivers is what keeps the
dependency one-way (`effects.py` imports this module, never the
reverse). `effects.py` imports the pieces its remaining hand-written
detectors still need.

Analysis limits are unchanged by this refactor. These passes are
syntactic and intraprocedural: they over-flag rather than miss within
the modeled surface, and are not a soundness proof. Recorded residuals:
`vault/wiki/questions/q1-taint-marker-soundness-boundary.md`.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..confidence import confidence_of
from ..diagnostics import Diagnostic, Position
from .ast_walk import walk, callee_name


# ----------------------------------------------------------------------
# Generic AST access
# ----------------------------------------------------------------------

_BIND_KINDS = ("Let", "Var", "Assign")


def _bind_target(n: Dict[str, Any]) -> Optional[str]:
    """The name a binding statement writes. `Let`/`Var` carry `name`;
    `Assign` carries `target` (parser.py). Every walker that reasons
    about what a name holds goes through here — BUGS.md BUG-013: the
    taint fixpoint, the literal-or-wrapper safe-name proof, the alias
    map and E0717's stable-name proof each walked only `Let`/`Assign`
    and read only `name`, so a `var` binding was never seen and an
    assignment was dropped — `var x = password; print(x)` was exit 0."""
    tgt = n.get("name") or n.get("target")
    return tgt if isinstance(tgt, str) else None


def _walk_binds(body: Any):
    """Yield (name, value, node) for every Let/Var/Assign in `body`."""
    for n in walk(body, *_BIND_KINDS):
        tgt = _bind_target(n)
        if tgt is not None and "value" in n:
            yield tgt, n["value"], n


def _bindings(body: Any) -> Dict[str, List[Any]]:
    """name -> every Let/Var/Assign value bound to it in this body."""
    out: Dict[str, List[Any]] = {}
    for name, value, _ in _walk_binds(body):
        out.setdefault(name, []).append(value)
    return out


def _mutable_names(body: Any) -> Set[str]:
    """Names with a `var` declaration or a re-assignment in this body."""
    return {_bind_target(n) for n in walk(body, "Var", "Assign")
            if _bind_target(n) is not None}


# ----------------------------------------------------------------------
# Marker taint machinery (shared by the marker-flow rows and E0729/E0730)
# ----------------------------------------------------------------------

def _is_marker_type(ty: Any, marker: str) -> bool:
    return isinstance(ty, dict) and ty.get("kind") == "GenericType" \
        and ty.get("name") == marker


def _type_carries_marker(ty: Any, marker: str,
                         carriers: frozenset = frozenset()) -> bool:
    """True if `marker` appears ANYWHERE in the type tree: at the top
    (`PII<String>`) or nested inside a container's type arguments
    (`List<PII<String>>`, `Option<Secret<T>>`, `Map<String, PII<T>>`),
    or if the tree names a record in `carriers` — a record with a
    marker-typed field (transitively), see `_marked_records`. A `User`
    with `email: PII<String>` CARRIES the marker, so a `User` value at a
    sink is a leak exactly as a `PII<String>` is (BUGS.md BUG-016).

    Deliberately separate from `_is_marker_type`, which stays
    top-level-only because it also serves `Authorized<T>` — a PROOF
    marker, where widening what counts as a proof RELAXES acceptance
    (the wrong direction). For the three TAINT markers widening flags
    more at sinks and prunes more at the sanctioned crossings, both
    consistent with over-flag-never-miss."""
    if _is_marker_type(ty, marker):
        return True
    if isinstance(ty, dict):
        if ty.get("kind") in ("TypeName", "GenericType") \
                and ty.get("name") in carriers:
            return True
        if ty.get("kind") == "GenericType":
            return any(_type_carries_marker(a, marker, carriers)
                       for a in ty.get("args") or [])
    return False


def _marked_records(ast: Dict[str, Any], marker: str) -> frozenset:
    """Record names whose fields carry `marker`, transitively (a record
    holding a carrier record carries too; fixpoint, so cycles are safe)."""
    recs = {d["name"]: d.get("fields", []) for d in ast.get("decls", [])
            if d.get("kind") == "RecordDecl"}
    carriers: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, fields in recs.items():
            if name not in carriers and any(
                    _type_carries_marker(f.get("type"), marker, frozenset(carriers))
                    for f in fields):
                carriers.add(name)
                changed = True
    return frozenset(carriers)


def _is_record_type(ty: Any, carriers: frozenset) -> bool:
    """A carrier record at the TOP of the type (`u: User`), as opposed to
    a marker wrapper (`Secret<User>`) or a container (`List<User>`)."""
    return isinstance(ty, dict) and ty.get("kind") in ("TypeName", "GenericType") \
        and ty.get("name") in carriers


# Stdlib constructors that produce a marker-carrying value. User functions
# declared `returns <Marker><...>` are added per-module by
# _marker_source_fns; a call to any of these is a taint source.
_STDLIB_MARKER_CONSTRUCTORS: Dict[str, frozenset] = {
    "Secret":    frozenset({"classify"}),
    "PII":       frozenset({"classifyPII"}),
    "Untrusted": frozenset({"classifyUntrusted"}),
}


def _marker_source_fns(ast: Dict[str, Any], marker: str) -> frozenset:
    """Functions whose call results carry `marker`: the stdlib
    constructors plus every user function declared with a marker-typed
    return. Signature-level only — bodies are not analyzed."""
    carriers = _marked_records(ast, marker)
    # A carrier record's constructor IS a call that yields a marked value.
    names = set(_STDLIB_MARKER_CONSTRUCTORS.get(marker, frozenset())) | set(carriers)
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl" \
                and _type_carries_marker(d.get("return_type"), marker, carriers):
            names.add(d["name"])
    return frozenset(names)


def _marker_field_names(ast: Dict[str, Any], marker: str) -> frozenset:
    """Record FIELD names declared with a type carrying `marker`.

    Matched by name, not by resolved record type: the `Field` node holds
    only the field name and a base expression, and resolving the base's
    record type needs type inference this pass does not have. Over-flags
    a same-named plain field on an unrelated record — the accepted
    direction (over-flag, never miss within the modeled surface).
    Residual: `vault/wiki/questions/q1-taint-marker-soundness-boundary.md`."""
    carriers = _marked_records(ast, marker)
    out = set()
    for d in ast.get("decls", []):
        if d.get("kind") == "RecordDecl":
            for f in d.get("fields", []):
                if _type_carries_marker(f.get("type"), marker, carriers):
                    out.add(f["name"])
    return frozenset(out)


def _marker_param_mask(ast: Dict[str, Any], marker: str) -> Dict[str, Tuple[bool, ...]]:
    """callable name -> per-argument mask, True where the declared type
    carries `marker`. Passing a marked value into such a slot is a
    sanctioned crossing — the callee owns the value from there (its own
    body is checked; what escapes is its return, covered by
    _marker_source_fns).

    Records are in this table too, keyed by the record name: a v0.1
    record constructor IS a call, positional in declared field order
    (`grammar/types.md`, "Records"), and a marker-typed FIELD preserves
    the marker exactly as a marker-typed param does. Without this, a
    record could never legitimately hold a marked value — every
    construction site would report E0729/E0730.

    Only callables with at least one marked slot are kept: an all-False
    mask is never consulted (`if mask:` at the prune site), and copying
    one entry per FunctionDecl per function made the marker-flow passes
    quadratic in function count (TC-04)."""
    carriers = _marked_records(ast, marker)
    out: Dict[str, Tuple[bool, ...]] = {}
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl":
            mask = tuple(_type_carries_marker(p.get("type"), marker, carriers)
                         for p in d.get("params", []))
        elif d.get("kind") == "RecordDecl":
            mask = tuple(_type_carries_marker(f.get("type"), marker, carriers)
                         for f in d.get("fields", []))
        else:
            continue
        if any(mask):
            out[d["name"]] = mask
    return out


def _expr_leaks_marked(node: Any, tainted: Set[str], unwrap,
                       source_fns: frozenset = frozenset(),
                       param_mask: Optional[Dict[str, Tuple[bool, ...]]] = None,
                       marked_fields: frozenset = frozenset(),
                       rec_names: frozenset = frozenset()) -> bool:
    """True if `node` exposes a tainted name, a read of a marker-typed
    record field, or a call to a marker-producing function, outside an
    `unwrap(...)` call (the sanctioned exit for this marker). `unwrap` is
    a single name or a set of names. An argument consumed by a
    marker-typed parameter of a user-declared callee — or by a
    marker-typed FIELD of a record constructor — is pruned per
    `param_mask`: that crossing is sanctioned.

    `rec_names` are names known to hold a carrier RECORD (`u: User`,
    see `_record_names`). Such a name is tainted — the whole record at a
    sink leaks its marked field — but reading one of its UNMARKED fields
    (`u.name`) is not a leak and is pruned. The prune applies only to a
    name whose type is the record itself, never to `s: Secret<User>`:
    there every field is secret."""
    unwraps = {unwrap} if isinstance(unwrap, str) else unwrap
    if isinstance(node, dict):
        kind = node.get("kind")
        if kind == "Call":
            callee = callee_name(node)
            if callee in unwraps:
                return False  # sanctioned, audited exit — prune
            if callee in source_fns:
                return True   # call returns a marker-typed value
            mask = (param_mask or {}).get(callee)
            if mask:
                args = node.get("args") or []
                open_args = [a for i, a in enumerate(args)
                             if i >= len(mask) or not mask[i]]
                rest = [v for k, v in node.items() if k != "args"]
                return _expr_leaks_marked(open_args + rest, tainted, unwrap,
                                          source_fns, param_mask, marked_fields,
                                          rec_names)
        if kind == "Field":
            if node.get("name") in marked_fields:
                return True   # read of a marker-typed record field
            base = node.get("value")
            if isinstance(base, dict) and base.get("kind") == "Ident" \
                    and base.get("name") in rec_names:
                return False  # plain field of a carrier record — not the marked one
        if kind == "Ident" and node.get("name") in tainted:
            return True
        return any(_expr_leaks_marked(v, tainted, unwrap, source_fns,
                                      param_mask, marked_fields, rec_names)
                   for v in node.values())
    if isinstance(node, list):
        return any(_expr_leaks_marked(x, tainted, unwrap, source_fns,
                                      param_mask, marked_fields, rec_names)
                   for x in node)
    return False


def _fn_aliases(fn_decl: Dict[str, Any], targets: frozenset) -> Dict[str, Set[str]]:
    """alias name -> set of target function names it may refer to, from
    straight-line `let f = fnName` / `var f = fnName` / `f = g` bindings
    (bare Ident values; chains followed by fixpoint; conservative UNION
    when a name is rebound). Used flag-more only — an aliased unwrapper
    is never honored, an aliased SINK is a sink (BUGS.md BUG-015)."""
    binds: List[Tuple[str, str]] = []
    for name, v, _ in _walk_binds(fn_decl.get("body", [])):
        if isinstance(v, dict) and v.get("kind") == "Ident":
            binds.append((name, v["name"]))
    out: Dict[str, Set[str]] = {}
    changed = True
    while changed:
        changed = False
        for name, src in binds:
            ts = ({src} if src in targets else set()) | out.get(src, set())
            if ts - out.get(name, set()):
                out.setdefault(name, set()).update(ts)
                changed = True
    return out


def _sink_targets(name: Optional[str], aliases: Dict[str, Set[str]],
                  sinks) -> List[str]:
    """The sinks a call to `name` reaches: `name` itself, or every sink
    an alias of that name may refer to. Flag-more only — resolution can
    add sinks, never remove one."""
    if name in sinks:
        return [name]
    return sorted(aliases.get(name, set()) & set(sinks))


def _aliased_mask(pmask: Dict[str, Tuple[bool, ...]],
                  aliases: Dict[str, Set[str]]) -> Dict[str, Tuple[bool, ...]]:
    """pmask extended with alias entries — ONLY single-target aliases
    (pruning is the accept-more direction; ambiguity must over-flag)."""
    out = dict(pmask)
    for a, ts in aliases.items():
        if len(ts) == 1:
            t = next(iter(ts))
            if t in pmask and a not in out:
                out[a] = pmask[t]
    return out


def _pattern_bind_names(pat: Any) -> Set[str]:
    """Names bound by a match pattern (BindPat leaves, recursively —
    nested constructor patterns included)."""
    return {n["name"] for n in walk(pat, "BindPat") if "name" in n}


def _record_names(fn_decl: Dict[str, Any], carriers: frozenset,
                  rec_fns: frozenset) -> frozenset:
    """Names whose EVERY binding is a carrier record at the top of its
    type: a `: User` annotation (param, let, var), a `User(...)`
    constructor call, a call to a function declared `returns User`, or a
    bare alias of such a name (chains, fixpoint). One binding of any
    other shape disqualifies the name — `u = pw` would make a plain-field
    prune on `u` a miss. Syntactic and intraprocedural like everything
    here; an unresolved shape stays out, which only over-flags."""
    def top(ty: Any) -> bool:
        return _is_record_type(ty, carriers)

    body = fn_decl.get("body", [])
    binds: Dict[str, List[Tuple[Dict[str, Any], Any]]] = {}
    for name, value, n in _walk_binds(body):
        binds.setdefault(name, []).append((n, value))
    params = {p["name"] for p in fn_decl.get("params", []) if top(p.get("type"))}

    def rec_shaped(n: Dict[str, Any], v: Any, known: Set[str]) -> bool:
        if top(n.get("type")):
            return True
        if isinstance(v, dict):
            if v.get("kind") == "Call":
                c = callee_name(v)
                return c in carriers or c in rec_fns
            if v.get("kind") == "Ident":
                return v.get("name") in known
        return False

    names: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for cand in params | set(binds):
            if cand not in names and all(rec_shaped(n, v, names)
                                         for n, v in binds.get(cand, [])):
                names.add(cand)
                changed = True
    return frozenset(names)


def _record_fns(ast: Dict[str, Any], carriers: frozenset) -> frozenset:
    """User functions declared to return a carrier record at the top."""
    return frozenset(d["name"] for d in ast.get("decls", [])
                     if d.get("kind") == "FunctionDecl"
                     and _is_record_type(d.get("return_type"), carriers))


def _marked_taint(fn_decl: Dict[str, Any], marker: str, unwrap,
                  source_fns: frozenset = frozenset(),
                  param_mask: Optional[Dict[str, Tuple[bool, ...]]] = None,
                  marked_fields: frozenset = frozenset(),
                  carriers: frozenset = frozenset(),
                  rec_fns: frozenset = frozenset()) -> Tuple[Set[str], frozenset]:
    """(tainted, rec_names): names holding a `marker`-typed value —
    marker-typed params, let/var annotated with a marker-carrying type,
    plus any let/var/assign target bound to an expression carrying a
    tainted name (fixpoint; an `unwrap(...)` call breaks the taint). A
    call to a `source_fns` member seeds taint (signature-level
    interprocedural). Bindings introduced by a `match`/match-expression
    arm pattern over a tainted scrutinee, and a `for` loop variable over
    a tainted iterable, are tainted (every arm, every binding —
    conservative; BUGS.md BUG-001 and BUG-014).

    A read of a marker-typed record field (`marked_fields`) is a taint
    source. A name typed with a carrier record (`u: User`) is tainted
    too — the whole record at a sink leaks the field — and is reported
    in `rec_names` so a read of one of its UNMARKED fields can be pruned
    (see `_expr_leaks_marked`)."""
    rec_names = _record_names(fn_decl, carriers, rec_fns) if carriers else frozenset()
    tainted: Set[str] = {
        p["name"] for p in fn_decl.get("params", [])
        if _type_carries_marker(p.get("type"), marker, carriers)
    }
    binds: List[Tuple[str, Any]] = []
    destructures: List[Tuple[Set[str], Any]] = []  # (bound names, source expr)

    body = fn_decl.get("body", [])
    for name, value, n in _walk_binds(body):
        if _type_carries_marker(n.get("type"), marker, carriers):
            tainted.add(name)  # the annotation says so
        binds.append((name, value))
    for n in walk(body, "Match", "MatchExpr"):
        if "scrutinee" not in n:
            continue
        names: Set[str] = set()
        for arm in n.get("arms", []):
            names |= _pattern_bind_names(arm.get("pattern"))
        if names:
            destructures.append((names, n["scrutinee"]))
    for n in walk(body, "For"):
        if isinstance(n.get("var"), str) and "iter" in n:
            destructures.append(({n["var"]}, n["iter"]))
    changed = True
    while changed:
        changed = False
        for name, value in binds:
            if name not in tainted and _expr_leaks_marked(
                    value, tainted, unwrap, source_fns, param_mask,
                    marked_fields, rec_names):
                tainted.add(name)
                changed = True
        for names, scrut in destructures:
            if not names <= tainted and _expr_leaks_marked(
                    scrut, tainted, unwrap, source_fns, param_mask,
                    marked_fields, rec_names):
                tainted |= names
                changed = True
    return tainted, rec_names


def _marked_tainted_names(fn_decl: Dict[str, Any], marker: str, unwrap,
                          source_fns: frozenset = frozenset(),
                          param_mask: Optional[Dict[str, Tuple[bool, ...]]] = None,
                          marked_fields: frozenset = frozenset(),
                          carriers: frozenset = frozenset(),
                          rec_fns: frozenset = frozenset()) -> Set[str]:
    """The tainted-name half of `_marked_taint`."""
    return _marked_taint(fn_decl, marker, unwrap, source_fns, param_mask,
                         marked_fields, carriers, rec_fns)[0]


# ======================================================================
# The spec table
# ======================================================================

@dataclass(frozen=True)
class Sink:
    """One sink of a marker-flow row.

    `arg_indices` None inspects every argument; a tuple restricts the
    check to those positions (writeFile's CONTENTS argument, not the
    path it writes to). `where` is this sink's verb phrase, substituted
    into the row's message template — that is what used to be an inline
    `"logs" if sink == "print" else "persists to disk"` conditional in
    check_secret_flow / check_pii_flow.
    """
    name: str
    arg_indices: Optional[Tuple[int, ...]] = None
    where: str = ""


@dataclass(frozen=True)
class MarkerFlowSpec:
    """*Marked value reaches sink without sanitizer.*

    `message` is formatted with `fn`, `sink` and `where`; `suggestion` is
    fixed prose. Both are byte-identical to the hand-written detector
    they replace — REPORT.md files quote the message and the fix-loop
    agent reads the suggestion.
    """
    name: str
    code: str
    marker: str
    sanitizer: str
    sinks: Tuple[Sink, ...]
    message: str
    suggestion: str


@dataclass(frozen=True)
class ArgRule:
    """How to judge one argument expression, and what to say when it fails.

    Checks run in the hand-written order: string literal (subject to
    `literal_bans`), sanctioned wrapper call, name proven to hold only
    safe values, `+` concatenation, everything else. A reason of None
    means the shape has no special wording and falls through to
    `default`; that is not an omission — E0719/E0720 deliberately give a
    non-wrapper call no phrasing of its own, and E0711/E0720 give
    concatenation none.

    `pin` is the reason returned when a wrapper call's FIRST argument —
    the template, base or host the wrapper pins everything else to —
    does not itself satisfy the rule. `sqlBind(userTemplate, v)` binds
    `v` into whatever `userTemplate` says; `safeJoin(userBase, p)` keeps
    `p` under a directory the attacker chose; `safeRedirect(userHost, p)`
    pins to the attacker's host. Every wrapper used to be accepted on its
    NAME alone (BUGS.md BUG-020). None for a rule whose wrapper has no
    pinning slot: `trusted(x)` takes the dynamic value itself. A Call the
    Python frontend emitted (`py`) is exempt — `shlex.quote(x)` and a
    SQLAlchemy expression arrive as wrapper calls with no template slot.
    """
    wrappers: Tuple[str, ...]
    not_a_node: str
    default: str
    call: Optional[str] = None
    concat: Optional[str] = None
    literal_bans: Tuple[Tuple[str, str], ...] = ()
    fixpoint: bool = True
    pin: Optional[str] = None


@dataclass(frozen=True)
class CalleeText:
    """The wording a literal-or-wrapper row uses when the Python frontend
    named the sink by a callee under `prefix` — one dotted prefix or a
    tuple of them (`str.startswith` takes either) — and, when `leaf` is
    set, only for that last component (`parse` vs `parseString`: the
    file form of an XML parser opens its source argument, the string
    form does not). `Call.callee` is the spelling `_callee_spelling`
    resolved: a dotted import path on a `qualified`/`guard`/`argv`
    match, the builtin name on `builtin`/`builtin_compile`, the
    attribute path as written (possibly chained, `self.db.cursor.execute`)
    on a `method` match. Text only: which calls are the sink, and what
    argument they refuse, is decided by the row and never here."""
    prefix: "str | Tuple[str, ...]"
    message: str
    suggestion: str
    leaf: Optional[str] = None


@dataclass(frozen=True)
class LiteralOrWrapperSpec:
    """*This argument must be a fixed literal or a sanctioned wrapper call.*

    `message` and `suggestion` are formatted with `fn`, `sink`, the
    `reason` the rule produced and, on a Python-frontend finding, the
    resolved `callee` (`xml.etree.ElementTree.fromstring`), its
    `callee_tail` (`ElementTree.fromstring`, the last two components) and
    its `callee_leaf` (`fromstring`).
    `safe_rule` is the rule that decides which NAMES count as safe when
    they reach the sink; it defaults to `rule` and differs only for
    E0720/E0727, which judge their argument by the deserialize rule but
    resolve literal-bound names by the template rule. `callee_text` is
    consulted in order and the first prefix match wins; an Aether-source
    finding has no callee and always gets the row's own text.
    """
    name: str
    code: str
    sinks: Tuple[str, ...]
    rule: ArgRule
    message: str
    suggestion: str
    arg_index: int = 0
    safe_rule: Optional[ArgRule] = None
    callee_text: Tuple[CalleeText, ...] = ()

    def text_for(self, callee: Optional[str]) -> Tuple[str, str]:
        """`(message, suggestion)` templates for a finding on `callee`."""
        leaf = (callee or "").rsplit(".", 1)[-1]
        for row in self.callee_text:
            if callee and callee.startswith(row.prefix) \
                    and row.leaf in (None, leaf):
                return row.message, row.suggestion
        return self.message, self.suggestion


# `trusted(x)` is the explicit-trust boundary: an auditable assertion
# that a dynamic value came from a vetted source. It is the escape hatch
# for the two literal-or-wrapper rows with no safer sanitizer (E0719
# template, E0720 deserialize) — the dual of reveal()/redact().
TRUSTED = "trusted"


# --- marker-flow: 6 rows ----------------------------------------------

_LOG_SINK = Sink("print", None, "logs")
_DISK_SINK = Sink("writeFile", (1,), "persists to disk")

MARKER_FLOW_SPECS: Tuple[MarkerFlowSpec, ...] = (
    MarkerFlowSpec(
        name="check_secret_flow", code="E0712", marker="Secret", sanitizer="reveal",
        sinks=(_LOG_SINK, _DISK_SINK),
        message=("function {fn!r} {where} a Secret value via "
                 "{sink!r}; a value marked Secret<...> must not reach a "
                 "log or persistence sink in the clear"),
        suggestion=("do not expose the secret; if disclosure is truly "
                    "intended, wrap it in reveal(...) at the "
                    "call site so the exposure is explicit and auditable"),
    ),
    MarkerFlowSpec(
        name="check_pii_flow", code="E0715", marker="PII", sanitizer="redact",
        sinks=(_LOG_SINK, _DISK_SINK),
        message=("function {fn!r} {where} a PII value via {sink!r}; "
                 "personal data marked PII<...> must not cross a "
                 "log/persistence sink in the clear"),
        suggestion=("mask it with redact(...) before the sink, or "
                    "keep PII out of logs/files entirely; redact(...) is "
                    "the auditable, consent-safe disclosure"),
    ),
    MarkerFlowSpec(
        name="check_log_injection", code="E0724", marker="Untrusted", sanitizer="sanitizeLog",
        sinks=(_LOG_SINK,),
        message=("function {fn!r} {where} an Untrusted value via {sink!r}; "
                 "embedded CR/LF can forge fake log entries (log "
                 "injection)"),
        suggestion=("wrap it in sanitizeLog(...), which strips the "
                    "control characters an attacker uses to forge log lines"),
    ),
    MarkerFlowSpec(
        name="check_reflected_xss", code="E0725", marker="Untrusted", sanitizer="htmlEscape",
        sinks=(Sink("htmlResponse", None, "writes"),),
        message=("function {fn!r} {where} an Untrusted value into an HTML "
                 "response via {sink!r}; unescaped markup "
                 "executes in the victim's browser (reflected XSS)"),
        suggestion=("wrap it in htmlEscape(...), which escapes "
                    "<, >, &, \" and ' so the value renders as text, not "
                    "markup (sanitizeLog does NOT protect here)"),
    ),
    MarkerFlowSpec(
        name="check_header_injection", code="E0726", marker="Untrusted", sanitizer="sanitizeHeader",
        sinks=(Sink("setHeader", None, "puts"),),
        message=("function {fn!r} {where} an Untrusted value in a response "
                 "header via {sink!r}; embedded CR/LF "
                 "injects headers or a second response (response "
                 "splitting)"),
        suggestion=("wrap it in sanitizeHeader(...), which strips the "
                    "CR/LF used to break out of the header value"),
    ),
    MarkerFlowSpec(
        name="check_csv_injection", code="E0728", marker="Untrusted", sanitizer="csvEscape",
        sinks=(Sink("csvCell", None, "writes"),),
        message=("function {fn!r} {where} an Untrusted value into a CSV "
                 "cell via {sink!r}; a leading = + - @ makes "
                 "it a formula when opened in a spreadsheet (CSV injection)"),
        suggestion=("wrap it in csvEscape(...), which neutralizes a "
                    "leading formula trigger so the value stays inert text"),
    ),
)


# --- literal-or-wrapper: 7 rules, 8 rows -------------------------------

_PATH_RULE = ArgRule(
    wrappers=("safeJoin",),
    not_a_node="path is not a fixed literal - can be steered by input",
    call="path is a computed call - route it through safeJoin()",
    default="path is a dynamic expression - route it through safeJoin()",
    literal_bans=(("..", "literal path contains '..' - escapes its directory"),),
    # No `pin` here, deliberately: `safeJoin(base, rel)` strips '..' and
    # absolute roots from `rel`, and a base directory handed in as a
    # PARAMETER is the idiom (7 corpus sites; both zipslip demos'
    # fixed.aeth). The base is program-chosen, not the untrusted half,
    # so pinning it would flag the sanctioned exit itself. Recorded as a
    # residual in q1 rather than enforced (BUGS.md BUG-020 covers the
    # three wrappers whose first argument IS the untrusted-facing text).
    # E0711 resolves safe names in ONE pass, not to a fixpoint — the only
    # row that does. A fixpoint proves a superset of names safe, i.e.
    # reports a subset of traversals, so switching is a relax-direction
    # behaviour change, not a refactor. Probed across all 427 `.aeth` in
    # the tree: the two agree on every file, so the difference is latent,
    # not live. Kept as found rather than silently widened.
    fixpoint=False,
)

_SQL_RULE = ArgRule(
    wrappers=("sqlBind",),
    not_a_node="query is not a fixed literal",
    call="query is a computed call - use sqlBind(template, value)",
    concat="query is built by string concatenation - use sqlBind(...)",
    default="query is a dynamic expression - use sqlBind(template, value)",
    pin="sqlBind template is not a fixed literal - binding cannot parameterize the query text itself",
)

_SHELL_RULE = ArgRule(
    wrappers=("shellArg",),
    not_a_node="command is not a fixed literal",
    call="command is a computed call - use shellArg(template, value)",
    concat="command is built by string concatenation - use shellArg(...)",
    default="command is a dynamic expression - use shellArg(template, value)",
    pin="shellArg template is not a fixed literal - quoting cannot protect the command line itself",
)

_REDIRECT_RULE = ArgRule(
    wrappers=("safeRedirect",),
    not_a_node="redirect target is not a fixed literal",
    call="target is a computed call - use safeRedirect(host, path)",
    concat="target is built by concatenation - use safeRedirect(host, path)",
    default="target is a dynamic expression - use safeRedirect(host, path)",
    pin="safeRedirect host is not a fixed literal - the pinned host is itself steerable",
)

_TEMPLATE_RULE = ArgRule(
    wrappers=(TRUSTED,),
    not_a_node="template is not a fixed literal",
    concat="template is built by string concatenation",
    default="template is a dynamic expression, not a fixed literal",
)

# The template rule's contract exactly — literal-only, `trusted(...)` the
# sole wrapper, no sanitizer exists — worded for the thing an interpreter
# runs. There is no way to escape attacker-authored code into something
# safe to execute.
_CODE_RULE = ArgRule(
    wrappers=(TRUSTED,),
    not_a_node="source is not a fixed literal",
    concat="source is built by string concatenation",
    default="source is a dynamic expression, not a fixed literal",
)

_DESERIALIZE_RULE = ArgRule(
    wrappers=(TRUSTED,),
    not_a_node="argument is not a fixed literal",
    default="argument is untrusted / dynamic data",
)

# E0727's Python text, shared by its stdlib rows. The facts are the Python
# docs' (`library/xml.html`, "XML security", and the 3.11 page's table
# footnotes), measured 2026-09-11 on CPython 3.11.15 / Expat 2.7.4:
# demos/case_studies/LOOP_LOG.md iteration 53. The DoS clause is hedged
# the way the docs hedge it, per issue; "large tokens" (CVE-2023-52425)
# is a re-parse cost, not an entity attack, so it is not called one.
_EXPAT_DOS = ("an older Expat (Python may use the system copy) may be open "
              "to denial of service: the Python docs put the fixes at 2.4.1 "
              "(billion laughs, quadratic blowup), 2.6.0 (large tokens) and "
              "2.7.2 (disproportional memory use)")
_EXPAT_DIRECT_MSG = ("function {fn!r} parses untrusted XML via {callee} "
                     "({reason}); this parser never expands external entities, "
                     "so there is no XXE file read or SSRF through entities on "
                     "any Expat, but " + _EXPAT_DOS)
_SAX_MSG = ("function {fn!r} parses untrusted XML via {callee} ({reason}); "
            "{callee_leaf} builds its own parser with external entities off "
            "(since Python 3.7.1) and takes no parser argument, so there is "
            "no XXE through entities, but " + _EXPAT_DOS)
_DOM_MSG = ("function {fn!r} parses untrusted XML via {callee} ({reason}); "
            "external entities are off by default (since Python 3.7.1), but "
            "a parser= argument built with xml.sax.make_parser() and "
            "setFeature(feature_external_ges, True) resolves them, reading "
            "local files and reaching internal URLs (XXE), and " + _EXPAT_DOS)
# A parse() spelling opens its SOURCE argument itself (measured: a str is
# open()ed as a local path; xml.sax.parse and lxml.etree.parse also fetch a
# URL). E0727 judges entity resolution; no row judges that open — q1's
# recorded miss.
_SRC_PATH = ("; the source string of {callee} is itself opened as a local "
             "path, which no row judges")
_SRC_PATH_OR_URL = ("; the source string of {callee} is itself opened as a "
                    "local file or, when no such file exists, fetched with "
                    "urllib.request.urlopen(), which no row judges")
# `pyexpat.EXPAT_VERSION` is the string "expat_2.7.4"; the tuple is what a
# startup check can compare. defusedxml substitutes its defused parser only
# when `parser` is None — a caller's parser is passed straight through
# (measured: the secret came back through defusedxml.minidom.parseString
# with a feature_external_ges parser), hence "no parser= argument".
_DEFUSED_FIX = ("parse with defusedxml.{callee_tail} and no parser= argument "
                "(it defuses only the parser it builds itself), which then "
                "refuses entity declarations outright; otherwise check "
                "pyexpat.version_info >= (2, 7, 2) at startup")
_DEFUSED_FIX_SRC = _DEFUSED_FIX + "; never pass an untrusted path as the source"
_DEFUSED_FIX_SRC_URL = _DEFUSED_FIX + ("; never pass an untrusted path or URL as "
                                       "the source (defusedxml.sax.parse opens it "
                                       "the same way)")
# The lxml binding `_safe_xml_parser_names` recognises: resolve_entities
# False, and no_network / load_dtd / dtd_validation absent or at their safe
# value (an external DTD is fetched under load_dtd=True, no_network=False —
# measured). tests/test_py_frontend_sinks.py pins this exact string in the
# hint AND checks it as a clean fix shape, so they cannot drift.
_LXML_SAFE_PARSER = ("lxml.etree.XMLParser(resolve_entities=False, "
                     "no_network=True, load_dtd=False)")
_LXML_MSG = ("function {fn!r} parses untrusted XML via {callee} ({reason}); "
             "lxml read local files through external entities by default "
             "before 5.0 (December 2023) and still does under "
             "resolve_entities=True (a URL only when no_network=False is set "
             "as well), so a crafted <!ENTITY SYSTEM ...> reads local files "
             "(XXE)")
_LXML_FIX = ("bind parser = " + _LXML_SAFE_PARSER + " in this function and "
             "pass it as the parser argument, positionally or as parser=; "
             "that binding clears this finding")

LITERAL_OR_WRAPPER_SPECS: Tuple[LiteralOrWrapperSpec, ...] = (
    LiteralOrWrapperSpec(
        name="check_fs_path_safety", code="E0711", sinks=("writeFile", "readFile"), rule=_PATH_RULE,
        message=("function {fn!r} calls {sink!r} with an unsafe path "
                 "({reason}); a path traversal here can read or "
                 "overwrite arbitrary files"),
        suggestion=("use a fixed string literal, or build the path with "
                    "safeJoin(baseDir, untrustedPart) which strips "
                    "'..' and absolute roots so it cannot escape baseDir"),
    ),
    LiteralOrWrapperSpec(
        name="check_injection", code="E0713", sinks=("sqlQuery", "sqlExec", "sqlByOwner"), rule=_SQL_RULE,
        message=("function {fn!r} builds a SQL query for "
                 "{sink!r} unsafely ({reason}); untrusted "
                 "input concatenated into a query is an injection"),
        suggestion=("use a fixed literal, or parameterize with "
                    "sqlBind(\"... ? ...\", value) which escapes the "
                    "value so it cannot break out of the query"),
    ),
    LiteralOrWrapperSpec(
        name="check_command_injection", code="E0714", sinks=("shellExec",), rule=_SHELL_RULE,
        message=("function {fn!r} builds a shell command for "
                 "{sink!r} unsafely ({reason}); untrusted "
                 "input concatenated into a command line is a command "
                 "injection"),
        suggestion=("use a fixed literal, or place the untrusted value with "
                    "shellArg(\"... ? ...\", value) which quotes it as a "
                    "single argument so it cannot inject shell syntax"),
    ),
    LiteralOrWrapperSpec(
        name="check_open_redirect", code="E0718", sinks=("redirect",), rule=_REDIRECT_RULE,
        message=("function {fn!r} redirects to an untrusted target "
                 "({reason}); an open redirect sends users to an "
                 "attacker-controlled site from a trusted link"),
        suggestion=("redirect to a fixed literal path, or pin the host with "
                    "safeRedirect(\"your-host.example\", path) so the "
                    "target can only stay on your origin"),
    ),
    LiteralOrWrapperSpec(
        name="check_template_injection", code="E0719", sinks=("renderTemplate",), rule=_TEMPLATE_RULE,
        message=("function {fn!r} renders a dynamic template via "
                 "{sink!r} ({reason}); untrusted input in "
                 "the template is server-side template injection (RCE)"),
        suggestion=("keep the template a fixed string literal; pass "
                    "untrusted values as the second (data) argument, which "
                    "the engine escapes instead of evaluating"),
    ),
    LiteralOrWrapperSpec(
        name="check_deserialization", code="E0720", sinks=("deserialize",), rule=_DESERIALIZE_RULE,
        # A name bound only to literals is a trusted constant.
        safe_rule=_TEMPLATE_RULE,
        message=("function {fn!r} deserializes untrusted data via "
                 "{sink!r} ({reason}); an unrestricted "
                 "decoder on attacker-controlled bytes is remote code "
                 "execution"),
        suggestion=("decode with schemaDecode(schema, data), which pins "
                    "the output to a fixed schema and cannot instantiate "
                    "arbitrary types"),
    ),
    LiteralOrWrapperSpec(
        name="check_xxe", code="E0727", sinks=("parseXml",), rule=_DESERIALIZE_RULE,
        safe_rule=_TEMPLATE_RULE,
        # The Aether stdlib `parseXml` MODELS an entity-resolving parser
        # (`runtime.py`), so on an `.aeth` source this text is exact.
        message=("function {fn!r} parses untrusted XML via "
                 "{sink!r} ({reason}); an entity-resolving "
                 "parser reads local files and reaches internal URLs (XXE)"),
        suggestion=("parse with parseXmlSafe(data), which disables external "
                    "entity resolution (no file read, no SSRF, no billion-"
                    "laughs)"),
        # The Python callees the frontend maps to `parseXml` are not one
        # hazard, and `parseXmlSafe` does not exist for a Python user.
        # Every fact below was measured 2026-09-11 (CPython 3.11.15,
        # Expat 2.7.4, lxml 6.1.1 / libxml2 2.11.9, a local HTTP server
        # for the URL claims) and is recorded in
        # demos/case_studies/LOOP_LOG.md iteration 53. Rows are tried in
        # order; the first prefix (and leaf) match wins, so each family's
        # `parse` row precedes its general row.
        callee_text=(
            # lxml: external entities read local files by default before
            # 5.0.0 (2023-12-29, its changelog: "lxml no longer expands
            # external entities (XXE) by default") and on every version
            # under `resolve_entities=True`. A URL is fetched only when
            # `no_network=False` is set as well — `no_network=True` is the
            # default (XMLParser docstring), and `resolve_entities=True`
            # alone made 0 requests. lxml.etree.parse(source) opens or
            # fetches its SOURCE with any parser, the hardened one
            # included (measured) — outside this row. The frontend clears
            # a hardened parser bound in the same function, passed
            # positionally or as `parser=` (`_safe_xml_parser_names`,
            # `_sink_match`).
            CalleeText(
                prefix="lxml.", leaf="parse",
                message=_LXML_MSG + ("; the source string of {callee} is itself a "
                                     "filename or URL lxml opens with any parser, "
                                     "which no row judges"),
                suggestion=_LXML_FIX + "; never pass an untrusted path or URL as the source",
            ),
            CalleeText(prefix="lxml.", message=_LXML_MSG, suggestion=_LXML_FIX),
            # xml.sax.parse / parseString build a fresh make_parser() in
            # their own body, with general external entities off since
            # Python 3.7.1 (the xml.sax docs' "Changed in version 3.7.1"
            # note), and take no parser argument — so the feature cannot
            # be on through these callees. xml.sax.parse's SOURCE is a
            # system identifier: an existing file is opened, anything
            # else is urlopen()ed (the xml.sax docs; measured: 1 request).
            # A parser OBJECT with setFeature(feature_external_ges, True)
            # reads the file and fetches the URL (measured), but its own
            # `.parse` is a receiver-bound method, not a mapped sink:
            # q1's recorded miss, the next TYPE gap.
            CalleeText(prefix="xml.sax.", leaf="parse",
                       message=_SAX_MSG + _SRC_PATH_OR_URL, suggestion=_DEFUSED_FIX_SRC_URL),
            CalleeText(prefix="xml.sax.", message=_SAX_MSG, suggestion=_DEFUSED_FIX),
            # minidom and pulldom take a `parser=` SAX parser. One built
            # with xml.sax.make_parser() and setFeature(feature_external_ges,
            # True) reads the file AND fetches the URL through both
            # (measured). Off by default (since 3.7.1); the frontend does
            # not track setFeature, so both states get this finding. The
            # parse() forms open a str source as a local path.
            CalleeText(prefix=("xml.dom.minidom.", "xml.dom.pulldom."), leaf="parse",
                       message=_DOM_MSG + _SRC_PATH, suggestion=_DEFUSED_FIX_SRC),
            CalleeText(prefix=("xml.dom.minidom.", "xml.dom.pulldom."),
                       message=_DOM_MSG, suggestion=_DEFUSED_FIX),
            # cElementTree is ElementTree's parser under a deprecated
            # name, and defusedxml.cElementTree is deprecated too: the
            # hint names defusedxml.ElementTree.
            CalleeText(
                prefix="xml.etree.cElementTree.", leaf="parse",
                message=_EXPAT_DIRECT_MSG + _SRC_PATH,
                suggestion=_DEFUSED_FIX_SRC.replace("defusedxml.{callee_tail}",
                                                    "defusedxml.ElementTree.{callee_leaf}"),
            ),
            CalleeText(
                prefix="xml.etree.cElementTree.",
                message=_EXPAT_DIRECT_MSG,
                suggestion=_DEFUSED_FIX.replace("defusedxml.{callee_tail}",
                                                "defusedxml.ElementTree.{callee_leaf}"),
            ),
            # ElementTree and expatbuilder: straight on Expat, which "does
            # not access local files or create network connections"
            # (Python docs, "XML security"). ElementTree raises ParseError
            # on an external entity, expatbuilder drops it (measured; the
            # 3.11 table's footnotes 2-3 for ElementTree/minidom). Not
            # version-dependent; only the DoS clause is. Their parse()
            # forms open() a str source as a local path (a URL raises
            # OSError; measured).
            CalleeText(prefix="xml.", leaf="parse",
                       message=_EXPAT_DIRECT_MSG + _SRC_PATH, suggestion=_DEFUSED_FIX_SRC),
            CalleeText(prefix="xml.", message=_EXPAT_DIRECT_MSG, suggestion=_DEFUSED_FIX),
            # defusedxml with a caller's parser (SINK_GUARDS rows keyed on
            # `parser=`): defusedxml substitutes its defused parser only
            # when `parser` is None, and passes any other straight through
            # — measured: the secret came back through
            # defusedxml.minidom.parseString(xxe, parser=<feature_external_ges>).
            CalleeText(
                prefix="defusedxml.",
                message=("function {fn!r} parses untrusted XML via {callee} with a "
                         "parser= argument ({reason}); defusedxml defuses only the "
                         "parser it builds itself and passes a caller's parser "
                         "straight through, so one built with xml.sax.make_parser() "
                         "and setFeature(feature_external_ges, True) reads local "
                         "files and reaches internal URLs (XXE)"),
                suggestion=("drop the parser= argument (or pass parser=None) so "
                            "defusedxml builds its own parser, which refuses entity "
                            "declarations outright"),
            ),
        ),
    ),
    LiteralOrWrapperSpec(
        name="check_code_injection", code="E0731", sinks=("evalCode",), rule=_CODE_RULE,
        message=("function {fn!r} executes dynamic code via {sink!r} "
                 "({reason}); an interpreter fed attacker-authored source "
                 "is arbitrary code execution (code injection)"),
        suggestion=("keep the source a fixed string literal and never build "
                    "code from input; a script that genuinely ships with the "
                    "application may be asserted with trusted(...)"),
    ),
)


# Sanctioned unwrappers a marker-flow row does NOT own. `trusted(...)`
# clears Untrusted<T> at a call-site boundary as well, so E0729/E0730
# must honour it; it is nobody's row sanitizer, so it is declared rather
# than derived.
_EXTRA_UNWRAPPERS: Dict[str, Tuple[str, ...]] = {"Untrusted": (TRUSTED,)}


def marker_sink_sanitizers() -> Dict[str, Dict[str, str]]:
    """marker -> sink name -> the sanitizer that marker's row demands AT
    THAT SINK. `boundary_markers()` flattens this into one set per
    marker, which is exactly the coarseness BUGS.md BUG-023 reports:
    `sanitizeLog(u)` clears an Untrusted crossing into a callee that
    feeds `htmlResponse`, whose sanitizer is `htmlEscape`. Derived from
    MARKER_FLOW_SPECS; nothing restates the map."""
    out: Dict[str, Dict[str, str]] = {}
    for spec in MARKER_FLOW_SPECS:
        for s in spec.sinks:
            out.setdefault(spec.marker, {})[s.name] = spec.sanitizer
    return out


def _marker_sink_args() -> Dict[str, Optional[Tuple[int, ...]]]:
    """sink name -> the argument positions marker-flow rows check there
    (None = every argument), unioned across rows."""
    out: Dict[str, Optional[Tuple[int, ...]]] = {}
    for spec in MARKER_FLOW_SPECS:
        for s in spec.sinks:
            if s.name not in out:
                out[s.name] = s.arg_indices
            elif out[s.name] is None or s.arg_indices is None:
                out[s.name] = None
            else:
                out[s.name] = tuple(sorted(set(out[s.name]) | set(s.arg_indices)))
    return out


def _marker_sink_unwrappers() -> Dict[str, frozenset]:
    """sink name -> every sanitizer a marker row demands AT that sink,
    plus the sink-agnostic assertions (`trusted(...)`). A parameter that
    reaches a sink only THROUGH one of these does not reach it raw:
    counting it reported the idiomatic callee that sanitizes internally
    (`htmlResponse(htmlEscape(s))`) as feeding the sink unsanitized, and
    told the caller to sanitize a second time (BUGS.md BUG-024)."""
    extra = {u for us in _EXTRA_UNWRAPPERS.values() for u in us}
    out: Dict[str, Set[str]] = {}
    for spec in MARKER_FLOW_SPECS:
        for s in spec.sinks:
            out.setdefault(s.name, set()).add(spec.sanitizer)
    return {s: frozenset(v | extra) for s, v in out.items()}


def param_sink_reach(ast: Dict[str, Any]) -> Dict[str, Dict[int, frozenset]]:
    """user function name -> param index -> the marker-flow SINK names
    that parameter reaches inside the body. A parameter reaches a sink
    when its Ident appears in one of the argument positions that sink's
    rows actually check (`Sink.arg_indices`) — the same rule
    `marker_flow` applies. Aliased sinks count (`_sink_targets`,
    flag-more).

    E0729 consumes this to judge WHICH sanitizer clears a boundary
    crossing (BUGS.md BUG-023). One level only, and by direct Ident:
    a callee that rebinds the parameter, or passes it on to a THIRD
    function, contributes no sinks — the summary then names none and
    E0729 keeps its pre-BUG-023 behaviour. The sanitizer prune is
    syntactic at the sink call: it recognises `htmlResponse(htmlEscape(s))`
    (BUGS.md BUG-024) but not a sanitize-into-a-local, which the direct-Ident
    rule already drops from the summary anyway. Residual recorded in
    `vault/wiki/questions/q1-taint-marker-soundness-boundary.md`."""
    sinks = _marker_sink_args()
    unwrap_at = _marker_sink_unwrappers()
    out: Dict[str, Dict[int, frozenset]] = {}
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        params = d.get("params", [])
        if not params:
            continue
        al = _fn_aliases(d, frozenset(sinks))
        per: Dict[int, Set[str]] = {}
        for call in walk(d.get("body", []), "Call"):
            args = call.get("args") or []
            for sink in _sink_targets(callee_name(call), al, sinks):
                idx = sinks[sink]
                checked = args if idx is None else \
                    [args[i] for i in idx if i < len(args)]
                for i, p in enumerate(params):
                    # tainted={param}, unwrapped by whatever THIS sink
                    # accepts: "this Ident arrives here unsanitized".
                    if _expr_leaks_marked(checked, {p["name"]},
                                          unwrap_at.get(sink, frozenset())):
                        per.setdefault(i, set()).add(sink)
        if per:
            out[d["name"]] = {i: frozenset(v) for i, v in per.items()}
    return out


def boundary_markers() -> Dict[str, frozenset]:
    """Marker -> sanctioned call-site unwrappers, DERIVED from
    MARKER_FLOW_SPECS. E0729 (marker boundary) and E0730 (return
    laundering) consume this; nothing restates the map. Key order follows
    the spec table, which is the order the two detectors report in."""
    out: Dict[str, Set[str]] = {}
    for spec in MARKER_FLOW_SPECS:
        out.setdefault(spec.marker, set()).add(spec.sanitizer)
    for marker, extra in _EXTRA_UNWRAPPERS.items():
        out.setdefault(marker, set()).update(extra)
    return {m: frozenset(v) for m, v in out.items()}


# ======================================================================
# The two drivers
# ======================================================================

def _arg_reason(node: Any, safe_names: Set[str], rule: ArgRule) -> Optional[str]:
    """None if `node` satisfies `rule`, else the short reason it does not
    — the reason is part of the diagnostic message."""
    if not isinstance(node, dict):
        return rule.not_a_node
    kind = node.get("kind")
    if kind == "StringLit":
        text = node.get("value") or ""
        for banned, why in rule.literal_bans:
            if banned in text:
                return why
        return None
    if kind == "Call":
        if callee_name(node) in rule.wrappers:
            if rule.pin is None or node.get("py"):
                return None
            # The wrapper pins everything to its first argument; that
            # argument has to be pinned itself (BUG-020).
            args = node.get("args") or []
            if not args or _arg_reason(args[0], safe_names, rule) is not None:
                return rule.pin
            return None
        return rule.call if rule.call is not None else rule.default
    if kind == "Ident" and node.get("name") in safe_names:
        return None
    if kind == "BinOp" and node.get("op") == "+" and rule.concat is not None:
        return rule.concat
    return rule.default


def _safe_names(body: Any, rule: ArgRule) -> Set[str]:
    """Names bound ONLY to values `rule` accepts, across every binding to
    them in this body. A single unsafe binding disqualifies the name, and
    so does a `var` declaration or a re-assignment: a mutable name is not
    a fixed literal (BUGS.md BUG-013 — `let p = "/etc/motd"; p = userPath;
    readFile(p)` was proven safe by the `let` alone because the
    assignment was invisible). Iterated to a fixpoint so a name bound to
    an earlier safe name is itself safe — except where the row asks for a
    single pass."""
    binds = _bindings(body)
    mutable = _mutable_names(body)
    safe: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in binds.items():
            if name in safe or name in mutable:
                continue
            if all(_arg_reason(v, safe, rule) is None for v in values):
                safe.add(name)
                changed = True
        if not rule.fixpoint:
            break
    return safe


def literal_or_wrapper(spec: LiteralOrWrapperSpec) -> Callable[[Dict[str, Any]], List[Diagnostic]]:
    """Build the `check_*` pass for one literal-or-wrapper row."""
    safe_rule = spec.safe_rule or spec.rule

    sink_set = frozenset(spec.sinks)

    def check(ast: Dict[str, Any]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        for d in ast.get("decls", []):
            if d.get("kind") != "FunctionDecl":
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            body = d.get("body", [])
            safe_names = _safe_names(body, safe_rule)
            aliases = _fn_aliases(d, sink_set)
            for call in walk(body, "Call"):
                # An alias of a sink is the sink (`let run = sqlQuery`).
                targets = _sink_targets(callee_name(call), aliases, sink_set)
                if not targets:
                    continue
                args = call.get("args") or []
                if len(args) <= spec.arg_index:
                    continue
                reason = _arg_reason(args[spec.arg_index], safe_names, spec.rule)
                if reason is None:
                    continue
                pos = call.get("pos") or fpos
                # How the Python frontend named this call a sink — absent
                # on an Aether-source finding, where nothing was guessed.
                match = call.get("match")
                # WHICH Python callee it resolved to; picks the row's
                # wording (`callee_text`) and nothing else.
                callee = call.get("callee")
                message, suggestion = spec.text_for(callee)
                parts = (callee or "").split(".")
                words = {"fn": fn, "reason": reason, "callee": callee,
                         "callee_tail": ".".join(parts[-2:]),
                         "callee_leaf": parts[-1]}
                for sink in targets:
                    diags.append(Diagnostic(
                        code=spec.code,
                        category="capability",
                        severity="error",
                        message=message.format(sink=sink, **words),
                        position=Position(pos.get("line", 0), pos.get("column", 0)),
                        suggestion=suggestion.format(sink=sink, **words),
                        confidence=confidence_of(match),
                        extra=({"function": fn, "sink": sink, "reason": reason}
                               | ({"match": match} if match else {})
                               | ({"callee": callee} if callee else {})),
                    ))
        return diags

    return check


def marker_flow(spec: MarkerFlowSpec) -> Callable[[Dict[str, Any]], List[Diagnostic]]:
    """Build the `check_*` pass for one marker-flow row."""
    sinks = {s.name: s for s in spec.sinks}

    sink_names = frozenset(sinks)

    def check(ast: Dict[str, Any]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        src_fns = _marker_source_fns(ast, spec.marker)
        pmask = _marker_param_mask(ast, spec.marker)
        mfields = _marker_field_names(ast, spec.marker)
        carriers = _marked_records(ast, spec.marker)
        rec_fns = _record_fns(ast, carriers)
        # Alias targets, once per module (TC-04): sources, marked
        # callables and this row's sinks.
        targets = src_fns | frozenset(pmask) | sink_names
        for d in ast.get("decls", []):
            if d.get("kind") != "FunctionDecl":
                continue
            al = _fn_aliases(d, targets)
            src_l = src_fns | frozenset(a for a, ts in al.items() if ts & src_fns)
            pmask_l = _aliased_mask(pmask, al)
            tainted, rec_names = _marked_taint(d, spec.marker, spec.sanitizer,
                                               src_l, pmask_l, mfields,
                                               carriers, rec_fns)
            # `not mfields` is load-bearing: a function that only reads
            # `u.email` has no tainted NAMES, and the old guard skipped it.
            if not tainted and not src_l and not mfields:
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            for call in walk(d.get("body", []), "Call"):
                # An alias of a sink is the sink (`let out = print`).
                hits = _sink_targets(callee_name(call), al, sink_names)
                if not hits:
                    continue
                args = call.get("args") or []
                pos = call.get("pos") or fpos
                match = call.get("match")
                for sname in hits:
                    sink = sinks[sname]
                    checked = args if sink.arg_indices is None else \
                        [args[i] for i in sink.arg_indices if i < len(args)]
                    if not any(_expr_leaks_marked(a, tainted, spec.sanitizer,
                                                  src_l, pmask_l, mfields, rec_names)
                               for a in checked):
                        continue
                    diags.append(Diagnostic(
                        code=spec.code,
                        category="capability",
                        severity="error",
                        message=spec.message.format(fn=fn, sink=sname, where=sink.where),
                        position=Position(pos.get("line", 0), pos.get("column", 0)),
                        suggestion=spec.suggestion,
                        confidence=confidence_of(match),
                        extra=({"function": fn, "sink": sname}
                               | ({"match": match} if match else {})),
                    ))
        return diags

    return check


SPECS_BY_NAME: Dict[str, Any] = {
    s.name: s for s in MARKER_FLOW_SPECS + LITERAL_OR_WRAPPER_SPECS
}


def build(name: str) -> Callable[[Dict[str, Any]], List[Diagnostic]]:
    """Generate the detector for one row, under the public name
    `effects.py` binds it to. The name is load-bearing:
    `tests/test_ratchet.py` counts registered detectors by `fn.__name__`,
    so two rows must never share one."""
    spec = SPECS_BY_NAME[name]
    driver = marker_flow if isinstance(spec, MarkerFlowSpec) else literal_or_wrapper
    fn = driver(spec)
    fn.__name__ = fn.__qualname__ = name
    fn.__doc__ = (f"Return {spec.code} diagnostics. Generated from the "
                  f"{driver.__name__} row in passes/detector_specs.py.")
    return fn
