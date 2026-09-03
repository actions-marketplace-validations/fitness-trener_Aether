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

from ..diagnostics import Diagnostic, Position
from .ast_walk import walk, callee_name


# ----------------------------------------------------------------------
# Generic AST access
# ----------------------------------------------------------------------

def _bindings(body: Any) -> Dict[str, List[Any]]:
    """name -> every Let/Assign value bound to it in this body."""
    out: Dict[str, List[Any]] = {}
    for n in walk(body, "Let", "Assign"):
        if "name" in n and "value" in n:
            out.setdefault(n["name"], []).append(n["value"])
    return out


# ----------------------------------------------------------------------
# Marker taint machinery (shared by the marker-flow rows and E0729/E0730)
# ----------------------------------------------------------------------

def _is_marker_type(ty: Any, marker: str) -> bool:
    return isinstance(ty, dict) and ty.get("kind") == "GenericType" \
        and ty.get("name") == marker


def _type_carries_marker(ty: Any, marker: str) -> bool:
    """True if `marker` appears ANYWHERE in the type tree: at the top
    (`PII<String>`) or nested inside a container's type arguments
    (`List<PII<String>>`, `Option<Secret<T>>`, `Map<String, PII<T>>`).

    Deliberately separate from `_is_marker_type`, which stays
    top-level-only because it also serves `Authorized<T>` — a PROOF
    marker, where widening what counts as a proof RELAXES acceptance
    (the wrong direction). For the three TAINT markers widening flags
    more at sinks and prunes more at the sanctioned crossings, both
    consistent with over-flag-never-miss."""
    if _is_marker_type(ty, marker):
        return True
    if isinstance(ty, dict) and ty.get("kind") == "GenericType":
        return any(_type_carries_marker(a, marker)
                   for a in ty.get("args") or [])
    return False


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
    names = set(_STDLIB_MARKER_CONSTRUCTORS.get(marker, frozenset()))
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl" \
                and _type_carries_marker(d.get("return_type"), marker):
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
    out = set()
    for d in ast.get("decls", []):
        if d.get("kind") == "RecordDecl":
            for f in d.get("fields", []):
                if _type_carries_marker(f.get("type"), marker):
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
    construction site would report E0729/E0730."""
    out: Dict[str, Tuple[bool, ...]] = {}
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl":
            out[d["name"]] = tuple(_type_carries_marker(p.get("type"), marker)
                                   for p in d.get("params", []))
        elif d.get("kind") == "RecordDecl":
            out[d["name"]] = tuple(_type_carries_marker(f.get("type"), marker)
                                   for f in d.get("fields", []))
    return out


def _expr_leaks_marked(node: Any, tainted: Set[str], unwrap,
                       source_fns: frozenset = frozenset(),
                       param_mask: Optional[Dict[str, Tuple[bool, ...]]] = None,
                       marked_fields: frozenset = frozenset()) -> bool:
    """True if `node` exposes a tainted name, a read of a marker-typed
    record field, or a call to a marker-producing function, outside an
    `unwrap(...)` call (the sanctioned exit for this marker). `unwrap` is
    a single name or a set of names. An argument consumed by a
    marker-typed parameter of a user-declared callee — or by a
    marker-typed FIELD of a record constructor — is pruned per
    `param_mask`: that crossing is sanctioned."""
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
                                          source_fns, param_mask, marked_fields)
        if kind == "Field" and node.get("name") in marked_fields:
            return True   # read of a marker-typed record field
        if kind == "Ident" and node.get("name") in tainted:
            return True
        return any(_expr_leaks_marked(v, tainted, unwrap, source_fns,
                                      param_mask, marked_fields)
                   for v in node.values())
    if isinstance(node, list):
        return any(_expr_leaks_marked(x, tainted, unwrap, source_fns,
                                      param_mask, marked_fields)
                   for x in node)
    return False


def _fn_aliases(fn_decl: Dict[str, Any], targets: frozenset) -> Dict[str, Set[str]]:
    """alias name -> set of target function names it may refer to, from
    straight-line `let f = fnName` / `f = g` bindings (bare Ident
    values; chains followed by fixpoint; conservative UNION when a name
    is rebound). Used flag-more only — an aliased unwrapper is never
    honored."""
    binds: List[Tuple[str, str]] = []
    for n in walk(fn_decl.get("body", []), "Let", "Assign"):
        if "name" in n:
            v = n.get("value")
            if isinstance(v, dict) and v.get("kind") == "Ident":
                binds.append((n["name"], v["name"]))
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


def _marked_tainted_names(fn_decl: Dict[str, Any], marker: str, unwrap,
                          source_fns: frozenset = frozenset(),
                          param_mask: Optional[Dict[str, Tuple[bool, ...]]] = None,
                          marked_fields: frozenset = frozenset()) -> Set[str]:
    """Names holding a `marker`-typed value: marker-typed params, plus any
    let/assign target bound to an expression carrying a tainted name
    (fixpoint; an `unwrap(...)` call breaks the taint). A call to a
    `source_fns` member seeds taint (signature-level interprocedural).
    Match-arm pattern bindings over a tainted scrutinee are tainted
    (every arm, every binding — conservative).

    A read of a marker-typed record field (`marked_fields`) is a taint
    source; the record-typed name itself is NOT tainted, so passing the
    record on stays a clean crossing."""
    tainted: Set[str] = {
        p["name"] for p in fn_decl.get("params", [])
        if _type_carries_marker(p.get("type"), marker)
    }
    binds: List[Tuple[str, Any]] = []
    destructures: List[Tuple[Set[str], Any]] = []  # (arm-bound names, scrutinee)

    body = fn_decl.get("body", [])
    for n in walk(body, "Let", "Assign"):
        if "name" in n and "value" in n:
            binds.append((n["name"], n["value"]))
    for n in walk(body, "Match"):
        if "scrutinee" not in n:
            continue
        names: Set[str] = set()
        for arm in n.get("arms", []):
            names |= _pattern_bind_names(arm.get("pattern"))
        if names:
            destructures.append((names, n["scrutinee"]))
    changed = True
    while changed:
        changed = False
        for name, value in binds:
            if name not in tainted and _expr_leaks_marked(
                    value, tainted, unwrap, source_fns, param_mask, marked_fields):
                tainted.add(name)
                changed = True
        for names, scrut in destructures:
            if not names <= tainted and _expr_leaks_marked(
                    scrut, tainted, unwrap, source_fns, param_mask, marked_fields):
                tainted |= names
                changed = True
    return tainted


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
class LiteralOrWrapperSpec:
    """*This argument must be a fixed literal or a sanctioned wrapper call.*

    `message` is formatted with `fn`, `sink` and the `reason` the rule
    produced. `safe_rule` is the rule that decides which NAMES count as
    safe when they reach the sink; it defaults to `rule` and differs only
    for E0720/E0727, which judge their argument by the deserialize rule
    but resolve literal-bound names by the template rule.
    """
    name: str
    code: str
    sinks: Tuple[str, ...]
    rule: ArgRule
    message: str
    suggestion: str
    arg_index: int = 0
    safe_rule: Optional[ArgRule] = None


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
        message=("function {fn!r} parses untrusted XML via "
                 "{sink!r} ({reason}); an entity-resolving "
                 "parser reads local files and reaches internal URLs (XXE)"),
        suggestion=("parse with parseXmlSafe(data), which disables external "
                    "entity resolution (no file read, no SSRF, no billion-"
                    "laughs)"),
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
    """Names bound ONLY to values `rule` accepts, across every Let/Assign
    to them in this body. A single unsafe binding disqualifies the name.
    Iterated to a fixpoint so a name bound to an earlier safe name is
    itself safe — except where the row asks for a single pass."""
    binds = _bindings(body)
    safe: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in binds.items():
            if name in safe:
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

    def check(ast: Dict[str, Any]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        for d in ast.get("decls", []):
            if d.get("kind") != "FunctionDecl":
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            body = d.get("body", [])
            safe_names = _safe_names(body, safe_rule)
            for call in walk(body, "Call"):
                sink = callee_name(call)
                if sink not in spec.sinks:
                    continue
                args = call.get("args") or []
                if len(args) <= spec.arg_index:
                    continue
                reason = _arg_reason(args[spec.arg_index], safe_names, spec.rule)
                if reason is None:
                    continue
                pos = call.get("pos") or fpos
                diags.append(Diagnostic(
                    code=spec.code,
                    category="capability",
                    severity="error",
                    message=spec.message.format(fn=fn, sink=sink, reason=reason),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=spec.suggestion,
                    confidence=1.0,
                    extra={"function": fn, "sink": sink, "reason": reason},
                ))
        return diags

    return check


def marker_flow(spec: MarkerFlowSpec) -> Callable[[Dict[str, Any]], List[Diagnostic]]:
    """Build the `check_*` pass for one marker-flow row."""
    sinks = {s.name: s for s in spec.sinks}

    def check(ast: Dict[str, Any]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        src_fns = _marker_source_fns(ast, spec.marker)
        pmask = _marker_param_mask(ast, spec.marker)
        mfields = _marker_field_names(ast, spec.marker)
        for d in ast.get("decls", []):
            if d.get("kind") != "FunctionDecl":
                continue
            al = _fn_aliases(d, src_fns | frozenset(pmask))
            src_l = src_fns | frozenset(a for a, ts in al.items() if ts & src_fns)
            pmask_l = _aliased_mask(pmask, al)
            tainted = _marked_tainted_names(d, spec.marker, spec.sanitizer,
                                            src_l, pmask_l, mfields)
            # `not mfields` is load-bearing: a function that only reads
            # `u.email` has no tainted NAMES, and the old guard skipped it.
            if not tainted and not src_l and not mfields:
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            for call in walk(d.get("body", []), "Call"):
                name = callee_name(call)
                sink = sinks.get(name)
                if sink is None:
                    continue
                args = call.get("args") or []
                checked = args if sink.arg_indices is None else \
                    [args[i] for i in sink.arg_indices if i < len(args)]
                if not any(_expr_leaks_marked(a, tainted, spec.sanitizer,
                                              src_l, pmask_l, mfields)
                           for a in checked):
                    continue
                pos = call.get("pos") or fpos
                diags.append(Diagnostic(
                    code=spec.code,
                    category="capability",
                    severity="error",
                    message=spec.message.format(fn=fn, sink=name, where=sink.where),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=spec.suggestion,
                    confidence=1.0,
                    extra={"function": fn, "sink": name},
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
