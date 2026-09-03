"""Static effect-checking pass (Phase B.1 + B.2).

Walks every FunctionDecl, builds a name → declared-effects map (user
functions plus the stdlib registry below), then for each call site within
a function body verifies the callee's declared effects are covered by
the caller's declared effects. Diagnostic E0801 on violation.

B.2 update: effects can carry a literal-string argument
(e.g. `net.fetch("https://api.x/*")`). The argument is a glob that the
caller's permission must cover. Subsumption rules below.

Effect representation:
  An effect is a (path_tuple, arg_or_None) pair.
    - path_tuple: tuple of dotted-path segments, e.g. ("net", "fetch")
    - arg: literal string (typically a glob), or None if not specified

Subsumption (caller_eff ⊇ callee_eff):
  - paths must be equal, AND one of:
    1. caller_arg is None — caller permits this effect on any argument
    2. caller_arg == callee_arg — exact match
    3. caller_arg is a glob (contains `*`) and the regex derived from
       caller_arg matches callee_arg as a string

Notes / limits (v1 scope):
  - Only direct calls of named functions (`foo(x)`) are checked. Calls
    through HOFs or function-typed parameters are skipped.
  - The `pure` annotation declares the empty effect set.
  - Constructors (Some/None/Ok/Err and user-defined union cases) are pure.
  - Glob comparison is one-way: caller_arg is treated as a glob, callee_arg
    as the literal it must match. Two-glob comparison ("does caller's glob
    cover callee's glob") is approximated by string regex match — true
    glob-language subset is undecidable in general; for v1 the common case
    of "caller has the wildcard, callee has the URL" works correctly.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Set, Tuple, Iterable, Optional

from ..diagnostics import Diagnostic, Position
from .ast_walk import walk, callee_name
from .detector_specs import (
    build, boundary_markers, _is_marker_type, _type_carries_marker,
    _marker_source_fns, _marker_param_mask, _marker_field_names, _expr_leaks_marked,
    _fn_aliases, _aliased_mask, _marked_taint,
    _marked_records, _record_fns, _sink_targets, _walk_binds, _bind_target,
    marker_sink_sanitizers, param_sink_reach,
    _BIND_KINDS,
)


# (path_tuple, arg_or_None)
EffectEntry = Tuple[Tuple[str, ...], Optional[str]]


# ----------------------------------------------------------------------
# Stdlib effect registry
# ----------------------------------------------------------------------
# Tuples mirror the dotted paths emitted by `record_effect(*path)` in
# runtime.py. Pure stdlib functions are absent from this map (lookup
# returns the empty list). Stdlib effects don't carry args (no glob).

_STDLIB_EFFECTS: Dict[str, List[EffectEntry]] = {
    "print":      [(("log",),         None)],
    "readLine":   [(("log",),         None)],
    "readFile":   [(("fs", "read"),   None)],
    "writeFile":  [(("fs", "write"),  None)],
    "now":        [(("time", "now"),  None)],
    "sqlQuery":   [(("db", "query"),  None)],
    "sqlExec":    [(("db", "exec"),   None)],
    "sqlByOwner": [(("db", "exec"),   None)],
    "shellExec":  [(("exec", "run"),  None)],
    "redirect":   [(("net", "redirect"), None)],
}


def _arg_str(eff_node: Dict[str, Any]) -> Optional[str]:
    """Extract a literal-string arg from an effect AST node, or None."""
    arg = eff_node.get("arg")
    if arg is None:
        return None
    if isinstance(arg, dict) and arg.get("kind") == "StringLit":
        return arg.get("value")
    # Non-string args (rare) are not modelled; treat as no arg.
    return None


def _declared_effects(fn_decl: Dict[str, Any]) -> List[EffectEntry]:
    """Compute the effect list declared by a FunctionDecl AST node.

    `effects pure` declares the empty list. Other entries are stored as
    (path_tuple, arg_str_or_None).
    """
    out: List[EffectEntry] = []
    for eff in fn_decl.get("effects", []):
        path = tuple(eff.get("path", []))
        if not path or path == ("pure",):
            continue
        out.append((path, _arg_str(eff)))
    return out


# ----------------------------------------------------------------------
# Subsumption: does any caller effect cover this callee effect?
# ----------------------------------------------------------------------

_GLOB_REGEX_CACHE: Dict[str, re.Pattern] = {}


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Compile a glob pattern (`*` is wildcard) to a regex anchored start-to-end.

    Cached because compilation is hot-path inside the subsumption check.
    """
    cached = _GLOB_REGEX_CACHE.get(pattern)
    if cached is not None:
        return cached
    parts = ["^"]
    for c in pattern:
        if c == "*":
            parts.append(".*")
        elif c in r".+?^$()[]{}|\\":
            parts.append("\\" + c)
        else:
            parts.append(c)
    parts.append("$")
    rx = re.compile("".join(parts))
    _GLOB_REGEX_CACHE[pattern] = rx
    return rx


def _arg_covers(caller_arg: Optional[str], callee_arg: Optional[str]) -> bool:
    """Does the caller's arg permission cover the callee's arg requirement?"""
    if caller_arg is None:
        return True
    if callee_arg is None:
        # Caller is restricted; callee says it does the unrestricted form.
        return False
    if caller_arg == callee_arg:
        return True
    if "*" in caller_arg:
        return bool(_glob_to_regex(caller_arg).match(callee_arg))
    return False


def _effect_covered(caller_effects: List[EffectEntry],
                    callee_eff: EffectEntry) -> bool:
    """Does any entry in caller_effects cover this single callee entry?"""
    callee_path, callee_arg = callee_eff
    for c_path, c_arg in caller_effects:
        if c_path == callee_path and _arg_covers(c_arg, callee_arg):
            return True
    return False


# ----------------------------------------------------------------------
# E0710 — overly-broad effect scope (SSRF / capability-smuggling class)
# ----------------------------------------------------------------------
# A declared effect whose glob leaves the host/authority unpinned admits
# ANY host — including internal endpoints like the cloud metadata service
# at 169.254.169.254. That is the structural precondition of the entire
# SSRF vulnerability class (CVE-2026-53754 crawl4ai, CVE-2026-46556
# FlaskBB, and many more): a fetch scope broad enough that attacker-
# controlled input can steer it inward. E0801/E0701 are satisfied by
# such a scope, so a dedicated check refuses the broad promise itself.
#
# The rule is deliberately conservative and one-directional: it only
# fires on net.fetch effects whose WILDCARD spans the authority. Path and
# query wildcards (`https://api.x/charge/*`) and subdomain pins
# (`https://*.corp.example/*`) are host-pinned and pass untouched.

# --- the one URL-authority parser behind E0710 / E0721 / E0722 ---------
# Each check used to slice the scope string its own way (`split(":")`,
# `startswith("169.254.")`, `startswith("127.")`), and each slice was a
# hole: `127.0.0.1@evil.com` read as loopback, `[::1]` read as host `[`,
# `https://api.*` read as pinned, `2852039166` (169.254.169.254 in
# decimal) read as an ordinary host. One helper, three consumers.

def _scope_authority(arg: str) -> str:
    """`scheme://AUTHORITY/path` -> AUTHORITY (scheme optional)."""
    rest = arg.split("://", 1)[1] if "://" in arg else arg
    return re.split(r"[/?#]", rest, maxsplit=1)[0]


def _authority_host(authority: str) -> str:
    """The host a request to this authority actually goes to: userinfo
    (everything up to the LAST `@`) dropped, IPv6 brackets dropped, a
    `:port` dropped, lower-cased."""
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:          # host:port (a bare IPv6 has more colons)
        host = host.split(":", 1)[0]
    return host.lower()


def _ipv4_from_numeric(host: str) -> Optional[ipaddress.IPv4Address]:
    """inet_aton's forgiving spellings, canonicalised: decimal
    `2852039166`, hex `0xa9fea9fe`, octal `0251.0376.0251.0376`, short
    `169.254.43518` (the last part fills the remaining bytes). None if
    the text is not one of these."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    vals: List[int] = []
    for p in parts:
        try:
            if p[:2].lower() == "0x":
                v = int(p[2:], 16)
            elif len(p) > 1 and p[0] == "0":
                v = int(p, 8)
            else:
                v = int(p, 10)
        except ValueError:
            return None
        if v < 0:
            return None
        vals.append(v)
    *lead, last = vals
    if any(v > 255 for v in lead):
        return None
    width = 8 * (4 - len(lead))
    if last >= (1 << width):
        return None
    n = 0
    for v in lead:
        n = (n << 8) | v
    return ipaddress.IPv4Address((n << width) | last)


def _host_ip(host: str, numeric: bool):
    """ipaddress object for a host literal, or None. `numeric` also
    accepts the inet_aton spellings — used where an obfuscated spelling
    must be FLAGGED (E0722), never where it would EXEMPT (E0721)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return _ipv4_from_numeric(host) if numeric else None


def _net_authority_wildcarded(arg: Optional[str]) -> Optional[str]:
    """If this net.fetch glob leaves the host/authority unpinned, return a
    short human reason; otherwise None (the scope is host-pinned)."""
    if arg is None:
        return "no URL scope declared - admits any host"
    if arg == "*":
        return "bare '*' - admits any host"
    if "://" in arg:
        scheme, rest = arg.split("://", 1)
        if "*" in scheme:
            return "wildcard scheme - admits any protocol and host"
    else:
        rest = arg
    # Authority = everything up to the first path/query separator.
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if authority in ("", "*"):
        return "wildcard host - admits any host (e.g. 169.254.169.254)"
    # A leading '*' that is not a subdomain pin (`*.host`) spans the host.
    if authority.startswith("*") and not authority.startswith("*."):
        return "wildcard host prefix - admits arbitrary hosts"
    if "*" in authority:
        # The only wildcard a pinned authority may carry is ONE leading
        # `*.` on the host, with a registrable domain behind it. `*.*`,
        # `api.*`, `a*`, `api.example.com*`, `[*]` and a userinfo-masked
        # `trusted@*` all match hosts the author never named.
        host = _authority_host(authority)
        pin = host.startswith("*.") and "*" not in host[2:]
        if pin and "." not in host[2:]:
            return "wildcard subdomain pin on a bare TLD - admits any host under it"
        if not pin or authority.count("*") != 1:
            return "wildcard inside the host/authority - admits arbitrary hosts"
    return None


def check_effect_scope(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0710 diagnostics for net.fetch effects with an unpinned host.

    One diagnostic per (function, broad effect). Runs on declared effects,
    so it flags the over-broad promise regardless of call sites.
    """
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        pos = d.get("pos") or {"line": 0, "column": 0}
        for path, arg in _declared_effects(d):
            if path != ("net", "fetch"):
                continue
            reason = _net_authority_wildcarded(arg)
            if reason is None:
                continue
            shown = "net.fetch" if arg is None else f"net.fetch({arg!r})"
            diags.append(Diagnostic(
                code="E0710",
                category="capability",
                severity="error",
                message=(
                    f"function {fn!r} declares effect '{shown}' with an "
                    f"unpinned host ({reason}); pin the host so the scope "
                    f"cannot be steered to an internal endpoint"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    "replace the wildcard host with a concrete host, e.g. "
                    "net.fetch(\"https://api.your-service.example/path/*\"); "
                    "path/query wildcards and *.subdomain pins are allowed"
                ),
                confidence=1.0,
                extra={
                    "function": fn,
                    "effect_arg": arg,
                    "reason": reason,
                },
            ))
    return diags


# ----------------------------------------------------------------------
# E0721 — cleartext transmission (CWE-319)
# ----------------------------------------------------------------------
# A net.fetch scope with an `http://` scheme sends the request (and any
# credentials/PII in it) unencrypted — a passive network attacker reads or
# tampers with it. E0710 checks host *pinning*; a pinned `http://` host
# satisfies E0710 yet is still cleartext, so this is an orthogonal sibling.
# Loopback (localhost / 127.0.0.0/8 / ::1 / 0.0.0.0) is exempt — those
# never leave the host, so plain http there is not a transmission risk.

_LOOPBACK_HOSTS = ("localhost", "0.0.0.0")


def _is_loopback_host(host: str) -> bool:
    """`localhost`, `0.0.0.0`, or an address literal the `ipaddress`
    module calls loopback (127.0.0.0/8, ::1, ::ffff:127.x). A name that
    merely STARTS with `127.` (`127.0.0.1.evil.com`) is a public host;
    an obfuscated spelling (`2130706433`) is not a sanctioned loopback."""
    if host in _LOOPBACK_HOSTS:
        return True
    ip = _host_ip(host, numeric=False)
    if ip is None:
        return False
    v4 = ip.ipv4_mapped if ip.version == 6 else None
    return ip.is_loopback or (v4 is not None and v4.is_loopback)


def _net_is_cleartext(arg: Optional[str]) -> Optional[str]:
    """If this net.fetch glob transmits over cleartext http:// to a
    non-loopback host, return a short reason; otherwise None."""
    if not arg or "://" not in arg:
        return None
    scheme, rest = arg.split("://", 1)
    if scheme.lower() != "http":
        return None  # https, or a wildcard scheme (E0710's concern)
    host = _authority_host(re.split(r"[/?#]", rest, maxsplit=1)[0])
    if _is_loopback_host(host):
        return None
    return f"http:// scheme sends '{host}' traffic unencrypted"


def check_cleartext_transmission(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0721 diagnostics for net.fetch effects using cleartext
    http:// to a non-loopback host."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        pos = d.get("pos") or {"line": 0, "column": 0}
        for path, arg in _declared_effects(d):
            if path != ("net", "fetch"):
                continue
            reason = _net_is_cleartext(arg)
            if reason is None:
                continue
            diags.append(Diagnostic(
                code="E0721",
                category="capability",
                severity="error",
                message=(
                    f"function {fn!r} declares effect 'net.fetch({arg!r})' "
                    f"over cleartext ({reason}); credentials and PII in the "
                    f"request are exposed to a passive network attacker"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    "use the https:// scheme, e.g. "
                    "net.fetch(\"https://...\"); plain http is allowed only "
                    "for loopback hosts (localhost / 127.0.0.1)"
                ),
                confidence=1.0,
                extra={"function": fn, "effect_arg": arg, "reason": reason},
            ))
    return diags


# ----------------------------------------------------------------------
# E0722 — server-side request to the link-local / metadata range (CWE-918)
# ----------------------------------------------------------------------
# E0710 refuses an UNPINNED fetch scope (the wildcard SSRF precondition).
# But a scope PINNED to the link-local range 169.254.0.0/16 — which holds
# the cloud metadata endpoint 169.254.169.254 (AWS/GCP/Azure IMDS, the
# crown-jewel SSRF target for IAM-credential theft) — is host-pinned, so
# it satisfies E0710 and E0721 (if https) and slips through. Fetching that
# range from application code is almost never legitimate; this refuses it
# as a declared reach. Private RFC-1918 ranges are deliberately NOT flagged
# (legit in microservice meshes); link-local IMDS is the high-signal case.

_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_IMDS_V6 = ipaddress.ip_address("fd00:ec2::254")          # AWS IMDS over IPv6
_IMDS_HOSTS = frozenset({
    "metadata.google.internal", "metadata",                 # GCP
    "instance-data",                                        # AWS EC2 DNS alias
    "100.100.100.200",                                      # Alibaba Cloud
})


def _net_is_link_local(arg: Optional[str]) -> Optional[str]:
    """If this net.fetch glob pins a host in 169.254.0.0/16 — in any
    spelling — or a cloud metadata service name, return a short reason;
    otherwise None."""
    if not arg:
        return None
    host = _authority_host(_scope_authority(arg))
    # The original string test, kept as-is: nothing it flags may go
    # quiet (`169.254.169.254.nip.io` stays caught by it).
    if host.startswith("169.254."):
        return f"link-local host {host!r} — the cloud metadata range (IMDS)"
    ip = _host_ip(host, numeric=True)
    if ip is not None:
        v4 = ip.ipv4_mapped if ip.version == 6 else ip
        if v4 is not None and v4 in _LINK_LOCAL_V4:
            return (f"link-local host {host!r} (= {v4}) — the cloud "
                    f"metadata range (IMDS)")
        if ip == _IMDS_V6:
            return f"IPv6 metadata host {host!r} — the AWS IMDS endpoint"
    if host in _IMDS_HOSTS:
        return f"cloud metadata host {host!r} — the instance metadata service (IMDS)"
    return None


def check_metadata_fetch(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0722 diagnostics for net.fetch effects pinned to the
    link-local / cloud-metadata range."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        pos = d.get("pos") or {"line": 0, "column": 0}
        for path, arg in _declared_effects(d):
            if path != ("net", "fetch"):
                continue
            reason = _net_is_link_local(arg)
            if reason is None:
                continue
            diags.append(Diagnostic(
                code="E0722",
                category="capability",
                severity="error",
                message=(
                    f"function {fn!r} declares effect 'net.fetch({arg!r})' "
                    f"to the {reason}; a server-side request to the metadata "
                    f"endpoint exfiltrates IAM credentials (SSRF)"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    "application code should never fetch 169.254.0.0/16; if a "
                    "cloud credential is needed, obtain it through the SDK/"
                    "credential provider, not a raw metadata HTTP request"
                ),
                confidence=1.0,
                extra={"function": fn, "effect_arg": arg, "reason": reason},
            ))
    return diags


# ----------------------------------------------------------------------
# E0712 / E0715 / E0724 / E0725 / E0726 / E0728 — marker-flow detectors
# ----------------------------------------------------------------------
# Six detectors of ONE shape: a value carrying a taint marker reaches a
# sink without passing through that marker's sanctioned exit. The shape,
# the six rows, and the taint machinery they share live in
# `passes/detector_specs.py`; this module binds the generated passes to
# the names every import site already uses.
#
#   E0712  Secret     print, writeFile contents  reveal()          CWE-532
#   E0715  PII        print, writeFile contents  redact()          GDPR egress
#   E0724  Untrusted  print                      sanitizeLog()     CWE-117
#   E0725  Untrusted  htmlResponse               htmlEscape()      CWE-79
#   E0726  Untrusted  setHeader                  sanitizeHeader()  CWE-113
#   E0728  Untrusted  csvCell                    csvEscape()       CWE-1236
#
# `Secret<T>` / `PII<T>` are confidentiality markers erased at runtime;
# `Untrusted<T>` is the taint-SOURCE marker applied where a value crosses
# a trust boundary. Each row has its OWN sanctioned exit and they do not
# substitute for one another — stripping CR/LF (sanitizeLog) does not
# neutralize markup, so only htmlEscape clears taint for the HTML sink,
# and only csvEscape for a spreadsheet cell. E0728 is the first sink in a
# non-HTTP context, which is why the marker generalizes past web output.
#
# `net.fetch` egress is a declared effect rather than a call, so a
# network body sink waits on a body-carrying stdlib sink (noted, not
# shipped).
#
# Taint here is syntactic and intraprocedural: it over-flags rather than
# misses within the modeled surface, and is not a soundness proof.
# Residuals: vault/wiki/questions/q1-taint-marker-soundness-boundary.md.

check_secret_flow      = build("check_secret_flow")
check_pii_flow         = build("check_pii_flow")
check_log_injection    = build("check_log_injection")
check_reflected_xss    = build("check_reflected_xss")
check_header_injection = build("check_header_injection")
check_csv_injection    = build("check_csv_injection")


# ----------------------------------------------------------------------
# E0711 / E0713 / E0714 / E0718 / E0719 / E0720 / E0727
#   — literal-or-wrapper detectors
# ----------------------------------------------------------------------
# Seven detectors of ONE shape: the argument a sink is steered by must be
# a fixed literal or the result of a sanctioned wrapper call; anything
# else is refused with a short REASON that lands in the message. The
# shape, the seven rows and their argument rules live in
# `passes/detector_specs.py`; this module binds the generated passes to
# the names every import site already uses.
#
#   E0711  writeFile/readFile  path      safeJoin()       CWE-22
#   E0713  sqlQuery/Exec/ByOwner query   sqlBind()        CWE-89
#   E0714  shellExec          command    shellArg()       CWE-78
#   E0718  redirect           target     safeRedirect()   CWE-601
#   E0719  renderTemplate     template   (none)           CWE-94
#   E0720  deserialize        data       schemaDecode()   CWE-502
#   E0727  parseXml           data       parseXmlSafe()   CWE-611
#   E0731  evalCode           source     (none)           CWE-94/95
#
# The precondition each refuses is the same one: a command, query, path,
# URL, template or document assembled from input the caller does not
# control. A string literal cannot be steered; a value routed through the
# row's wrapper cannot escape its base (safeJoin strips '..' and absolute
# roots, sqlBind/shellArg escape or quote the value, safeRedirect pins
# the host). E0711 additionally refuses a literal containing '..'.
#
# E0719 and E0720 have NO safer sanitizer by design — there is no way to
# render an attacker-authored template or to run an unrestricted decoder
# over attacker bytes safely. Their sanctioned form is the fixed literal;
# `trusted(...)` is the explicit, auditable escape hatch, and E0727's is
# the hardened parser `parseXmlSafe`, which is a different call rather
# than a wrapper. E0720/E0727 judge their argument by the deserialize
# rule but resolve literal-bound NAMES by the template rule — the spec
# table carries that as `safe_rule`.

check_fs_path_safety     = build("check_fs_path_safety")
check_injection          = build("check_injection")
check_command_injection  = build("check_command_injection")
check_open_redirect      = build("check_open_redirect")
check_template_injection = build("check_template_injection")
check_deserialization    = build("check_deserialization")
check_xxe                = build("check_xxe")
check_code_injection     = build("check_code_injection")


# ----------------------------------------------------------------------
# E0729 — marker laundering: a marked value passed to an unmarked param
# ----------------------------------------------------------------------
# A value carrying a confidentiality/taint marker (Secret<T>, PII<T>,
# Untrusted<T>) must not be passed to a user-function parameter typed
# WITHOUT that marker: inside the callee the value carries no taint, so
# every sink pass goes blind (the launder that lets `logIt(password)`
# print the secret unflagged). Sanctioned exits: the marker's own
# unwrappers at the call site, or declaring the callee parameter with the
# marker type so taint travels with the value. v1 scope: user-declared
# callees only (direct named calls); stdlib transforms and HOF /
# function-typed callees are recorded residuals. Authorized<T> is
# deliberately excluded — it is a proof marker, and dropping a proof only
# over-restricts the callee.

# Marker -> sanctioned call-site unwrappers. DERIVED from the marker-flow
# spec table by `boundary_markers()`, so adding a marker-flow row extends
# E0729/E0730 without editing them. It used to be restated here, and
# built lazily to reach `_TRUSTED` 1,300 lines below its use; the table
# removes both.
_BOUNDARY_MARKERS = boundary_markers()


def check_marker_boundary(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0729 diagnostics for a marker-carrying value passed to a
    user-declared function parameter not typed with that marker."""
    decls = {d["name"]: d for d in ast.get("decls", [])
             if d.get("kind") == "FunctionDecl"}
    reach = param_sink_reach(ast)          # BUG-023: which sink a param feeds
    sink_san = marker_sink_sanitizers()    # marker -> sink -> its sanitizer
    diags: List[Diagnostic] = []
    for marker, unwraps in _BOUNDARY_MARKERS.items():
        row_san = sink_san.get(marker, {})
        sanitizers = frozenset(row_san.values())
        src_fns = _marker_source_fns(ast, marker)
        pmask = _marker_param_mask(ast, marker)
        mfields = _marker_field_names(ast, marker)
        carriers = _marked_records(ast, marker)
        rec_fns = _record_fns(ast, carriers)
        # Alias targets once per module (TC-04). Every user function is a
        # target here: an alias of a plain-param callee is exactly the
        # laundering shape (BUG-002).
        targets = src_fns | frozenset(decls) | frozenset(pmask)
        for d in decls.values():
            al = _fn_aliases(d, targets)
            src_l = src_fns | frozenset(a for a, ts in al.items() if ts & src_fns)
            pmask_l = _aliased_mask(pmask, al)
            tainted, rec_names = _marked_taint(d, marker, unwraps, src_l, pmask_l,
                                               mfields, carriers, rec_fns)
            if not tainted and not src_l and not mfields:
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            # Parameters of THIS function declared with a function type
            # (`grammar/grammar.ebnf` line 88). A call through one of
            # these reaches a callee chosen by the caller's caller —
            # invisible to every pass here (BUGS.md BUG-022).
            ftparams = {p["name"] for p in d.get("params", [])
                        if isinstance(p.get("type"), dict)
                        and p["type"].get("kind") == "FunctionType"}
            leaks = lambda node, uw: _expr_leaks_marked(   # noqa: E731
                node, tainted, uw, src_l, pmask_l, mfields, rec_names)
            for call in walk(d.get("body", []), "Call"):
                cname = callee_name(call)
                direct = decls.get(cname)
                cands = [direct] if direct is not None else \
                    [decls[t] for t in sorted(al.get(cname, set())) if t in decls]
                if not cands:
                    if cname not in ftparams:
                        continue  # stdlib / unknown: covered by sink passes
                    # No sanctioned crossing exists here on purpose: a
                    # function TYPE's parameter types are not checked
                    # against the function that actually arrives, so
                    # declaring `function(Secret<String>) returns Unit`
                    # would be an exit that proves nothing. Unwrap at the
                    # call site instead.
                    for arg in call.get("args") or []:
                        if not leaks(arg, unwraps):
                            continue
                        pos = call.get("pos") or fpos
                        diags.append(Diagnostic(
                            code="E0729",
                            category="capability",
                            severity="error",
                            message=(
                                f"function {fn!r} passes a {marker}<...>-marked "
                                f"value through function-typed parameter "
                                f"{cname!r}; the callee is not known at analysis "
                                f"time, so the marker is erased and every sink "
                                f"check goes blind (taint laundering)"
                            ),
                            position=Position(pos.get("line", 0),
                                              pos.get("column", 0)),
                            suggestion=(
                                f"unwrap explicitly at the call site via one "
                                f"of: " + ", ".join(sorted(unwraps)) + "(...); "
                                f"a function-typed parameter is not a sanctioned "
                                f"crossing, because nothing checks which function "
                                f"arrives in it"
                            ),
                            confidence=1.0,
                            extra={"function": fn, "callee": cname,
                                   "param": cname, "marker": marker,
                                   "via": "function_type"},
                        ))
                    continue
                for callee in cands:
                    params = callee.get("params", [])
                    for i, arg in enumerate(call.get("args") or []):
                        if i >= len(params):
                            break
                        if _type_carries_marker(params[i].get("type"), marker, carriers):
                            continue  # marker declared — taint travels
                        why = ""
                        extra_reason = {}
                        if not leaks(arg, unwraps):
                            # Cleared — but by WHICH unwrapper? A row
                            # sanitizer is sink-specific, and
                            # `boundary_markers()` unions them all
                            # (BUGS.md BUG-023). Accept only when the one
                            # that cleared it is right for every sink the
                            # callee's parameter feeds.
                            reached = reach.get(callee["name"], {}).get(i, frozenset())
                            wrong = [s for s in sorted(reached) if s in row_san]
                            if not wrong or not leaks(arg, frozenset()):
                                continue
                            mism = None
                            for u in sorted(unwraps):
                                if leaks(arg, {u}):
                                    continue          # not what cleared it
                                bad = [s for s in wrong if row_san[s] != u]
                                if u not in sanitizers or not bad:
                                    mism = None       # trusted(...) assertion,
                                    break             # or the right sanitizer
                                if mism is None:
                                    mism = (u, bad[0], row_san[bad[0]])
                            if mism is None:
                                continue
                            why = (f"; it was cleared with {mism[0]}(...), but "
                                   f"{callee['name']!r} passes it to "
                                   f"{mism[1]!r}, whose sanitizer is {mism[2]}")
                            extra_reason = {"cleared_with": mism[0],
                                            "reaches_sink": mism[1],
                                            "needs": mism[2]}
                        pos = call.get("pos") or fpos
                        if why:
                            fix = (f"apply {extra_reason['needs']}(...) instead - "
                                   f"it is the sanitizer for "
                                   f"{extra_reason['reaches_sink']!r} - or type "
                                   f"the parameter as {marker}<...> so the marker "
                                   f"travels and each sink is checked in place")
                        else:
                            fix = (f"type the parameter as {marker}<...> so the "
                                   f"marker travels with the value, or unwrap "
                                   f"explicitly at the call site via one of: "
                                   + ", ".join(sorted(unwraps)) + "(...)")
                        diags.append(Diagnostic(
                            code="E0729",
                            category="capability",
                            severity="error",
                            message=(
                                f"function {fn!r} passes a {marker}<...>-marked "
                                f"value to parameter {params[i].get('name')!r} of "
                                f"{callee['name']!r}, which is not typed "
                                f"{marker}<...>; inside the callee the marker is "
                                f"erased and every sink check goes blind "
                                f"(taint laundering)" + why
                            ),
                            position=Position(pos.get("line", 0),
                                              pos.get("column", 0)),
                            suggestion=fix,
                            confidence=1.0,
                            extra={"function": fn, "callee": callee["name"],
                                   "param": params[i].get("name"),
                                   "marker": marker, **extra_reason},
                        ))
    return diags


# ----------------------------------------------------------------------
# E0730 — return laundering: tainted value under a plain return type
# ----------------------------------------------------------------------

def check_return_laundering(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0730 diagnostics for a function that RETURNS a
    marker-carrying value while its declared return type does not carry
    the marker. The dual of E0729: seeding trusts declared return types,
    so a plain-typed return of a tainted value makes the signature lie
    and washes the marker for every caller. Sanctioned exits: declare
    the marker-typed return (taint then travels via seeding), or unwrap
    at the return site. Authorized<T> excluded (proof marker)."""
    diags: List[Diagnostic] = []
    for marker, unwraps in _BOUNDARY_MARKERS.items():
        src_fns = _marker_source_fns(ast, marker)
        pmask = _marker_param_mask(ast, marker)
        mfields = _marker_field_names(ast, marker)
        carriers = _marked_records(ast, marker)
        rec_fns = _record_fns(ast, carriers)
        targets = src_fns | frozenset(pmask)   # once per module (TC-04)
        for d in ast.get("decls", []):
            if d.get("kind") != "FunctionDecl":
                continue
            if _type_carries_marker(d.get("return_type"), marker, carriers):
                continue  # honest signature — callers taint via seeding
            al = _fn_aliases(d, targets)
            src_l = src_fns | frozenset(a for a, ts in al.items() if ts & src_fns)
            pmask_l = _aliased_mask(pmask, al)
            tainted, rec_names = _marked_taint(d, marker, unwraps, src_l, pmask_l,
                                               mfields, carriers, rec_fns)
            if not tainted and not src_l and not mfields:
                continue
            fn = d["name"]
            fpos = d.get("pos") or {"line": 0, "column": 0}
            declared = (d.get("return_type") or {}).get("name", "Unit")
            for ret in walk(d.get("body", []), "Return"):
                val = ret.get("value")
                if val is None:
                    continue
                if not _expr_leaks_marked(val, tainted, unwraps,
                                          src_l, pmask_l, mfields, rec_names):
                    continue
                pos = ret.get("pos") or fpos
                diags.append(Diagnostic(
                    code="E0730",
                    category="capability",
                    severity="error",
                    message=(
                        f"function {fn!r} returns a {marker}<...>-marked "
                        f"value but its declared return type "
                        f"({declared}) does not carry the marker; every "
                        f"caller receives the value with the marker "
                        f"washed off (return laundering)"
                    ),
                    position=Position(pos.get("line", 0),
                                      pos.get("column", 0)),
                    suggestion=(
                        f"declare the return type as {marker}<...> so "
                        f"taint travels to callers, or unwrap explicitly "
                        f"at the return site via one of: "
                        + ", ".join(sorted(unwraps)) + "(...)"
                    ),
                    confidence=1.0,
                    extra={"function": fn, "marker": marker,
                           "declared_return": declared},
                ))
    return diags


# ----------------------------------------------------------------------
# E0202 — non-exhaustive match on a union (unhandled variant)
# ----------------------------------------------------------------------
# Aether's `match` is exhaustive at RUNTIME (a missed variant raises). This
# lifts that to a STATIC guarantee — the architectural-integrity promise:
# the compiler refuses a match that does not handle every case of the
# scrutinee's union (or carry a wildcard/binding catch-all). A new variant
# added to a union then forces every match to be updated, at compile time.
# Conservative: only fires when the scrutinee's union type is resolvable
# from a parameter or let-binding annotation; otherwise it stays silent.

def _union_cases(ast: Dict[str, Any]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for d in ast.get("decls", []):
        if d.get("kind") == "UnionDecl":
            out[d["name"]] = {c["name"] for c in d.get("cases", [])}
    return out


def _type_name(ty: Any) -> Optional[str]:
    if isinstance(ty, dict) and ty.get("kind") in ("TypeName", "GenericType"):
        return ty.get("name")
    return None


def _pattern_case(pat: Any) -> Optional[str]:
    """Case name a ConstructorPat covers; None if the pattern is a
    catch-all (wildcard / bare binding)."""
    if not isinstance(pat, dict):
        return None
    if pat.get("kind") == "ConstructorPat":
        path = pat.get("path") or []
        return path[-1] if path else None
    return None  # WildcardPat / BindPat → catch-all (handled by caller)


def _is_catch_all(pat: Any) -> bool:
    return isinstance(pat, dict) and pat.get("kind") in ("WildcardPat", "BindPat")


def check_exhaustiveness(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0202 diagnostics for a match that omits a union case with no
    catch-all, when the scrutinee's union type is statically resolvable."""
    unions = _union_cases(ast)
    if not unions:
        return []
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        # Name -> declared type name, from params and let bindings.
        types: Dict[str, str] = {}
        for p in d.get("params", []):
            tn = _type_name(p.get("type"))
            if tn:
                types[p["name"]] = tn

        for n in walk(d.get("body", []), "Let"):
            if "name" in n:
                tn = _type_name(n.get("type"))
                if tn:
                    types[n["name"]] = tn

        for m in walk(d.get("body", []), "Match", "MatchExpr"):
            scrut = m.get("scrutinee") or {}
            if scrut.get("kind") != "Ident":
                continue
            uname = types.get(scrut.get("name"))
            if uname not in unions:
                continue
            arms = m.get("arms") or []
            if any(_is_catch_all(a.get("pattern")) for a in arms):
                continue
            covered = {c for c in (_pattern_case(a.get("pattern")) for a in arms) if c}
            missing = unions[uname] - covered
            if not missing:
                continue
            pos = m.get("pos") or d.get("pos") or {"line": 0, "column": 0}
            diags.append(Diagnostic(
                code="E0202",
                category="type",
                severity="error",
                message=(
                    f"function {fn!r} matches on {uname!r} but does not "
                    f"handle case(s) {', '.join(sorted(missing))}; a "
                    f"non-exhaustive match traps an unhandled variant at "
                    f"runtime"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"add a case for each of {', '.join(sorted(missing))}, "
                    f"or a wildcard `case _` catch-all"
                ),
                confidence=1.0,
                extra={"function": fn, "union": uname, "missing": sorted(missing)},
            ))
    return diags


# ----------------------------------------------------------------------
# E0203 — unreachable match arm (CWE-561, dead code)
# ----------------------------------------------------------------------
# The complement of E0202: E0202 catches too FEW arms (a missed variant);
# E0203 catches redundant ones — an arm that can never execute because a
# prior wildcard/binding already catches everything, or a duplicate
# constructor case. A dead arm is a logic error (usually a mis-ordered or
# copy-pasted case). Purely about arm ordering, so it needs no type info
# and applies to every match.

def check_unreachable_arms(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0203 diagnostics for match arms that can never be reached."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        for m in walk(d.get("body", []), "Match", "MatchExpr"):
            arms = m.get("arms") or []
            mpos = m.get("pos") or d.get("pos") or {"line": 0, "column": 0}
            seen: Set[str] = set()
            catch_all = False
            for arm in arms:
                pat = arm.get("pattern")
                reason = None
                if catch_all:
                    reason = "arm follows a wildcard catch-all that already matches everything"
                elif _is_catch_all(pat):
                    catch_all = True
                else:
                    case = _pattern_case(pat)
                    if case is not None and case in seen:
                        reason = f"duplicate case {case!r} — already handled by an earlier arm"
                    elif case is not None:
                        seen.add(case)
                if reason is None:
                    continue
                pos = (pat.get("pos") if isinstance(pat, dict) else None) or mpos
                diags.append(Diagnostic(
                    code="E0203",
                    category="type",
                    severity="error",
                    message=(
                        f"function {fn!r} has an unreachable match arm "
                        f"({reason}); the code in it never runs"
                    ),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=(
                        "remove the dead arm, or reorder so the specific "
                        "cases precede the wildcard"
                    ),
                    confidence=1.0,
                    extra={"function": fn, "reason": reason},
                ))
    return diags


# ----------------------------------------------------------------------
# E0204 — dead code after a terminator (CWE-561)
# ----------------------------------------------------------------------
# A statement that follows an unconditional `return` / `break` / `continue`
# in the SAME block can never execute. It is always a logic error — a
# misplaced statement, a stray early return, or a merge artifact. Purely
# structural: scan every statement list for a terminator that is not the
# last element.

_TERMINATORS = ("Return", "Break", "Continue")


def _stmt_lists(node: Any) -> Iterable[List[Any]]:
    """Yield every list that is a block of statements (its elements are
    statement dicts carrying a `kind`)."""
    if isinstance(node, dict):
        for v in node.values():
            yield from _stmt_lists(v)
    elif isinstance(node, list):
        if node and all(isinstance(x, dict) and "kind" in x for x in node):
            yield node
        for x in node:
            yield from _stmt_lists(x)


def check_dead_code(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0204 diagnostics for a statement after a terminator."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        for block in _stmt_lists(d.get("body", [])):
            for i, stmt in enumerate(block[:-1]):
                if stmt.get("kind") not in _TERMINATORS:
                    continue
                dead = block[i + 1]
                pos = dead.get("pos") or stmt.get("pos") or {"line": 0, "column": 0}
                term = stmt.get("kind").lower()
                diags.append(Diagnostic(
                    code="E0204",
                    category="type",
                    severity="error",
                    message=(
                        f"function {fn!r} has unreachable code after a "
                        f"{term}; the statement can never execute"
                    ),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=(
                        f"remove the dead statement, or move it before the "
                        f"{term}"
                    ),
                    confidence=1.0,
                    extra={"function": fn, "after": term},
                ))
                break  # one diagnostic per block
    return diags


# ----------------------------------------------------------------------
# E0205 — unused let binding (dead store, CWE-563)
# ----------------------------------------------------------------------
# A `let x = ...` whose `x` is never read is a dead store — usually a bug
# (the wrong variable is used downstream, or a computation was left
# dangling). The `_`-prefix is the intentional-discard convention
# (`let _r = writeFile(...)` keeps the effect, drops the value) and is
# exempt. Detection is a use/def scan: a bound name that appears as an
# Ident nowhere in the function body is unused.

def _ident_reads(node: Any, out: Set[str]) -> None:
    out.update(n["name"] for n in walk(node, "Ident")
               if isinstance(n.get("name"), str))


def check_unused_binding(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0205 diagnostics for a let binding whose name is never read
    (excluding the `_`-prefixed intentional-discard convention)."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        body = d.get("body", [])
        reads: Set[str] = set()
        _ident_reads(body, reads)
        # Collect let bindings in source order.
        lets: List[Dict[str, Any]] = []

        lets.extend(n for n in walk(body, "Let")
                    if isinstance(n.get("name"), str))

        for let in lets:
            name = let["name"]
            if name.startswith("_") or name in reads:
                continue
            pos = let.get("pos") or d.get("pos") or {"line": 0, "column": 0}
            diags.append(Diagnostic(
                code="E0205",
                category="type",
                severity="error",
                message=(
                    f"function {fn!r} binds {name!r} with `let` but never "
                    f"reads it; a dead store is usually a mistaken variable"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"use {name!r}, remove the binding, or — if you only "
                    f"need the value's side effect — rename it to `_{name}`"
                ),
                confidence=1.0,
                extra={"function": fn, "binding": name},
            ))
    return diags


# ----------------------------------------------------------------------
# E0206 — ignored Result / unchecked error (CWE-252)
# ----------------------------------------------------------------------
# A bare statement calling a `Result<...>`-returning function silently
# drops the error case — the classic "forgot to check the return value"
# bug (a failed writeFile that looks like it succeeded). The sanctioned
# handling is to bind the result (`let r = ...` then match it, or the
# `let _r = ...` explicit-discard convention) or `match` it inline.

_STDLIB_RESULT_FNS = {"writeFile", "readFile", "readLine", "parseInt", "parseFloat"}


def _result_returning_fns(ast: Dict[str, Any]) -> Set[str]:
    out = set(_STDLIB_RESULT_FNS)
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl":
            rt = d.get("return_type") or {}
            if isinstance(rt, dict) and rt.get("name") == "Result":
                out.add(d["name"])
    return out


def check_ignored_result(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0206 diagnostics for a bare statement that discards a
    Result-returning call (an unchecked error)."""
    result_fns = _result_returning_fns(ast)
    diags: List[Diagnostic] = []

    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        fpos = d.get("pos") or {"line": 0, "column": 0}
        for stmt in walk(d.get("body", []), "ExprStmt"):
            expr = stmt.get("expr") or {}
            if expr.get("kind") != "Call" or callee_name(expr) not in result_fns:
                continue
            callee = callee_name(expr)
            pos = expr.get("pos") or stmt.get("pos") or fpos
            diags.append(Diagnostic(
                code="E0206",
                category="type",
                severity="error",
                message=(
                    f"function {fn!r} discards the Result of "
                    f"{callee!r}; an unchecked error (e.g. a failed "
                    f"write) is silently ignored"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"bind and handle it (`let r = {callee}(...)` then "
                    f"`match r`), or `let _r = ...` to discard the "
                    f"error explicitly"
                ),
                confidence=1.0,
                extra={"function": fn, "callee": callee},
            ))
    return diags


# ----------------------------------------------------------------------
# E0207 — unsatisfiable refinement type (impossible type)
# ----------------------------------------------------------------------
# A refinement `T where P` whose predicate no value can satisfy (e.g.
# `Int where self >= 10 and self <= 5`) is a dead type — always a bounds
# typo, and every parameter of that type is uninhabitable. Light, SOUND
# interval analysis: intersect the analyzable `self OP const` clauses of a
# conjunction; flag only when that interval is provably empty. Unanalyzable
# clauses widen to (-inf, +inf), so the check never false-positives.

def _clause_bound(node: Any):
    """A `self OP const` (or `const OP self`) clause → (lo, hi) where each
    is (value, inclusive) or None. Returns None if not analyzable."""
    if not (isinstance(node, dict) and node.get("kind") == "BinOp"):
        return None
    op = node.get("op")
    left, right = node.get("left") or {}, node.get("right") or {}

    def num(n):
        if isinstance(n, dict) and n.get("kind") in ("IntLit", "FloatLit"):
            return n.get("value")
        return None

    # Normalize to `self OP const`.
    if left.get("kind") == "Ident" and left.get("name") == "self":
        c = num(right)
    elif right.get("kind") == "Ident" and right.get("name") == "self":
        c = num(left)
        op = {">=": "<=", "<=": ">=", ">": "<", "<": ">", "==": "=="}.get(op, op)
    else:
        return None
    if c is None:
        return None
    if op == ">=":
        return ((c, True), None)
    if op == ">":
        return ((c, False), None)
    if op == "<=":
        return (None, (c, True))
    if op == "<":
        return (None, (c, False))
    if op == "==":
        return ((c, True), (c, True))
    return None


def _refine_interval(pred: Any):
    """(lo, hi) bounds for a conjunction of self-clauses; each bound is
    (value, inclusive) or None (unbounded). Non-conjunction / unknown
    shapes widen to unbounded (sound)."""
    if isinstance(pred, dict) and pred.get("kind") == "BinOp" and pred.get("op") == "and":
        lo1, hi1 = _refine_interval(pred["left"])
        lo2, hi2 = _refine_interval(pred["right"])
        # tighter lower bound = larger value
        lo = lo1 if lo2 is None else lo2 if lo1 is None else (
            lo1 if lo1[0] > lo2[0] else lo2 if lo2[0] > lo1[0]
            else (lo1[0], lo1[1] and lo2[1]))
        hi = hi1 if hi2 is None else hi2 if hi1 is None else (
            hi1 if hi1[0] < hi2[0] else hi2 if hi2[0] < hi1[0]
            else (hi1[0], hi1[1] and hi2[1]))
        return (lo, hi)
    b = _clause_bound(pred)
    return b if b is not None else (None, None)


def _interval_empty(lo, hi) -> bool:
    if lo is None or hi is None:
        return False
    if lo[0] > hi[0]:
        return True
    if lo[0] == hi[0] and not (lo[1] and hi[1]):
        return True
    return False


def check_unsatisfiable_refinement(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0207 diagnostics for a refinement type no value can satisfy."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "TypeDecl":
            continue
        pred = d.get("refinement")
        if not pred:
            continue
        lo, hi = _refine_interval(pred)
        base = d.get("base") or {}
        if isinstance(base, dict) and base.get("name") == "Int":
            # Over Int an open bound is a closed bound one step in:
            # `self > 5 and self < 6` admits no integer.
            if lo is not None and not lo[1] and isinstance(lo[0], int):
                lo = (lo[0] + 1, True)
            if hi is not None and not hi[1] and isinstance(hi[0], int):
                hi = (hi[0] - 1, True)
        if not _interval_empty(lo, hi):
            continue
        pos = d.get("pos") or {"line": 0, "column": 0}
        diags.append(Diagnostic(
            code="E0207",
            category="type",
            severity="error",
            message=(
                f"type {d['name']!r} has an unsatisfiable refinement "
                f"(bounds [{lo[0]}, {hi[0]}] admit no value); every "
                f"parameter of this type is uninhabitable"
            ),
            position=Position(pos.get("line", 0), pos.get("column", 0)),
            suggestion="fix the bounds — the lower bound exceeds the upper",
            confidence=1.0,
            extra={"type": d["name"], "lo": lo[0], "hi": hi[0]},
        ))
    return diags


# ----------------------------------------------------------------------
# E0716 — missing authorization before a data mutation (CWE-862/863)
# ----------------------------------------------------------------------
# The bigtech auth-check-before-mutation class (Ivanti EPMM
# CVE-2023-35078 shape: an API path that mutates state with no
# authorization check on it). Every prior detector is "tainted value
# must NOT reach a sink"; this one is the inversion: a mutating sink
# REQUIRES a proof of authorization in its dataflow. `sqlExec(stmt,
# auth)` — a data-mutating statement (effect `db.exec`) — must receive,
# as its second argument, a value proven `Authorized<T>`: a direct
# `authorize(...)` guard call, an `Authorized<T>`-typed parameter
# (authorization performed by the caller and carried across the
# boundary), or a name bound only to such expressions. Anything else —
# including omitting the argument — is refused. Conservative direction:
# a proof Aether cannot see is refused (over-flag, never miss).
#
# Authorized<T> is NOMINAL: only authorize(...) mints it. Trusting an
# Authorized<T> parameter is sound only because every call site of the
# enclosing program is checked too — three companion obligations keep
# the proof from being laundered:
#   1. an argument bound to an Authorized<...> parameter of a
#      user-defined function must itself be a proof (a raw String
#      handed to a helper is rejected AT THE CALL SITE, so no unproven
#      value ever reaches a trusted parameter);
#   2. `let`/`var`/`const` with an Authorized<...> annotation must be
#      initialized with a proof (annotation cannot mint the type);
#   3. a function that takes an Authorized<...> parameter cannot be
#      used as a first-class value (an indirect call would bypass
#      obligation 1).
# Rebinding demotes: a name with ANY non-proof binding (Let, Var, or
# Assign) is disqualified by the all-bindings rule below.

_MUTATION_SINKS = ("sqlExec",)   # authorization proof required at arg index 1
_AUTH_MARKER = "Authorized"
_AUTH_GUARD = "authorize"
# Both guards mint Authorized<T>: authorizeResource is the resource-bound
# strengthening (its id-binding is E0717's job, not E0716's).
_AUTH_GUARDS = ("authorize", "authorizeResource")


def _expr_is_authorized(node: Any, authorized: Set[str],
                        minters: Set[str] = frozenset()) -> bool:
    """True iff this expression IS an authorization proof: a direct
    authorize(...)/authorizeResource(...) call, a call to a user function
    whose declared return type is Authorized<...> (its return sites are
    checked by check_authorization, so the value is proven by induction),
    or a name proven Authorized. (Allowlist — the inverse polarity of
    _expr_leaks_marked.)"""
    if not isinstance(node, dict):
        return False
    kind = node.get("kind")
    if kind == "Call":
        callee = callee_name(node)
        if callee in _AUTH_GUARDS or callee in minters:
            return True
        return False
    if kind == "Ident" and node.get("name") in authorized:
        return True
    return False


def _minted_kind(fn_decl: Dict[str, Any]) -> str:
    """'direct' if the declared return type is Authorized<...>, 'result'
    if it is Result/Option<...> with an Authorized<...> payload, '' if the
    function does not mint proofs."""
    rt = fn_decl.get("return_type")
    if _is_marker_type(rt, _AUTH_MARKER):
        return "direct"
    if isinstance(rt, dict) and rt.get("kind") == "GenericType" \
            and rt.get("name") in ("Result", "Option") \
            and any(_is_marker_type(a, _AUTH_MARKER)
                    for a in rt.get("args", [])):
        return "result"
    return ""


def _is_result_proof_expr(node: Any, r_proven: Set[str],
                          result_minters: Set[str]) -> bool:
    """True iff this expression carries a Result/Option-wrapped proof: a
    call to a result-minting function, or a name bound only to such."""
    if not isinstance(node, dict):
        return False
    kind = node.get("kind")
    if kind == "Call" and callee_name(node) in result_minters:
        return True
    if kind == "Ident" and node.get("name") in r_proven:
        return True
    return False


def _ok_pattern_bindings(pattern: Any) -> List[str]:
    """Names bound in payload position of an Ok(...)/Some(...) pattern —
    the only place a Result/Option-wrapped proof unwraps to a proof."""
    if not isinstance(pattern, dict) or pattern.get("kind") != "ConstructorPat":
        return []
    path = pattern.get("path") or []
    if not path or path[-1] not in ("Ok", "Some"):
        return []
    return [a["name"] for a in pattern.get("args", [])
            if isinstance(a, dict) and a.get("kind") == "BindPat"]


def _authorized_names(fn_decl: Dict[str, Any],
                      minters: Set[str] = frozenset(),
                      result_minters: Set[str] = frozenset(),
                      ) -> Tuple[Set[str], Set[str]]:
    """(authorized, result_proven): names proven to hold an Authorized<T>
    value, and names proven to hold a Result/Option-wrapped proof.

    Authorized names are: Authorized-typed params; names whose EVERY
    Let/Var/Assign binding is an authorized expression (fixpoint; one
    unproven binding disqualifies the name — the same all-bindings rule
    as _safe_path_names, inverted marker); and names bound in Ok(...)/
    Some(...) payload position of a match whose scrutinee is proven to
    carry a Result/Option-wrapped proof (and which are never rebound to
    a non-proof)."""
    authorized: Set[str] = {
        p["name"] for p in fn_decl.get("params", [])
        if _is_marker_type(p.get("type"), _AUTH_MARKER)
    }
    binds: Dict[str, List[Any]] = {}
    grants: List[Tuple[Any, List[str]]] = []  # (scrutinee, Ok/Some-bound names)

    # Let/Var carry "name"; Assign carries "target". All three are
    # bindings — missing Assign here would let `tok = raw` keep a
    # previously-proven name authorized (silent demotion miss).
    body = fn_decl.get("body", [])
    for tgt, value, _ in _walk_binds(body):
        binds.setdefault(tgt, []).append(value)
    for n in walk(body, "Match", "MatchExpr"):
        for arm in n.get("arms", []) or []:
            names = _ok_pattern_bindings(arm.get("pattern"))
            if names:
                grants.append((n.get("scrutinee"), names))
    r_proven: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in binds.items():
            if name not in authorized and \
                    all(_expr_is_authorized(v, authorized, minters)
                        for v in values):
                authorized.add(name)
                changed = True
            if name not in r_proven and \
                    all(_is_result_proof_expr(v, r_proven, result_minters)
                        for v in values):
                r_proven.add(name)
                changed = True
        for scrut, names in grants:
            if not _is_result_proof_expr(scrut, r_proven, result_minters):
                continue
            for n in names:
                # the pattern binding is a proof unless a Let/Var/Assign
                # elsewhere rebinds the name to a non-proof
                if n not in authorized and \
                        all(_expr_is_authorized(v, authorized, minters)
                            for v in binds.get(n, [])):
                    authorized.add(n)
                    changed = True
    return authorized, r_proven


def _authorized_param_indices(fn_decl: Dict[str, Any]) -> List[Tuple[int, str]]:
    """(index, name) of every Authorized<...>-typed parameter."""
    return [(i, p["name"]) for i, p in enumerate(fn_decl.get("params", []))
            if _is_marker_type(p.get("type"), _AUTH_MARKER)]


def _walk_marker_binds(node: Any) -> Iterable[Dict[str, Any]]:
    """Yield every Let/Var node annotated with the Authorized<...> marker."""
    return (n for n in walk(node, "Let", "Var")
            if _is_marker_type(n.get("type"), _AUTH_MARKER))


def _escaped_gated_idents(node: Any, gated: Set[str]) -> Iterable[str]:
    """Yield names of Authorized-gated functions referenced as VALUES —
    anywhere except as a call's direct callee. An indirect call through a
    function value would bypass the call-site obligation, so the escape
    itself is refused."""
    if isinstance(node, dict):
        if node.get("kind") == "Call":
            func = node.get("func")
            if not (isinstance(func, dict) and func.get("kind") == "Ident"):
                yield from _escaped_gated_idents(func, gated)
            for a in node.get("args") or []:
                yield from _escaped_gated_idents(a, gated)
            return
        if node.get("kind") == "Ident" and node.get("name") in gated:
            yield node["name"]
            return
        for v in node.values():
            yield from _escaped_gated_idents(v, gated)
    elif isinstance(node, list):
        for x in node:
            yield from _escaped_gated_idents(x, gated)


def _e0716(fn: str, msg: str, pos: Dict[str, Any], suggestion: str,
           extra: Dict[str, Any]) -> Diagnostic:
    return Diagnostic(
        code="E0716",
        category="capability",
        severity="error",
        message=msg,
        position=Position(pos.get("line", 0), pos.get("column", 0)),
        suggestion=suggestion,
        confidence=1.0,
        extra=dict(extra, function=fn),
    )


def check_authorization(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0716 diagnostics for a mutating sink reached without an
    authorization proof in its dataflow (missing authorization), and for
    the three laundering obligations that keep Authorized<T> nominal:
    unproven arguments to Authorized<...> parameters, Authorized<...>
    annotations initialized with non-proofs, and Authorized-gated
    functions escaping as first-class values."""
    diags: List[Diagnostic] = []
    fns = {d["name"]: d for d in ast.get("decls", [])
           if d.get("kind") == "FunctionDecl"}
    gated = {name: idxs for name, idxs in
             ((n, _authorized_param_indices(f)) for n, f in fns.items())
             if idxs}
    minters = {n for n, f in fns.items() if _minted_kind(f) == "direct"}
    result_minters = {n for n, f in fns.items()
                      if _minted_kind(f) == "result"}
    for d in ast.get("decls", []):
        if d.get("kind") == "ConstDecl" \
                and _is_marker_type(d.get("type"), _AUTH_MARKER) \
                and not _expr_is_authorized(d.get("value"), set(), minters):
            pos = d.get("pos") or {"line": 0, "column": 0}
            diags.append(_e0716(
                d.get("name", "<const>"),
                f"const {d.get('name')!r} is declared "
                f"{_AUTH_MARKER}<...> but its value is not an "
                f"{_AUTH_GUARD}(...) proof; the annotation cannot mint "
                f"the authorization type (CWE-862)",
                pos,
                f"initialize the const with {_AUTH_GUARD}(principal, action)",
                {"name": d.get("name"), "reason": "annotation coercion"},
            ))
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        fpos = d.get("pos") or {"line": 0, "column": 0}
        authorized, r_proven = _authorized_names(d, minters, result_minters)
        body = d.get("body", [])
        # Obligation 1 — call-site proof for Authorized<...> parameters.
        # This is what makes trusting those parameters (above) sound: a
        # raw value is rejected where it enters, so it can never arrive.
        for call in walk(body, "Call"):
            callee = callee_name(call)
            idxs = gated.get(callee)
            if not idxs:
                continue
            args = call.get("args") or []
            for i, pname in idxs:
                token = args[i] if i < len(args) else None
                if token is not None and \
                        _expr_is_authorized(token, authorized, minters):
                    continue
                reason = ("no argument given for the Authorized parameter"
                          if token is None else
                          "the argument is not a proven Authorized<...> value")
                pos = call.get("pos") or fpos
                diags.append(_e0716(
                    fn,
                    f"function {fn!r} passes an unproven value to the "
                    f"{_AUTH_MARKER}<...> parameter {pname!r} of "
                    f"{callee!r} ({reason}); a helper's parameter list "
                    f"does not discharge the authorization obligation "
                    f"(CWE-862)",
                    pos,
                    f"pass {_AUTH_GUARD}(principal, action) (or a value "
                    f"proven Authorized) as argument {i} of {callee}",
                    {"callee": callee, "param": pname, "reason": reason},
                ))
        # Obligation 2 — annotation cannot mint the type.
        for b in _walk_marker_binds(body):
            if _expr_is_authorized(b.get("value"), authorized, minters):
                continue
            pos = b.get("pos") or fpos
            diags.append(_e0716(
                fn,
                f"function {fn!r} binds {b.get('name')!r} as "
                f"{_AUTH_MARKER}<...> but its value is not an "
                f"{_AUTH_GUARD}(...) proof; the annotation cannot mint "
                f"the authorization type (CWE-862)",
                pos,
                f"replace the initializer with {_AUTH_GUARD}(principal, "
                f"action), or drop the {_AUTH_MARKER} annotation",
                {"name": b.get("name"), "reason": "annotation coercion"},
            ))
        # Obligation 3 — gated functions must not escape as values.
        for gname in _escaped_gated_idents(body, set(gated)):
            diags.append(_e0716(
                fn,
                f"function {fn!r} uses the {_AUTH_MARKER}-gated function "
                f"{gname!r} as a value; an indirect call would bypass "
                f"the call-site authorization check (CWE-862)",
                fpos,
                f"call {gname} directly, or wrap it in a function that "
                f"takes the {_AUTH_MARKER}<...> proof explicitly",
                {"callee": gname, "reason": "gated function escapes"},
            ))
        # Obligation 4 — a proof-minting return type is a promise: every
        # return site must actually hand back a proof (or, for Result/
        # Option minters, an Err/None or a proof-carrying Ok/Some).
        # This is what lets _expr_is_authorized trust minter calls.
        mint = _minted_kind(d)
        if mint:
            for ret in walk(body, "Return"):
                val = ret.get("value")
                ok = False
                if mint == "direct":
                    ok = _expr_is_authorized(val, authorized, minters)
                elif isinstance(val, dict):
                    if val.get("kind") == "Call":
                        cn = callee_name(val)
                        rargs = val.get("args") or []
                        if cn in ("Err", "None"):
                            ok = True
                        elif cn in ("Ok", "Some"):
                            ok = len(rargs) == 1 and _expr_is_authorized(
                                rargs[0], authorized, minters)
                    if not ok:
                        ok = _is_result_proof_expr(val, r_proven,
                                                   result_minters)
                if not ok:
                    pos = ret.get("pos") or fpos
                    diags.append(_e0716(
                        fn,
                        f"function {fn!r} declares an "
                        f"{_AUTH_MARKER}<...>-minting return type but this "
                        f"return site does not produce an "
                        f"{_AUTH_GUARD}(...)-derived proof; the return "
                        f"type cannot mint the authorization (CWE-862)",
                        pos,
                        f"return {_AUTH_GUARD}(principal, action) (or wrap "
                        f"a proven value in Ok/Some), or change the "
                        f"declared return type",
                        {"reason": "return does not mint declared proof"},
                    ))
        sink_al = _fn_aliases(d, frozenset(_MUTATION_SINKS))
        for call in walk(d.get("body", []), "Call"):
            hits = _sink_targets(callee_name(call), sink_al, _MUTATION_SINKS)
            if not hits:
                continue
            sink = hits[0]   # an alias of the mutating sink IS the sink
            args = call.get("args") or []
            token = args[1] if len(args) > 1 else None
            if token is not None and \
                    _expr_is_authorized(token, authorized, minters):
                continue
            reason = ("no authorization argument given" if token is None else
                      "the authorization argument is not a proven "
                      "Authorized<...> value")
            pos = call.get("pos") or fpos
            diags.append(Diagnostic(
                code="E0716",
                category="capability",
                severity="error",
                message=(
                    f"function {fn!r} performs a data mutation via "
                    f"{sink!r} without an authorization proof ({reason}); "
                    f"a mutation reachable without an auth check is the "
                    f"missing-authorization class (CWE-862)"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"pass {_AUTH_GUARD}(principal, action) as the second "
                    f"argument of {sink}, or take an "
                    f"{_AUTH_MARKER}<String> parameter so the caller's "
                    f"authorization is carried across the boundary"
                ),
                confidence=1.0,
                extra={"function": fn, "sink": sink, "reason": reason},
            ))
    return diags


# ----------------------------------------------------------------------
# E0717 — cross-tenant data access / IDOR (CWE-639)
# ----------------------------------------------------------------------
# The resource-binding extension of E0716. E0716 proves *an*
# authorization happened on the dataflow — but not that it named the
# SAME resource the sink touches, so tenant A's perfectly valid session
# token still mutates tenant B's row (broken object-level authorization,
# OWASP API1; the Facebook photo-delete and Peloton account-data shapes).
# The resource-scoped sink `sqlByOwner(stmt, resourceId, proof)` must
# receive a proof produced by `authorizeResource(principal, action,
# resourceId)` for the SAME resource id: both id expressions must
# resolve to the same identity key — an identical literal, or the same
# *stable* name (a param or a name bound exactly once, so it denotes one
# value for the whole body; a rebound name could change between the
# guard and the sink and is refused). Conservative direction throughout:
# any relation the checker cannot prove — computed ids, rebound names,
# proofs carried across a call boundary as plain Authorized<T> params —
# is refused (over-flag, never miss).

_RESOURCE_SINK = "sqlByOwner"          # (stmt, resourceId, proof)
_RES_AUTH_GUARD = "authorizeResource"  # (principal, action, resourceId)


def _stable_names(fn_decl: Dict[str, Any]) -> Set[str]:
    """Names that denote ONE value for the whole body: params that are
    never reassigned, plus names bound exactly once. Only these can
    witness that the guard's id and the sink's id are the same value."""
    counts: Dict[str, int] = {}

    # Let, Var AND Assign each bind — a `var` declaration that was not
    # counted let `var id = a; ...; id = b` pass as bound once (BUG-013).
    for n in walk(fn_decl.get("body", []), *_BIND_KINDS):
        tgt = _bind_target(n)
        if tgt is not None:
            counts[tgt] = counts.get(tgt, 0) + 1
    params = {p["name"] for p in fn_decl.get("params", [])}
    stable = {p for p in params if counts.get(p, 0) == 0}
    stable |= {n for n, c in counts.items() if c == 1 and n not in params}
    return stable


def _id_key(node: Any, stable: Set[str]) -> Optional[Tuple[str, Any]]:
    """Canonical identity of a resource-id expression: a fixed literal or
    a stable name. None = identity unprovable (refused)."""
    if not isinstance(node, dict):
        return None
    kind = node.get("kind")
    if kind in ("StringLit", "IntLit"):
        return ("lit", node.get("value"))
    if kind == "Ident" and node.get("name") in stable:
        return ("name", node.get("name"))
    return None


def _resource_proof_ids(fn_decl: Dict[str, Any],
                        stable: Set[str]) -> Dict[str, Tuple[str, Any]]:
    """Map from stable names bound to an authorizeResource(...) call to
    the id key that call was bound to. Only stable (bound-exactly-once)
    names qualify — a rebindable proof name proves nothing."""
    out: Dict[str, Tuple[str, Any]] = {}

    for name, val, _ in _walk_binds(fn_decl.get("body", [])):
        if name in stable and isinstance(val, dict) \
                and val.get("kind") == "Call" \
                and callee_name(val) == _RES_AUTH_GUARD:
            args = val.get("args") or []
            key = _id_key(args[2], stable) if len(args) > 2 else None
            if key is not None:
                out[name] = key
    return out


def _proof_id_key(node: Any, proof_ids: Dict[str, Tuple[str, Any]],
                  stable: Set[str]) -> Optional[Tuple[str, Any]]:
    """The resource id this proof expression is bound to: a direct
    authorizeResource(_, _, id) call, or a stable name bound to one.
    None = not a resource-bound proof."""
    if not isinstance(node, dict):
        return None
    kind = node.get("kind")
    if kind == "Call" and callee_name(node) == _RES_AUTH_GUARD:
        args = node.get("args") or []
        return _id_key(args[2], stable) if len(args) > 2 else None
    if kind == "Ident":
        return proof_ids.get(node.get("name"))
    return None


def _fmt_id_key(key: Tuple[str, Any]) -> str:
    tag, val = key
    return repr(val) if tag == "lit" else f"name {val!r}"


def check_resource_authorization(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0717 diagnostics for a resource-scoped mutation whose
    authorization proof is missing, unbound, or bound to a DIFFERENT
    resource id than the one the sink touches (IDOR, CWE-639)."""
    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        fn = d["name"]
        fpos = d.get("pos") or {"line": 0, "column": 0}
        stable = _stable_names(d)
        proof_ids = _resource_proof_ids(d, stable)
        sink_al = _fn_aliases(d, frozenset({_RESOURCE_SINK}))
        for call in walk(d.get("body", []), "Call"):
            if not _sink_targets(callee_name(call), sink_al, {_RESOURCE_SINK}):
                continue
            args = call.get("args") or []
            rid = args[1] if len(args) > 1 else None
            proof = args[2] if len(args) > 2 else None
            rid_key = _id_key(rid, stable) if rid is not None else None
            proof_key = _proof_id_key(proof, proof_ids, stable) if proof is not None else None
            if rid_key is not None and proof_key is not None and rid_key == proof_key:
                continue
            if proof is None:
                reason = "no resource-bound authorization proof given"
            elif proof_key is None:
                reason = (f"the proof is not a proven "
                          f"{_RES_AUTH_GUARD}(...) bound to a resource id")
            elif rid_key is None:
                reason = ("the sink's resource id is not a fixed literal "
                          "or a stable (never-rebound) name, so its "
                          "identity cannot be proven")
            else:
                reason = (f"the proof authorizes resource "
                          f"{_fmt_id_key(proof_key)} but the sink mutates "
                          f"resource {_fmt_id_key(rid_key)}")
            pos = call.get("pos") or fpos
            diags.append(Diagnostic(
                code="E0717",
                category="capability",
                severity="error",
                message=(
                    f"function {fn!r} mutates a resource via "
                    f"{_RESOURCE_SINK!r} whose authorization is not bound "
                    f"to the same resource id ({reason}); an authorized "
                    f"caller reaching ANOTHER tenant's row is the IDOR / "
                    f"cross-tenant class (CWE-639)"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"authorize the SAME id the sink uses: pass "
                    f"{_RES_AUTH_GUARD}(principal, action, resourceId) as "
                    f"the third argument of {_RESOURCE_SINK} with the "
                    f"identical resourceId (a literal, or a name that is "
                    f"never rebound) as the second argument"
                ),
                confidence=1.0,
                extra={"function": fn, "sink": _RESOURCE_SINK, "reason": reason},
            ))
    return diags


# ----------------------------------------------------------------------
# E0723 — hardcoded credential in source (CWE-798)
# ----------------------------------------------------------------------
# The single most common real-world security finding (millions of keys
# leaked to public repos yearly). A secret baked into a string literal is
# in version control forever and ships in every build. This is a
# literal-content scan — a new detector family — matching high-confidence
# provider credential shapes so false positives are near zero (demo
# passwords like "hunter2" do not match; a real AKIA... key does). The fix
# is to source the secret from the environment / a secret manager, never
# a literal.

_CREDENTIAL_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"),                     "AWS access key id"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),           "GitHub token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"),               "Google API key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),        "Slack token"),
    (re.compile(r"sk_live_[0-9A-Za-z]{20,}"),             "Stripe live secret key"),
    # Provider prefixes with a length floor: each is a documented token
    # format, none matched anything in 4,946 framework files or the
    # in-tree corpus when added (slice-3 record). Specific `sk-` shapes
    # come before the generic one so the label names the provider.
    (re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}"),        "OpenAI project API key"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{40,}"),         "Anthropic API key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{48,}\b"),              "OpenAI API key"),
    (re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),              "Hugging Face token"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),             "Groq API key"),
    (re.compile(r"\bya29\.[0-9A-Za-z_\-]{30,}"),          "Google OAuth access token"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),        "GitLab personal access token"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "SendGrid API key"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),              "npm access token"),
    (re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"), "PyPI API token"),
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
     "Slack incoming-webhook URL"),
    # The PEM header alone is prose ("expected -----BEGIN RSA PRIVATE
    # KEY-----" in an error message); a key has a base64 body after it.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\s*[A-Za-z0-9+/=]){40,}"),
     "private key (PEM)"),
]


def check_hardcoded_secret(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return E0723 diagnostics for string literals that match a known
    provider-credential shape (a hardcoded secret, CWE-798)."""
    diags: List[Diagnostic] = []
    for lit in walk(ast, "StringLit"):
        val = lit.get("value")
        if not isinstance(val, str):
            continue
        if lit.get("synthetic"):
            # The Python frontend inlines a module-level constant at each
            # read site; the literal is written once, at its definition,
            # and that is where it is reported.
            continue
        for pat, label in _CREDENTIAL_PATTERNS:
            if pat.search(val):
                pos = lit.get("pos") or {"line": 0, "column": 0}
                diags.append(Diagnostic(
                    code="E0723",
                    category="capability",
                    severity="error",
                    message=(
                        f"string literal contains a hardcoded {label}; a "
                        f"credential in source is committed to version "
                        f"control and shipped in every build"
                    ),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=(
                        "load the secret at runtime from the environment or "
                        "a secret manager (e.g. getEnv(\"...\")), never a "
                        "string literal"
                    ),
                    confidence=1.0,
                    extra={"credential_kind": label},
                ))
                break  # one diagnostic per literal
    return diags


# ----------------------------------------------------------------------
# AST walking
# ----------------------------------------------------------------------

def _format_effect(eff: EffectEntry) -> str:
    path, arg = eff
    p = ".".join(path)
    if arg is None:
        return f"'{p}'"
    return f"'{p}({arg!r})'"


def _format_effect_list(effs: List[EffectEntry]) -> str:
    if not effs:
        return "'pure'"
    # Sort on an ORDERING KEY, not on the entry. An EffectEntry's arg is
    # Optional[str], so two effects sharing a path — `net.fetch` and
    # `net.fetch("https://...")`, which is legal and meaningful — made
    # tuple comparison fall through to `None < str` and crash the whole
    # check with a TypeError instead of emitting E0801. BUGS.md BUG-003.
    return ", ".join(_format_effect(e)
                     for e in sorted(effs, key=lambda e: (e[0], e[1] or "")))


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

def check_effects(ast: Dict[str, Any]) -> List[Diagnostic]:
    """Return a list of E0801 diagnostics, one per call-site violation."""
    user_effects: Dict[str, List[EffectEntry]] = {}
    union_cases: Set[str] = set()
    for d in ast.get("decls", []):
        if d.get("kind") == "FunctionDecl":
            user_effects[d["name"]] = _declared_effects(d)
        elif d.get("kind") == "UnionDecl":
            for c in d.get("cases", []):
                union_cases.add(c["name"])
        elif d.get("kind") == "RecordDecl":
            user_effects[d["name"]] = []

    for name in ("Some", "None", "Ok", "Err"):
        union_cases.add(name)

    # A call through an alias (`let sh = shellExec; sh("ls")`) is a call
    # to the target — resolved flag-more, so an alias can only ADD
    # obligations (BUGS.md BUG-015).
    alias_targets = frozenset(user_effects) | frozenset(_STDLIB_EFFECTS)

    diags: List[Diagnostic] = []
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        caller_name = d["name"]
        caller_effects = _declared_effects(d)
        pos = d.get("pos") or {"line": 0, "column": 0}
        al = _fn_aliases(d, alias_targets)

        for call in walk(d.get("body", []), "Call"):
            name = callee_name(call)
            if name is None or name in union_cases:
                continue
            direct = name in user_effects or name in _STDLIB_EFFECTS \
                or name.endswith("?") or name.endswith("!")
            # A function passed as a VALUE runs under this call, so its
            # effects are the caller's obligation just as a callee's are
            # (BUGS.md BUG-022): `apply(logIt, s)` from a `pure` caller
            # performs `log`. A pure function value adds nothing, so
            # `map(double, xs)` stays clean.
            passed = [a["name"] for a in (call.get("args") or [])
                      if isinstance(a, dict) and a.get("kind") == "Ident"
                      and a.get("name") not in union_cases
                      and (a.get("name") in user_effects
                           or a.get("name") in _STDLIB_EFFECTS)]
            targets = [(c, False) for c in
                       ([name] if direct else sorted(al.get(name, set())))]
            targets += [(c, True) for c in passed]
            for callee, as_value in targets:
                if callee in user_effects:
                    callee_effects = user_effects[callee]
                else:
                    callee_effects = _STDLIB_EFFECTS.get(callee, [])

                for callee_eff in callee_effects:
                    if _effect_covered(caller_effects, callee_eff):
                        continue
                    missing_pretty = _format_effect(callee_eff)
                    caller_pretty = _format_effect_list(caller_effects)
                    if as_value:
                        what = (f"passes {callee!r} as a value to {name!r}, "
                                f"whose effect {missing_pretty} is not covered "
                                f"by the caller")
                    else:
                        via = "" if callee == name else f" (through alias {name!r})"
                        what = (f"calls {callee!r}{via} which has effect "
                                f"{missing_pretty} not covered by the caller")
                    diags.append(Diagnostic(
                        code="E0801",
                        category="effect",
                        severity="error",
                        message=(
                            f"function {caller_name!r} (effects {caller_pretty}) "
                            + what
                        ),
                        position=Position(pos.get("line", 0), pos.get("column", 0)),
                        suggestion=(
                            f"add {missing_pretty} to {caller_name}'s effects "
                            f"clause, or change the call site"
                        ),
                        confidence=1.0,
                        extra={
                            "caller": caller_name,
                            "callee": callee,
                            "caller_effects": [
                                [list(p), a] for p, a in caller_effects
                            ],
                            "missing_effect": [list(callee_eff[0]), callee_eff[1]],
                            **({"via": "function_value"} if as_value else {}),
                        },
                    ))
    return diags
