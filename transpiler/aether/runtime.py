"""Aether v0.1 runtime — the Python implementation of stdlib functions
and the constructors for Result/Option/Unions.

All Aether identifiers are mangled to avoid colliding with Python builtins:

    foo       -> _ae_foo
    foo?      -> _ae_foo_q
    foo!      -> _ae_foo_e

The emitter rewrites every identifier through `mangle()`. The runtime
exposes its functions under their mangled names so the emitted code
just calls them directly.
"""

from __future__ import annotations
import re
from typing import Any, Callable, Dict, List, Tuple, Optional


# ----------------------------------------------------------------------
# Identifier mangling
# ----------------------------------------------------------------------

PY_RESERVED = {
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
    "match", "case",
}


def mangle(name: str) -> str:
    base = name
    suffix = ""
    if base.endswith("?"):
        base, suffix = base[:-1], "_q"
    elif base.endswith("!"):
        base, suffix = base[:-1], "_e"
    return f"_ae_{base}{suffix}"


# ----------------------------------------------------------------------
# Effect tracking (test mode)
# ----------------------------------------------------------------------

class EffectTracker:
    """Records every effect invocation; can be checked against declared sets."""

    def __init__(self, strict: bool = False):
        self.strict = strict
        self.allowed: List[Tuple[str, ...]] = []
        self.observed: List[Tuple[str, ...]] = []

    def push_frame(self, declared: List[Tuple[str, ...]]):
        self.allowed.append(declared)

    def pop_frame(self):
        self.allowed.pop()

    def record(self, path: Tuple[str, ...]):
        self.observed.append(path)
        if self.strict and self.allowed:
            top = self.allowed[-1]
            if ("pure",) in top:
                # pure means no effects allowed
                from .diagnostics import AetherError, Diagnostic, Position
                raise AetherError(Diagnostic(
                    code="E0501", category="effect", severity="error",
                    message=f"effect {'.'.join(path)} performed in a function declared 'pure'",
                    position=Position(0, 0),
                    suggestion="declare this effect in the function's effects clause",
                    confidence=1.0,
                ))
            # match-prefix check
            ok = any(self._prefix_match(declared, path) for declared in top)
            if not ok:
                from .diagnostics import AetherError, Diagnostic, Position
                raise AetherError(Diagnostic(
                    code="E0502", category="effect", severity="error",
                    message=f"effect {'.'.join(path)} not in declared effect set",
                    position=Position(0, 0),
                    suggestion=f"add '{'.'.join(path)}' to the function's effects clause",
                    confidence=1.0,
                ))

    @staticmethod
    def _prefix_match(declared: Tuple[str, ...], observed: Tuple[str, ...]) -> bool:
        if len(declared) > len(observed):
            return False
        return declared == observed[:len(declared)]


_TRACKER = EffectTracker(strict=False)


def set_effect_strict(strict: bool):
    _TRACKER.strict = strict


def push_effect_frame(declared):
    _TRACKER.push_frame(declared)


def pop_effect_frame():
    _TRACKER.pop_frame()


def record_effect(*path):
    _TRACKER.record(path)


# ----------------------------------------------------------------------
# Constructors for built-in unions
# ----------------------------------------------------------------------

def _make_union(tag: str, *args):
    """Tagged-union value: a tuple where [0] is the tag, [1:] are payloads."""
    return (tag,) + args


# These are exposed at the AST level as `Some(x)`, `None()`, `Ok(x)`, `Err(e)`.
def _ae_Some(x):                       return _make_union("Some", x)
def _ae_None():                        return _make_union("None")
def _ae_Ok(x):                         return _make_union("Ok", x)
def _ae_Err(e):                        return _make_union("Err", e)


# ----------------------------------------------------------------------
# Stdlib: List
# ----------------------------------------------------------------------

def _ae_length(xs):
    if isinstance(xs, str):
        return len(xs)
    return len(xs)

def _ae_empty_q(xs):                   return len(xs) == 0
def _ae_head(xs):                      return _ae_Some(xs[0]) if xs else _ae_None()
def _ae_tail(xs):
    if not xs:
        from .diagnostics import AetherError, Diagnostic, Position
        raise AetherError(Diagnostic(
            code="E0305", category="contract", severity="error",
            message="tail of empty list",
            position=Position(0, 0),
            suggestion="check empty?(xs) before calling tail",
            extra={"stdlib_function": "tail"},
        ))
    return list(xs[1:])

def _ae_append(xs, x):                 return list(xs) + [x]
def _ae_prepend(x, xs):                return [x] + list(xs)
def _ae_concat(xs, ys):                return list(xs) + list(ys)

def _ae_get(coll, key):
    if isinstance(coll, dict):
        return _ae_Some(coll[key]) if key in coll else _ae_None()
    if isinstance(coll, list):
        if 0 <= key < len(coll):
            return _ae_Some(coll[key])
        return _ae_None()
    raise TypeError(f"_ae_get: unsupported collection type {type(coll)}")

def _ae_map(xs, f):                    return [f(x) for x in xs]
def _ae_filter(xs, p):                 return [x for x in xs if p(x)]

def _ae_foldLeft(xs, z, f):
    a = z
    for x in xs:
        a = f(a, x)
    return a

def _ae_reverse(xs):                   return list(reversed(xs))
def _ae_range(lo, hi):                 return list(range(lo, hi))


# ----------------------------------------------------------------------
# Stdlib: Map
# ----------------------------------------------------------------------

def _ae_size(s):                       return len(s)
def _ae_set(m, k, v):
    new = dict(m)
    new[k] = v
    return new

def _ae_remove(m, k):
    new = dict(m)
    new.pop(k, None)
    return new

def _ae_has_q(m, k):                   return k in m
def _ae_keys(m):                       return list(m.keys())
def _ae_values(m):                     return list(m.values())


# ----------------------------------------------------------------------
# Stdlib: Set (immutable, frozenset-backed)
# ----------------------------------------------------------------------

def _ae_add(s, x):                     return frozenset(s | {x})
def _ae_contains_q(s, x):              return x in s


# ----------------------------------------------------------------------
# Stdlib: String
# ----------------------------------------------------------------------

def _ae_slice(s, lo, hi):              return s[lo:hi]
def _ae_split(s, sep):                 return s.split(sep) if sep else list(s)
def _ae_join(parts, sep):              return sep.join(parts)
def _ae_trim(s):                       return s.strip()
def _ae_toLower(s):                    return s.lower()
def _ae_toUpper(s):                    return s.upper()
def _ae_replace(s, frm, to):           return s.replace(frm, to)
def _ae_startsWith_q(s, p):            return s.startswith(p)
def _ae_endsWith_q(s, p):              return s.endswith(p)

def _ae_parseInt(s):
    try:
        return _ae_Ok(int(s))
    except (ValueError, TypeError):
        return _ae_Err(f"could not parse Int: {s!r}")

def _ae_parseFloat(s):
    try:
        return _ae_Ok(float(s))
    except (ValueError, TypeError):
        return _ae_Err(f"could not parse Float: {s!r}")

def _ae_intToString(n):                return str(n)


# ----------------------------------------------------------------------
# Stdlib: IO
# ----------------------------------------------------------------------

def _ae_print(s):
    record_effect("log")
    print(s)
    return None  # Unit

def _ae_readLine():
    record_effect("log")
    try:
        return _ae_Ok(input())
    except EOFError:
        return _ae_Err("EOF")

def _ae_readFile(path):
    record_effect("fs", "read")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return _ae_Ok(f.read())
    except OSError as e:
        return _ae_Err(str(e))

def _ae_writeFile(path, contents):
    record_effect("fs", "write")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(contents)
        return _ae_Ok(None)
    except OSError as e:
        return _ae_Err(str(e))

def _ae_sqlQuery(q):
    # Models a database call — carries the `db.query` effect. The demo
    # returns a marker instead of touching a real DB. E0713 refuses a
    # query string built by raw concatenation of untrusted input.
    record_effect("db", "query")
    return "ROWS(" + q + ")"

def _ae_sqlBind(template, value):
    # Pure. Parameterized-query binding: substitute the first `?` in
    # `template` with a safely-escaped literal of `value`. This is the
    # sanctioned way to put untrusted input into a query; E0713 accepts a
    # sqlBind(...) result and refuses raw string concatenation.
    escaped = "'" + str(value).replace("'", "''") + "'"
    return template.replace("?", escaped, 1)

def _ae_trusted(x):
    # Pure, identity at runtime. An EXPLICIT, auditable trust assertion:
    # wrapping a dynamic value in trusted(...) states "this source is
    # vetted" (a config bundle shipped with the app, a template from a
    # trusted store). E0719/E0720 accept a trusted(...) argument where
    # they otherwise require a literal — the dual of reveal()/redact().
    return x

def _ae_deserialize(data):
    # Models an UNRESTRICTED decoder (pickle/readObject/unsafe-YAML) — the
    # dangerous sink. E0720 refuses it on untrusted (non-literal) input.
    # The demo returns the data unchanged; the point is the static refusal.
    return str(data)

def _ae_schemaDecode(schema, data):
    # Pure. The sanctioned decoder: pinned to a fixed `schema`, it can only
    # produce the declared shape, so attacker bytes cannot instantiate
    # arbitrary types. E0720 accepts schemaDecode(...) on any data.
    return schema + ":" + str(data)

def _ae_parseXml(data):
    # Models an entity-resolving XML parser — the XXE sink. Returns a
    # marker; the point is the static E0727 refusal on untrusted input.
    return "xml:" + str(data)

def _ae_parseXmlSafe(data):
    # Pure. The hardened parser: external entity resolution disabled, so a
    # <!ENTITY SYSTEM ...> cannot read files or reach URLs. The E0727 fix.
    return "xml-safe:" + str(data)

def _ae_renderTemplate(template, data):
    # Pure. Renders a fixed template by substituting the first `{}`
    # placeholder with `data` (the engine escapes data — it never
    # evaluates it). E0719 requires `template` to be a fixed literal so
    # untrusted input cannot steer template syntax (SSTI / RCE).
    return template.replace("{}", str(data), 1)

def _ae_evalCode(source):
    # Models an interpreter over SOURCE TEXT (exec/eval/compile) — the
    # code-injection sink (CWE-94/95). The reference runtime NEVER executes
    # the source; it returns a marker, like _ae_parseXml. The point is the
    # static E0731 refusal on a non-literal source: attacker-authored code
    # has no sanitizer, only a fixed literal or an explicit trusted(...).
    return "code:" + str(source)

def _ae_sqlExec(stmt, auth):
    # Models a data-MUTATING database statement (UPDATE/DELETE/INSERT) —
    # carries the `db.exec` effect (capability `db`). The demo returns a
    # marker instead of touching a real DB. E0716 refuses a call whose
    # `auth` argument is not a proven Authorized<...> value, and E0713
    # refuses a `stmt` built by raw concatenation.
    record_effect("db", "exec")
    return "MUTATED(" + stmt + " by " + str(auth) + ")"


def _ae_authorize(principal, action):
    # Pure. The sanctioned authorization guard: checks that `principal`
    # may perform `action` and returns an Authorized<String> proof token.
    # `Authorized<T>` is a compile-time-only marker (erased at runtime);
    # the protection is static — E0716 refuses a mutating sink whose
    # dataflow carries no authorize(...) / Authorized<T> proof. The demo
    # models the policy decision as a token; a real backend would consult
    # a policy store here.
    return "AUTH(" + str(principal) + ":" + str(action) + ")"


def _ae_sqlByOwner(stmt, resourceId, proof):
    # Models a RESOURCE-SCOPED data mutation (UPDATE/DELETE on one row) —
    # carries the `db.exec` effect (capability `db`). The demo returns a
    # marker instead of touching a real DB. E0717 refuses a call whose
    # `proof` is not an authorizeResource(...) result bound to the SAME
    # `resourceId` the sink mutates (IDOR / cross-tenant, CWE-639), and
    # E0713 refuses a `stmt` built by raw concatenation.
    record_effect("db", "exec")
    return "MUTATED(" + stmt + " @ " + str(resourceId) + " by " + str(proof) + ")"


def _ae_authorizeResource(principal, action, resourceId):
    # Pure. The object-level authorization guard: checks that `principal`
    # may perform `action` ON `resourceId` and returns an
    # Authorized<String> proof token bound to that resource. The binding
    # is static — E0717 requires sqlByOwner's proof to name the SAME id
    # the sink mutates; a proof for a different id is refused. The demo
    # models the policy decision as a token; a real backend would check
    # row ownership here.
    return ("AUTH(" + str(principal) + ":" + str(action)
            + "@" + str(resourceId) + ")")


def _ae_shellExec(cmd):
    # Models a shell execution — carries the `exec.run` effect (requires
    # capability `exec`). The demo returns a marker instead of spawning a
    # real process. E0714 refuses a command line built by raw
    # concatenation of untrusted input.
    record_effect("exec", "run")
    return "EXEC(" + cmd + ")"

def _ae_shellArg(template, value):
    # Pure. Substitute the first `?` in `template` with `value` quoted as
    # a single shell argument (POSIX single-quote escaping: ' -> '\''),
    # so it cannot inject `;`/`|`/`$( )` shell syntax. The sanctioned way
    # to place untrusted input on a command line; E0714 accepts a
    # shellArg(...) result and refuses raw string concatenation.
    quoted = "'" + str(value).replace("'", "'\\''") + "'"
    return template.replace("?", quoted, 1)

def _ae_redirect(url):
    # Models an HTTP redirect — carries the `net.redirect` effect. E0718
    # refuses a target steerable by untrusted input (open redirect).
    record_effect("net", "redirect")
    return "REDIRECT(" + url + ")"

def _ae_safeRedirect(host, path):
    # Pure. Build a redirect target pinned to `host`: strip any scheme,
    # authority, and leading slashes from `path` so the result can only
    # ever point at `host`. The sanctioned repair for E0718 — it defeats
    # both absolute-url and protocol-relative (//evil.com) open redirects.
    p = str(path)
    if "://" in p:
        after = p.split("://", 1)[1]
        p = after.split("/", 1)[1] if "/" in after else ""
    p = p.lstrip("/\\")
    return "https://" + str(host).strip("/") + "/" + p

def _ae_classifyPII(x):
    # Pure. Wrap a value as PII<T>, a compile-time-only taint marker
    # (erased at runtime). E0715 refuses a PII value reaching a log or
    # disk sink unless masked with redact().
    return x

def _ae_classifyUntrusted(x):
    # Pure. Mark a value as Untrusted<T> at a trust boundary (a request
    # field, an uploaded name). Compile-time-only. E0724 refuses an
    # Untrusted value reaching a log sink unless cleaned with sanitizeLog().
    return x

def _ae_sanitizeLog(x):
    # Pure. Strip the CR/LF/control characters an attacker uses to forge
    # log lines. The sanctioned exit for E0724.
    s = str(x)
    return "".join(c for c in s if c == "\t" or (ord(c) >= 32 and c not in "\r\n"))

def _ae_htmlResponse(body):
    # Models writing an HTTP HTML response body — the reflected-XSS sink.
    # Returns the body unchanged; the point is the static E0725 refusal.
    return str(body)

def _ae_htmlEscape(x):
    # Pure. Escape the five HTML metacharacters so an Untrusted value
    # renders as text, not markup. The sanctioned exit for E0725.
    s = str(x)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))

def _ae_csvCell(v):
    # Models writing a value into a CSV cell — the formula-injection sink.
    # Returns the value; the point is the static E0728 refusal.
    return str(v)

def _ae_csvEscape(v):
    # Pure. Neutralize a leading formula trigger (= + - @, tab, CR) by
    # prefixing a single quote so a spreadsheet treats the cell as text.
    # The sanctioned exit for E0728.
    s = str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

def _ae_setHeader(name, value):
    # Models setting an HTTP response header — the response-splitting sink.
    # Returns None; the point is the static E0726 refusal of untrusted values.
    return None

def _ae_sanitizeHeader(x):
    # Pure. Strip the CR/LF an attacker uses to break out of a header value
    # and inject headers / a second response. The sanctioned exit for E0726.
    return "".join(c for c in str(x) if c not in "\r\n")

def _ae_redact(x):
    # Pure. The sanctioned, consent-safe masking of a PII<T> value. Emails
    # keep the first char + domain; everything else keeps the first char.
    # E0715 treats a redact(...) subtree as an intended, masked disclosure.
    s = str(x)
    if "@" in s:
        local, _, domain = s.partition("@")
        head = local[:1] if local else ""
        return head + "***@" + domain
    return (s[:1] + "***") if s else "***"

def _ae_classify(x):
    # Pure. Wrap a value as Secret<T>. `Secret<T>` is a compile-time-only
    # taint marker (erased at runtime — a Secret<String> IS its string).
    # The protection is static: E0712 refuses a Secret flowing into a log
    # sink. classify() marks a value secret; reveal() is the sanctioned,
    # auditable exit.
    return x

def _ae_reveal(x):
    # Pure. Unwrap a Secret<T> to its T. This is the ONLY sanctioned way
    # to expose a secret; E0712 treats a reveal(...) subtree as an
    # intentional, code-reviewed disclosure and does not flag it.
    return x

def _ae_safeJoin(base, rel):
    # Pure. Join `rel` under `base`, discarding any component that would
    # escape it: `..`, `.`, absolute roots, and drive/backslash prefixes.
    # The result is guaranteed to stay within `base`. This is the
    # sanctioned way to build a filesystem path from untrusted input —
    # it defeats path traversal / Zip-Slip by construction, and E0711
    # recognizes it as the safe wrapper around readFile/writeFile paths.
    parts = [p for p in re.split(r"[/\\]", rel) if p not in ("", ".", "..")]
    b = base.rstrip("/\\")
    return (b + "/" + "/".join(parts)) if parts else b


# ----------------------------------------------------------------------
# Stdlib: Time / Hash / Math
# ----------------------------------------------------------------------

_DETERMINISTIC_CLOCK_MS = None
_DETERMINISTIC_CLOCK_INIT = 1714579200000   # 2024-05-01T00:00:00Z (stable anchor)


def set_deterministic(seed: int = 0) -> None:
    """C.5 deterministic test mode: pin time + random seed so an agent
    fix-loop, the benchmark harness, and any reproducer the user files
    against an Aether program produce identical output across runs.

    What this controls:
      - `now()` returns `_DETERMINISTIC_CLOCK_INIT` ms on the first call
        and advances by 1 ms on each subsequent call.
      - Python's `random.seed(seed)` is set in case a future stdlib
        function uses it.

    What this does NOT control:
      - Python's dict/set iteration order, which depends on
        `PYTHONHASHSEED` and must be set before interpreter startup.
        The CLI's `--deterministic` flag warns about this when it sees
        an unset hash seed and the bench harness sets it explicitly.
    """
    global _DETERMINISTIC_CLOCK_MS
    _DETERMINISTIC_CLOCK_MS = _DETERMINISTIC_CLOCK_INIT
    import random
    random.seed(seed)


def is_deterministic() -> bool:
    return _DETERMINISTIC_CLOCK_MS is not None


def _ae_now():
    record_effect("time", "now")
    global _DETERMINISTIC_CLOCK_MS
    if _DETERMINISTIC_CLOCK_MS is not None:
        ms = _DETERMINISTIC_CLOCK_MS
        _DETERMINISTIC_CLOCK_MS = ms + 1
        return {"_kind": "Instant", "epochMillis": ms}
    import time
    return {"_kind": "Instant", "epochMillis": int(time.time() * 1000)}

def _ae_sha256(b):
    import hashlib
    return hashlib.sha256(b).digest()

def _ae_sha1(b):
    import hashlib
    return hashlib.sha1(b).digest()

def _ae_md5(b):
    import hashlib
    return hashlib.md5(b).digest()

# --- Bytes <-> Int bridge + char codes (gap 1.1: unblocks base58/bech32/JWT) ---

def _e0305_raise(msg: str, suggestion: str):
    from .diagnostics import AetherError, Diagnostic, Position
    raise AetherError(Diagnostic(
        code="E0305", category="contract", severity="error",
        message=msg, position=Position(0, 0),
        suggestion=suggestion, confidence=1.0))

def _ae_ord(s):
    if len(s) != 1:
        _e0305_raise(f"ord requires a single-character string, got length {len(s)}",
                     "require length(s) == 1 at the call site")
    return ord(s)

def _ae_chr(n):
    if n < 0 or n > 0x10FFFF:
        _e0305_raise(f"chr code point {n} outside 0..1114111",
                     "require 0 <= n <= 1114111 at the call site")
    return chr(n)

def _ae_byteAt(b, i):
    if i < 0 or i >= len(b):
        _e0305_raise(f"byteAt index {i} out of range for {len(b)} bytes",
                     "require 0 <= i < bytesLen(b) at the call site")
    return b[i]

def _ae_bytesLen(b):
    return len(b)

def _ae_bytesFromList(xs):
    for x in xs:
        if x < 0 or x > 255:
            _e0305_raise(f"bytesFromList element {x} outside 0..255",
                         "every element must satisfy 0 <= x <= 255")
    return bytes(xs)

def _ae_bytesToList(b):
    return list(b)

def _ae_stringToBytes(s):
    return s.encode("utf-8")

def _ae_bytesToString(b):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        _e0305_raise("bytesToString: input is not valid UTF-8",
                     "only decode byte sequences produced from valid UTF-8 text")

def _ae_formatFloat(x, ndigits):
    """Fixed-point decimal string, round-half-even on the exact binary
    value of x (gap 1.3). Identical to CPython format(x, '.Nf'), but the
    behaviour is SPECIFIED here, not inherited: Decimal(float) is exact,
    quantize applies IEEE-754 roundTiesToEven at the requested digit."""
    if ndigits < 0:
        _e0305_raise(f"formatFloat ndigits {ndigits} must be >= 0",
                     "require ndigits >= 0 at the call site")
    from decimal import Decimal, ROUND_HALF_EVEN
    q = Decimal(1).scaleb(-ndigits)
    d = Decimal(x).quantize(q, rounding=ROUND_HALF_EVEN)
    return f"{d:f}"

def _ae_abs(x):                        return abs(x)
def _ae_min(a, b):                     return min(a, b)
def _ae_max(a, b):                     return max(a, b)
def _ae_floor(x):                      import math; return math.floor(x)
def _ae_ceil(x):                       import math; return math.ceil(x)
def _ae_pow(a, b):                     return a ** b

def _ae_sqrt(x):
    if x < 0:
        from .diagnostics import AetherError, Diagnostic, Position
        raise AetherError(Diagnostic(
            code="E0305", category="contract", severity="error",
            message="sqrt of negative",
            position=Position(0, 0),
            suggestion="ensure x >= 0.0 before calling sqrt",
            extra={"stdlib_function": "sqrt", "value": x},
        ))
    import math; return math.sqrt(x)


# ----------------------------------------------------------------------
# D.1 stdlib expansion
#
# Each function below is pure (no effect declaration; the static effect
# pass treats absence as `pure`). Tested by `tests/test_stdlib_d1.py`.
# ----------------------------------------------------------------------

# --- List ----------------------------------------------------------

def _ae_sort(xs):                       return sorted(xs)
def _ae_sortBy(xs, key):                return sorted(xs, key=key)
def _ae_take(xs, n):                    return list(xs[:max(0, n)])
def _ae_drop(xs, n):                    return list(xs[max(0, n):])
def _ae_sum(xs):                        return sum(xs)
def _ae_product(xs):
    p = 1
    for x in xs:
        p *= x
    return p
def _ae_all(xs, p):                     return all(bool(p(x)) for x in xs)
def _ae_any(xs, p):                     return any(bool(p(x)) for x in xs)
def _ae_find(xs, p):
    for x in xs:
        if bool(p(x)):
            return _ae_Some(x)
    return _ae_None()
def _ae_flatMap(xs, f):
    out = []
    for x in xs:
        out.extend(f(x))
    return out
def _ae_count(xs, p):                   return sum(1 for x in xs if bool(p(x)))
def _ae_flatten(xss):
    out = []
    for xs in xss:
        out.extend(xs)
    return out

# --- Map -----------------------------------------------------------

def _ae_mapValues(m, f):
    return {k: f(v) for k, v in m.items()}

# --- Set -----------------------------------------------------------
# (named `setUnion` etc. because `union` is a reserved keyword in Aether.)

def _ae_setUnion(a, b):                 return frozenset(set(a) | set(b))
def _ae_setIntersection(a, b):          return frozenset(set(a) & set(b))
def _ae_setDifference(a, b):            return frozenset(set(a) - set(b))

# --- String --------------------------------------------------------

def _ae_repeat(s, n):                   return s * max(0, n)
def _ae_padLeft(s, n, c):
    if not c:
        return s
    while len(s) < n:
        s = c[0] + s
    return s
def _ae_padRight(s, n, c):
    if not c:
        return s
    while len(s) < n:
        s = s + c[0]
    return s
def _ae_chars(s):                       return list(s)

# --- Math ----------------------------------------------------------

def _ae_gcd(a, b):
    import math
    return math.gcd(abs(int(a)), abs(int(b)))
def _ae_lcm(a, b):
    import math
    a, b = abs(int(a)), abs(int(b))
    if a == 0 or b == 0:
        return 0
    return a * b // math.gcd(a, b)


# ----------------------------------------------------------------------
# Result / Option helpers
# ----------------------------------------------------------------------

def _ae_isOk_q(r):                     return r[0] == "Ok"
def _ae_isErr_q(r):                    return r[0] == "Err"
def _ae_unwrapOr(r, default):          return r[1] if r[0] == "Ok" else default

def _ae_isSome_q(o):                   return o[0] == "Some"
def _ae_isNone_q(o):                   return o[0] == "None"
def _ae_unwrapOrElse(o, default):      return o[1] if o[0] == "Some" else default


# ----------------------------------------------------------------------
# Contract assertion helper
# ----------------------------------------------------------------------

def _ae_assert_contract(cond: bool, kind: str, expr: str, fn: str, args=None):
    """Raise a structured contract error if `cond` is False.

    D.2 split: `requires` failures use E0301, `ensures` failures use
    E0304. An agent fix-loop reading the code alone can immediately tell
    whether the failure is on the caller side (provide better input) or
    the implementation side (the function lied about what it returns).
    """
    if cond:
        return
    from .diagnostics import AetherError, Diagnostic, Position
    if kind == "ensures":
        code = "E0304"
        suggestion = (f"the implementation of {fn} does not satisfy its "
                      f"declared postcondition: {expr}")
    else:
        code = "E0301"
        suggestion = (f"caller of {fn} must satisfy its precondition: "
                      f"{expr}")
    raise AetherError(Diagnostic(
        code=code, category="contract", severity="error",
        message=f"{kind} clause failed in {fn}: {expr}",
        position=Position(0, 0),
        extra={"function": fn, "clause_kind": kind,
               "clause_text": expr, "args": args or {}},
        confidence=1.0,
        suggestion=suggestion,
    ))



def _ae_check_refinement(value, predicate_fn, type_name: str,
                          binding_name: str, predicate_text: str = ""):
    """Boundary-crossing check for a refinement type (B.4 polished).

    Called at function entry for any parameter whose declared type is a
    refinement (e.g. `type PositiveInt = Int where self > 0`). The
    `predicate_fn` is a hoisted module-level `_ae_refn_<TypeName>` helper
    emitted by the compiler. `predicate_text` is the source-rendered
    predicate ("self > 0") used in the diagnostic message and `extra`
    field so an agent fix-loop can see *why* the value was rejected,
    not just that it was.
    """
    try:
        ok = bool(predicate_fn(value))
    except Exception as e:
        from .diagnostics import AetherError, Diagnostic, Position
        msg = (f"refinement predicate for {type_name} raised "
               f"{type(e).__name__} on value bound to {binding_name!r}")
        if predicate_text:
            msg += f" (predicate: {predicate_text})"
        raise AetherError(Diagnostic(
            code="E0303", category="refinement", severity="error",
            message=msg,
            position=Position(0, 0),
            suggestion=("ensure refinement predicates are total over their "
                        "base type (handle every possible input)"),
            confidence=1.0,
            extra={"type": type_name, "binding": binding_name,
                   "predicate": predicate_text,
                   "value_repr": repr(value)[:80]},
        )) from e
    if not ok:
        from .diagnostics import AetherError, Diagnostic, Position
        pred_clause = f" where ({predicate_text})" if predicate_text else ""
        msg = (f"value bound to {binding_name!r} (= {value!r}) fails refinement "
               f"{type_name}{pred_clause}")
        raise AetherError(Diagnostic(
            code="E0302", category="refinement", severity="error",
            message=msg,
            position=Position(0, 0),
            suggestion=(f"caller must ensure {binding_name} satisfies "
                        f"{type_name}{pred_clause}"),
            confidence=1.0,
            extra={"type": type_name, "binding": binding_name,
                   "predicate": predicate_text,
                   "value_repr": repr(value)[:80]},
        ))
    return value


# ----------------------------------------------------------------------
# Build the global namespace dict the emitter injects into exec()
# ----------------------------------------------------------------------

def build_namespace() -> Dict[str, Any]:
    g: Dict[str, Any] = {}
    EXPORTS = {
        "_make_union", "_TRACKER",
        "push_effect_frame", "pop_effect_frame",
        "record_effect", "set_effect_strict",
        "set_deterministic", "is_deterministic",
    }
    for name, val in globals().items():
        if name.startswith("_ae_") or name in EXPORTS:
            g[name] = val
    return g
