"""B.1 regression tests for the static effect-checking pass.

Two test corpora:
  - positive: programs that should pass the check (effects declared
    correctly across every call site)
  - negative: programs that should produce at least one E0801 diagnostic

Each negative case documents the architectural error it surfaces.

These tests exercise the pass directly via `check_effects`, not via
the CLI — that keeps them fast and isolates the pass logic from the
arg-parsing layer.
"""

from __future__ import annotations
import os
import sys
from typing import List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.parser import parse                         # noqa: E402
from aether.passes.effects import check_effects         # noqa: E402
from aether.diagnostics import Diagnostic               # noqa: E402


# ----------------------------------------------------------------------
# Positive corpus — must produce zero diagnostics
# ----------------------------------------------------------------------

POSITIVE: List[str] = [
    # 1. Pure helper called from pure caller.
    """
function double(x: Int) returns Int
  effects pure
do
  return x * 2
end

function quad(x: Int) returns Int
  effects pure
do
  return double(double(x))
end
""",
    # 2. log caller calling pure helper.
    """
function double(x: Int) returns Int
  effects pure
do
  return x * 2
end

function main() returns Unit
  effects log
do
  print(intToString(double(5)))
end
""",
    # 3. log caller calling log stdlib (print).
    """
function main() returns Unit
  effects log
do
  print("hi")
end
""",
    # 4. Recursive pure function.
    """
function fact(n: Int) returns Int
  requires n >= 0
  effects pure
do
  if n <= 1 then
    return 1
  else
    return n * fact(n - 1)
  end
end
""",
    # 5. Mutual recursion, both pure.
    """
function isEven?(n: Int) returns Bool
  requires n >= 0
  effects pure
do
  if n == 0 then
    return true
  else
    return isOdd?(n - 1)
  end
end

function isOdd?(n: Int) returns Bool
  requires n >= 0
  effects pure
do
  if n == 0 then
    return false
  else
    return isEven?(n - 1)
  end
end
""",
    # 6. Caller declares fs.read AND log; calls both.
    """
function loadAndLog(path: String) returns Unit
  effects fs.read, log
do
  match readFile(path) do
    case Ok(s) do
      print(s)
    end
    case Err(e) do
      print(e)
    end
  end
end
""",
    # 7. Tagged-union construction is pure (constructor calls).
    """
union Dir do
  case North
  case South
end

function flip(d: Dir) returns Dir
  effects pure
do
  match d do
    case North() do
      return Dir.South()
    end
    case South() do
      return Dir.North()
    end
  end
end
""",
    # 8. HOF parameter call is skipped (dynamic).
    """
function applyTwice(f: function(Int) returns Int, x: Int) returns Int
  effects pure
do
  return f(f(x))
end

function double(x: Int) returns Int
  effects pure
do
  return x * 2
end

function main() returns Unit
  effects log
do
  print(intToString(applyTwice(double, 3)))
end
""",
    # 9. Caller with multiple effects calls each callee.
    """
function audit(path: String) returns Unit
  effects fs.read, fs.write, log
do
  match readFile(path) do
    case Ok(s) do
      let _e: Result<Unit, String> = writeFile("/tmp/audit.log", s)
      print("audited")
    end
    case Err(_e) do
      print("error")
    end
  end
end
""",
    # 10. time.now caller.
    """
function timestamp() returns Unit
  effects time.now, log
do
  let t: Instant = now()
  print(intToString(t.epochMillis))
end
""",
]


# ----------------------------------------------------------------------
# Negative corpus — must produce at least one E0801
# ----------------------------------------------------------------------
# Each entry: (source, expected_caller, expected_callee, brief_note).

NEGATIVE = [
    # 1. pure function calls print (log).
    ("""
function greet() returns Unit
  effects pure
do
  print("hi")
end
""", "greet", "print", "pure caller calls log stdlib"),

    # 2. pure function calls another function that's log.
    ("""
function shout() returns Unit
  effects log
do
  print("LOUD")
end

function main() returns Unit
  effects pure
do
  shout()
end
""", "main", "shout", "pure caller calls log user-fn"),

    # 3. log function calls fs.read function.
    ("""
function load() returns String
  effects fs.read
do
  match readFile("/etc/x") do
    case Ok(s) do
      return s
    end
    case Err(_e) do
      return ""
    end
  end
end

function main() returns Unit
  effects log
do
  print(load())
end
""", "main", "load", "log caller doesn't cover fs.read callee"),

    # 4. log function calls fs.write stdlib directly.
    ("""
function logIt(s: String) returns Unit
  effects log
do
  let _r: Result<Unit, String> = writeFile("/tmp/x", s)
  print(s)
end
""", "logIt", "writeFile", "log caller doesn't cover fs.write stdlib"),

    # 5. pure function calls fs.read stdlib.
    ("""
function readPure(path: String) returns String
  effects pure
do
  match readFile(path) do
    case Ok(s) do
      return s
    end
    case Err(_e) do
      return ""
    end
  end
end
""", "readPure", "readFile", "pure caller calls fs.read stdlib"),

    # 6. fs.read function calls fs.write function (different effect).
    ("""
function copy(src: String, dst: String) returns Unit
  effects fs.read
do
  match readFile(src) do
    case Ok(s) do
      let _e: Result<Unit, String> = writeFile(dst, s)
    end
    case Err(_e) do
      return
    end
  end
end
""", "copy", "writeFile", "missing fs.write declaration"),

    # 7. pure caller calls now (time.now).
    ("""
function stamp() returns Int
  effects pure
do
  let t: Instant = now()
  return t.epochMillis
end
""", "stamp", "now", "pure caller calls time.now stdlib"),

    # 8. log caller calls a function that needs time.now.
    ("""
function takeStamp() returns Instant
  effects time.now
do
  return now()
end

function logStamp() returns Unit
  effects log
do
  let t: Instant = takeStamp()
  print(intToString(t.epochMillis))
end
""", "logStamp", "takeStamp", "log caller doesn't cover time.now"),

    # 9. pure caller transitively calls log via two-hop chain.
    ("""
function level1() returns Unit
  effects log
do
  print("a")
end

function level2() returns Unit
  effects log
do
  level1()
end

function level3() returns Unit
  effects pure
do
  level2()
end
""", "level3", "level2", "two-hop transitive log violation"),

    # 10. fs.read caller calls log function.
    ("""
function noisy() returns Unit
  effects log
do
  print("noise")
end

function reader() returns String
  effects fs.read
do
  noisy()
  match readFile("/x") do
    case Ok(s) do
      return s
    end
    case Err(_e) do
      return ""
    end
  end
end
""", "reader", "noisy", "fs.read caller doesn't cover log"),
]


# ----------------------------------------------------------------------
# Runners
# ----------------------------------------------------------------------

def _check(src: str) -> List[Diagnostic]:
    return check_effects(parse(src, "<test>"))


def test_positive_corpus():
    failures = []
    for i, src in enumerate(POSITIVE, start=1):
        diags = _check(src)
        if diags:
            failures.append((i, diags))
    if failures:
        for i, diags in failures:
            print(f"  positive #{i} unexpectedly produced diagnostics:")
            for d in diags:
                print(f"    [{d.code}] {d.message}")
    assert not failures, f"{len(failures)} positive case(s) wrongly flagged"
    print(f"B.1 positive: {len(POSITIVE)}/{len(POSITIVE)} clean (no false positives)")


def test_negative_corpus():
    failures = []
    for i, (src, exp_caller, exp_callee, note) in enumerate(NEGATIVE, start=1):
        diags = _check(src)
        if not diags:
            failures.append((i, "no diagnostic", note))
            continue
        if not any(d.code == "E0801" for d in diags):
            failures.append((i, f"got codes {[d.code for d in diags]}", note))
            continue
        if not any(d.extra.get("caller") == exp_caller and
                   d.extra.get("callee") == exp_callee for d in diags):
            failures.append((i, f"got pairs "
                             f"{[(d.extra.get('caller'), d.extra.get('callee')) for d in diags]}",
                             note))
    if failures:
        for i, problem, note in failures:
            print(f"  negative #{i} ({note}): {problem}")
    assert not failures, f"{len(failures)} negative case(s) not caught correctly"
    print(f"B.1 negative: {len(NEGATIVE)}/{len(NEGATIVE)} caught (no false negatives)")


def test_default_on_through_cli():
    """Running `aether check` on a violating file must exit non-zero."""
    import subprocess
    bad = """
function greet() returns Unit
  effects pure
do
  print("x")
end
"""
    p = "/tmp/_b1_cli_test.aeth"
    with open(p, "w") as f:
        f.write(bad)
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "check", p],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert r.returncode == 2, f"expected exit 2, got {r.returncode}; stderr={r.stderr}"
    assert "E0801" in r.stderr, f"expected E0801 in stderr; got {r.stderr}"
    # And opt-out should pass.
    r = subprocess.run(
        [sys.executable, "-B", "-m", "transpiler.aether.cli", "check",
         "--no-static-effects", p],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, f"--no-static-effects expected exit 0, got {r.returncode}"
    print("B.1 cli: default-on rejects, --no-static-effects passes")


if __name__ == "__main__":
    test_positive_corpus()
    test_negative_corpus()
    test_default_on_through_cli()
    print("B.1 ALL STATIC EFFECT TESTS PASS")


# ----------------------------------------------------------------------
# B.2: effect-glob matching
# ----------------------------------------------------------------------

POSITIVE_GLOB = [
    # 1. Broad caller (no arg) covers specific callee.
    """
function fetchUser(id: Int) returns String
  effects net.fetch("https://api.x/users/*")
do
  return "u"
end

function dispatch(id: Int) returns String
  effects net.fetch
do
  return fetchUser(id)
end
""",
    # 2. Wildcard caller covers specific literal callee.
    """
function fetchUserList() returns String
  effects net.fetch("https://api.x/users")
do
  return ""
end

function dispatch() returns String
  effects net.fetch("https://api.x/*")
do
  return fetchUserList()
end
""",
    # 3. Exact arg match.
    """
function fetchUserList() returns String
  effects net.fetch("https://api.x/users")
do
  return ""
end

function dispatch() returns String
  effects net.fetch("https://api.x/users")
do
  return fetchUserList()
end
""",
    # 4. Multi-level wildcard glob.
    """
function fetchTracker() returns String
  effects net.fetch("https://api.x/v2/tracker/123")
do
  return ""
end

function gateway() returns String
  effects net.fetch("https://api.x/v*/tracker/*")
do
  return fetchTracker()
end
""",
    # 5. Wildcard at start.
    """
function fetchExternal() returns String
  effects net.fetch("https://other.com/x")
do
  return ""
end

function gateway() returns String
  effects net.fetch("*/x")
do
  return fetchExternal()
end
""",
]

NEGATIVE_GLOB = [
    # 1. Wrong host: glob over api.x doesn't cover api.y.
    ("""
function fetchExternal() returns String
  effects net.fetch("https://api.y/users")
do
  return ""
end

function dispatch() returns String
  effects net.fetch("https://api.x/*")
do
  return fetchExternal()
end
""", "dispatch", "fetchExternal", "wrong host"),

    # 2. Caller has specific URL, callee has the unrestricted version.
    ("""
function fetchAny() returns String
  effects net.fetch
do
  return ""
end

function dispatch() returns String
  effects net.fetch("https://api.x/users")
do
  return fetchAny()
end
""", "dispatch", "fetchAny", "caller too narrow for unrestricted callee"),

    # 3. Different exact URLs.
    ("""
function fetchA() returns String
  effects net.fetch("https://api.x/a")
do
  return ""
end

function fetchB() returns String
  effects net.fetch("https://api.x/b")
do
  return fetchA()
end
""", "fetchB", "fetchA", "different literal URLs"),

    # 4. Glob doesn't cover: different path.
    ("""
function fetchSecret() returns String
  effects net.fetch("https://api.x/admin/secret")
do
  return ""
end

function userGateway() returns String
  effects net.fetch("https://api.x/users/*")
do
  return fetchSecret()
end
""", "userGateway", "fetchSecret", "glob path mismatch"),

    # 5. Wildcard caller for one host doesn't cover literal on a different host.
    ("""
function fetchOther() returns String
  effects net.fetch("https://other.com/x")
do
  return ""
end

function dispatch() returns String
  effects net.fetch("https://api.x/*")
do
  return fetchOther()
end
""", "dispatch", "fetchOther", "wrong host literal"),
]


def test_positive_glob():
    failures = []
    for i, src in enumerate(POSITIVE_GLOB, start=1):
        diags = _check(src)
        if diags:
            failures.append((i, diags))
    if failures:
        for i, diags in failures:
            print(f"  glob positive #{i} unexpectedly produced:")
            for d in diags:
                print(f"    [{d.code}] {d.message[:130]}")
    assert not failures, f"{len(failures)} glob-positive case(s) wrongly flagged"
    print(f"B.2 glob positive: {len(POSITIVE_GLOB)}/{len(POSITIVE_GLOB)} clean")


def test_negative_glob():
    failures = []
    for i, (src, exp_caller, exp_callee, note) in enumerate(NEGATIVE_GLOB, start=1):
        diags = _check(src)
        if not diags:
            failures.append((i, "no diagnostic", note))
            continue
        if not any(d.code == "E0801" for d in diags):
            failures.append((i, f"got codes {[d.code for d in diags]}", note))
            continue
        if not any(d.extra.get("caller") == exp_caller and
                   d.extra.get("callee") == exp_callee for d in diags):
            failures.append((i, f"got pairs "
                             f"{[(d.extra.get('caller'), d.extra.get('callee')) for d in diags]}",
                             note))
    if failures:
        for i, problem, note in failures:
            print(f"  glob negative #{i} ({note}): {problem}")
    assert not failures, f"{len(failures)} glob-negative case(s) not caught"
    print(f"B.2 glob negative: {len(NEGATIVE_GLOB)}/{len(NEGATIVE_GLOB)} caught")


# ----------------------------------------------------------------------
# Iter 51 / BUGS.md BUG-022 — a function passed as a VALUE is an escape
# ----------------------------------------------------------------------
# `apply(logIt, s)` runs logIt's `log` effect under the caller, but only
# the CALLEE's effects were ever unioned into the obligation, so a `pure`
# main handing a `log` function to a `pure` apply was exit 0.

FN_VALUE_ESCAPE_SRC = """
function logIt(s: String) returns Unit
  effects log
do
  print(s)
end

function apply(f: function(String) returns Unit, x: String) returns Unit
  effects pure
do
  f(x)
end

function main(s: String) returns Unit
  effects pure
do
  apply(logIt, s)
end
"""


def test_function_value_effect_escape():
    diags = [d for d in _check(FN_VALUE_ESCAPE_SRC) if d.code == "E0801"]
    pairs = {(d.extra.get("caller"), d.extra.get("callee")) for d in diags}
    assert ("main", "logIt") in pairs, \
        f"passing a log function as a value must obligate the caller; got {pairs}"
    d = next(d for d in diags if d.extra.get("caller") == "main")
    assert d.extra.get("via") == "function_value"
    assert "passes 'logIt' as a value to 'apply'" in d.message
    print("B.1 E0801: function value passed as an argument is an effect escape")


def test_pure_function_value_clean():
    src = """
function double(n: Int) returns Int
  effects pure
do
  return n * 2
end

function run(xs: List<Int>) returns List<Int>
  effects pure
do
  return map(double, xs)
end
"""
    assert _check(src) == [], "a pure function value adds no obligation"
    print("B.1 E0801: map(double, xs) stays clean")


def test_covered_function_value_clean():
    src = FN_VALUE_ESCAPE_SRC.replace("effects pure", "effects log")
    assert [d for d in _check(src) if d.code == "E0801"] == [], \
        "declaring the effect covers the passed value"
    print("B.1 E0801: a caller declaring the effect covers the passed value")


def test_shadowed_name_is_not_a_function_value():
    # Review of iter-51: the function-value rule resolved a bare Ident
    # argument by GLOBAL name with no check that it was bound locally,
    # so a plain String PARAMETER named after a `log` function invented
    # an effect for a string. BUGS.md BUG-024.
    src = """
function logIt(s: String) returns Unit
  effects log
do
  print(s)
end

function main(logIt: String) returns String
  effects pure
do
  return concat(logIt, "x")
end
"""
    assert _check(src) == [], "a shadowing parameter is a value, not a function"
    src2 = """
function notify(s: String) returns Unit
  effects net
do
  httpGet(s)
end

function keep(s: String) returns String
  effects pure
do
  return s
end

function main() returns String
  effects pure
do
  let notify = "hello"
  return keep(notify)
end
"""
    assert _check(src2) == [], "a shadowing let-binding is a value too"
    print("B.1 E0801: a locally shadowed name is not a function value")


def test_aliased_function_value_escape():
    # The same edit closes the gap iter-51 documented: `let g = logIt`
    # then `apply(g, s)` is the same obligation as passing logIt.
    src = FN_VALUE_ESCAPE_SRC.replace(
        "  apply(logIt, s)", "  let g = logIt\n  apply(g, s)")
    diags = [d for d in _check(src) if d.code == "E0801"]
    pairs = {(d.extra.get("caller"), d.extra.get("callee")) for d in diags}
    assert ("main", "logIt") in pairs,         f"an alias of a function value carries the same effects; got {pairs}"
    d = next(d for d in diags if d.extra.get("caller") == "main")
    assert d.extra.get("via") == "function_value"
    assert "passes 'g' (alias of 'logIt')" in d.message
    print("B.1 E0801: an aliased function value is an effect escape")


# Tack the B.2 tests onto the __main__ runner.
if __name__ == "__main__":
    test_positive_glob()
    test_negative_glob()
    test_function_value_effect_escape()
    test_pure_function_value_clean()
    test_covered_function_value_clean()
    test_shadowed_name_is_not_a_function_value()
    test_aliased_function_value_escape()
    print("B.2 glob tests pass")
