"""Wave 2 of the 2026-09-24 audit: the compiler refuses again.

Every program below was ACCEPTED (`check` exit 0) at 52f04aa. Each test
asserts the exact multiset of codes the analysis now reports, so a
regression in either direction (a miss, or a new over-flag on the
sanctioned shapes) goes red.

  A5  one binder iterator: `for` / `match` names re-bind a proven name
  A1  contracts, refinement predicates and const initializers are code
  A2  a callee the checker cannot name has the closed-world effect bound

Run: python -B tests/test_compiler_refuses.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.parser import parse               # noqa: E402
from aether.passes import analyze_flat        # noqa: E402


def codes(src: str) -> list:
    return sorted(d.code for d in analyze_flat(parse(src, "<w2>")))


def diags(src: str) -> list:
    return analyze_flat(parse(src, "<w2>"))


# ----------------------------------------------------------------------
# A5 — value-less binders disqualify a proven name
# ----------------------------------------------------------------------

def test_a5_for_shadow_path():
    assert codes("""
function f(paths: List<String>) returns Unit
  effects fs.read
do
  let p: String = "/etc/motd"
  for p in paths do
    let _r: Result<String, String> = readFile(p)
  end
end
""") == ["E0711"]


def test_a5_match_shadow_path():
    assert codes("""
function f(o: Option<String>) returns Unit
  effects fs.read, log
do
  let p: String = "/etc/motd"
  match o do
    case Some(p) do
      let _r: Result<String, String> = readFile(p)
    end
    case None() do
      print("none")
    end
  end
end
""") == ["E0711"]


def test_a5_for_shadow_sql():
    assert codes("""
function q(xs: List<String>) returns Unit
  effects db.query
do
  let s: String = "SELECT 1"
  for s in xs do
    let _r: String = sqlQuery(s)
  end
end
""") == ["E0713"]


def test_a5_for_shadow_idor():
    assert codes("""
function upd(ids: List<String>, user: String) returns Unit
  effects db.exec
do
  let id: String = "doc-1"
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", id)
  for id in ids do
    let stmt: String = sqlBind("UPDATE docs SET body='x' WHERE id = ?", id)
    let _r: String = sqlByOwner(stmt, id, proof)
  end
end
""") == ["E0717"]


def test_a5_for_shadow_authorized():
    # A proven token re-bound by a loop over raw tokens is not a proof.
    assert codes("""
function f(toks: List<String>, u: String) returns Unit
  effects db.exec
do
  let tok = authorize(u, "orders:cancel")
  for tok in toks do
    let _r: String = sqlExec("UPDATE t SET x = 1", tok)
  end
end
""") == ["E0716"]


def test_a5_raw_param_later_assigned_a_proof():
    # A parameter is a binder: its raw value reaches the sink before the
    # assignment, so "every binding is a proof" must include it.
    assert codes("""
function f(tok: String, u: String) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE t SET x = 1", tok)
  tok = authorize(u, "orders:cancel")
end
""") == ["E0716"]


def test_a5_sanctioned_shapes_stay_clean():
    # The fixed forms: a literal never re-bound, and a proof minted from
    # the loop variable inside the loop for a name bound once.
    assert codes("""
function f() returns Unit
  effects db.query
do
  let s: String = "SELECT 1"
  let _r: String = sqlQuery(s)
end
""") == []
    assert codes("""
function upd(id: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", id)
  let stmt: String = sqlBind("UPDATE docs SET body='x' WHERE id = ?", id)
  let _r: String = sqlByOwner(stmt, id, proof)
end
""") == []


def test_a5_as_pattern_carries_taint():
    # `case Some(x) as y` binds y to the scrutinee itself.
    assert codes("""
function f(o: Option<Secret<String>>) returns Unit
  effects log
do
  match o do
    case Some(x) as y do
      print(y)
    end
    case None() do
      print("none")
    end
  end
end
""").count("E0712") == 1


# ----------------------------------------------------------------------
# A1 — requires / ensures / refinement predicates / const initializers
# ----------------------------------------------------------------------

def test_a1_requires_effect():
    ds = diags("""
function double(x: Int) returns Int
  requires isOk?(writeFile("out.txt", "pure fn wrote this"))
  effects pure
do
  return x * 2
end
""")
    assert sorted(d.code for d in ds) == ["E0801"]
    assert ds[0].extra["caller"] == "double"
    assert ds[0].extra["missing_effect"] == [["fs", "write"], None]


def test_a1_ensures_effect():
    assert codes("""
function f(x: Int) returns Int
  ensures isOk?(writeFile("out.txt", "x"))
  effects pure
do
  return x
end
""") == ["E0801"]


def test_a1_refinement_predicate_effect():
    ds = diags("""
type Logged = Int where isOk?(writeFile("out.txt", "predicate wrote this"))
function double(x: Logged) returns Int
  effects pure
do
  return x * 2
end
""")
    assert [d.code for d in ds] == ["E0801"]
    assert ds[0].extra["caller"] == "<type Logged where>"


def test_a1_const_initializer_effect():
    assert codes("""
module M
  requires capability log
  exports main
end
const X: Bool = isOk?(writeFile("out.txt", "const init wrote this"))
function main() returns Unit
  effects log
do
  print("hello")
end
""") == ["E0701", "E0801"]


def test_a1_requires_shell_injection():
    assert codes("""
function tidy(name: String) returns Int
  requires shellExec("rm -rf " + name) != ""
  effects pure
do
  return 1
end
""") == ["E0714", "E0801"]


def test_a1_pure_contracts_stay_clean():
    assert codes("""
type Small = Int where self > 0 and self < 10
const LIMIT: Int = 5
function f(x: Small) returns Int
  requires x < LIMIT
  ensures result >= 0
  effects pure
do
  return x
end
""") == []


# ----------------------------------------------------------------------
# A2 — function values the checker cannot name
# ----------------------------------------------------------------------

LOG_IT = """
function logIt(s: String) returns Unit
  effects log
do
  print(s)
end
"""


def _unknown(src):
    ds = [d for d in diags(src) if d.code == "E0801"]
    assert ds and all(d.extra.get("via") == "unknown_callee" for d in ds), \
        [(d.code, d.extra) for d in ds]
    return ds


def test_a2_indexed_list_under_module():
    src = """
module Reporter
  requires capability log
  exports main
end
function launder(s: String) returns Unit
  effects pure
do
  let ws = [writeFile]
  let _r = ws[0]("pwned.txt", s)
end
function main() returns Unit
  effects log
do
  launder("x")
  print("done")
end
"""
    assert codes(src) == ["E0701", "E0701", "E0801"]
    d = _unknown(src)[0]
    assert d.extra["caller"] == "launder" and d.extra["callee"] == "writeFile"
    assert d.extra["shape"] == "an indexed element"


def test_a2_returned_function():
    _unknown(LOG_IT + """
function getF() returns function(String) returns Unit
  effects pure
do
  let g = [logIt]
  return g[0]
end
function launder(s: String) returns Unit
  effects pure
do
  let h = getF()
  h(s)
end
""")


def test_a2_const_alias():
    ds = [d for d in diags("""
const g: function(String) returns Unit = print
function launder(s: String) returns Unit
  effects pure
do
  g(s)
end
""") if d.code == "E0801"]
    assert [(d.extra["caller"], d.extra["callee"]) for d in ds] == [("launder", "print")]


def test_a2_list_element_to_hof():
    _unknown(LOG_IT + """
function launder(s: String) returns List<String>
  effects pure
do
  let fs = [logIt]
  return map([s], fs[0])
end
""")


def test_a2_if_expr_function():
    _unknown("""
function launder(s: String) returns Unit
  effects pure
do
  let h = if true then print else print end
  h(s)
end
""")


def test_a2_pattern_bound_function():
    _unknown("""
function launder(s: String) returns Unit
  effects pure
do
  let m = {"k": writeFile}
  let r = get(m, "k")
  match r do
    case Some(w) do
      let _x = w("pwned.txt", s)
    end
    case None do
      return
    end
  end
end
""")


def test_a2_record_field_function():
    _unknown(LOG_IT + """
function launder(b: Map<String, String>, s: String) returns Unit
  effects pure
do
  let keep = logIt
  b.f(s)
end
""")


def test_a2_sanctioned_shapes_stay_clean():
    # BUG-022: a call through a function-typed parameter is charged where
    # the function is passed; main declares `log`, so nothing fires.
    assert codes("""
function apply(f: function(String) returns Unit, s: String) returns Unit
  effects pure
do
  f(s)
end
function main() returns Unit
  effects log
do
  apply(print, "ok")
end
""") == []
    # Only PURE functions escape as values: the bound is empty, proven pure.
    assert codes("""
function double(n: Int) returns Int
  effects pure
do
  return n * 2
end
function run(xs: List<Int>) returns Int
  effects pure
do
  let fs = [double]
  let ys = map(xs, fs[0])
  return fs[0](length(ys))
end
""") == []
    # A caller that declares the bound is covered.
    assert codes(LOG_IT + """
function run(s: String) returns Unit
  effects log
do
  let fs = [logIt]
  fs[0](s)
end
""") == []
    # An effectful function that escapes does not taint a direct call.
    assert codes(LOG_IT + """
function keep() returns List<function(String) returns Unit>
  effects pure
do
  return [logIt]
end
function run(xs: List<Int>) returns Int
  effects pure
do
  return length(xs)
end
""") == []


# ----------------------------------------------------------------------
# A4 — injective mangling; runtime helpers outside the user namespace
# ----------------------------------------------------------------------

import io                                            # noqa: E402
import itertools                                     # noqa: E402
from contextlib import redirect_stdout               # noqa: E402
from aether.emitter import emit                      # noqa: E402
from aether import runtime as _rt                    # noqa: E402
from aether.diagnostics import AetherError           # noqa: E402


def run(src: str):
    """(stdout, diagnostic code or None) of running `src`."""
    code = compile(emit(parse(src, "<w2>")), "<w2>", "exec")
    g = _rt.build_namespace()
    g["__name__"] = "__main__"
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(code, g)
    except AetherError as e:
        return buf.getvalue(), e.diag.code
    return buf.getvalue(), None


def test_a4_user_function_cannot_replace_contract_checker():
    out, code = run("""
function assert_contract(c: Bool, k: String, e: String, f: String) returns Unit
  effects pure
do
  return
end
function withdraw(balance: Int, amount: Int) returns Int
  requires amount > 0
  effects pure
do
  return balance - amount
end
function main() returns Unit
  effects log
do
  print(intToString(withdraw(10, 0 - 1000)))
end
""")
    assert (out, code) == ("", "E0301"), (out, code)


def test_a4_user_function_cannot_replace_refinement_checker():
    out, code = run("""
type PositiveInt = Int where self > 0
function check_refinement(v: Int, p: Int, t: String, b: String, x: String) returns Int
  effects pure
do
  return v
end
function need(n: PositiveInt) returns Int
  effects pure
do
  return n
end
function main() returns Unit
  effects log
do
  print(intToString(need(0 - 9)))
end
""")
    assert (out, code) == ("", "E0302"), (out, code)


def test_a4_question_suffix_does_not_collide():
    out, code = run("""
function valid?(s: String) returns Bool
  effects pure
do
  return true
end
function valid_q(s: String) returns Bool
  effects log
do
  print("wrong function ran")
  return false
end
function main() returns Unit
  effects log
do
  if valid?("x") then
    print("done")
  end
end
""")
    assert (out, code) == ("done\n", None), (out, code)


def test_a4_temporaries_do_not_collide():
    out, _ = run("""
function main() returns Unit
  effects log
do
  let scrut1 = 7
  match Some(1) do
    case Some(v) do
      print(intToString(scrut1 + v))
    end
    case None() do
      print("none")
    end
  end
end
""")
    assert out == "8\n", out


def test_a4_mangle_is_injective():
    alphabet = ["a", "q", "e", "_", "1"]
    seen = {}
    for n in range(1, 6):
        for base in map("".join, itertools.product(alphabet, repeat=n)):
            if base[0].isdigit():
                continue
            for name in (base, base + "?", base + "!"):
                m = _rt.mangle(name)
                assert m.isidentifier(), m
                assert seen.setdefault(m, name) == name, (name, seen[m], m)
                assert _rt.unmangle(m) == name, (name, m)
    assert _rt.mangle("valid?") != _rt.mangle("valid_q")


def test_a4_runtime_helpers_unreachable_from_user_names():
    # Every name the namespace exposes is either a stdlib function that
    # its Aether name mangles to, or unreachable from ANY identifier.
    helpers = []
    for name in _rt.build_namespace():
        aeth = _rt.unmangle(name)
        if aeth is None:
            helpers.append(name)
        else:
            assert _rt.mangle(aeth) == name
    assert "_aert_assert_contract" in helpers and "_aert_check_refinement" in helpers
    for h in helpers + ["_aert_refn_T", "_aert_scrut", "_aert_tmp1",
                        "_aert_matchexpr1", "_aert_old1"]:
        assert _rt.unmangle(h) is None, h
    # and no emitted helper spelling is left in the user namespace
    py = emit(parse("""
type P = Int where self > 0
function f(x: P) returns Int
  requires x < 10
  ensures result > old(x) - 1
  effects pure
do
  return match Some(x) do
    case Some(v) do v
    end
    case None() do 0
    end
  end
end
""", "<w2>"))
    import re
    for tok in set(re.findall(r"\b_ae\w*", py)):
        assert tok.startswith("_aert_") or _rt.unmangle(tok) is not None, tok


# ----------------------------------------------------------------------
# A3 — runtime capability grant (a RUNTIME guarantee, not a static proof)
# ----------------------------------------------------------------------

LAUNDER_UNDER_LOG = """
module Reporter
  requires capability log
  exports main
end
function launder(s: String) returns Unit
  effects pure
do
  let _r = writeFile("wave2_must_not_exist.txt", s)
end
function main() returns Unit
  effects log
do
  launder("x")
end
"""


def _no_file():
    p = os.path.join(os.getcwd(), "wave2_must_not_exist.txt")
    if os.path.exists(p):
        os.remove(p)
        return False
    return True


def test_a3_effect_outside_grant_fails_at_runtime():
    # `run()` never runs the static passes: this is what
    # `aether run --no-static-effects --no-capability-check` executes.
    out, code = run(LAUNDER_UNDER_LOG)
    assert code == "E0701", (out, code)
    assert _no_file(), "the write happened before the check"


def test_a3_release_mode_enforces_too():
    code_obj = compile(emit(parse(LAUNDER_UNDER_LOG, "<w2>"), release=True),
                       "<w2>", "exec")
    g = _rt.build_namespace()
    g["__name__"] = "__main__"
    try:
        exec(code_obj, g)
        raised = None
    except AetherError as e:
        raised = e.diag.code
    assert raised == "E0701" and _no_file()


def test_a3_const_initializer_under_module():
    out, code = run("""
module M
  requires capability log
  exports main
end
const X: Bool = isOk?(writeFile("wave2_must_not_exist.txt", "x"))
function main() returns Unit
  effects log
do
  print("hello")
end
""")
    assert (out, code) == ("", "E0701") and _no_file(), (out, code)


def test_a3_granted_and_moduleless_programs_run():
    assert run("""
module M
  requires capability log
  exports main
end
function main() returns Unit
  effects log
do
  print("ok")
end
""") == ("ok\n", None)
    # A program without a module keeps the implicit all-grant, and a
    # previous program's grant does not leak into it.
    run(LAUNDER_UNDER_LOG)
    assert run("""
function main() returns Unit
  effects time.now, log
do
  let _t = now()
  print("free")
end
""") == ("free\n", None)


def test_bug050_remove_on_set():
    out, code = run("""
function main() returns Unit
  effects log
do
  let s: Set<Int> = setUnion([1], [2])
  let t = remove(s, 1)
  print(intToString(size(t)))
end
""")
    assert (out, code) == ("1\n", None), (out, code)


# ----------------------------------------------------------------------
# A7 — a net.fetch glob `*` does not cross `/ @ : ? #` in the authority
# ----------------------------------------------------------------------

def _fetch(callee_url: str, caller_glob: str) -> list:
    return codes(f"""
function reach() returns Unit
  effects net.fetch("{callee_url}")
do
  return
end
function sync() returns Unit
  effects net.fetch("{caller_glob}")
do
  reach()
end
""")


def test_a7_glob_does_not_span_the_path():
    assert _fetch("https://evil.com/.corp.example/x",
                  "https://*.corp.example/*") == ["E0801"]


def test_a7_glob_does_not_span_userinfo():
    assert _fetch("https://api.example.com@evil.com/v1/x",
                  "https://api.example.com*") == ["E0710", "E0801"]


def test_a7_subdomain_and_path_globs_still_cover():
    assert _fetch("https://api.corp.example/v1/items?x=1",
                  "https://*.corp.example/*") == []
    assert _fetch("https://api.example.com/charge/42",
                  "https://api.example.com/charge/*") == []


# ----------------------------------------------------------------------
# A6 — refinements checked wherever a refined value is bound (RUNTIME)
# ----------------------------------------------------------------------

POS = "type PositiveInt = Int where self > 0\n"


def _main(body: str, decls: str = "") -> tuple:
    return run(POS + decls + """
function main() returns Unit
  effects log
do
""" + body + """
end
""")


def test_a6_every_binding_site_is_checked():
    cases = {
        "return": ("  print(intToString(bad()))", """
function bad() returns PositiveInt
  effects pure
do
  return 0 - 5
end
"""),
        "typed let": ("  let n: PositiveInt = 0 - 7\n  print(intToString(n))", ""),
        "var reassign": ("  var n: PositiveInt = 1\n  n = 0 - 2\n  print(intToString(n))", ""),
        "record field": ("  let a = Account(0 - 100)\n  print(intToString(a.balance))",
                         "record Account do\n  balance: PositiveInt\nend\n"),
        "list element": ("  print(intToString(total([3, 0 - 4])))", """
function total(xs: List<PositiveInt>) returns Int
  effects pure
do
  return sum(xs)
end
"""),
        "const": ("  print(intToString(LIMIT))", "const LIMIT: PositiveInt = 0 - 1\n"),
        "chained base": ("  print(intToString(useSmall(0 - 50)))", """
type Small = PositiveInt where self < 10
function useSmall(n: Small) returns Int
  effects pure
do
  return n
end
"""),
    }
    for label, (body, decls) in cases.items():
        out, code = _main(body, decls)
        assert (out, code) == ("", "E0302"), (label, out, code)


def test_a6_valid_values_pass():
    out, code = _main("""  let n: PositiveInt = 3
  let a = Account(n)
  print(intToString(total([a.balance, good()]) + LIMIT))""", """
record Account do
  balance: PositiveInt
end
const LIMIT: PositiveInt = 1
function good() returns PositiveInt
  effects pure
do
  return 2
end
function total(xs: List<PositiveInt>) returns Int
  effects pure
do
  return sum(xs)
end
""")
    assert (out, code) == ("6\n", None), (out, code)

# ----------------------------------------------------------------------
# A10 — deep input is a structured diagnostic, never a traceback
# ----------------------------------------------------------------------

def _parse_code(src: str):
    try:
        parse(src, "<w2>")
    except AetherError as e:
        return e.diag.code
    return None


def _ret(expr: str) -> str:
    return ("function f() returns Int\n  effects pure\ndo\n  return "
            + expr + "\nend\n")


def test_a10_deep_parens_and_long_chains_are_e0201():
    assert _parse_code(_ret("(" * 150 + "1" + ")" * 150)) == "E0201"
    assert _parse_code(_ret(" + ".join(["1"] * 500))) == "E0201"


def test_a10_bounded_depth_still_analyzes_and_runs():
    src = _ret(" + ".join(["1"] * 190)) + """
function main() returns Unit
  effects log
do
  print(intToString(f()))
end
"""
    assert codes(src) == []
    assert run(src) == ("190\n", None)


def test_a10_unemittable_construct_is_e9001():
    try:
        emit(parse("const X: Int = old(1)\n", "<w2>"))
        got = None
    except AetherError as e:
        got = e.diag.code
    assert got == "E9001"

def test_a3_capability_firewall_demo_fails_at_runtime():
    # demos/capability-firewall/log_formatter.aeth with every static pass
    # skipped: `exfil` DECLARES net.fetch under a module granting only
    # log, and is refused when invoked (no stdlib call needed).
    path = os.path.join(ROOT, "demos", "capability-firewall", "log_formatter.aeth")
    out, code = run(open(path, encoding="utf-8").read())
    assert code == "E0701", (out, code)

if __name__ == "__main__":
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            n += 1
            print(f"ok  {name}")
    print(f"WAVE 2 REFUSAL: {n} tests pass")
