"""E0208 — name resolution (known-gaps round G3, BUG-086).

Before: a call to or a read of a name nothing declares passed `check`
(exit 0) and failed at `run` with a Python NameError; a misspelt sink
(`sqlQeury("SELECT " + u)`) produced no E0713 because no taint pass can
name it. Now every identifier must reach a binding: parameter, block-
scoped local, top-level decl (imports included) or runtime export.

This is name resolution, not type checking: nothing here checks a
binding's type, arity or kind.

Run: python -B tests/test_name_resolution.py   (exit 0 = pass)
"""
from __future__ import annotations
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.parser import parse, parse_collect             # noqa: E402
from aether.passes import analyze_flat                     # noqa: E402
from aether.passes.imports import load_program             # noqa: E402
from aether.passes.names import check_name_resolution, RUNTIME_NAMES  # noqa: E402


def _names(src: str):
    return check_name_resolution(parse(src))


def _codes(src: str):
    return sorted(d.code for d in analyze_flat(parse(src)))


MISSPELT_SINK = """
function lookup(u: String) returns Unit
  effects db.query
do
  sqlQeury("SELECT * FROM users WHERE name = '" + u + "'")
end
"""


def test_misspelt_sink_is_E0208():
    # Red before this pass: analyze_flat returned [] (exit 0, no E0713).
    assert _codes(MISSPELT_SINK) == ["E0208"], _codes(MISSPELT_SINK)
    d = _names(MISSPELT_SINK)[0]
    assert d.extra == {"function": "lookup", "name": "sqlQeury",
                       "kind": "call", "suggestion": "sqlQuery"}, d.extra
    assert (d.position.line, d.position.column) == (5, 3), d.position
    # Spelt right, the injection detector sees the sink.
    assert _codes(MISSPELT_SINK.replace("sqlQeury", "sqlQuery")) == ["E0713"]
    print("E0208: misspelt sink refused, with the sink as the suggestion")


def test_undeclared_call_and_value():
    src = """
function main() returns Int
  effects pure
do
  frobnicate(1)
  return y + 1
end
"""
    got = [(d.code, d.extra["name"], d.extra["kind"]) for d in _names(src)]
    assert got == [("E0208", "frobnicate", "call"), ("E0208", "y", "value")], got
    print("E0208: an undeclared call and an undeclared read are both refused")


CLEAN = """
union Shape do
  case Circle(r: Int)
  case Square(s: Int)
end

record Point do
  x: Int
  y: Int
end

const LIMIT: Int = 10

type Small = Int where self < LIMIT

function double(x: Int) returns Int
  requires x >= 0
  ensures result == x * 2
  effects pure
do
  return x * 2
end

function area(s: Shape) returns Int
  effects pure
do
  match s do
    case Circle(r) do
      return r * r
    end
    case Square(side) do
      return side * side
    end
  end
end

function main() returns Unit
  effects log
do
  let p = Point(1, 2)
  let c = Shape.Circle(3)
  let q = Square(4)
  var total = area(c) + area(q) + p.x
  for n in range(0, LIMIT) do
    total = total + double(n)
  end
  let xs = map([1, 2], double)
  let k = match head(xs) do
    case Some(v) do v end
    case None do 0 end
  end
  let length = 3
  if c is Circle then
    print(intToString(total + k + length))
  end
  let r: Result<Int, String> = Ok(1)
  match r do
    case Ok(v) do print(intToString(v)) end
    case Err(e) do print(e) end
  end
end
"""


def test_legit_program_is_clean():
    assert _names(CLEAN) == [], [d.message for d in _names(CLEAN)]
    print("E0208: params, locals, for/match binders, constructors, const, "
          "stdlib, result/self, function values, `is` types: all resolve")


def _block(body: str, params: str = "c: Bool") -> str:
    return (f"function f({params}) returns Int\n  effects pure\ndo\n"
            f"{body}\nend\n")


def test_block_scoping_and_shadowing():
    after_if = _block("  if c then\n    let y = 1\n    return y\n  end\n"
                      "  return y")
    got = [(d.code, d.extra["name"]) for d in _names(after_if)]
    assert got == [("E0208", "y")], got
    for_var_after = _block("  for i in range(0, 3) do\n    let z = i\n"
                           "    return z\n  end\n  return i")
    assert [d.extra["name"] for d in _names(for_var_after)] == ["i"]
    arm_after = _block("  match Some(1) do\n    case Some(v) do return v end\n"
                       "    case None do return 0 end\n  end\n  return v")
    assert [d.extra["name"] for d in _names(arm_after)] == ["v"]
    before_let = _block("  let a = b\n  let b = 1\n  return a + b")
    assert [d.extra["name"] for d in _names(before_let)] == ["b"]
    # Visible: an outer binding inside a nested block, a param shadowed by
    # a let, a local shadowing a stdlib name.
    ok = _block("  let y = 1\n  if c then\n    while c do\n      return y\n"
                "    end\n  end\n  let c = 2\n  let print = c\n  return print",
                params="c: Bool")
    assert _names(ok) == [], [d.message for d in _names(ok)]
    # `result` outside an `ensures`, `self` outside a refinement: unbound.
    bad = _block("  return result + self")
    assert [d.extra["name"] for d in _names(bad)] == ["result", "self"]
    print("E0208: block-scoped (if/for/match/use-before-let), shadowing ok")


def test_const_sees_only_earlier_decls():
    # A const initializer runs at module load in declaration order:
    # `const A = B` above `const B` passed check and was a NameError at run.
    src = """const A: Int = B
const B: Int = 1
const C: Int = B + 1

function main() returns Int
  effects pure
do
  return A + C
end
"""
    got = [(d.extra["function"], d.extra["name"]) for d in _names(src)]
    assert got == [("<const A>", "B")], got
    print("E0208: a const initializer sees only declarations above it")


def test_imports_resolved_and_unresolved():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "lib.aeth"), "w", encoding="utf-8") as f:
            f.write("function helper(x: Int) returns Int\n  effects pure\n"
                    "do\n  return x\nend\n")
        main = os.path.join(tmp, "main.aeth")
        src = ("import lib\n\nfunction main() returns Int\n  effects pure\n"
               "do\n  return helper(1)\nend\n")
        ast, pd, idg = load_program(src, main)
        assert not pd and not idg
        assert check_name_resolution(ast) == []
        ast, _pd, _idg = load_program(src.replace("helper(", "helpr("), main)
        got = [(d.code, d.extra["name"], d.extra["suggestion"])
               for d in check_name_resolution(ast)]
        assert got == [("E0208", "helpr", "helper")], got
        # Imports not resolved: the imported file may bind any name.
        ast, _pd, _idg = load_program(src.replace("helper(", "helpr("), main,
                                      resolve=False)
        assert check_name_resolution(ast) == []
    print("E0208: imported names resolve; silent when imports are unresolved")


def test_partial_parse_is_silent():
    src = ("function broken( returns Int\n  effects pure\ndo\n  return 1\nend\n\n"
           "function main() returns Int\n  effects pure\ndo\n"
           "  return broken(1)\nend\n")
    ast, diags = parse_collect(src)
    assert [d.code for d in diags] == ["E0201"]
    assert ast.get("partial") is True
    assert check_name_resolution(ast) == []
    print("E0208: silent on a partial AST (the failed decl may bind the name)")


def test_runtime_names_are_derived():
    # Derived from the runtime, not hand-kept: every stdlib function the
    # emitted code can reach, and none of the runtime's own helpers.
    from aether import runtime
    assert {"print", "sqlQuery", "Some", "None", "Ok", "Err", "empty?"} <= RUNTIME_NAMES
    assert all(runtime.mangle(n) in vars(runtime) for n in RUNTIME_NAMES)
    assert not any(n.startswith("_aert_") for n in RUNTIME_NAMES)
    print(f"E0208: {len(RUNTIME_NAMES)} stdlib names derived from runtime.unmangle")


def test_python_never_gets_E0208():
    # check-py skips the `semantic` stage, where E0208 lives.
    from aether.py_frontend import PY_SKIP_STAGES, py_to_ir
    from aether.passes import analyze
    assert "semantic" in PY_SKIP_STAGES
    ir = py_to_ir("def f(u):\n    frobnicate(u)\n    return undefined_name\n")[0]
    got = [d.code for _s, ds in analyze(ir, skip=PY_SKIP_STAGES) for d in ds]
    assert got == [], got
    print("E0208: never emitted on Python (semantic stage skipped)")


if __name__ == "__main__":
    test_misspelt_sink_is_E0208()
    test_undeclared_call_and_value()
    test_legit_program_is_clean()
    test_block_scoping_and_shadowing()
    test_const_sees_only_earlier_decls()
    test_imports_resolved_and_unresolved()
    test_partial_parse_is_silent()
    test_runtime_names_are_derived()
    test_python_never_gets_E0208()
    print("E0208 name resolution: ALL PASS")
