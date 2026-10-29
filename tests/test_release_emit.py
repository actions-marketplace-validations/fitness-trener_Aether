"""--release emit: frames + ensures elided, requires + refinements kept
(gap 6: perf credibility of emitted code).

Standalone (`python -B tests/test_release_emit.py`, exit 0).
"""
from __future__ import annotations
import io
import os
import sys
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))
sys.path.insert(0, ROOT)

from aether.parser import parse             # noqa: E402
from aether.emitter import emit             # noqa: E402
from aether.runtime import build_namespace  # noqa: E402

SRC = """
type Percentage = Int where self >= 0 and self <= 100

function applyDiscount(basePrice: Int, pct: Percentage) returns Int
  requires basePrice >= 0
  ensures result <= basePrice
  effects pure
do
  return basePrice - (basePrice * pct) / 100
end

function main() returns Unit
  effects log
do
  print(intToString(applyDiscount(200, 25)))
end
"""


def _run_py(py: str) -> str:
    code = compile(py, "<rel>", "exec")
    g = build_namespace()
    g["__name__"] = "__main__"
    buf = io.StringIO()
    with redirect_stdout(buf):
        exec(code, g)
    return buf.getvalue()


def test_release_elides_frames_and_ensures():
    ast = parse(SRC, "<rel>")
    py = emit(ast, release=True)
    assert "push_effect_frame" not in py
    assert "pop_effect_frame" not in py
    assert "'ensures'" not in py
    # boundary checks survive
    assert "'requires'" in py
    assert "_aert_check_refinement" in py


def test_release_same_output_as_debug():
    ast = parse(SRC, "<rel>")
    assert _run_py(emit(ast)) == _run_py(emit(ast, release=True)) == "150\n"


def test_default_emit_unchanged():
    ast = parse(SRC, "<rel>")
    py = emit(ast)
    assert "push_effect_frame" in py and "'ensures'" in py


def main() -> int:
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            f()
            print(f"ok {n}")
    print("OK: release emit tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
