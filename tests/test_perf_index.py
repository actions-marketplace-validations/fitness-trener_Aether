"""Analysis cost stays linear in detectors, and the shortcuts that make it
so change no output (audit 2026-09-24 F5, Wave 7).

  1. Walk budget: every detector used to re-walk every function for its
     binders, its calls and its contexts — 5.4M `walk()` frames on the
     three slowest framework files. Under `analyze()` those are built
     once (`ast_walk.shared_index`). A synthetic 40-function Python
     module must stay under 20 walks per function (97 before Wave 7,
     14 after, 3 of them per-finding argument scans).
  2. The marker rows (`marker_absent`) skip a program with no marker type
     and no marker constructor anywhere. Forcing them to run instead must
     give the same diagnostics on every corpus `.aeth` and on the Python
     module above — the skip is output-identical, not a heuristic.
  3. The shared index changes nothing either: every corpus `.aeth` gives
     the same diagnostics with the index as with each detector run on its
     own (the uncached path a direct `check_x(ast)` call takes).
  4. The Python frontend walks each scope once (6.8 walked nodes per AST
     node before the gaps round's G7, under 3 after); its output is
     checked byte-identical on the framework corpus, not here.

Run: python -B tests/test_perf_index.py   (exit 0 = pass)
"""
from __future__ import annotations
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether import parser                                     # noqa: E402
from aether.passes import STAGES, analyze_flat                # noqa: E402
from aether.passes import ast_walk, capability, detector_specs, effects  # noqa: E402
from aether.py_frontend import py_to_ir                       # noqa: E402

N_FUNCS = 40
PY_SRC = "import os, subprocess, sqlite3\n" + "".join(
    f"def f{i}(a, b):\n"
    f"    x = a + b\n"
    f"    for y in b:\n"
    f"        x = x + y\n"
    f"    subprocess.run('ls ' + x, shell=True)\n"
    f"    sqlite3.connect('db').execute('SELECT ' + a)\n"
    f"    return open(os.path.join('/tmp', a)).read()\n\n"
    for i in range(N_FUNCS))


def _dump(diags):
    return [d.to_dict() for d in diags]


def _corpus():
    for p in sorted(glob.glob(os.path.join(ROOT, "**", "*.aeth"), recursive=True)):
        try:
            with open(p, encoding="utf-8") as f:
                yield p, parser.parse(f.read(), p)
        except Exception:
            continue   # parse-error fixtures are test_corpus's business


def test_walk_budget_per_function():
    ast = py_to_ir(PY_SRC)[0]
    count = [0]
    real = ast_walk.walk

    def counting(*a, **k):
        count[0] += 1
        return real(*a, **k)

    mods = (ast_walk, capability, detector_specs, effects)
    for m in mods:
        m.walk = counting
    try:
        diags = analyze_flat(ast)
    finally:
        for m in mods:
            m.walk = real
    per_fn = count[0] / N_FUNCS
    assert diags, "the module is meant to produce findings"
    assert per_fn < 20, f"{per_fn:.1f} walks per function (budget 20)"


def test_marker_skip_is_output_identical():
    progs = [("<py>", py_to_ir(PY_SRC)[0])] + list(_corpus())
    real = detector_specs.marker_absent
    skipped = []
    for path, ast in progs:
        normal = _dump(analyze_flat(ast))
        detector_specs.marker_absent = effects.marker_absent = lambda a, m: False
        try:
            forced = _dump(analyze_flat(ast))
        finally:
            detector_specs.marker_absent = effects.marker_absent = real
        assert normal == forced, f"{path}: marker skip changed the output"
        skipped.append(all(real(ast, m) for m in ("Secret", "PII", "Untrusted")))
    assert len(progs) > 300, len(progs)
    assert any(skipped) and not all(skipped), "the corpus must exercise both paths"


def test_shared_index_is_output_identical():
    n = 0
    for path, ast in _corpus():
        shared = _dump(analyze_flat(ast))
        alone = _dump([d for _name, fns in STAGES for fn in fns for d in fn(ast)])
        assert shared == alone, f"{path}: shared index changed the output"
        n += 1
    assert n > 300, n


def test_frontend_walks_each_scope_once():
    """The frontend reads each scope's Python AST in ONE walk (`_DefIndex`,
    gaps round G7): its binding tables, calls, statements and walrus scan
    used to walk every file ~7 times (imports, module bindings, attribute
    assignments, then per def: bindings, calls, statements, walrus)."""
    import ast as pyast
    from aether import py_frontend
    nodes = sum(1 for _ in pyast.walk(pyast.parse(PY_SRC)))
    seen = [0]
    real_walk, real_fast = pyast.walk, py_frontend._walk

    def counting(real):
        def w(node):
            for n in real(node):
                seen[0] += 1
                yield n
        return w
    pyast.walk, py_frontend._walk = counting(real_walk), counting(real_fast)
    try:
        py_to_ir(PY_SRC)
    finally:
        pyast.walk, py_frontend._walk = real_walk, real_fast
    ratio = seen[0] / nodes
    assert ratio < 3, f"{ratio:.1f} walked nodes per AST node (budget 3)"


def main() -> int:
    tests = [test_walk_budget_per_function, test_marker_skip_is_output_identical,
             test_shared_index_is_output_identical, test_frontend_walks_each_scope_once]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"  [FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} perf-index checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
