"""Monotonic ratchet — Aether may only improve.

The self-teaching loop edits the compiler autonomously. This gate makes the
improvement one-directional:

  1. Detector count never drops. The number of distinct diagnostic codes
     the transpiler emits, and the number of detector passes registered in
     `aether.passes.STAGES`, must meet or exceed a committed FLOOR
     (`ratchet_baseline.json`). Removing a detector — even if its code,
     doc, and test are all deleted together so the rest of the suite stays
     green — drops the count below the floor and turns THIS gate red.

  2. Gains get locked. When an iteration adds a detector, this test prints
     a reminder to raise the floor in the same commit, so the addition can
     never be silently removed later.

  3. Fixed bugs stay fixed. Every `[FIXED ...]` entry in BUGS.md must name
     a regression test that still exists, so a repaired bug cannot quietly
     reappear.

  4. Recall never drops. A detector that still EXISTS can stop finding
     things (a `return []` counts as a detector). The floor also covers
     what the detectors are proven to find: every finding the `.aeth`
     corpus claims in its `// expect:` headers (test_corpus.py holds each
     file to its claim, so the sum can only shrink by editing claims
     down), and every Python sink/sanitizer table row (tests/
     test_sink_rows.py makes each row fire).

The baseline is compared against the merge-base with origin/main, not
only HEAD: in CI, HEAD *is* the commit under test, so lowering the floor
and deleting a detector in one commit used to pass (audit 2026-09-24 F1).

Run: python -B tests/test_ratchet.py   (exit 0 = pass)
"""
from __future__ import annotations
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE_REL = "tests/ratchet_baseline.json"
sys.path.insert(0, ROOT)

from tools.diagnostic_codes import constructed_codes  # noqa: E402


def _emitted_codes() -> set:
    """Distinct Exxxx codes the toolchain constructs — now genuinely the
    same enumeration as the D.2 catalog test, because both call the one
    scanner in `tools/diagnostic_codes.py`. This docstring used to claim
    that while walking a different root with a narrower regex."""
    return constructed_codes(ROOT)


def _gated_detectors() -> set:
    """Detector check_* functions registered in the analysis registry.

    Counts what actually EXECUTES, by import — not what a regex finds in
    cli.py source text. A detector that is defined but never registered
    no longer counts toward the ratchet."""
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether.passes import STAGES
    return {fn.__name__ for _stage, fns in STAGES for fn in fns}


# Every caller that runs static analysis must cross the registry. The
# absence of this check is what let tools/scan.py ship blind to
# E0207/E0729/E0730 and sdk.py (so the editor) run 2 detectors of 30.
_ANALYZE_CALLERS = [
    os.path.join("transpiler", "aether", "cli.py"),
    os.path.join("transpiler", "aether", "sdk.py"),
    os.path.join("tools", "scan.py"),
]


def test_analysis_routes_through_registry():
    """No caller may re-assemble a private detector list. Each must call
    `analyze` / `analyze_flat` from `aether.passes`."""
    offenders = []
    for rel in _ANALYZE_CALLERS:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            text = f.read()
        if "analyze" not in text:
            offenders.append(rel)
    assert not offenders, (
        "RATCHET: these callers no longer route through the analysis "
        "registry (`aether.passes.analyze`) — a hand-maintained detector "
        "list is exactly the drift this check exists to stop:\n  "
        + "\n  ".join(offenders))
    print(f"registry: all {len(_ANALYZE_CALLERS)} analysis callers route "
          f"through analyze()")


def _baseline() -> dict:
    with open(os.path.join(ROOT, "tests", "ratchet_baseline.json"),
              encoding="utf-8") as f:
        return json.load(f)


def test_detector_count_ratchet():
    base = _baseline()
    codes = len(_emitted_codes())
    dets = len(_gated_detectors())
    floor_c = base["min_emitted_codes"]
    floor_d = base["min_gated_detectors"]

    assert codes >= floor_c, (
        f"RATCHET REGRESSION: emitted diagnostic codes dropped to {codes}, "
        f"below the floor {floor_c}. A detector was removed — the ratchet "
        f"forbids it. Restore it or explain in BUGS.md why it is unsound.")
    assert dets >= floor_d, (
        f"RATCHET REGRESSION: gated detector passes dropped to {dets}, below "
        f"the floor {floor_d}. Restore the removed check_* pass.")

    if codes > floor_c or dets > floor_d:
        print(f"  NOTE: ratchet gain not locked — raise ratchet_baseline.json "
              f"to min_emitted_codes={codes}, min_gated_detectors={dets} in "
              f"this commit so the gain is permanent.")
    print(f"ratchet: {codes} codes >= floor {floor_c}, "
          f"{dets} detectors >= floor {floor_d}")


# The tables tests/test_sink_rows.py pins, row for row.
_PY_TABLES = ("SINK_BY_QUALIFIED", "SINK_BY_METHOD", "SINK_BY_BUILTIN",
              "SINK_GUARDS", "SANITIZER_BY_QUALIFIED")


def _corpus_claimed_findings() -> int:
    from tools.expectations import corpus_files, parse_header
    total = 0
    for path in corpus_files(ROOT):
        with open(path, encoding="utf-8") as f:
            want, _run = parse_header(f.read(), path)
        total += sum((want or {}).values())
    return total


def _py_table_rows() -> int:
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether import py_frontend
    return sum(len(getattr(py_frontend, t)) for t in _PY_TABLES)


def test_recall_floor():
    base = _baseline()
    now = {"min_corpus_claimed_findings": _corpus_claimed_findings(),
           "min_py_table_rows": _py_table_rows()}
    low = [f"{k}: {now[k]} < floor {base[k]}" for k in now if now[k] < base[k]]
    assert not low, (
        "RATCHET REGRESSION (recall): " + "; ".join(low) + ". Corpus claims "
        "only shrink when a header is edited down to match a detector that "
        "stopped firing; table rows only shrink when a sink spelling is "
        "deleted. Restore it.")
    gain = {k: v for k, v in now.items() if v > base[k]}
    if gain:
        print("  NOTE: recall gain not locked — raise ratchet_baseline.json to "
              + ", ".join(f"{k}={v}" for k, v in gain.items()))
    print("ratchet: recall " + ", ".join(f"{k.removeprefix('min_')} {v} >= "
                                          f"{base[k]}" for k, v in now.items()))


def test_skip_names_are_stages():
    """`analyze(skip=...)` refuses a name that is not a stage — a misspelt
    skip used to be ignored, silently running the stage (audit F4)."""
    sys.path.insert(0, os.path.join(ROOT, "transpiler"))
    from aether.passes import analyze
    try:
        analyze({"decls": []}, skip=("smt",))
    except ValueError:
        print("registry: an unknown skip name is an error")
        return
    raise AssertionError("analyze(skip=('smt',)) must raise: 'smt' is not a stage")


def _detector_codes() -> list:
    """Documented codes the self-teaching loop owns: the security range
    (E07xx) and the static-semantic range (E02xx, excluding the parse code
    E0201). These are the codes the ratchet's legitimacy guard protects."""
    docs = open(os.path.join(ROOT, "grammar", "diagnostics.md"),
                encoding="utf-8").read()
    documented = set(re.findall(r'\*\*(E\d{4})\*\*', docs))
    return sorted(c for c in documented
                  if c.startswith("E07") or (c.startswith("E02") and c != "E0201"))


def _gate_suites() -> list:
    """The suites scripts/run_all.py runs — one discovery, read from there."""
    spec = importlib.util.spec_from_file_location(
        "_run_all", os.path.join(ROOT, "scripts", "run_all.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.test_files()


def _asserted_codes_in(src: str) -> set:
    """Exxxx codes in string constants inside the TEST of an `assert` —
    `assert codes == ["E0713"]`, `assert "E0714" in got`. Not comments,
    not docstrings, not an assert's message: text that asserts nothing
    proves nothing (audit F1: any substring of any test file counted).
    A NEGATIVE comparison (`not in`, `!=`, `is not`, `not ...`) asserts
    the code is absent, which proves nothing about it firing: skipped."""
    neg = (ast.NotIn, ast.NotEq, ast.IsNot)

    def positive(node):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return
        if isinstance(node, ast.Compare) and any(isinstance(o, neg) for o in node.ops):
            return
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.update(re.findall(r'E\d{4}', node.value))
        for child in ast.iter_child_nodes(node):
            positive(child)

    out = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assert):
            positive(node.test)
    return out


def _asserted_codes() -> set:
    out = set()
    for f in _gate_suites():
        with open(f, encoding="utf-8") as fh:
            out |= _asserted_codes_in(fh.read())
    return out


def test_legitimacy_counts_assertions_only():
    got = _asserted_codes_in(
        '# E0001 in a comment\n'
        'def t():\n'
        '    """E0002 in a docstring"""\n'
        '    note = "E0003"\n'
        '    assert codes == ["E0004"], "E0005 in the message"\n'
        '    assert "E0006" in got\n'
        '    assert "E0007" not in got and got != ["E0008"]\n'
        '    assert not ("E0009" in got)\n')
    assert got == {"E0004", "E0006"}, got
    print("legitimacy: only a code inside an assert's (positive) test counts")


def test_detectors_legitimately_checked():
    """An improvement must be REAL, not a bumped number. Every protected
    detector code must be (1) actually emitted by the transpiler, and
    (2) asserted by a test that proves it fires. This blocks inflating the
    ratchet with a documented-but-dead `code=` string or a phantom
    detector: to raise the count you must ship a wired, tested detector."""
    detector = _detector_codes()
    emitted = _emitted_codes()
    asserted = _asserted_codes()

    not_emitted = [c for c in detector if c not in emitted]
    assert not not_emitted, (
        "LEGITIMACY: these documented detector codes are not emitted by any "
        "transpiler pass (a doc row without a real detector):\n  "
        + ", ".join(not_emitted))

    not_tested = [c for c in detector if c not in asserted]
    assert not not_tested, (
        "LEGITIMACY: these detector codes appear in no `assert` of any suite "
        "the gate runs (a mention in a comment, docstring or message proves "
        "nothing — add a test that asserts the code fires):\n  "
        + ", ".join(not_tested))

    print(f"legitimacy: all {len(detector)} detector codes are emitted AND "
          f"proven by a test")


def _git(*args) -> str | None:
    try:
        r = subprocess.run(["git", *args], cwd=ROOT,
                           capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    except (FileNotFoundError, OSError):
        return None


def _reference_commits() -> list:
    """Commits whose baseline the working tree must meet or exceed.

    HEAD catches an uncommitted edit. The merge-base with origin/main
    catches a lowering COMMITTED on the branch — in CI, HEAD is the commit
    under test, so HEAD alone compared the change against itself. The
    parent catches it on main itself (merge-base == HEAD there) and for a
    floor key the branch introduced, which main does not have yet."""
    head = _git("rev-parse", "HEAD")
    if head is None:
        return []
    refs = {head}
    parent = _git("rev-parse", "--verify", "--quiet", "HEAD~1")
    if parent:
        refs.add(parent)
    base = _git("merge-base", "HEAD", "origin/main")
    if base is None:
        print("  WARNING: no origin/main ref (shallow clone or no remote) — "
              "comparing against HEAD and its parent only; a lowering "
              "committed earlier on this branch is NOT caught. CI must "
              "check out with fetch-depth: 0.")
    else:
        refs.add(base)
    return sorted(refs)


def test_baseline_never_lowered():
    """The one edit the count-floor can't catch itself: lowering a number
    in the baseline. Every number must be >= its value at each reference
    commit (`_reference_commits`) — you can raise the floor, never lower
    it. Skips cleanly without git or before the first committed baseline."""
    cur = _baseline()
    checked = []
    for ref in _reference_commits():
        committed = _git("show", f"{ref}:{BASELINE_REL}")
        if committed is None:
            continue
        prev = json.loads(committed)
        lowered = [k for k, v in prev.items()
                   if isinstance(v, int) and cur.get(k, 0) < v]
        assert not lowered, (
            f"RATCHET REGRESSION: the baseline was LOWERED against {ref[:10]} for "
            + ", ".join(f"{k} ({prev[k]} -> {cur.get(k)})" for k in lowered)
            + ". The ratchet is one-directional — a baseline number may only "
              "be raised. Restore it; Aether does not lose ground.")
        checked.append(ref[:10])
    if not checked:
        print("ratchet: no committed baseline to compare (first commit / no git)")
        return
    print(f"ratchet: baseline >= every reference commit ({', '.join(checked)})")


def test_fixed_bugs_stay_fixed():
    """Every BUGS.md [FIXED] entry must reference an existing regression
    test, so a repaired bug cannot silently reappear."""
    bugs_path = os.path.join(ROOT, "BUGS.md")
    if not os.path.isfile(bugs_path):
        print("ratchet: no BUGS.md — nothing to enforce")
        return
    with open(bugs_path, encoding="utf-8") as f:
        text = f.read()
    # A real FIXED marker carries a commit hash: `[FIXED 0f356e1]`. The
    # `[FIXED <commit>]` placeholder in the Fix-protocol instructions is not
    # a real entry and is deliberately not matched.
    marker = re.compile(r'\[FIXED\s+[0-9a-f]{6,}\]')
    fixed = marker.findall(text)
    missing = []
    for block in re.split(r'(?=^#{1,3}\s)', text, flags=re.M):
        # The "Fix protocol" section is documentation (it contains a format
        # example), not a real entry — skip it.
        if block.lstrip().lower().startswith("## fix protocol"):
            continue
        if not marker.search(block):
            continue
        m = re.search(r'test:\s*(\S+)', block)
        if not m:
            missing.append(block.strip().splitlines()[0] if block.strip() else "?")
            continue
        ref = m.group(1)
        # a file path under the repo, or a pytest-style path::marker
        path = ref.split("::", 1)[0]
        if not os.path.isfile(os.path.join(ROOT, path)):
            missing.append(f"{ref} (missing file)")
    assert not missing, (
        "RATCHET: these [FIXED] BUGS.md entries lack an existing regression "
        "test (add `test: tests/....py` to each):\n  " + "\n  ".join(missing))
    print(f"ratchet: {len(fixed)} FIXED bug(s), all with a live regression test")


if __name__ == "__main__":
    test_detector_count_ratchet()
    test_recall_floor()
    test_analysis_routes_through_registry()
    test_skip_names_are_stages()
    test_legitimacy_counts_assertions_only()
    test_detectors_legitimately_checked()
    test_baseline_never_lowered()
    test_fixed_bugs_stay_fixed()
    print("RATCHET: Aether only moves forward")
