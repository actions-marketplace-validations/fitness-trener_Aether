"""F.2 fix-loop — protocol + deterministic reference implementation.

This file is NOT a full agent. It is the **protocol** an LLM-driven
agent would follow against the Aether toolchain, with a deterministic
reference implementation for the subset of diagnostics whose
structured `extra` dict is sufficient for a mechanical repair.

The loop NEVER repairs by weakening a declared constraint unless told
to. Two transformers exist, and both widen:

  - E0801 (effect not covered): append `missing_effect` to the caller's
    `effects` clause.
  - E0701 (capability not declared): append `required_capability` to
    the module's `requires capability` list.

Widening the declaration is exactly what Aether exists to refuse: on
`demos/capability-firewall/log_formatter.aeth` the loop used to grant
the log formatter `net` and report `final state: clean` — it granted
the exfiltration the demo exists to block (audit 2026-09-24 D1). So
every candidate edit is compared with the program before it
(`widening`), whichever transformer produced it. By default a widening
edit is NOT applied: the loop stops with status `not_repaired`, the
would-be widening, and the call-site patch target (removing or
replacing the call is the repair that keeps the constraint).
`--allow-widen` applies them, tags each step `"weakens_constraint":
true`, warns, and the run ends `widened` with a non-zero exit — never
`clean`.

Diagnostic codes that require *intent-level* reasoning to repair
(E0301 requires, E0302 refinement boundary, E0304 ensures, E0305
stdlib precondition) are explicitly OUT OF SCOPE for the
deterministic reference. They are the codes where a real LLM gets
plugged into the same protocol — see `llm_fix_demo.py` for the
one-shot Claude 3.5 Sonnet demo on E0304 (Layer 1 replay) and E0302
(Layer 2 live positive control). `aether fix-loop --live` judges the
model's fix with the same `widening` rule.

The loop runs until `sdk.check` returns clean, a repair would widen
(`not_repaired`), or no diagnostic has a registered transformer
(`stuck`; the real agent would hand control to its LLM at that point).
Exit (the table in diagnostics.py): 0 only on `clean`; 1 for
`not_repaired`, `stuck`, `widened`, `max_iters_reached`; 2 usage; 3 the
loop itself crashed.

Outputs (UTF-8, LF line ends; neither may be the input file):
  - `<source>.transcript.json` — ordered list of steps
  - `<source>.fixed.aeth`      — the final source: the input verbatim
    when nothing was applied, otherwise re-printed with its full-line
    comments kept (see `pretty`)

Run:
  aether fix-loop demos/payment_workflow/broken.aeth

It lives in the package, not in `demos/`, so that `aether fix-loop`
works in a pip-installed copy: the wheel ships only `aether/`, and
importing it from `demos/` failed in every installed copy since 0.3.0
(BUGS.md BUG-026). `demos/payment_workflow/fix_loop.py` is kept as the
demo's by-path entry point.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from . import sdk
from .diagnostics import EXIT_CLEAN, EXIT_CRASH, EXIT_FINDINGS, EXIT_USAGE
from .parser import parse
from .pretty import asts_equal_ignoring_pos
from .passes.effects import _declared_effects, _effect_covered, _format_effect
from .passes.patch_target import compute_patch_target


# ---------------------------------------------------------------------
# Transformers: each takes (ast, diag) and mutates the AST in place.
# ---------------------------------------------------------------------

def _effect_node_for_path_and_arg(path, arg_text=None):
    """Build a parser-shaped Effect node."""
    if arg_text is None:
        return {"path": list(path), "arg": None}
    return {
        "path": list(path),
        "arg": {"kind": "StringLit", "value": arg_text},
    }


def fix_E0801(ast, diag):
    """Effect not covered. Append the missing effect to the caller's
    effects clause, dropping any explicit `pure` since the function is
    no longer pure once it has effects. WIDENS the declaration."""
    caller_name = diag.extra.get("caller")
    missing = diag.extra.get("missing_effect")  # [path_list, arg_text_or_None]
    if not caller_name or not missing:
        return ast
    path, arg = missing
    new_eff = _effect_node_for_path_and_arg(tuple(path), arg)
    for d in ast.get("decls", []):
        if d.get("kind") != "FunctionDecl":
            continue
        if d.get("name") != caller_name:
            continue
        effs = [e for e in d.get("effects", [])
                if e.get("path") != ["pure"]]
        if not any(e.get("path") == list(path) and e.get("arg") == new_eff["arg"]
                   for e in effs):
            effs.append(new_eff)
        d["effects"] = effs
        break
    return ast


def fix_E0701(ast, diag):
    """Capability not declared. Append `required_capability` to the
    module's `requires capability` list. WIDENS the declaration."""
    cap = diag.extra.get("required_capability")
    if not cap:
        return ast
    for d in ast.get("decls", []):
        if d.get("kind") != "ModuleDecl":
            continue
        caps = list(d.get("capabilities", []))
        if cap not in caps:
            caps.append(cap)
        d["capabilities"] = caps
        break
    return ast


_TRANSFORMERS = {
    "E0801": fix_E0801,
    "E0701": fix_E0701,
}


# ---------------------------------------------------------------------
# Widening: does `after` declare more authority than `before`?
# ---------------------------------------------------------------------

def widening(before_ast, after_ast):
    """Every way `after_ast` declares more than `before_ast`, as text:
    an effect a function declares that its old clause did not cover (so
    `net.fetch("https://a/x")` -> `net.fetch("https://a/*")` counts, and
    a narrowing does not), or a module capability that was not required.
    A function new in `after` is held to the union of every effect the
    input declared anywhere. Dropping `pure` alone adds nothing and is
    not counted; dropping it to add an effect is, through the effect.

    Structural, not per-transformer, so an LLM's edit is judged by the
    same rule as the deterministic loop's. [] means no widening."""
    def fns(ast):
        return {d["name"]: _declared_effects(d)
                for d in (ast or {}).get("decls", []) or []
                if d.get("kind") == "FunctionDecl"}

    def caps(ast):
        return {c for d in (ast or {}).get("decls", []) or []
                if d.get("kind") == "ModuleDecl"
                for c in d.get("capabilities", []) or []}

    before = fns(before_ast)
    anywhere = [e for effs in before.values() for e in effs]
    out = []
    for name, effs in fns(after_ast).items():
        old = before.get(name, anywhere)
        out += [f"function {name}: effects + {_format_effect(e)}"
                for e in effs if not _effect_covered(old, e)]
    out += [f"module: requires capability + {c!r}"
            for c in sorted(caps(after_ast) - caps(before_ast))]
    return out


def source_widening(before_src, after_src, filename="<fix-loop>"):
    """`widening` over two sources. An unparseable side yields [] — it is
    not a program, and `check` rejects it on its own."""
    try:
        return widening(parse(before_src, filename), parse(after_src, filename))
    except Exception:
        return []


def _blocked_reason(diag, widen):
    extra = diag.extra or {}
    if diag.code == "E0801":
        who = f"{extra.get('caller')}'s declared effects"
        call = f"the call to {extra.get('callee')!r}"
    else:
        who = "the module's declared capabilities"
        call = (f"the call in {extra.get('function')!r} that needs "
                f"{extra.get('required_capability')!r}")
    return (f"not repaired: fixing this would widen {who} "
            f"({'; '.join(widen)}); remove or replace {call}")


# ---------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------

def fix_loop(source, max_iters=20, filename="<fix-loop>", allow_widen=False):
    transcript = []
    widened = False
    for i in range(max_iters):
        r = sdk.check(source, filename=filename)
        if r.ok:
            if widened:
                transcript.append({
                    "iteration": i, "status": "widened",
                    "note": ("check passes only because declared "
                             "effects/capabilities were widened; this is "
                             "not a repair"),
                })
            else:
                transcript.append({"iteration": i, "status": "clean"})
            return source, transcript
        applied = False
        blocked = []
        for diag in r.diagnostics:
            t = _TRANSFORMERS.get(diag.code)
            if t is None:
                continue
            candidate = sdk.edit(
                source,
                lambda ast, _t=t, _d=diag: _t(ast, _d),
                filename=filename,
            )
            before_ast = parse(source, filename)
            after_ast = parse(candidate, filename)
            if asts_equal_ignoring_pos(before_ast, after_ast):
                continue    # changed nothing (e.g. the caller is in an import)
            widen = widening(before_ast, after_ast)
            diag_info = {"code": diag.code, "message": diag.message,
                         "extra": diag.extra}
            if widen and not allow_widen:
                blocked.append(dict(
                    diag_info,
                    would_widen=widen,
                    reason=_blocked_reason(diag, widen),
                    patch_target=compute_patch_target(r.ast, diag)))
                continue
            entry = {
                "iteration": i,
                "diagnostic": diag_info,
                "transformer": t.__name__,
                "weakens_constraint": bool(widen),
            }
            if widen:
                entry["widens"] = widen
                widened = True
            source = candidate
            transcript.append(entry)
            applied = True
            break
        if not applied:
            status = "not_repaired" if blocked else "stuck"
            entry = {"iteration": i, "status": status}
            if blocked:
                entry["blocked"] = blocked
            entry["remaining_codes"] = sorted({d.code for d in r.diagnostics})
            entry["remaining_count"] = len(r.diagnostics)
            transcript.append(entry)
            return source, transcript
    transcript.append({"iteration": max_iters, "status": "max_iters_reached"})
    return source, transcript


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("source", help="path to broken .aeth source")
    p.add_argument("--out-source", default=None,
                   help="where to write the fixed .aeth (default: <source>.fixed.aeth)")
    p.add_argument("--out-transcript", default=None,
                   help="where to write the fix transcript JSON "
                        "(default: <source>.transcript.json)")
    p.add_argument("--allow-widen", action="store_true",
                   help="apply repairs that widen a declared effects clause "
                        "or module capability list; each step is tagged "
                        "weakens_constraint and the exit stays non-zero")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    src_path = Path(args.source)
    out_src = (Path(args.out_source) if args.out_source
               else src_path.with_suffix(".fixed.aeth"))
    out_tr = (Path(args.out_transcript) if args.out_transcript
              else src_path.with_suffix(".transcript.json"))
    # A source path without `.aeth` made `str.replace` a no-op, so the
    # transcript overwrote the input (audit 2026-09-24 D8).
    if len({src_path.resolve(), out_src.resolve(), out_tr.resolve()}) != 3:
        sys.stderr.write("fix-loop: the input, --out-source and "
                         "--out-transcript must be three different files\n")
        return EXIT_USAGE
    try:
        src = src_path.read_text(encoding="utf-8-sig")
    except OSError as e:
        sys.stderr.write(f"fix-loop: cannot read {src_path}: {e}\n")
        return EXIT_USAGE
    try:
        fixed, transcript = fix_loop(src, filename=str(src_path),
                                     allow_widen=args.allow_widen)
    except Exception:
        # The loop itself failed: a bug in Aether, never "not repaired".
        import traceback
        traceback.print_exc()
        return EXIT_CRASH
    with open(out_src, "w", encoding="utf-8", newline="\n") as f:
        f.write(fixed)
    with open(out_tr, "w", encoding="utf-8", newline="\n") as f:
        json.dump(transcript, f, indent=2)
        f.write("\n")
    final = transcript[-1]
    status = final.get("status", "fixed")
    # The outcome, not progress: printed even under --quiet.
    for b in final.get("blocked", []):
        sys.stderr.write(f"[{b['code']}] {b['reason']}\n")
    n_widen = sum(1 for t in transcript if t.get("weakens_constraint"))
    if n_widen:
        sys.stderr.write(
            f"fix-loop: WARNING: --allow-widen applied {n_widen} repair(s) "
            "that WIDEN declared effects/capabilities; the program now "
            "declares more authority than its author gave it\n")
    if not args.quiet:
        print(f"fix-loop iterations: {len([t for t in transcript if 'diagnostic' in t])}")
        print(f"final state: {status}")
        print(f"wrote fixed source: {out_src}")
        print(f"wrote transcript:   {out_tr}")
    return EXIT_CLEAN if status == "clean" else EXIT_FINDINGS


if __name__ == "__main__":
    raise SystemExit(main())
