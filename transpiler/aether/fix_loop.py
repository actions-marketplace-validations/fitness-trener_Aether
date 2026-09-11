"""F.2 fix-loop — protocol + deterministic reference implementation.

This file is NOT a full agent. It is the **protocol** an LLM-driven
agent would follow against the Aether toolchain, with a deterministic
reference implementation for the subset of diagnostics whose
structured `extra` dict is sufficient for a mechanical repair.

Two diagnostic codes are mechanically repairable today:

  - E0801 (effect not covered): append `missing_effect` from the
    diagnostic's `extra` dict to the caller's `effects` clause.
  - E0701 (capability not declared): append `required_capability`
    from the diagnostic's `extra` dict to the module's
    `requires capability` list.

Both are deterministic AST transforms — the `extra` dict carries
enough structure for the rewrite to be unambiguous. The deterministic
path is what we run on CI and in unit tests: it produces an identical
transcript on every invocation and serves as the executable contract
for what "mechanically actionable diagnostic" means.

Diagnostic codes that require *intent-level* reasoning to repair
(E0301 requires, E0302 refinement boundary, E0304 ensures, E0305
stdlib precondition) are explicitly OUT OF SCOPE for the
deterministic reference. They are the codes where a real LLM gets
plugged into the same protocol — see `llm_fix_demo.py` for the
one-shot Claude 3.5 Sonnet demo on E0304 (Layer 1 replay) and E0302
(Layer 2 live positive control).

The framing matters: an Aether-using agent's actual fix-loop combines
both — deterministic repair for the codes where it's sound, LLM
inference for the codes where it isn't. `fix_loop.py` ships the
deterministic half cleanly; `llm_fix_demo.py` ships proof of the
other half.

The loop runs until `sdk.check` returns clean or no more diagnostics
have a registered transformer (declared "stuck"; the real agent would
hand control to its LLM at that point).

Outputs:
  - `transcript.json` — full ordered list of (diagnostic, fix) tuples
  - `fixed.aeth`      — the final source

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

from . import sdk
from .parser import parse
from .pretty import pretty


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
    no longer pure once it has effects."""
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
    module's `requires capability` list."""
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
# Driver
# ---------------------------------------------------------------------

def fix_loop(source, max_iters=20, filename="<fix-loop>"):
    transcript = []
    for i in range(max_iters):
        r = sdk.check(source, filename=filename)
        if r.ok:
            transcript.append({"iteration": i, "status": "clean"})
            return source, transcript
        applied = False
        for diag in r.diagnostics:
            t = _TRANSFORMERS.get(diag.code)
            if t is None:
                continue
            entry = {
                "iteration": i,
                "diagnostic": {
                    "code": diag.code,
                    "message": diag.message,
                    "extra": diag.extra,
                },
                "transformer": t.__name__,
            }
            # Capture the diagnostic + extra in a closure-safe form
            captured = diag
            tr = t
            source = sdk.edit(
                source,
                lambda ast, _t=tr, _d=captured: _t(ast, _d),
                filename=filename,
            )
            transcript.append(entry)
            applied = True
            break
        if not applied:
            transcript.append({
                "iteration": i,
                "status": "stuck",
                "remaining_codes": sorted({d.code for d in r.diagnostics}),
                "remaining_count": len(r.diagnostics),
            })
            return source, transcript
    transcript.append({"iteration": max_iters, "status": "max_iters_reached"})
    return source, transcript


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("source", help="path to broken .aeth source")
    p.add_argument("--out-source", default=None,
                   help="where to write the fixed .aeth (default: <source>.fixed.aeth)")
    p.add_argument("--out-transcript", default=None,
                   help="where to write the fix transcript JSON")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    with open(args.source) as f:
        src = f.read()
    fixed, transcript = fix_loop(src, filename=args.source)
    out_src = args.out_source or args.source.replace(".aeth", ".fixed.aeth")
    out_tr = args.out_transcript or args.source.replace(".aeth", ".transcript.json")
    with open(out_src, "w") as f:
        f.write(fixed)
    with open(out_tr, "w") as f:
        json.dump(transcript, f, indent=2)
    if not args.quiet:
        print(f"fix-loop iterations: {len([t for t in transcript if 'diagnostic' in t])}")
        final = transcript[-1]
        print(f"final state: {final.get('status', 'fixed')}")
        print(f"wrote fixed source: {out_src}")
        print(f"wrote transcript:   {out_tr}")
    return 0 if transcript[-1].get("status") == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())
