"""D.3 module-validation pass.

The B.3 capability pass enforces the cross-cutting "what effects can
this module transitively perform" question; the module pass below
enforces the smaller, surface-level structural invariants:

  E0702: a name in `exports` doesn't refer to any declared function /
         type / record / union / const in the program.
  E0703: more than one `module ... end` declaration in a single file
         (the v0.3 surface is single-file; cross-file module
         composition is reserved for v0.4).
  E0704: a module declares a capability the runtime doesn't recognise
         (i.e. not one of {log, fs, net, db, exec, time, random, panic,
         mutate}) — or a function declares an effect whose capability
         (its first path segment) is not one of them, which no module
         could ever grant (audit 2026-09-24 A11).

Default-on; opt out with `aether check --no-module-check` (added
alongside the existing `--no-static-effects` / `--no-capability-check`
opt-outs).

The check is single-file by design. Cross-file module composition is
documented as reserved in `docs/MODULE_STORY.md`.
"""

from __future__ import annotations
from typing import Any, Dict, List, Set

from ..diagnostics import Diagnostic, Position


# Names of known capabilities (subset; matches `passes/capability.py`'s
# `effect_capability` head-segment vocabulary plus the two free effects).
_KNOWN_CAPABILITIES: Set[str] = {
    "log", "fs", "net", "db", "exec", "time", "random", "panic", "mutate",
}


def check_modules(ast: Dict[str, Any]) -> List[Diagnostic]:
    diags: List[Diagnostic] = []
    decls = ast.get("decls", [])

    # E0704 on a declared effect. Python has no effects clause: the
    # frontend's paths (`env`, `process`) are inferred, not declared.
    for d in decls if ast.get("lang") != "python" else ():
        if d.get("kind") != "FunctionDecl":
            continue
        for eff in d.get("effects") or []:
            path = eff.get("path") or []
            if not path or path == ["pure"] or path[0] in _KNOWN_CAPABILITIES:
                continue
            pos = d.get("pos") or {"line": 0, "column": 0}
            name = ".".join(path)
            diags.append(Diagnostic(
                code="E0704",
                category="module",
                severity="error",
                message=(
                    f"function {d['name']!r} declares effect {name!r}, whose "
                    f"capability {path[0]!r} is not a known capability; no "
                    f"module can grant it"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=(
                    f"declare an effect of a known capability "
                    f"({', '.join(sorted(_KNOWN_CAPABILITIES))}), or remove "
                    f"{name!r}"
                ),
                confidence=1.0,
                extra={"function": d["name"], "effect": name,
                       "capability": path[0],
                       "known": sorted(_KNOWN_CAPABILITIES)},
            ))

    # E0703: more than one ModuleDecl.
    modules = [d for d in decls if d.get("kind") == "ModuleDecl"]
    if len(modules) > 1:
        for extra in modules[1:]:
            pos = extra.get("pos") or {"line": 0, "column": 0}
            diags.append(Diagnostic(
                code="E0703",
                category="module",
                severity="error",
                message=(
                    f"duplicate module declaration {extra['name']!r}; "
                    f"this file already declared module {modules[0]['name']!r}"
                ),
                position=Position(pos.get("line", 0), pos.get("column", 0)),
                suggestion=("a single Aether file may contain at most one "
                            "`module ... end` declaration in v0.3 (cross-file "
                            "module composition is v0.4 work)"),
                confidence=1.0,
                extra={"first_module": modules[0]["name"],
                       "duplicate_module": extra["name"]},
            ))
    if not modules:
        return diags

    # The single module declaration (or the first one — we still validate
    # against it even if E0703 fired so that exports/capabilities errors
    # are also surfaced in one pass).
    declared_names: Set[str] = set()
    for d in decls:
        k = d.get("kind")
        if k in {"FunctionDecl", "TypeDecl", "RecordDecl", "UnionDecl", "ConstDecl"}:
            declared_names.add(d.get("name", ""))

    for m in modules:
        pos = m.get("pos") or {"line": 0, "column": 0}
        # E0702: exports reference undeclared names.
        for exported in m.get("exports", []):
            if exported not in declared_names:
                diags.append(Diagnostic(
                    code="E0702",
                    category="module",
                    severity="error",
                    message=(
                        f"module {m['name']!r} exports {exported!r}, but no "
                        f"function, type, record, union, or const named "
                        f"{exported!r} is declared in this file"
                    ),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=(f"declare {exported!r} or remove it from the "
                                f"module's exports list"),
                    confidence=1.0,
                    extra={"module": m["name"], "exported": exported,
                           "declared_names": sorted(declared_names)},
                ))
        # E0704: capability name not in the known vocabulary.
        for cap in m.get("capabilities", []):
            if cap not in _KNOWN_CAPABILITIES:
                diags.append(Diagnostic(
                    code="E0704",
                    category="module",
                    severity="error",
                    message=(
                        f"module {m['name']!r} requires capability {cap!r}, "
                        f"which is not a known capability"
                    ),
                    position=Position(pos.get("line", 0), pos.get("column", 0)),
                    suggestion=(
                        f"known capabilities are: "
                        f"{', '.join(sorted(_KNOWN_CAPABILITIES))}"
                    ),
                    confidence=1.0,
                    extra={"module": m["name"], "capability": cap,
                           "known": sorted(_KNOWN_CAPABILITIES)},
                ))
    return diags
