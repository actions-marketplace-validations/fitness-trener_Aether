"""H.E.3 cross-file import resolution.

Minimal multi-file resolution for the v0.3 toolchain. Resolves
`import foo` declarations to `foo.aeth` in the same directory as the
importing file, parses each imported file, recursively resolves *its*
imports, and concatenates every top-level declaration into a single
"combined" Program AST that the standard static passes
(`check_effects`, `check_capabilities`, `check_modules`) can run over
unchanged.

What this *does* support, as of v0.3:

- Single-segment imports (`import foo`) resolving to a sibling file.
- Transitive import chains (A imports B imports C).
- Cycle detection (E0706) — surfaces a structured diagnostic instead
  of recursing infinitely.
- File-not-found (E0705).

What it *does not* support (deferred to v2):

- Dotted import paths (`import pkg.mod`) — the parser already accepts
  them; resolution treats only the leaf segment.
- Aliased imports (`import foo as bar`) — parsed, ignored at resolution
  time; downstream name resolution is by raw decl name.
- Symbol-level export filtering — every top-level decl of an imported
  file is currently fused into the caller's namespace regardless of
  whether the importing module's `exports` clause names it.
- Per-package version pinning, package manifests, lockfiles — v2.

This is a deliberate v1 scope choice. The verification primitives
(effects, capabilities, refinements) are the contribution; package
management is the *deployment* layer that ships in v2 once the language
identity has converged.

Every surface loads a program through `load_program` below — the CLI's
`check`/`run`/`emit`/`pack`, `sdk.check` (and so the LSP and the
fix-loop) and `tools/scan.py`. It used to be the CLI alone: the SDK, the
LSP, the fix-loop and the scanner parsed a single file and never resolved
imports, so a cross-file E0801 and an unresolved-import E0705 were
"clean" everywhere except `check` (audit 2026-09-24 D2). Imports resolve
against the directory of `filename`; for a pseudo-name such as `<sdk>`
that is the working directory.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from ..diagnostics import AetherError, Diagnostic, Position


def _diag(code: str, msg: str, pos_dict: Optional[Dict[str, int]],
          suggestion: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Diagnostic:
    pos = pos_dict or {"line": 0, "column": 0}
    return Diagnostic(
        code=code,
        category="module",
        severity="error",
        message=msg,
        position=Position(pos.get("line", 0), pos.get("column", 0)),
        suggestion=suggestion,
        confidence=1.0,
        extra=extra or {},
    )


def load_program(source_or_ast, filename: str, *, collect: bool = True,
                 resolve: bool = True):
    """THE program loader: parse + resolve imports. Returns
    `(ast, parse_diags, import_diags)` and never raises for a lex or
    parse error — those come back in `parse_diags` (with `ast` None on a
    lex error). `collect` picks the lenient multi-error parser (C.6);
    `collect=False` is the strict one, which stops at the first error.
    Accepts an already-parsed Program too (`sdk.check(ast)`).

    Import resolution runs only when the program has an `ImportDecl` and
    `resolve` is set (the CLI's `--no-import-resolution`). The two lists
    are kept apart because the surfaces treat them differently: a parse
    error still leaves a partial AST the SDK/LSP analyse, while an import
    error means the program is not the one the user wrote, and every
    surface stops before analysis — as `check` always has."""
    from ..parser import parse as _parse_strict, parse_collect
    if isinstance(source_or_ast, str):
        try:
            if collect:
                ast, parse_diags = parse_collect(source_or_ast, filename)
            else:
                ast, parse_diags = _parse_strict(source_or_ast, filename), []
        except AetherError as e:
            return None, list(e.diagnostics), []
    else:
        ast, parse_diags = source_or_ast, []
    parse_diags = list(parse_diags)
    if (ast is None or not resolve
            or not any(d.get("kind") == "ImportDecl"
                       for d in ast.get("decls", []) or [])):
        return ast, parse_diags, []
    combined, import_diags = resolve_imports(ast, filename)
    return combined, parse_diags, list(import_diags)


def resolve_imports(
    ast: Dict[str, Any],
    source_path: str,
) -> Tuple[Dict[str, Any], List[Diagnostic]]:
    """Public entry point. Returns (combined_ast, diagnostics).

    If `diagnostics` is non-empty, the returned AST still contains every
    decl that resolved successfully — the caller may decide to bail or
    continue with the partial program.
    """
    abs_source = os.path.abspath(source_path)
    visiting: Set[str] = set()
    resolved: Dict[str, Dict[str, Any]] = {}
    diags: List[Diagnostic] = []
    combined_decls: List[Dict[str, Any]] = []
    _walk(ast, abs_source, visiting, resolved, combined_decls, diags,
          is_entry=True)
    # `imports_resolved` tells E0208 (passes/names.py) the imported
    # names are in `decls`; `partial` rides along from the lenient parser.
    combined = {"kind": "Program", "decls": combined_decls,
                "imports_resolved": True}
    if ast.get("partial"):
        combined["partial"] = True
    return combined, diags


def _walk(
    ast: Dict[str, Any],
    abs_path: str,
    visiting: Set[str],
    resolved: Dict[str, Dict[str, Any]],
    out_decls: List[Dict[str, Any]],
    out_diags: List[Diagnostic],
    *,
    is_entry: bool,
) -> None:
    """DFS over the import graph. Records every (non-ImportDecl) decl
    of every visited file into `out_decls`, in import-then-self order
    so that downstream passes see imports' decls before the caller's."""
    if abs_path in resolved:
        # Already imported earlier on this DFS; nothing to do — its decls
        # are already in out_decls.
        return
    if abs_path in visiting:
        # Cycle detected. Surface E0706 anchored on the importing decl
        # whose ImportDecl `pos` is the most useful caller-facing
        # location. We don't have it here on the call site of the cycle
        # break; emit a file-level diagnostic instead.
        out_diags.append(_diag(
            "E0706",
            f"import cycle detected involving {abs_path!r}",
            None,
            suggestion=(
                "imports must form a DAG; break the cycle by extracting "
                "the shared definitions into a third file that both ends "
                "of the cycle import"
            ),
            extra={"file": abs_path, "stack": sorted(visiting)},
        ))
        return

    visiting.add(abs_path)
    base_dir = os.path.dirname(abs_path)

    for d in ast.get("decls", []) or []:
        if d.get("kind") != "ImportDecl":
            continue
        path_segments = d.get("path") or []
        if not path_segments:
            continue
        # v0.3: only the leaf segment is used.
        name = path_segments[-1]
        target_path = os.path.abspath(os.path.join(base_dir, name + ".aeth"))
        if not os.path.isfile(target_path):
            out_diags.append(_diag(
                "E0705",
                f"cannot resolve import {'.'.join(path_segments)!r}: "
                f"no such file {target_path!r}",
                d.get("pos"),
                suggestion=(
                    f"create {name!r}.aeth alongside the importing file, "
                    f"or remove the import declaration"
                ),
                extra={"resolved_to": target_path, "path": path_segments},
            ))
            continue
        # Parse the target. parse_collect is the lenient form used by
        # the SDK; for cross-file resolution we prefer strict parse so
        # that an unparseable dependency surfaces as a hard failure
        # rather than a silent partial.
        from ..parser import parse as _parse_strict
        try:
            # utf-8-sig, like the CLI's own reader: a BOM'd dependency is
            # not a lex error.
            with open(target_path, "r", encoding="utf-8-sig") as fh:
                target_src = fh.read()
            target_ast = _parse_strict(target_src, target_path)
        except AetherError as e:
            out_diags.append(e.diag)
            continue
        except OSError as e:
            out_diags.append(_diag(
                "E0705",
                f"cannot read import {'.'.join(path_segments)!r}: {e}",
                d.get("pos"),
                extra={"resolved_to": target_path, "os_error": str(e)},
            ))
            continue
        # Recurse into the imported file's own imports.
        _walk(target_ast, target_path, visiting, resolved, out_decls,
              out_diags, is_entry=False)

    # After all of *this file's* imports have been processed, append
    # this file's own non-import decls. For the entry file we also
    # preserve its ImportDecl nodes (downstream tooling may want to
    # see them); for transitive dependencies we drop the ImportDecls
    # since we've already inlined their effect.
    for d in ast.get("decls", []) or []:
        if d.get("kind") == "ImportDecl":
            if is_entry:
                out_decls.append(d)
            continue
        out_decls.append(d)

    visiting.discard(abs_path)
    resolved[abs_path] = ast
