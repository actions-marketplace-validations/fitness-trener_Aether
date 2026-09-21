"""Static analysis passes that run between parse and exec.

`STAGES` is the single definition of which detectors exist and in what
order they run. Every caller that runs static analysis — the CLI, the
agent SDK, the LSP server, the SARIF scanner, the tests — crosses
`analyze()` / `analyze_flat()` rather than assembling its own list.
Before this registry there were four hand-maintained copies and three had
drifted (`tools/scan.py` was blind to E0207/E0729/E0730; `sdk.py`, and so
the editor, ran 2 of 30 detectors).

A stage is a named group that shares a short-circuit: `analyze()` returns
diagnostics grouped by stage so the CLI can keep printing the first
non-empty stage and stop, exactly as it did when the stages were
hand-wired functions.

SMT contract proving is deliberately NOT a stage: different signature
(`ast, timeout_ms`), an optional z3 dependency, and the only analysis
where `severity == "warning"` must not fail the run. It stays hand-wired
in `cli.py` after the loop.

No exception handling here. A pass that crashes propagates — measured 0
crashes across 799 inputs (370 whole files + 429 truncated mid-typing
buffers), and a crashing detector must go red, not silent. Liveness for
long-lived servers is the LSP request boundary's job, not analysis's.
"""
from .capability import check_capabilities
from .effects import (
    check_effects, check_effect_scope, check_fs_path_safety, check_secret_flow,
    check_injection, check_command_injection, check_pii_flow,
    check_authorization, check_resource_authorization, check_open_redirect,
    check_template_injection, check_deserialization, check_cleartext_transmission,
    check_metadata_fetch, check_hardcoded_secret, check_log_injection,
    check_reflected_xss, check_header_injection, check_xxe,
    check_csv_injection, check_marker_boundary, check_return_laundering,
    check_code_injection,
    check_exhaustiveness, check_unreachable_arms,
    check_dead_code, check_unused_binding, check_ignored_result,
    check_unsatisfiable_refinement,
)
from .modules import check_modules

STAGES = [
    # B.1/B.2 — call-site effects must be a subset of declared effects.
    ("effects", [check_effects]),
    # E0710-E0731 — reach-scope / taint-flow security detectors.
    ("security", [
        check_effect_scope, check_fs_path_safety, check_secret_flow,
        check_injection, check_command_injection, check_pii_flow,
        check_authorization, check_resource_authorization, check_open_redirect,
        check_template_injection, check_deserialization,
        check_cleartext_transmission, check_metadata_fetch,
        check_hardcoded_secret, check_log_injection, check_reflected_xss,
        check_header_injection, check_xxe, check_csv_injection,
        check_marker_boundary, check_return_laundering,
        check_code_injection,
    ]),
    # E0202-E0207 — static semantic checks.
    ("semantic", [
        check_exhaustiveness, check_unreachable_arms, check_dead_code,
        check_unused_binding, check_ignored_result,
        check_unsatisfiable_refinement,
    ]),
    # B.3 — transitive capability composition.
    ("capability", [check_capabilities]),
    # D.3 — module validation.
    ("modules", [check_modules]),
]


def analyze(ast, skip=()):
    """Run every registered detector. Returns [(stage_name, [Diagnostic])]
    in `STAGES` order, one entry per stage (possibly empty), so a caller
    can short-circuit on the first non-empty stage.

    `skip` names stages not to run — the CLI's `--no-scope-check` family.
    A skipped stage is absent from the result, not reported empty."""
    return [(name, [d for fn in fns for d in fn(ast)])
            for name, fns in STAGES if name not in skip]


def analyze_flat(ast, skip=()):
    """`analyze()` flattened to one diagnostic list, stage order preserved."""
    return [d for _stage, diags in analyze(ast, skip) for d in diags]
