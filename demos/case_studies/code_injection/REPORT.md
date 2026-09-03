# Case study — Code injection: an interpreter fed attacker-authored source (CWE-94/95)

**Iteration 49 of the self-teaching loop.** Class: code injection — the
agent-framework incident shape, where the Python an LLM wrote (or any
caller-supplied string) is handed to `exec()` / `eval()` / `compile()`
and runs with the process's full privileges. This is THE hazard of the
population the Python scanner targets: every "run code" tool in an agent
framework is this shape by construction
(`bench/framework_scan/_work/src`: smolagents `tools.py:575`
`exec(tool_code, module.__dict__)`, agno `tools/python.py:159`, browser-use
`mcp/cli_mcp.py:105,128`, crewai `flow/runtime/_actions.py:309`).

## The gap (confirmed empirically first)

Before this iteration `exec(model_output)` on Python produced **no
finding**: the call was a `dynamic_construct` UNPROVABLE note (a
capability remark, visible only under `--strict`), never a diagnostic —
`check-py` exit 0 on the `exec_llm.py` probe. On the Aether side there
was no sink to name the class at all.

## The rule (E0731)

`evalCode`'s argument (the source) must be a fixed string literal, or a
name bound only to literals. A source built by concatenation, taken from
a parameter, or produced by any other call is refused.

There is **no sanitizer** for this class — unlike E0713 (`sqlBind`) or
E0714 (`shellArg`), there is no way to escape attacker-authored code
into something safe to run. The sanctioned form is the fixed literal;
`trusted(...)` is the explicit, auditable escape hatch for a source the
program vouches for (a script bundled with the application) — exactly
E0719's contract. On Python the row is `exec` / `eval` / `compile` →
`evalCode`; `ast.literal_eval` is deliberately NOT a sink (it evaluates
literals only), and a local `def exec(...)` shadow is not the builtin.

## Before → after

| Form | `aether check` |
|---|---|
| `evalCode(toolCode)` (vulnerable.aeth) | **E0731, exit 2** |
| `evalCode("print('hello')")` / `evalCode(trusted(bundledScript))` (fixed.aeth) | OK, exit 0 |

`aether run fixed.aeth` prints a marker: the reference runtime never
executes the source; it models the sink so the static refusal is the
product.

## Design note — E0719's shape, one more row

E0731 is a `LiteralOrWrapperSpec` row using `_TEMPLATE_RULE` verbatim
(`transpiler/aether/passes/detector_specs.py`): literal-only, `trusted()`
the sole wrapper. Zero new machinery; the whole slice is one table row,
one runtime stub, one frontend mapping, docs, tests and this corpus.

## Residual limit (stated honestly)

The rule judges the SHAPE of the source argument at the call site.
`exec(compile(src, "<s>", "exec"))` is reported once, at the `compile`
where the source text enters (the outer `exec` of a code object is not
a second finding). A source read from disk or the network
(`readFile(...)` → `evalCode`) is refused as non-literal — correct for
model output written to a temp file, but it also refuses a trusted
on-disk script, which is what `trusted(...)` exists for. On Python, a
name bound to a literal in ANOTHER function, or `getattr(builtins,
"exec")`, stays outside the modeled surface (reflection remains an
UNPROVABLE note only).
