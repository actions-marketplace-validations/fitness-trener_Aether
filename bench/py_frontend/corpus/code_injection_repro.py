# Real-world shape — code injection (CWE-94/95): an interpreter fed
# attacker-authored source.
#
# The agent-framework "run Python" tool: the code the model wrote goes
# straight to exec()/eval()/compile(). A prompt injection in a page the
# agent read decides what the model emits, and the interpreter runs it
# with the process's full privileges. bench/framework_scan/_work/src has
# five such exec() sites (smolagents/tools.py:575, agno/tools/python.py:159,
# browser_use/mcp/cli_mcp.py:105+128, crewai/flow/runtime/_actions.py:309)
# and nine compile() sites.
#
# The vulnerable shapes:

import ast


def run_tool(tool_code):
    ns = {}
    exec(tool_code, ns)
    return ns


def run_tool_eval(expr):
    return eval(expr)


def run_tool_compile(src):
    return compile(src, "<agent>", "exec")


def run_tool_concat(snippet):
    exec("import os\n" + snippet)


def run_tool_exec_of_compile(src):
    # Reported ONCE, at compile(): that is where the source text enters.
    exec(compile(src, "<s>", "exec"), {})


# The fixes. There is no sanitizer for attacker-authored code: the source
# must be a fixed literal, or the value must never reach an interpreter.

def run_tool_safe():
    exec("print('hello')")


def run_tool_eval_safe():
    return eval("1 + 1")


def run_tool_literal_eval_safe(expr):
    # ast.literal_eval evaluates LITERALS only - no names, no calls. It is
    # the documented replacement for eval() on data, and is not a sink.
    return ast.literal_eval(expr)


def run_tool_exec_of_compile_safe():
    exec(compile("print(1)", "<s>", "exec"), {})


# (A module-level `def exec(...)` shadows the builtin for the WHOLE module,
# so that case lives in tests/test_py_frontend_sinks.py, not beside the
# vulnerable shapes above.)

# In Aether this maps 1:1 onto E0731:
#   exec(tool_code)                <-> evalCode(toolCode)              -> E0731
#   exec("print('hello')")         <-> evalCode("print('hello')")      -> clean
#   (Aether's other sanctioned exit is trusted(bundledScript) - an explicit,
#    auditable assertion that the source shipped with the application.)
