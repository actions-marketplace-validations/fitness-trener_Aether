"""How sure the ANALYSIS is that a call is the sink it says — the
per-finding axis.

`risk.py` rates the CLASS a code names: "if this is real, how bad?".
This module rates one FINDING's evidence: "how sure am I that this call
site is the sink the rule matched?". The two are orthogonal on purpose
(`vault/wiki/questions/q6-risk-vs-severity-two-axes.md`), and neither is
`Diagnostic.severity`, which is the gate.

What this is NOT:

  * not severity — it never decides whether a run fails;
  * not risk — a `compile()` finding is `critical` risk at 0.6
    confidence, and that is not a contradiction;
  * not a probability of exploitability. It says nothing about whether
    the tainted value is reachable from a request handler, only about
    whether the callee is what the rule thinks it is.

The evidence is what the Python frontend already computes. `_sink_name`
identifies a sink in several ways and they are not equally certain. Only
the ORDER of the two floor kinds below is measured
(`bench/framework_scan/REPORT.md` §8 priced `method` and
`builtin_compile` on 4,946 files); the 0.95/0.9 split above the floor is
reasoning about how much of the callee the frontend actually resolved,
not a measured false-positive rate. None of these numbers is a
probability:

  * `qualified` / `guard` — the callee resolved through the file's
    imports to a known dotted path. The name is not a guess.
  * `builtin` — a bare builtin (`exec`, `eval`, `open`), with the
    module's own shadowing rebindings already excluded by `_sink_name`.
  * `argv` — a literal `["bash", "-c", cmd]` argv. The program and the
    flag are constants in the source.
  * `builtin_compile` — `compile()` produces a code object and executes
    nothing. Section 8 read all 8 corpus E0731 sites: 4 call `compile()`
    without running the result — three syntax-checking linters and a
    round-trip test. `exec(compile(src))` is reported once and rated
    `builtin`: that source IS executed.
  * `method` — matched on the METHOD NAME with the receiver's type
    unresolved. This is q5's sanctioned over-flag, and section 8 priced
    it: of 24 new `from_string` hits about 8 are non-jinja
    `.from_string` methods (momento `CredentialProvider`, llama-cpp
    `LlamaGrammar`, bigquery, networkx), and 4 of the new `fetch_all`
    hits are langchain-community HTTP loaders, not databases.

An ABSENT match means an Aether-source finding: the sink is spelled in
the `.aeth` source, nothing was guessed, so it is 1.0. An UNKNOWN
non-empty match is the least-confident value, never the most — a new
frontend match kind must not be able to claim certainty by being new.

Like `risk.py`, this table is read at OUTPUT time. It changes no
detector's decision and no finding's existence: the same findings fire,
in a different order. `tests/test_confidence.py` is what keeps the
vocabulary honest against the frontend.
"""

from __future__ import annotations

# The least-confident rating in the table. An unrecognised match kind
# degrades to it (see `confidence_of`).
FLOOR = 0.6

CONFIDENCE = {
    # Resolved through the file's imports to a known dotted path. Not
    # 1.0: the resolution is still syntactic, and a module rebound at
    # runtime would not be seen.
    "qualified": 0.95,
    "guard": 0.95,
    # A bare builtin name, with local `def`/binding shadows excluded.
    "builtin": 0.9,
    # Literal program and literal flag in the argv list.
    "argv": 0.9,
    # `compile()` builds a code object; whether it is ever executed is
    # outside the call. 4 of 8 measured sites never run it (three
    # linters, one round-trip test); `exec(compile(...))` rates `builtin`.
    "builtin_compile": FLOOR,
    # Method name only, receiver type unresolved (q5's over-flag).
    "method": FLOOR,
}

# An Aether-source finding: no match kind, because nothing was matched
# by guesswork — the sink is spelled in the source.
AETHER_SOURCE = 1.0


def confidence_of(match) -> float:
    """Confidence in [0,1] for a frontend match kind.

    `None`/empty means an Aether-source finding (1.0). Any other
    unrecognised value degrades to `FLOOR`, not to 1.0: the table may
    briefly lag a new frontend match kind, and the lag must cost
    precision, never claim certainty. `tests/test_confidence.py` is what
    makes the lag impossible to ship.
    """
    if not match:
        return AETHER_SOURCE
    return CONFIDENCE.get(match, FLOOR)
