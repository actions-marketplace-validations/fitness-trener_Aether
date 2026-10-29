# Demo 3 — log-only service writes a file (B.3: capability composition)

## What this shows

A `module AuditService` declares `requires capability log`. A refactor
adds `persistAudit`, which honestly declares `effects fs.write` (B.1
forces local honesty about effects). The composition is rejected by
B.3's capability check: `[E0701] function 'persistAudit' directly
performs effect 'fs.write' which requires capability 'fs', but no
module in this program declares it`. The Python equivalent just opens
the file.

## Why this matters at scale

Capability grants are how you reason about a service's blast radius:
"this audit module only needs log; you can deploy it in a sandbox
without filesystem access." When a refactor quietly adds a new effect
that needs a new capability, the deployment manifest, the auditor's
threat model, and the on-call's mental model all silently disagree
with the code. Aether refuses to let the module declaration lie about
what it transitively requires.

## How to reproduce

```sh
# Aether: rejected at check time, exit 1 with structured diagnostic
python3 -B -m transpiler.aether.cli check \
    demos/architectural-integrity/demo_03_module_capability_leak/aether/main.aeth

# Python: runs, prints, writes /tmp/demo03_audit.log, exit 0 — bug is invisible
python3 demos/architectural-integrity/demo_03_module_capability_leak/python/main.py
```

## Grading

The Aether side is wedge-graded: `expected_exit_code: 2`,
`expected_stderr_pattern: "E0701.*fs.write.*capability 'fs'"`. The
diagnostic extra dict carries `required_capability` and
`declared_capabilities` so an agent fix-loop can mechanically generate
the corrective module declaration.
