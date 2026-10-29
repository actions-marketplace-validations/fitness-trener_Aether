# Demo 2 — users-only gateway hits an admin URL (B.2: effect-glob matching)

## What this shows

A function declared `net.fetch("https://api.x/users/*")` calls a helper
declared `net.fetch("https://api.x/admin/token")`. Aether's effect-glob
check refuses to compile this: `[E0801] function 'userGateway' (effects
'net.fetch('https://api.x/users/*')') calls 'fetchAdminToken' which has
effect 'net.fetch('https://api.x/admin/token')' not covered by the
caller`. In Python the equivalent code runs and emits the admin URL,
with no warning.

## Why this matters at scale

URL discipline is one of the most common architectural promises a
service makes: "this adapter reaches only the users API; SSRF auditors
trust it." A refactor that wires the same adapter into an admin path
breaks that promise without breaking any type signature or unit test.
The architectural error compiles, ships, and only fails after a security
review (or an incident) catches it. Aether refuses to compile the
composition that would let that happen.

## How to reproduce

```sh
# Aether: rejected at check time, exit 1 with structured diagnostic
python3 -B -m transpiler.aether.cli check \
    demos/architectural-integrity/demo_02_net_glob_mismatch/aether/main.aeth

# Python: runs, prints both URLs, exit 0 — bug is invisible
python3 demos/architectural-integrity/demo_02_net_glob_mismatch/python/main.py
```

## Grading

The Aether side is wedge-graded: `expected_exit_code: 2`,
`expected_stderr_pattern: "E0801.*userGateway.*admin"`. The diagnostic
extra dict names both effects so an agent fix-loop knows the caller's
glob and the offending callee call.
