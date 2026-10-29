# Demo 5 — payment workflow with four broken promises (composition)

## What this shows

One realistic-shaped payment workflow that breaks all four architectural
promises Aether checks:

1. **Refinement** — `apply_discount(100, 120)` violates `Percentage`'s
   `self >= 0 and self <= 100` predicate.
2. **Capability** — module declared `requires capability log`, but
   reachable code performs `net.fetch`.
3. **Effect-glob** — `chargeGateway` declares
   `net.fetch("https://api.x/charge/*")`, but its body routes through
   `refundOverride` which hits `https://api.x/admin/refund`.
4. **Effect-locality** — `buildPayload` declares `effects pure`, but a
   stray debug `print(...)` snuck in during refactor.

Aether refuses to compile. In the current run order, the effects pass
fires first and surfaces (3) and (4) together as two `E0801`s with
exit 1. Removing those static failures lets the refinement-boundary
check (1) fire at runtime with `E0302`. The Python equivalent runs end
to end, exits 0, and silently produces a negative price plus an
admin-path HTTP call.

## Why this matters at scale

Real systems break by *composition*, not by any single bug. Aether's
claim is not "fewer bugs than Python" — it is **"the compiler refuses
the architectural lies that Python lets ship"**. Demo 5 is the smallest
worked example of that claim.

## How to reproduce

```sh
# Aether: rejected at check time with TWO structured E0801s, exit 1
python3 -B -m transpiler.aether.cli check \
    demos/architectural-integrity/demo_05_composition/aether/main.aeth

# Python: runs end-to-end, prints debug + HTTP GET admin URL + "done", exit 0
python3 demos/architectural-integrity/demo_05_composition/python/main.py
```

## Grading

Wedge-graded: `expected_exit_code: 2`, `expected_stderr_pattern:
"E0801"`. A regression against this demo guarantees the composition of
B.1 + B.2 stays decisive — neither check is suppressed by the other.
