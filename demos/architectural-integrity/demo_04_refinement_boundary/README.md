# Demo 4 — discount of 120% slips past Python (B.4: refinement boundary)

## What this shows

`type Percentage = Int where self >= 0 and self <= 100`. A pricing
function takes `pct: Percentage` and is composed with a buggy coupon
lookup that returns 120. Aether refuses to call `applyDiscount` with
120 — the structured diagnostic
`[E0302] value bound to 'pct' (= 120) fails refinement Percentage where
((self >= 0) and (self <= 100))` names the type, the binding, the value,
and the predicate. In Python the same code returns a final price of
**-20** and exits 0.

## Why this matters at scale

Refinement types make data-validation a property of the boundary, not
a discipline the caller has to remember. A discount that's allowed to
be > 100% is the canonical "tests passed, prod broke" story: the
arithmetic still composed, the print still ran, the negative price
still serialized, and the failure shows up later as a chargeback or a
refund mishap. Aether's boundary check is checked once where the
refined type appears, and every caller automatically benefits.

## How to reproduce

```sh
# Aether: rejected at run time, exit 1 with structured diagnostic
python3 -B -m transpiler.aether.cli run \
    demos/architectural-integrity/demo_04_refinement_boundary/aether/main.aeth

# Python: runs, prints -20, exit 0 — bug is invisible
python3 demos/architectural-integrity/demo_04_refinement_boundary/python/main.py
```

## Grading

The Aether side is wedge-graded: `expected_exit_code: 2`,
`expected_stderr_pattern: "E0302.*= 120.*Percentage"`. The B.4 polish
ensures the diagnostic carries `type`, `binding`, `predicate`, and
`value_repr` in its `extra` dict, so an agent fix-loop can mechanically
generate the corrective clamp.
