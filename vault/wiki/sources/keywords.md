---
type: source_note
source_name: keywords
status: ingested
confidence: high
last_updated: 2026-07-03
---

# Source: keywords (grammar/keywords.md, v0.1)

## Profile
`grammar/keywords.md`, v0.1, ~118 lines. Defines the 47 reserved words (locked for v0.1),
grouped: declarations, function clauses, control flow, type/pattern, literals, spelled logical
operators, effects, parked reserved words. Also encodes parser-level naming conventions and the
LL(1) construct-anchoring rule.

## Core Concepts
| Concept | Gist | Where embedded |
|---|---|---|
| Spelled words, no symbolic ops | Every keyword is a full English word so model embeddings recall them; `and/or/not/implies` spelled, not symbolic | [[../clusters/design-rationale\|design-rationale]] |
| `requires` overload | Capability form (module) vs contract form (function); context disambiguates | [[../clusters/capability-model\|capability-model]] |
| `?`/`!` naming law | `?` iff predicate returning Bool; `!` iff non-pure effect or panic-on-failure — syntactic, lexer-enforced | [[../clusters/effect-system\|effect-system]] |
| LL(1) anchoring | Top-level construct identified by first keyword; statement by first keyword | [[../clusters/toolchain\|toolchain]] |
| Parked keywords | `async await yield spawn with defer trait impl` reserved, unused in v0.1 | [[../clusters/design-rationale\|design-rationale]] |

## Accepted / Rejected
- **Superseded 2026-09-24 (audit Wave 6):** the count is 56, pinned to `lexer.KEYWORDS` by `tests/test_spec_docs.py`; the `?`/`!`/uppercase naming rules are documented but not enforced (`grammar/keywords.md`). The v0.1 text below is kept as ingested.
- **Accepted (v0.1):** the 47-word count, the overload rule, the `?`/`!` convention, LL(1) claim.
- **Rejected/deferred:** none — the file is definitional. Parked words tracked as `context_level: parked`.

## Fact-check
Internal spec; no external claims.

## Related
- [[../clusters/effect-system|Cluster: effect system]]
- [[../clusters/design-rationale|Cluster: design rationale]]
- [[../index|Index]]
