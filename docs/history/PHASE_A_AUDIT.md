
## Amendment — better-targeted validation tasks (2026-05-03, later same day)

Following the discussion of validation-tasks-as-prompt-section-diagnostics, the
three validation tasks at slots v01, v03, v04 were swapped for tasks that
target specific prompt sections. Each new task has an identifiable
prompt-section it tests; if the model fails the task, you know which section
of `prompt/system_prompt.md` is weak.

| Slot | Old task | New task | Tests prompt section |
|---|---|---|---|
| v01 | `v01_compound_interest` | `v01_tagged_union_evaluator` | "Records and tagged unions" — payload-bearing union construction (qualified `Op.Add()`) and pattern-match destructuring |
| v03 | `v03_recursive_list_length` | `v03_lookup_with_default` | "Stdlib quick reference" — `Map` literal, `get` returning `Option`, `unwrapOrElse` |
| v04 | `v04_replace_words` | `v04_result_threading` | "Common mistakes #3 (`Option` vs `Result`)" — Result chaining via match, parseInt, structured error propagation |

The old tasks are deprecated stubs in their original directory slots
(`v01_compound_interest`, `v03_recursive_list_length`, `v04_replace_words`).
The runner skips entries with `"deprecated": true` in `grader.json`. Final
state: 10 active validation tasks, 5 deprecated stubs visible in the
workspace listing.

### Cross-set similarity, post-amendment

`scripts/ast_similarity.py` reports **0 ref-vs-bench pairs** above 0.70
(unchanged from before). **9 validation-vs-other pairs** above 0.70, all
reviewed at Layer 2:

| New pair | Score | Disposition |
|---|---:|---|
| `val:v03_lookup_with_default` ↔ `ref:06_word_count` | 0.839 | **Different problems and domains.** word_count counts whitespace-separated tokens; lookup_with_default queries a Map. Shared shape is `function with String input + Int output + stdlib helper`. Dismiss. |
| `val:v01_tagged_union_evaluator` ↔ `ref:02_factorial_recursive` | 0.701 | **Different problems.** factorial vs binary-op evaluation via union. Shared shape is `function + match/if + return Int`. Dismiss. |

The other seven flags carry over from the prior amendment with the same
dispositions; see the table earlier in this file.

## Deferred to Phase B prep

`contract_violation_demo` would directly test Aether's experimental wedge
(structured `requires` failure). Adding it requires a harness extension to
grade *exit code + stderr presence* in addition to stdout. About half a day
of harness work. Not done in Phase A; flagged here so it can be picked up
when v0.2 work begins (since v0.2 also strengthens contract enforcement,
this is the right time).

The judge prompt is saved at `audits/llm_judge_prompt.md` for use during
Phase C and during EXPERIMENT.md compilation.
