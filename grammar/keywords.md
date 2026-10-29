# Aether Keywords (v0.1)

Total: 56 reserved words — the `KEYWORDS` set in
`transpiler/aether/lexer.py`. `tests/test_spec_docs.py` fails if the count
or the keyword tables below disagree with it. A reserved word cannot be
used as an identifier (`let trait = 1` is a parse error, `E0201`) and
cannot take a trailing `?` or `!` (`E0106`).

Every keyword is a fully spelled English-style word. No symbolic operators are reserved beyond the arithmetic, comparison, and assignment set.

<!-- BEGIN keyword-tables (checked by tests/test_spec_docs.py) -->

## Declarations

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `module`    | Begins a module declaration; closes with `end`.                          |
| `import`    | Imports another file (`import ... as name` aliases it).                  |
| `exports`   | Lists the public names a module exposes.                                 |
| `capability`| In `requires capability X` inside a module: a capability the module needs. |
| `function`  | Declares a function; also spells function types, `function(T) returns U`. |
| `type`      | Declares a named type, optionally with refinement clause.                |
| `record`    | Declares a record (named struct of fields).                              |
| `union`     | Declares a tagged union type.                                            |
| `let`       | Introduces an immutable binding.                                         |
| `var`       | Introduces a mutable binding (inside a function body).                   |
| `const`     | Introduces a module-level constant.                                      |

## Function clauses

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `returns`   | Annotates the return type of a function.                                 |
| `requires`  | (contract form) Precondition expression on parameters; (module form) `requires capability X`. |
| `ensures`   | Postcondition expression; may reference `result` and `old(x)`.           |
| `effects`   | Lists the effects this function may perform.                             |
| `do`        | Opens a function or block body.                                          |
| `end`       | Closes a function, block, module, type, or match.                        |

`requires` is overloaded between *capability requires* (module level) and *contract requires* (function clause). The overload is unambiguous because the surrounding context fixes which form is legal.

## Control flow

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `if`        | Conditional. Has both expression form and statement form.                |
| `then`      | Separator after the `if` condition.                                      |
| `else`      | Alternative branch.                                                      |
| `elif`      | Else-if chain.                                                           |
| `match`     | Pattern match expression/statement.                                      |
| `case`      | Pattern arm in a match; a case of a `union`.                             |
| `for`       | Iteration over an iterable.                                              |
| `in`        | Used inside `for`, also membership test inside expressions.              |
| `while`     | Loop while a condition holds.                                            |
| `break`     | Exit the innermost loop.                                                 |
| `continue`  | Skip to the next iteration of the innermost loop.                        |
| `return`    | Return a value from a function.                                          |

## Type / pattern keywords

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `where`     | Refinement clause on a type.                                             |
| `as`        | Pattern alias (`pattern as name`) and `import ... as name`. Not a value cast. |
| `is`        | Runtime tag test (`s is Circle`); see `types.md`.                        |

## Literals and contract identifiers

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `true`      | Boolean literal.                                                         |
| `false`     | Boolean literal.                                                         |
| `null`      | The sole value of `Unit`. Not used for missing values — use `Option`.    |
| `self`      | Used inside a refinement to refer to the candidate value.                |
| `result`    | Used inside `ensures` to refer to the function's return value. Reserved everywhere (SPEC_ISSUES S-015). |
| `old`       | Used inside `ensures`: `old(expr)` is the value of `expr` at function entry. |

## Logical operators (spelled, not symbolic)

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `and`       | Short-circuit conjunction.                                               |
| `or`        | Short-circuit disjunction.                                               |
| `not`       | Logical negation.                                                        |
| `implies`   | Material implication. `a implies b` ≡ `not a or b`.                      |

## Bitwise operators (on `Int`)

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `band`      | Bitwise and.                                                             |
| `bor`       | Bitwise or.                                                              |
| `bxor`      | Bitwise exclusive or.                                                    |
| `shl`       | Shift left (`Int` is arbitrary-precision, so it never overflows).        |
| `shr`       | Shift right.                                                             |

## Effects

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `pure`      | Explicit annotation that a function has no effects.                      |

(`fs.read`, `net.fetch`, etc. are dotted paths, not single keywords. See `effects.md`.)

## Reserved but unused

| Keyword     | Meaning                                                                  |
|-------------|--------------------------------------------------------------------------|
| `async`     | Reserved; no syntax uses it.                                             |
| `await`     | Reserved; no syntax uses it.                                             |
| `yield`     | Reserved; no syntax uses it.                                             |
| `spawn`     | Reserved; no syntax uses it.                                             |
| `with`      | Reserved; no syntax uses it.                                             |
| `defer`     | Reserved; no syntax uses it.                                             |
| `trait`     | Reserved; no syntax uses it. Cannot be an identifier.                    |
| `impl`      | Reserved; no syntax uses it.                                             |

<!-- END keyword-tables -->

`_` is **not** a keyword: it is an identifier the parser reads as the
wildcard pattern inside `match`.

## Naming conventions (not enforced)

- A name ending in `?` is meant to be a predicate returning `Bool`.
- A name ending in `!` is meant to perform an effect or panic on failure.
- Type and constructor names are meant to start with an uppercase letter;
  values and functions with a lowercase one.

The lexer accepts `?` and `!` as identifier-trailing characters, and
nothing checks any of the three conventions (measured: `function
empty?(n: Int) returns Int`, a `pure` function named `go!` and a function
named `Main` all pass `check`).

## Identifiers that *aren't* keywords but are keywords elsewhere

Aether does not reserve `class`, `def`, `struct`, `interface` or `enum`;
they may be used as identifiers. (`trait` *is* reserved — see above.)

## Index of keyword categories used by the parser

The parser identifies a top-level construct by its first keyword:

    module | import | function | type | record | union | const

Inside a function body, a statement begins with one of:

    let | var | if | match | for | while | break | continue | return

or is an assignment (`name = expr`) or an expression statement.
