# Aether Type System (v0.1)

## What is checked, and when — read this first

**Aether has no type checker.** It does resolve names (E0208, below):
every identifier must refer to some binding. Type annotations are parsed,
kept in the AST, printed by `fmt`, and read by the specific passes listed
below; they are never checked against the values that flow into them.
Measured with `aether check` / `aether run` at `99f09cc` and again at
`52f04aa`; the `frobnicate` row re-measured with name resolution in place
(every other `check` below still exits 0):

| Program fragment | `check` | `run` |
|---|---|---|
| `function main() returns Int ... return "not an int"` | exit 0 | exit 0 |
| `let x: Int = "s"` then `return x` | exit 0 | exit 0 |
| `f("str")` where `f(a: Int)` | exit 0 | exit 0 |
| `f(1, 2, 3)` where `f` takes one parameter | exit 0 | Python `TypeError`, exit 1 |
| `frobnicate(1)`, never declared anywhere | E0208, exit 1 | not run (`check` refuses it) |
| `function empty?(n: Int) returns Int` (a `?` name not returning `Bool`) | exit 0 | exit 0 |

What *is* checked, split by when it happens. `aether run` runs every
static pass before it executes, so a program `check` refuses does not run.

**Statically** (at `check`, and before `run`):

- Lexing and parsing — `E01xx`, `E0201`.
- A `match` on a union that omits a case and has no wildcard — `E0202`;
  an unreachable arm — `E0203`; dead code after `return`/`break`/`continue`
  — `E0204`; an unread `let` — `E0205`; a discarded `Result` — `E0206`; a
  refinement whose integer bounds are unsatisfiable — `E0207`.
- Name resolution — `E0208`: a call to, or a read of, a name that is not
  a parameter, a local bound earlier in the same or an enclosing block, a
  top-level declaration (imports included) or a stdlib function. This
  proves a name refers to SOME binding — not that the binding has the
  right type, arity or kind; that is still unchecked (below). Silent on a
  partially parsed program and on one whose imports were not resolved.
- Effects: every call's effects must be declared by the caller — `E0801`
  (see `effects.md`).
- Capabilities: when the file declares a module, every effect's capability
  must be declared by it — `E0701`; module and import validity —
  `E0702`–`E0706`.
- The security family `E0710`–`E0731`, which reads the marker types below
  off signatures.
- Optionally, `--prove` (needs the `z3` extra) tries to prove `ensures`
  clauses and reports a counterexample as `E0901`.

**At runtime only** (runtime guarantees, not static proof):

- Refinement predicates — `E0302` (predicate false) / `E0303` (predicate
  raised) — when a value is bound at a parameter, a return, an annotated
  `let`/`var` and each assignment to it, a `const`, a record constructor
  field, or an element of a `List<Refined>`; a refined alias
  (`type Small = PositiveInt where self < 10`) also checks its base's
  predicate. Not checked: `Map`/`Option`/`Result`/`Set` payloads, a record
  field updated after construction, and an assignment to a name annotated
  in a different function (`audits/audit_2026-09-24_plan.md`, A6).
- `requires` / `ensures` contracts — `E0301` / `E0304`; stdlib
  preconditions — `E0305`.
- Declared effects, only under `--effect-strict` — `E0501` / `E0502`.

**Not checked at all:** expression types, return types, argument types,
arity, whether a called name is a function (a `let` or `const` holding an
`Int` passes E0208 when called), consistent use of generic parameters
(SPEC_ISSUES S-007), and the `?`/`!` naming conventions (`keywords.md`).

## Primitive types

    Int        // arbitrary-precision signed integer
    Float      // 64-bit IEEE-754
    Bool       // true | false
    String     // immutable UTF-8 string
    Bytes      // immutable byte sequence
    Unit       // the trivial type; its sole value is written `null`

`Int` is arbitrary-precision: arithmetic never overflows or wraps. This is
specified, not an accident of the Python runtime — contract reasoning
(`ensures`, SMT proving) assumes mathematical integers. Code that needs
fixed-width wrapping semantics must mask explicitly, e.g.
`x band 18446744073709551615` for u64.

## Parameterised types

    List<T>          // ordered sequence
    Map<K, V>        // key-value map
    Set<T>           // unordered set
    Option<T>        // Some(T) | None
    Result<T, E>     // Ok(T) | Err(E)

These are the *only* built-in collection and sum-type families. There is no `Array`, `Tuple` (records cover that), `Either`, or `Maybe`.

## Records

    record Point do
      x: Float
      y: Float
    end

In v0.1, construct records positionally — the record decl emits a
constructor with parameters in declared order:

    let p1 = Point(0.0, 0.0)
    let p2 = Point(p1.x + 1.0, p1.y)        // works in v0.1

A planned brace-init form is **not in v0.1** (see SPEC_ISSUES S-006):

    let p2 = Point { x = p.x + 1.0, y = p.y }   // ❌ parse error E0201

## Tagged unions

    union Shape do
      case Circle(radius: Float)
      case Rectangle(width: Float, height: Float)
      case Triangle(base: Float, height: Float)
    end

Constructors are accessed as `Shape.Circle(2.0)`. A `match` on a union
must handle every case or end with a wildcard arm: the static
exhaustiveness pass refuses a missing case with `E0202`.

## Refinement types

    type NonEmpty = String where length(self) > 0
    type PositiveInt = Int where self > 0
    type Probability = Float where self >= 0.0 and self <= 1.0

Inside the refinement clause, `self` is the candidate value. The predicate
is checked **at runtime** (`E0302`) at each binding site listed above:
parameters, returns, annotated `let`/`var` and their assignments, consts,
record constructor fields and `List<Refined>` elements; the same list
names the positions that are not checked. Between those sites the
refinement is assumed, not re-proved.

The one static check on a refinement is `E0207`: an integer interval that
no value satisfies (`Int where self >= 10 and self <= 5`). `--prove`
treats parameter refinements as assumptions when it tries an `ensures`
clause; it does not prove refinements themselves.

## Marker types

    Secret<T>   PII<T>   Untrusted<T>   Authorized<T>

Erased at runtime — a `Secret<String>` is its string. They exist for the
static security passes: a marker-typed value reaching a sink without its
sanctioned function (`reveal`, `redact`, `sanitizeLog`, `htmlEscape`, …)
is refused (`E0712`, `E0715`, `E0724`–`E0726`, `E0728`), a marker erased
at a call or a return is refused (`E0729`, `E0730`), and the `sqlExec` /
`sqlByOwner` sinks demand an `Authorized<…>` proof (`E0716`, `E0717`).
These passes are syntactic and intraprocedural: over-flag, never miss
within the modeled surface. The functions are listed in `stdlib.md`.

Phantom capability tags such as `FileHandle<Read>` or
`Connection<Postgres>` are **not implemented**: no such type exists in the
standard library and nothing checks one.

## Type ascription

    let x: Int = parseInt("42")     // parsed and kept; NOT checked (see the table above)
    let y = (3.14 as Float)         // ❌ NOT IN v0.1 — parse error E0201 (SPEC_ISSUES S-013)

`as` is accepted only as a pattern alias and in `import ... as`.

## Type tests

    if s is Circle then ... end

`is` is a runtime test that returns `Bool`. For `Int`, `Float`, `String`
and `Bool` it tests the runtime value's Python type; for any other name it
compares a union value's case tag (`s is Circle`). It is not a refinement
test — with `type Pos = Int where self > 0`, `5 is Pos` is `false`
(measured) — and it narrows nothing, because there are no static types to
narrow.

## Generic functions

    function map<T, U>(xs: List<T>, f: function(T) returns U) returns List<U>
      effects pure
      ensures result.length == xs.length
    do
      ...
    end

Type parameters are written in angle brackets after the function name.
They may appear in parameters, return type, contracts, and effect rows.
They are parsed and emitted unchanged; nothing checks that they are used
consistently (SPEC_ISSUES S-007).

## Subtyping

There is no subtyping. Passing a base value where a refinement type is
declared is allowed; the predicate is asserted at runtime where the value
is bound, e.g. on entry to the callee (see *Refinement types*).

## Inference

There is none. A `let` without an annotation has no static type, and one
with an annotation is not checked. Function parameters and return types
are always written.

## Equality and hashability

Equality is the runtime's equality on the emitted Python values; there is
no static comparability check. Hashability is Python's: a `List` or `Map`
used as a `Map` key or `Set` element raises Python's `TypeError` at runtime
(measured: `set(m, [1, 2], 3)` with `m: Map<List<Int>, Int>` passes
`check`, and `run` fails with `unhashable type: 'list'`).

## Not in v0.1

No syntax exists for these (a parse error, `E0201`):

- Trait/typeclass abstraction (`trait` and `impl` are reserved words).
- Variadic arguments.
- Default argument values.

Excluded by design but **not refused** — nothing checks for them, so they
reach the runtime (measured):

- Higher-kinded types: a parameter typed `F<_>` passes `check`; type
  names are not resolved.
- Implicit numeric coercion: `let a = 1 + 2.5` passes `check` and
  evaluates to `3.5`.
- Method-call syntax: `xs.length()` passes `check` and fails at runtime
  with a Python `TypeError`. Write `length(xs)`; field access `x.field` is
  the only `.` form that works.
- Subtyping: there is none to check (see *Subtyping*).
