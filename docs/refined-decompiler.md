# Refined Decompiler

A second layer of analysis over Ghidra's decompiler. The decompiler shows what the machine code
does; optimized machine code does things the source never said -- a `while` loop becomes a guard
around a `do`/`while`, a `?:` becomes two assignments around a conditional move, a three-line
helper is pasted into each of its callers, `strlen` is a pointer walk. The refinement engine works
that back toward the source and shows the result in its own window, next to the decompiler.

Nothing in the program is changed. The refined code is a view.

- [What it uses](#what-it-uses)
- [The window](#the-window)
- [How far a rewrite can be trusted](#how-far-a-rewrite-can-be-trusted)
- [Passes](#passes)
- [Rewrite rules](#rewrite-rules)
- [Configuration](#configuration)
- [From an agent: `ghidra_refine_function`](#from-an-agent-ghidra_refine_function)
- [Limits](#limits)
- [Code map](#code-map)

## What it uses

| Source | What the engine takes from it |
|--------|-------------------------------|
| Decompiler output | The token markup is parsed into a typed C syntax tree. All rewriting happens on that tree; code the parser does not understand is carried through verbatim. |
| P-code | Every node gets the width and signedness of the p-code operation behind its token, so `/` is the signed or unsigned machine division it really is, and pointer arithmetic scales the way `PTRADD` did. |
| Disassembly | Decides what the C cannot: an `if` is only folded into a select when its instructions contain no conditional jump (a `cmov`, `setcc`, `csel`). Each rewrite keeps the instructions it was derived from. |
| Symbolic execution (Z3) | Proves a rewritten expression equal to the original for all inputs; decides conditions that can only go one way; executes a loop body symbolically to show that its exit test is its entry guard. |
| Emulation | Runs the function's machine code under Ghidra's p-code emulator against the refined C on the same inputs and memory; evaluates calls whose arguments are constants; and, as concrete execution of the tree, tests every rewrite the solver cannot settle and fits library calls to what a loop is observed to do. |

## The window

Enable **RefinedDecompilerPlugin** in *File → Configure* (it is in the DecompFuncUtils package),
then open *Window → Refined Decompiler*, or right-click in the Decompiler and choose
**Refined Decompiler**.

- **Code** (left). Follows the cursor: put it in a function, in the Listing or the Decompiler,
  and that function is refined. Rewritten code is tinted -- green *proved*, blue *tested*, grey
  *structural*, amber *applied without a check* -- and hovering it shows what it replaced, why
  that was allowed, and the instructions behind it. Clicking a line goes to its address.
- **Rewrites** (below). Every change in the order it was made, plus anything a rule proposed and
  the verifier refused. Selecting a row selects the code it produced; double-click goes to the
  address.
- **Configuration** (beside the code when the window is wide, under it when it is docked as a
  narrow column). The pipeline that produced the code. Every control re-runs the
  engine after a short pause: toggle a pass, reorder passes with the arrows, change a parameter,
  switch a rule group, or type a rule of your own, and the code on the left follows. A run in
  progress is cancelled when a newer one is requested.
- **Status line.** Counts by justification, the emulator's verdict, and the time taken. Its
  tooltip lists the engine's notes (rule syntax errors, why a check was skipped).

Toolbar: refine again, show the decompiler's own output for comparison, hide the rewrite list,
hide the configuration, copy. The window's menu exports and imports the configuration as JSON and
resets it. The configuration is saved with the tool.

Presets at the top of the configuration: *Default*; *Proved rewrites only* (drops every pass that
justifies itself by testing rather than proof, and refuses unchecked rewrites); *Everything* (all
rule groups, selects even where a real branch was compiled); *Decompiler output* (no passes: the
engine as a plain second view).

## How far a rewrite can be trusted

Every rewrite carries one of these, and the window and the MCP tool both show it:

| Status | Meaning |
|--------|---------|
| **proven** | Z3 showed the replacement equal to the original for every input (inputs where the original would trap, such as a zero divisor, excluded). |
| **tested** | Original and replacement were run on the same invented inputs and memory -- 32 trials by default -- and agreed on every observable: value, memory written, calls made, variables assigned. Used where the solver cannot decide: loops, memory, calls into the program. |
| **structural** | Follows from the shape of the code alone: a dead assignment, an initializer-test-step loop written as `for`. |
| **assumed** | Applied without a check, because verification is off or neither instrument can model the code (a rule that introduces a function the engine has no meaning for). Refused instead when *Refuse rewrites that could not be checked* is on. |
| **refuted** | A check found an input where they differ. Never applied; listed with the counterexample. |

On top of the per-rewrite checks, the **emulator comparison** runs the whole function both ways:
the machine code under Ghidra's emulator, the refined C under the engine's interpreter, same
arguments, same memory (bytes the image does not define are derived from the address and a
per-trial seed, so both sides see the same "unknown" memory). It compares the returned value and
every byte written outside the stack frame. One side of that comparison is the instructions
themselves, so it does not share the decompiler's assumptions. A function that calls an import, or
that the interpreter cannot model, is reported as *not checked* -- never as agreeing.

Soundness notes worth knowing:

- A byte-copy loop is reported as `memcpy` on the assumption that source and destination do not
  overlap (the loop and a forward `memcpy` agree; `memcpy` proper leaves overlap undefined).
- An assignment is only deleted or folded away when its variable lives in a register, or lives on
  the stack in a function that never takes a stack address. The decompiler routinely shows a
  struct passed by address as unrelated-looking locals, and those stores are not dead.
- In a function with `goto`s, "not read again" is judged over the whole function rather than by
  what follows in the text.

## Passes

Passes run top to bottom and the list repeats (four rounds by default) while passes keep changing
the code, because one pass exposes work for another: a select has to exist before it can be folded
into the shift that makes it a division.

| Id | What it undoes | Justified by |
|----|----------------|--------------|
| `simplify` | Normalizes expressions so patterns line up: constants to the right of comparisons (`-1 < x` → `x >= 0`), `x + -1` → `x - 1`, negations absorbed into comparisons, constant arithmetic folded. | proof |
| `opaque` | Branches that cannot be taken: `if (((~x * x) & 1) == 0)` is always true. | proof |
| `select` | If-conversion. `x = b; if (c) x = a;` back to `x = c ? a : b` where the instructions show a conditional move, then MIN / MAX / abs where the prover confirms one. | test + proof |
| `fold-temps` | A temporary assigned once and read once in the next statement is folded into that read. | test |
| `rules` | Rewrite rules -- built-in groups plus your own. See below. | proof, else test |
| `loops` | Loop rotation: `if (c) { do { ... } while (c2); }` back to `while (c) { ... }` when the solver proves the exit test equals the guard after the body has run; `while (true)` with a break at one end; counted loops as `for`. | proof + test |
| `loop-idioms` | Open-coded `strlen`, `memset`, `memcpy`. The loop is run on sample inputs, a call is fitted to what it did, and loop and call are then compared on fresh runs. | test |
| `stores` | Merged constant stores: `*(undefined8 *)p = 0x31554644` back to `strncpy(p, "DFU1", 12)`; runs of zero stores to `memset`. | test |
| `inline` | Inlined helpers. Small functions of the program are reduced to one expression over their parameters; where that expression occurs, the call is put back. | test |
| `const-calls` | Calls with constant arguments to pure leaf functions are computed by emulating the callee. | emulation |
| `dead-stores` | Assignments nothing reads, left behind by the passes above. | structure |

Each pass has parameters (thresholds, switches); they are listed in the configuration panel and by
`ghidra_refine_function` with `describe: true`.

### An example

`hash3` in the test fixture is `mix(mix(mix(seed, a), b), c)` with `mix` inlined three times. The
decompiler shows:

```c
param_2 = ((param_1 ^ 0x811c9dc5) * 0x1000193 >> 0x13 | (param_1 ^ 0x811c9dc5) * 0x326000) ^ param_2;
param_3 = (param_2 * 0x1000193 >> 0x13 | param_2 * 0x326000) ^ param_3;
return param_3 * 0x1000193 >> 0x13 | param_3 * 0x326000;
```

`rules` recognizes each line as a rotate whose left half had the multiplication folded into it
(proved: `0x326000 == 0x1000193 << 13` mod 2^32). `mix` itself, refined the same way, is
`rotl((p0 ^ p1) * 0x1000193, 13)`, so `inline` finds the first copy; `fold-temps` then merges the
statements, which exposes the second copy, and so on:

```c
return mix(mix(mix(param_1, 0x811c9dc5), param_2), param_3);
```

and the emulator, running the original instructions, returns the same values as this line does.

## Rewrite rules

A rule is one line:

```
name: pattern => replacement where guard
```

```
rotl:      ($x << $a:const) | ($x >> $b:const) => rotl($x, $a)
               where unsigned($x) && $a + $b == bits($x)
sdiv-pow2: (($x < 0) ? $x + $m:const : $x) >> $s:const => $x / eval(1 << $s)
               where signed($x) && $m == mask($s)
```

- `$x` matches any expression, `$c:const` only a constant, `$v:var` only a variable. A name used
  twice must match the same thing both times.
- `(_)e` matches a cast to any type.
- Operands of commutative operators match in either order, and `a < b` also matches `b > a`.
- The guard is an integer expression over the bound constants, with `bits($x)`, `signed($x)`,
  `unsigned($x)`, `is_ptr($x)`, `is_const($x)`, `pure($x)`, `sval($c)` (a constant read as
  signed), `is_pow2(n)`, `log2(n)`, `mask(n)` (= 2^n − 1), and `signed_op()` / `unsigned_op()`
  (whether the matched root is the signed machine operation).
- In a replacement, `eval(expr)` becomes the constant it evaluates to, and `as_signed($x)` /
  `as_unsigned($x)` cast only where the signedness actually changes. Literals take the width of
  the operand they meet.
- `abs`, `MIN`, `MAX`, `rotl`, `rotr`, `bswap` have known meaning and can be proved. Any other
  function name is allowed; such a rewrite is *assumed*.
- A rule continues on following lines that are indented. `#` starts a comment.
  `[group-name off] description` starts a group.

**A rule only proposes.** Each match is tested and, where the solver can, proved before it is
applied, at that site, with the widths found there. A rule that is right for 32-bit operands and
wrong for 64-bit ones is applied to the former and refused, with a counterexample, at the latter.
Writing a wrong rule costs time, not correctness.

Built-in groups (`src/main/resources/decompfuncutils/refine/builtin.rules`):

| Group | Default | Contents |
|-------|---------|----------|
| `bit-idioms` | on | rotates (also with a multiplication folded in), sign extraction, absolute value from shifts or selects |
| `division` | on | signed division by a power of two, `x - (x / d) * d` → `x % d` |
| `range` | on | `(x - lo) < n` unsigned → `lo <= x && x < lo + n`, and the inclusive and outside-range forms |
| `strength` | off | shifts and repeated adds back to multiplications |
| `masks` | off | `x & (2^n - 1)` as `x % 2^n`, unsigned `x >> n` as `x / 2^n` |

## Configuration

One JSON object drives the window, the MCP tool and saved presets:

```json
{
  "passes": [
    { "id": "simplify", "enabled": true, "params": {} },
    { "id": "select", "enabled": true, "params": { "evidence": "branchless", "maxSize": 12 } },
    { "id": "inline", "enabled": false, "params": {} }
  ],
  "maxRounds": 4,
  "verification": "prove",
  "rejectUnverified": false,
  "solverTimeoutMs": 800,
  "trials": 32,
  "ruleGroups": { "strength": true },
  "userRules": "times3: ($x << 1) + $x => $x * 3",
  "validate": true,
  "trace": false,
  "clarifyParens": true,
  "literals": "auto"
}
```

`passes` is in execution order. Passes the object does not mention are appended with their
defaults, so a configuration saved before a pass existed keeps working; unknown ids are dropped.
`verification` is `prove` (test, then Z3), `test`, or `off`. `trace` makes passes say why they
left something alone ("loop at 00101cd5: the final value of uVar1 fits neither strlen of an input
nor input + constant").

## From an agent: `ghidra_refine_function`

The MCP server exposes the engine as `ghidra_refine_function`:

```json
{ "name": "hash3" }
```

returns `refined` (the code), `rewrites` (each with `pass`, `rule`, `status`, `address`, `before`,
`after`, `detail`, `disassembly`), `validation` (`outcome`: `agrees` / `differs` / `not_checked`),
`summary`, and any `messages`. Arguments shape the run:

| Argument | Effect |
|----------|--------|
| `describe: true` | Return the catalog instead: passes with their parameters, rule groups with their rules, the rule syntax, the default configuration. |
| `disable` / `enable` | Pass ids to switch off or on. |
| `only` | Run exactly these passes. |
| `ruleGroups` | `{ "strength": true, "range": false }` |
| `rules` | Rule text, appended to the configuration's own. |
| `verification`, `rejectUnverified`, `validate`, `trace` | As in the configuration. |
| `config` | A whole or partial configuration object; the arguments above apply on top. |
| `includeOriginal: true` | Also return the decompiler's own output. |

## Limits

- **Expression-bodied helpers only.** `inline` recovers a helper whose refined body is a single
  returned expression. A helper with internal control flow that the optimizer then merged with its
  caller's (`clamp` in the fixture) is not recovered.
- **Three library loops.** `loop-idioms` knows `strlen`, `memset` and `memcpy`. Vectorized or
  unrolled loops are not recognized.
- **Integer code.** Floating-point expressions are parsed and printed but not reasoned about;
  rewrites inside them are not attempted, and a function that uses them is not emulator-checked.
- **Structured code.** Loop passes leave functions with `goto`s alone where a jump could enter the
  loop.
- **The emulator comparison needs a self-contained function**: integer and pointer parameters,
  no calls to imports. Calls into the program are followed on both sides.
- **x86 / x86-64 is what has been exercised.** The engine itself is architecture-neutral (it works
  on the decompiler's output and uses the calling convention for emulation), but the tests are an
  x86-64 ELF and Windows x64 binaries.

## Code map

```
src/main/java/decompfuncutils/refine/
  RefineEngine.java     pipeline, helper-pattern cache, catalog
  RefineConfig.java     configuration (JSON)
  RefineResult.java     refined text, rewrite log, validation
  Rewrite.java          one change and its justification
  Validator.java        machine code vs refined code
  ast/                  typed C syntax tree: parser from decompiler tokens, printer, utilities
  sem/                  meaning: CEval (arithmetic), CInterp (interpreter), CSym (Z3),
                        MachineEmu (p-code emulator), Verifier, Builtins, Mem
  rules/                rule text parser and matcher
  pass/                 the eleven passes
  ui/                   plugin, window, code view, configuration panel
src/main/resources/decompfuncutils/refine/builtin.rules
src/main/java/decompfuncutils/mcp/tools/RefineFunctionTool.java
tests/refine/           optimized fixture (source, build script, ELF)
tests/scripts/RefineEngineHeadlessTest.java     engine, tool and window contents (run_refine_test.ps1)
src/main/java/decompfuncutils/refine/ui/RefinedDecompilerPreview.java
                        opens the window in a real tool, off screen, and checks it
                        (run_refine_gui_test.ps1)
```

To add a pass: implement `RefinePass`, register it in `RefinePasses`. It appears in the
configuration panel, in `describe`, and in saved configurations without further work. Report every
change through `PassContext.accept(...)`, which verifies it and records the outcome.
