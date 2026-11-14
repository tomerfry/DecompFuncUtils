# Headless tests

End-to-end regression tests run inside Ghidra via `analyzeHeadless` against a
small purpose-built binary: the taint-query engine and p-code emulator, plus the
MCP server's two HTTP transports.

## Files

| File | Purpose |
|------|---------|
| `test_vuln.c` | Source of the test cases (UAF, double-free, tainted sinks, builder-buffer injection, allocation and length bugs, arithmetic, external call), each unsafe case paired with safe lookalikes. |
| `test_vuln.o` | Committed x86-64 Linux ELF object compiled from `test_vuln.c`. This is what the test imports. |
| `scripts/TaintHeadlessTest.java` | GhidraScript post-script: runs taint queries + emulation and prints `CHECK <name>: PASS/FAIL`. |
| `scripts/McpTransportHeadlessTest.java` | Starts the MCP server in-process and runs a full client handshake over both transports. |
| `scripts/McpSessionManagerHeadlessTest.java` | Drives the session manager's router with fake tool windows: binding, isolation between sessions, open/attach/release/close, closed windows, idle claims. |
| `scripts/McpSaveHeadlessTest.java` | Checks the dialog-free program save: a never-saved import is added to the project, becomes writable, and later edits survive a reopen. |
| `scripts/SymbolicHeadlessTest.java` | Exercises Z3 path constraints, symbolic memory, bounds, and concrete replay using deterministic x64 instruction fixtures. |
| `scripts/RefinementHeadlessTest.java` | Exercises non-returning functions and atomic stack-local replacement through JSON-RPC on an isolated Ghidra database. |
| `scripts/DataflowHeadlessTest.java` | Exercises the data-flow slicer behind the Decompiler hover from real decompiler tokens, its tooltip HTML, and the `ghidra_get_dataflow` MCP tool. |
| `extlink/libtestdep.c`, `extlink/testmain.c` | Source of the cross-module link fixtures: an exported shared object and an executable that imports from it. Rebuild with `extlink/build.ps1` (needs clang + lld). |
| `extlink/libtestdep.so.1`, `extlink/testmain` | Committed ELF pair. `testmain` carries `DT_NEEDED [libtestdep.so.1]` plus `UND` dynsym entries; the library defines and exports them. |
| `scripts/ResolveExternalsHeadlessTest.java` | Exercises `ghidra_resolve_externals`: puts every import back into `<EXTERNAL>`, clears the library association, then checks the tool re-attributes both and stores the exporting address. Independent of whether this Ghidra's own External Symbol Resolver works. |
| `scripts/BacklinkImportsHeadlessTest.java` | Exercises `ghidra_backlink_imports`: clickable `{@program ...}` back-links and bookmarks written into the library, block replacement on re-run, coexistence with another importer's block, and removal. |
| `scripts/CrossModuleAnalyzerHeadlessTest.java` | Exercises the `Cross-Module Import Linker` analyzer: that auto-analysis alone leaves the library back-linked, the one-shot path used by Analysis > One Shot, idempotence, and each analysis option. |
| `angr/angr_demo.c`, `angr/libangrdemo.so` | Source and committed ELF of the `ghidra_angr_emulate` fixture: small functions with one obvious behaviour each (stack arguments, out-parameters, structs, globals, libc calls, an import nothing models, a loop). Rebuild with `angr/build.ps1` (needs clang + lld). |
| `scripts/AngrEmulateHeadlessTest.java` | Exercises `ghidra_angr_emulate` by calling the fixture's functions by name: argument forms, results, the call trace, faults on missing pointers, stubs, solving for inputs, limits, error messages, and a Ghidra signature changing placement and typing. |
| `run_angr_test.ps1` | Build -> install -> run for the angr test. Needs a Python with angr (`tools/setup-angr.ps1`). |
| `refine/refine_demo.c`, `refine/librefinedemo.so` | Source and committed ELF of the refinement-engine fixture: an **optimized** (`-O2`) build in which every function has one obvious source-level meaning the optimizer obscured (division by a constant, rotated loops, conditional moves, open-coded `strlen` / `memset` / `memcpy`, merged stores, inlined helpers, an opaque predicate, a constant-argument call). Rebuild with `refine/build.ps1` (needs clang + lld). |
| `scripts/RefineEngineHeadlessTest.java` | Exercises the refinement engine: the syntax tree against the decompiler's output, what each pass recovers, how each rewrite is justified, configuration and rule changes, the emulator comparison, the `ghidra_refine_function` tool, and the contents of the Refined Decompiler window. |
| `run_refine_test.ps1` | Build -> install -> run for the refinement test. `-Script` / `-Binary` / `-ScriptArgs` / `-ShowAll` also make it the runner for the diagnostic scripts below. |
| `run_refine_gui_test.ps1` | Opens the Refined Decompiler in a real (off-screen) Ghidra tool window on the fixture, drives it, and saves pictures. See *In a real window* below. |
| `scripts/RefineShow.java` | Diagnostic helper: refined code and rewrite log for every function of a binary (`REFINE_DUMP_OUT` = file to write, `REFINE_TRACE=1`, `REFINE_SIGS` = prototypes to apply first). |
| `scripts/RefineDump.java` | Diagnostic helper: checks that the syntax tree reprints the decompiler's output for every function of a binary, and lists statements the parser kept as raw text. |
| `scripts/RefineSnapshot.java` | Diagnostic helper: renders the Refined Decompiler window's contents for one function to a PNG, off screen (`REFINE_SNAPSHOT_OUT`). |
| `scripts/DebugDecomp.java` | Diagnostic helper: dumps decompiled C and the matcher log for a few functions. |
| `run_headless_test.ps1` | Build → install → run → report. Exits 0 on PASS, 1 on FAIL. |
| `build_binary.ps1` | Recompile `test_vuln.o` (only needed if you edit `test_vuln.c`; requires clang). |

## Running

```powershell
# GHIDRA_INSTALL_DIR must point at a Ghidra install (defaults to C:\Users\User\Ghidra)
pwsh tests/run_headless_test.ps1
# or skip the gradle build if the extension is already freshly installed:
pwsh tests/run_headless_test.ps1 -SkipBuild
# MCP transport handshake test instead of the taint/emulator one:
pwsh tests/run_headless_test.ps1 -Script McpTransportHeadlessTest.java
# Session manager routing (one fixed port, a window per session):
pwsh tests/run_headless_test.ps1 -Script McpSessionManagerHeadlessTest.java
# Symbolic exploration and bundled native Z3 loading:
pwsh tests/run_headless_test.ps1 -Script SymbolicHeadlessTest.java
# Function metadata and stack-local refinement:
pwsh tests/run_headless_test.ps1 -Script RefinementHeadlessTest.java
# Data-flow hover analysis and ghidra_get_dataflow:
pwsh tests/run_headless_test.ps1 -Script DataflowHeadlessTest.java
```

To check a *running* Ghidra's MCP server rather than a headless one, use
`tools/mcp-handshake-probe.ps1` (see the MCP section of the top-level README).

## What is covered

- **Data flow** (`DataflowHeadlessTest`): seeds taken from decompiler tokens the
  way the hover takes them (variable read, assignment target, declaration, call
  name, operator) and the tokens it must leave to other hovers (constants, types,
  the function's own name); `getenv()` results reaching `printf`/`memcpy`
  arguments, parameters reaching the return value and a branch condition,
  constants, memory reads, `&buf`, calls that may modify a value; depth and
  size caps; a sweep over every token of every function; tooltip HTML; and the
  MCP tool returning the same lists. The hover's Swing wiring (service
  registration, popup priority, the options checkbox) needs the GUI and is not
  covered.

- **Refinement** (`RefinementHeadlessTest`): setting/clearing non-returning flags,
  changed caller decompilation, external/thunk targets, ambiguous names, stack
  replacement previews, partial overlaps, arrays/structs/pointers, protected
  parameters and compound storage, invalid batches, and rollback after edits.
- **Symbolic exploration** (`SymbolicHeadlessTest`): witnesses satisfying multiple
  branches, contradictory constraints, avoided addresses, symbolic memory,
  exported emulator arguments, state/step/operation/loop limits, unsupported
  calls and pointers, input validation, and bit-vector arithmetic boundaries.
- **Branch witnesses**: exhaustive 8-bit input enumeration checks signed and
  unsigned comparisons, boundaries, masks, and Boolean negation for both
  witness validity and local feasibility.
- **Emulation limits**: final PC accuracy, breakpoints reached on the final
  allowed step, and invalid step limits/register names.
- **Structural multi-element matching** (exercises the statement-index optimization):
  use-after-free (`free($p); ...; *$p`) and double-free.
- **Taint constraint** `tainted($v)`: a tainted length into `memcpy` and a tainted
  `printf` format string both match; a constant-length `memcpy` does not.
- **Source-specific taint** `tainted($v, "source")`: `tainted($fmt, "getenv")` matches
  while `tainted($fmt, "read")` does not — confirms the source name actually filters.
- **Query engine regressions** (`testEngineRegressions`): three-element ordering
  with the third statement placed before the second, control-flow order for
  elements without a gap, nested calls in patterns and in the source, calls and
  assignments that only appear inside a condition, dereference without a gap,
  `...` in a right-hand-side call, stores, literal / wildcard operands and
  `<<`, `&`, `|` in argument patterns, conditions as pattern elements, statement
  distances, the single-statement wildcard, `guard:` clauses, gap negatives that
  compare call arguments, NULL checks found independently of statement
  boundaries, parameters as sources (`tainted`) versus real input
  (`tainted_ext`), buffer contents judged at the sink in program order, long
  computations that used to decay below the taint threshold, loops (a correct
  list-freeing loop versus a use in a later iteration), reported sink
  locations, and parse errors for unsupported syntax.
- **Vulnerability presets**: every preset in `positives` has safe lookalikes in
  `negatives` that must not match — command / format injection through builder
  buffers (constant input, write after the sink, a different buffer, an
  overwritten buffer), allocation-size overflow (division check, range check,
  `strlen`-derived sizes), allocation versus copy length (same size, derived
  size, compared sizes, same field read twice, `strlen` called twice),
  unchecked allocations (checked early, checked in a nested block), signed
  lengths (lower bound checked, unsigned, string length), `realloc`, TOCTOU
  (different path, reversed order), unchecked `read` results, constant stack
  overflows, and the exec / Windows process sinks.
- **Emulation**: a pure-arithmetic function returns the correct value; `skipCalls`
  steps over an external `printf` and still returns the right value, whereas without
  `skipCalls` the same run stops with `error` at the external call.
- **MCP transports** (`McpTransportHeadlessTest`), on a real loaded program:
  - *Streamable HTTP* (`/mcp`): `initialize` returns 200 with an `Mcp-Session-Id`,
    the `initialized` notification returns 202, `tools/list` and `tools/call`
    succeed, `GET` is refused with 405, an unknown session gets 404, and `DELETE`
    tears the session down.
  - *Legacy HTTP+SSE* (`/sse` + `/message`): the stream opens, the `endpoint`
    event advertises a fresh `sessionId`, and `initialize`/`tools/list` responses
    arrive as `event: message` frames.
  - JSON-RPC id fidelity: an integer id comes back as `1`, never `1.0`, which
    strict clients reject.

## How it works (and why the project lives in TEMP)

Ghidra loads the plugin as an **installed extension module**. The runner installs the
freshly built zip into an isolated settings tree under `$env:TEMP` (via
`XDG_CONFIG_HOME`) and refuses to run if a copy exists under `<install>/Ghidra/Extensions` — two
directories declaring the same module name make Ghidra abort with *"Multiple modules
collided: DecompFuncUtils"*. The isolated tree also means tests run fine while a GUI
Ghidra is open: installing into `%APPDATA%\ghidra` would fail because the running
JVM holds `DecompFuncUtils.jar` open. A running Ghidra — and its live MCP server —
is left untouched. For the same collision reason the throwaway Ghidra project is
created under `$env:TEMP`, never inside the repo (the repo itself is a module
directory and would be double-counted).

Accuracy regressions pair unsafe cases with safe lookalikes: environment-derived
numeric copy lengths versus fixed copies, tainted formats versus literal formats
with tainted data arguments, fortified printf argument positions, real wrapper
returns versus unrelated returns, and direct input-buffer sources versus later
reads or different buffers. Lifetime tests cover repeated harmless calls,
mutually exclusive frees, reallocation, and `free(NULL)`. The fixture uses
`-fno-builtin` so Clang preserves the API calls under test.

The buffer model follows modeled library calls (`read`/`recv`/`fgets`,
`strcpy`/`strcat`/`sprintf`/`memcpy`, …) on direct pointer arguments, in program
order. Byte-wise writes, writes made by callees, struct fields reached through
a stored-and-reloaded pointer, and C++ patterns (`find_no_npos_check`) remain
outside this regression coverage. A query that throws is counted
(`queries_ran_without_errors`), so an "excludes" check cannot pass because the
query failed.

`test_vuln.c` fixtures are parameter-free unsafe/safe pairs; add new ones at the
end and rebuild with `build_binary.ps1` (clang, `-O0 -fno-builtin`). Functions
used by the emulator and symbolic tests (`add3`, `with_call`, …) must keep their
code.

Additional regressions cover 64-node reachability chains in both engines, MCP query presets, one-function pagination without omissions or duplicates, coverage metadata, and invalid query arguments. Test runs use unique temporary settings and project directories; the runner stops immediately on a failed build.

## Cross-module link tests

`run_resolve_externals_test.ps1` drives both external-symbol tests over the
`extlink/` pair:

```powershell
.\tests\run_resolve_externals_test.ps1
.\tests\run_resolve_externals_test.ps1 -Script BacklinkImportsHeadlessTest.java -Analyze
```

Three things it has to get right, each of which produced a confusing failure:

- **`-Analyze`.** Off by default, because external symbols and exported entry
  points both come from the ELF loader, so the linking test needs no analysis
  and finishes in seconds. The back-link test *does* need it: call sites only
  exist once the callers have been disassembled, and without it the tool
  correctly reports `noCallSitesInImporter`.
- **The settings path.** The isolated tree under `XDG_CONFIG_HOME` must match
  what Ghidra computes, or the extension is never found and every script
  importing it fails with
  `missing requirement osgi.wiring.package=decompfuncutils...`. Layout version 3
  (Ghidra 12.3+) prefixes the parent directory with the user name --
  `User-ghidra`, not `ghidra` -- so the runner reads the version, release name
  and layout version from the install instead of hardcoding them.
- **`-WorkRoot`.** The settings tree and project go here, `TEMP` by default.
  Point it at a drive with room when the system drive is tight. Both runners now
  delete their scratch afterwards; before that, every run left an extracted copy
  of the extension behind.

The analyzer has its own script over the same pair. It needs `-Analyze`, since
what it checks is what auto-analysis leaves behind:

```powershell
.\tests\run_resolve_externals_test.ps1 -Script CrossModuleAnalyzerHeadlessTest.java -Analyze
```

## Refinement engine test

```powershell
.\tests\run_refine_test.ps1
```

Imports `refine/librefinedemo.so` with auto-analysis and runs `RefineEngineHeadlessTest`. No
Python and no compiler are needed (the solver is the bundled Z3, the fixture is committed). What
it checks:

- **The syntax tree**: every function of the fixture reprints token for token as the decompiler
  printed it, with no statement kept as raw text; node widths and signedness come from p-code;
  with every pass off the engine changes nothing.
- **Recovery**: one check per idiom in the fixture -- the expected source-level form is present
  and the artifact is gone -- and the functions the decompiler already shows correctly are left
  untouched.
- **Justification**: which rewrites are proved, tested or structural; that the loop-guard
  equivalence is a proof; that no rewrite on the fixture is unchecked or refuted; that turning
  verification off is labelled as such.
- **Configuration**: switching a pass, a rule group or a pass parameter changes the output as it
  should; pass order matters; a configuration survives JSON and a stale one is repaired;
  cancelling is reported; tracing explains a loop that was left alone.
- **User rules**: a correct rule is applied and proved; a wrong rule is refuted with a
  counterexample and changes nothing; a rule introducing an unknown function is applied as
  assumed, or refused when verification is demanded; guards and `eval`; syntax errors are reported
  with their line.
- **Emulator comparison**: the machine code agrees with the refined code on every fixture
  function -- and, with verification switched off and a deliberately wrong rule applied, the
  comparison reports the disagreement.
- **`ghidra_refine_function`** over JSON-RPC, including argument validation.
- **The window's contents**, built off screen: text-to-rewrite mapping, tooltips, line addresses,
  and that each configuration control edits the configuration and reports the change. The docking
  shell around it (toolbar actions, cursor tracking in a running tool) needs a real window; that
  is the next test.

### In a real window

```powershell
.\tests\run_refine_gui_test.ps1
```

Starts `decompfuncutils.refine.ui.RefinedDecompilerPreview` through Ghidra's own launcher: a code
browser tool window (Ghidra's core plugins, so Listing and Decompiler) on the fixture, with
`RefinedDecompilerPlugin` added the way *File → Configure* adds it. The window is placed off
screen and never takes focus; it is painted into `tests/_refined_gui_*.png`. It checks that

- the plugin loads, registers its window and actions, and raises no dialog;
- the window refines the function under the cursor and follows the cursor to another function;
- clicking a refined line moves the Listing to that line's address;
- switching a pass off, and typing a rule (a right one, then a wrong one), changes the code
  without anything else being pressed;
- the toolbar's *Show Decompiler Output* and *Show Configuration* do what they say;
- renaming the function in the program refreshes the window;
- the configuration is saved with the tool and restored;
- a hidden window does no work and catches up when shown again.

To look at what the engine does to some other binary:

```powershell
$env:REFINE_DUMP_OUT = "D:\temp\refined.txt"
.\tests\run_refine_test.ps1 -Script RefineShow.java -Binary C:\path\to\some.exe -ShowAll
```

## angr emulation test

```powershell
.\tools\setup-angr.ps1          # once: a private Python environment with angr
.\tests\run_angr_test.ps1
```

The runner uses the interpreter the extension itself would find (the one
`setup-angr.ps1` recorded) unless `-Python` names another, and exits 2 rather
than failing when there is none. It starts a real worker process, so it also
covers the export of Ghidra's memory image, the JSON protocol, worker reuse
between calls (the second call must be fast) and re-export after the program
changes.
