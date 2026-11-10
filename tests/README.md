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
| `scripts/McpSessionManagerHeadlessTest.java` | Drives the session manager's router with fake tool windows: binding, isolation between sessions, open/attach/release, closed windows, idle claims. |
| `scripts/SymbolicHeadlessTest.java` | Exercises Z3 path constraints, symbolic memory, bounds, and concrete replay using deterministic x64 instruction fixtures. |
| `scripts/RefinementHeadlessTest.java` | Exercises non-returning functions and atomic stack-local replacement through JSON-RPC on an isolated Ghidra database. |
| `scripts/DataflowHeadlessTest.java` | Exercises the data-flow slicer behind the Decompiler hover from real decompiler tokens, its tooltip HTML, and the `ghidra_get_dataflow` MCP tool. |
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
