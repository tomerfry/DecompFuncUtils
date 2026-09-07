# Headless tests

End-to-end regression tests run inside Ghidra via `analyzeHeadless` against a
small purpose-built binary: the taint-query engine and p-code emulator, plus the
MCP server's two HTTP transports.

## Files

| File | Purpose |
|------|---------|
| `test_vuln.c` | Source of the test cases (UAF, double-free, tainted sinks, arithmetic, external call). |
| `test_vuln.o` | Committed x86-64 Linux ELF object compiled from `test_vuln.c`. This is what the test imports. |
| `scripts/TaintHeadlessTest.java` | GhidraScript post-script: runs taint queries + emulation and prints `CHECK <name>: PASS/FAIL`. |
| `scripts/McpTransportHeadlessTest.java` | Starts the MCP server in-process and runs a full client handshake over both transports. |
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
```

To check a *running* Ghidra's MCP server rather than a headless one, use
`tools/mcp-handshake-probe.ps1` (see the MCP section of the top-level README).

## What is covered

- **Structural multi-element matching** (exercises the statement-index optimization):
  use-after-free (`free($p); ...; *$p`) and double-free.
- **Taint constraint** `tainted($v)`: a tainted length into `memcpy` and a tainted
  `printf` format string both match; a constant-length `memcpy` does not.
- **Source-specific taint** `tainted($v, "source")`: `tainted($fmt, "getenv")` matches
  while `tainted($fmt, "read")` does not — confirms the source name actually filters.
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

The buffer model recognizes direct pointer arguments; arbitrary loads from
input-filled scalar storage, memory overwrites, and interprocedural pointer
writes remain outside this regression coverage.

Additional regressions cover 64-node reachability chains in both engines, MCP query presets, one-function pagination without omissions or duplicates, coverage metadata, and invalid query arguments. Test runs use unique temporary settings and project directories; the runner stops immediately on a failed build.
