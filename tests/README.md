# Headless tests

End-to-end regression tests for the taint-query engine and the p-code emulator,
run inside Ghidra via `analyzeHeadless` against a small purpose-built binary.

## Files

| File | Purpose |
|------|---------|
| `test_vuln.c` | Source of the test cases (UAF, double-free, tainted sinks, arithmetic, external call). |
| `test_vuln.o` | Committed x86-64 Linux ELF object compiled from `test_vuln.c`. This is what the test imports. |
| `scripts/TaintHeadlessTest.java` | GhidraScript post-script: runs taint queries + emulation and prints `CHECK <name>: PASS/FAIL`. |
| `scripts/DebugDecomp.java` | Diagnostic helper: dumps decompiled C and the matcher log for a few functions. |
| `run_headless_test.ps1` | Build → install → run → report. Exits 0 on PASS, 1 on FAIL. |
| `build_binary.ps1` | Recompile `test_vuln.o` (only needed if you edit `test_vuln.c`; requires clang). |

## Running

```powershell
# GHIDRA_INSTALL_DIR must point at a Ghidra install (defaults to C:\Users\User\Ghidra)
pwsh tests/run_headless_test.ps1
# or skip the gradle build if the extension is already freshly installed:
pwsh tests/run_headless_test.ps1 -SkipBuild
```

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

## How it works (and why the project lives in TEMP)

Ghidra loads the plugin as an **installed extension module**. The runner installs the
freshly built zip into the per-user Extensions dir for the matching Ghidra version and
removes any copy under `<install>/Ghidra/Extensions` — two directories declaring the same
module name make Ghidra abort with *"Multiple modules collided: DecompFuncUtils"*. For the
same reason the throwaway Ghidra project is created under `$env:TEMP`, never inside the
repo (the repo itself is a module directory and would be double-counted).

Test cases deliberately use data flow the engine models: structural call patterns, **direct**
dereferences (`*p`, not `p[n]`), and taint that propagates through call **return values**
(e.g. `getenv`). Taint that only reaches a variable by a write through a pointer argument
(`read(fd, &len, 8)`) is not tracked by the reachability engine and is intentionally avoided.
