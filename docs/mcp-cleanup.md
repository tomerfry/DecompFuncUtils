# MCP cleanup controls

These tools operate on the session's active program. Install the newly built
extension and restart Ghidra, then reconnect the MCP client to discover them.

## Per-data constants

`ghidra_set_data_mutability` changes the **instance setting** on existing defined
data. It does not change memory-block permissions or data-type defaults.

```json
{"addresses":["00101230","00101234"],"mutability":"constant"}
```

This is useful for ARM literal-pool entries even when `.text` is already
read-only. Supported modes are `normal`, `constant`, `volatile`, and `writable`.
Use `normal` to restore normal mutability. Addresses must be exact starts of
defined data; instructions, undefined bytes, and interior addresses are rejected.
Define the literal-pool entries as data first if needed. The batch validates all
addresses before writing and is transactional. Results include previous and new
settings for each entry. Whether an expression folds still depends on the
decompiler's data-flow analysis and other annotations.

## Inspect and select a variable use

`ghidra_get_variable_uses` decompiles a function and exposes the selectors that
normally come from clicking a decompiler token:

```json
{"functionAddress":"00101000","variableName":"local_20","offset":0,"limit":100}
```

`variableName` and `operationAddress` are optional filters. Each returned use
includes `operationAddress`, `operationTime`, and `slot` (`-1` for the output,
otherwise a zero-based input index), plus storage, type, merge group, `canSplit`,
and any union fields. `total` and `hasMore` support pagination (maximum 500 rows).
Operation times refer to **decompiler p-code**, not raw instruction p-code.
Refresh inspection after each edit: recompilation can change the operation graph.
Both editing tools accept `expectedVariable` to reject a selector whose variable
name no longer matches.

## Split a variable lifetime

`ghidra_split_variable_lifetime` applies Ghidra's **Split Out As New Variable**
operation to the selected use's merge group, then persists a name and locked type:

```json
{
  "functionAddress":"00101000",
  "operationAddress":"00101048",
  "operationTime":17,
  "slot":-1,
  "expectedVariable":"iVar1",
  "newName":"second_object",
  "newType":"int"
}
```

Copy selectors from inspection, rather than assuming the example numbers apply.
`newType` is optional and must have the same size as the selected variable.
Undefined types are converted to unsigned integers of equivalent size so Ghidra
can lock the split. Only locals with `canSplit=true` are accepted; parameters,
already isolated variables, and mandatory merges cannot be split this way.

This separates lifetimes represented by distinct decompiler merge groups,
including reused storage when Ghidra has inferred separable groups. It does not
invent arbitrary live-range boundaries or promise to separate address-tied stack
objects that Ghidra has merged mandatorily. `ghidra_split_variable` remains the
separate tool for splitting storage into fields.

## Select a union member at one use

`ghidra_set_union_field` writes a persistent union-facet override for an exact
p-code edge. Get available `unionFields` and their ordinals from inspection:

```json
{
  "functionAddress":"00101000",
  "operationAddress":"00101064",
  "operationTime":23,
  "slot":1,
  "expectedVariable":"object",
  "fieldOrdinal":1
}
```

The selected use must have a union-related type (union, pointer, typedef, or
partial union). For a `SUBPIECE`, the output edge can resolve the input union.
`fieldOrdinal=-1` explicitly selects the whole union without a member; it is not
an override-removal operation. The tool returns the persisted dynamic hash and
first-use address. Overrides apply to the selected edge, not every use of a
variable or every operation at an instruction address. Decompile again to check
the resulting expression.

## Run a Ghidra script

`ghidra_run_script` uses installed Ghidra script providers. Java scripts are
supported by the standard installation; other languages require their providers.
The script must already exist on the machine hosting Ghidra. Select it by filename
in configured script directories or by absolute path:

An absolute path outside the configured directories registers its parent directory
with Ghidra's script bundle host, allowing Java compilation and sibling helper
classes. The directory remains registered for subsequent script calls.

```json
{
  "script":"C:/reverse/scripts/FixLiteralPools.java",
  "args":["00101230","00101280"],
  "address":"00101000",
  "timeoutSeconds":60,
  "maxOutputChars":65536
}
```

The script receives the session program as `currentProgram`, the supplied
`address` as `currentAddress` (otherwise the program minimum address), and string
arguments through `getScriptArgs()`. There is no implicit UI selection/highlight.
Use non-interactive scripts: GUI prompts remain interactive and cannot be answered
through this tool. Scripts must use the default `ENABLED` analysis mode; analysis
worker modes are rejected to avoid running them inside an incompatible transaction.

Execution runs off the Swing UI thread and is serialized with other mutations.
Script output and diagnostics are captured in `output`; `outputTruncated` reports
the configured character limit. Failures include captured output in the MCP error.
Database edits to the active program commit on success and roll back on exception
or cancellation. Scripts have the Ghidra process's full permissions: filesystem,
network, other-program edits, and other external side effects are not rolled back.

Timeouts (1–3600 seconds) and MCP cancellation signal the script's monitor.
Scripts must poll `monitor.checkCancelled()` or use cancellable Ghidra APIs.
The request and transaction stay active until the script actually exits; arbitrary
Java code cannot be safely killed. This avoids reporting rollback while a script
continues writing.

## Validation

Run `tests/run_headless_test.ps1 -Script CleanupControlsHeadlessTest.java` to build
and test against a disposable Ghidra database, independently of open GUI programs.
The fixture covers constant folding, inspection and pagination, persisted lifetime
splits and union overrides, script context/output, bounded output, and rollback on
script failures and cooperative timeouts. The MCP transport suite also exercises
the shared dispatcher: `tests/run_headless_test.ps1 -Script McpTransportHeadlessTest.java`.
