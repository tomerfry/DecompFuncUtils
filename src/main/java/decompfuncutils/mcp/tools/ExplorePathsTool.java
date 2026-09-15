package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.symbolic.SymbolicExplorer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import java.util.*;
import java.util.concurrent.Semaphore;

/** Bounded symbolic exploration, isolated from the concrete emulator and program database. */
public final class ExplorePathsTool implements McpTool {
    private static final Semaphore SLOT = new Semaphore(1);

    @Override public String name() { return "ghidra_explore_paths"; }
    @Override public boolean requiresEdt() { return false; }
    @Override public String description() {
        return "Explore feasible paths through one x86/x64 function using symbolic registers or memory " +
            "and Z3 bit-vector constraints. Find inputs reaching targetAddresses while avoiding avoidAddresses. " +
            "Solutions are replayed in Ghidra's concrete emulator. Explicit state, step, loop, and time limits " +
            "apply. Calls, symbolic addresses, division, and unsupported p-code stop affected paths and " +
            "report incomplete coverage. No program changes. Unseeded ordinary registers start at zero; " +
            "unmapped/uninitialized memory must be seeded. Requires a concrete stackPointer.";
    }

    @Override public Map<String, Object> inputSchema() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("entry", Map.of("type", "string", "description", "Instruction address in the function to explore"));
        p.put("targetAddresses", addresses("Stop before executing a target instruction; return its input witness", 1));
        p.put("avoidAddresses", addresses("Exclude paths reaching these instructions", 0));
        p.put("stackPointer", Map.of("type", "string", "description", "Concrete initial SP, decimal or 0x hex"));
        p.put("registers", Map.of("type", "object", "description", "Concrete register seeds",
            "additionalProperties", Map.of("type", "string")));
        p.put("memory", Map.of("type", "array", "maxItems", 64, "items", Map.of(
            "type", "object", "additionalProperties", false, "required", List.of("address", "hexBytes"),
            "properties", Map.of("address", Map.of("type", "string"), "hexBytes", Map.of("type", "string")))));
        p.put("symbolicInputs", Map.of("type", "array", "minItems", 1, "maxItems", 32, "items", Map.of(
            "type", "object", "additionalProperties", false, "required", List.of("name"),
            "properties", Map.of("name", Map.of("type", "string"),
                "register", Map.of("type", "string", "description", "Whole register; mutually exclusive with address/size"),
                "address", Map.of("type", "string", "description", "Concrete memory address"),
                "size", Map.of("type", "integer", "minimum", 1, "maximum", 64)),
            "oneOf", List.of(Map.of("required", List.of("register")), Map.of("required", List.of("address", "size"))))));
        p.put("maxStates", limit(128, 512, "Total execution states created"));
        p.put("maxStepsPerPath", limit(2000, 10000, "Instructions per path, including concrete replay"));
        p.put("maxVisitsPerAddress", limit(16, 256, "Loop bound per instruction per path"));
        p.put("maxPcodeOps", limit(100000, 500000, "Total p-code operations across all paths"));
        p.put("timeoutMs", limit(10000, 60000, "Overall execution deadline, including solver checks and replay"));
        p.put("solverTimeoutMs", limit(1000, 5000, "Per-check solver timeout, capped by remaining overall time"));
        return Map.of("type", "object", "additionalProperties", false, "properties", p,
            "required", List.of("entry", "targetAddresses", "stackPointer", "symbolicInputs"));
    }

    private static Map<String, Object> limit(int def, int max, String description) {
        return Map.of("type", "integer", "minimum", 1, "maximum", max, "default", def, "description", description);
    }

    private static Map<String, Object> addresses(String description, int min) {
        return Map.of("type", "array", "minItems", min, "maxItems", 64,
            "items", Map.of("type", "string"), "description", description);
    }

    @Override public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalStateException("No program is open");
        if (!SLOT.tryAcquire()) return Map.of("status", "busy", "complete", false,
            "reason", "Another symbolic exploration is running. Retry after it finishes.");
        try {
            return new SymbolicExplorer(program, arguments).explore();
        } catch (LinkageError e) {
            throw new IllegalStateException("Cannot load the bundled Z3 native solver on this host: " + e.getMessage(), e);
        } finally {
            SLOT.release();
        }
    }
}
