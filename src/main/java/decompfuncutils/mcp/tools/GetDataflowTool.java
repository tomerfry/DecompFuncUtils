package decompfuncutils.mcp.tools;

import decompfuncutils.DataflowSlicer;
import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Local data dependencies of a variable, call or statement inside one function:
 * the same "affected by / affects" lists the Decompiler data-flow hover shows.
 */
public class GetDataflowTool implements McpTool {

    private final DecompInterfacePool decompPool;

    public GetDataflowTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override
    public String name() { return "ghidra_get_dataflow"; }

    @Override
    public String description() {
        return "Local data dependencies inside one function. Give 'variable' (a decompiler variable name) for " +
            "everything that variable depends on and feeds, 'address' (an instruction address) for the call or " +
            "statement there, or both for that variable as read/written at that instruction. Returns affectedBy " +
            "(named variables, constants, call results, memory reads, function inputs), affects (call arguments, " +
            "memory writes, return value, branch conditions, variables it flows into) and mayBeModifiedBy (calls " +
            "whose side effects may change it). Intraprocedural and bounded; use the taint tools to cross calls.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("function", Map.of("type", "string", "description",
            "Function name or address (hex). Optional when 'address' is given: its containing function is used."));
        props.put("variable", Map.of("type", "string", "description",
            "Decompiler variable name (parameter, local or global) as shown by ghidra_decompile_function"));
        props.put("address", Map.of("type", "string", "description",
            "Instruction address (hex) of the call, assignment, store, branch or return to inspect"));
        props.put("maxDepth", Map.of("type", "integer", "minimum", 1, "maximum", 32,
            "default", DataflowSlicer.DEFAULT_MAX_DEPTH, "description", "Computation steps to follow in each direction"));
        props.put("maxItems", Map.of("type", "integer", "minimum", 1, "maximum", 200, "default", 50,
            "description", "Entries returned per list; the *Total fields keep the full counts"));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", props);
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalStateException("No program is open");
        String functionArg = optionalString(args, "function");
        String variable = optionalString(args, "variable");
        String addressArg = optionalString(args, "address");
        if (variable == null && addressArg == null) {
            throw new IllegalArgumentException("Provide 'variable', 'address', or both");
        }
        int maxDepth = DecompilerEditSupport.integer(
            args.getOrDefault("maxDepth", DataflowSlicer.DEFAULT_MAX_DEPTH), "maxDepth", 1, 32);
        int maxItems = DecompilerEditSupport.integer(args.getOrDefault("maxItems", 50), "maxItems", 1, 200);

        Address address = addressArg == null ? null : McpUtil.parseAddress(addressArg, program);
        Function function = resolveFunction(functionArg, address, program);
        if (address != null && !function.getBody().contains(address)) {
            throw new IllegalArgumentException("Address " + address + " is not inside " + function.getName());
        }

        DecompInterface decomp = decompPool.acquire(program);
        try {
            DecompileResults results = decomp.decompileFunction(function, 30, McpUtil.activeMonitor());
            HighFunction high = results.getHighFunction();
            if (!results.decompileCompleted() || high == null) {
                throw new IllegalStateException("Decompilation failed: " + results.getErrorMessage());
            }
            DataflowSlicer slicer = new DataflowSlicer(program, high, maxDepth, DataflowSlicer.DEFAULT_MAX_VISITED);
            DataflowSlicer.Seed seed = address != null
                ? slicer.seedForAddress(address, variable)
                : slicer.seedForVariable(variable);
            if (seed == null) {
                throw new IllegalArgumentException(address == null
                    ? "No variable named '" + variable + "' is used in " + function.getName()
                    : variable == null
                        ? "No decompiler operation at " + address + " (the instruction may have been folded away)"
                        : "Variable '" + variable + "' is not read or written at " + address);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("function", function.getName());
            out.put("functionAddress", function.getEntryPoint().toString());
            out.putAll(slicer.slice(seed).toMap(maxItems));
            return out;
        } finally {
            decompPool.release(program, decomp);
        }
    }

    private static Function resolveFunction(String functionArg, Address address, Program program) {
        Function function = null;
        if (functionArg != null) {
            function = DecompileFunctionTool.resolveFunction(Map.of("name", functionArg), program);
            if (function == null) {
                try {
                    function = DecompileFunctionTool.resolveFunction(Map.of("address", functionArg), program);
                } catch (RuntimeException notAnAddress) {
                    // reported below
                }
            }
            if (function == null) throw new IllegalArgumentException("Function not found: " + functionArg);
        } else if (address != null) {
            function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) throw new IllegalArgumentException("No function contains " + address);
        } else {
            throw new IllegalArgumentException("Provide 'function' (name or address) together with 'variable'");
        }
        if (function.isExternal()) throw new IllegalArgumentException(function.getName() + " is external");
        return function;
    }

    private static String optionalString(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) return null;
        if (!(value instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException(key + " must be a non-empty string");
        }
        return s.strip();
    }

    /** Lists in the result, for callers that hold the map rather than JSON. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> list(Object result, String key) {
        return (List<Map<String, Object>>) ((Map<String, Object>) result).get(key);
    }
}
