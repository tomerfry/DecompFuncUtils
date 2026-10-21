package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.*;

public class SetFunctionNoReturnTool implements McpTool {
    @Override public String name() { return "ghidra_set_function_no_return"; }

    @Override public String description() {
        return "Set or clear a function's non-returning flag without changing its signature. " +
            "Supports external functions. For thunks, Ghidra updates the ultimate target. " +
            "Re-decompile callers to reflect the new control flow; this does not repair listing bodies " +
            "or existing instruction flow overrides.";
    }

    @Override public Map<String, Object> inputSchema() {
        return Map.of("type", "object", "properties", Map.of(
            "address", Map.of("type", "string", "description", "Function address in hex (takes precedence over name)"),
            "name", Map.of("type", "string", "description", "Exact unique function name, optionally namespace-qualified"),
            "noReturn", Map.of("type", "boolean", "description", "true to mark non-returning; false to clear")),
            "required", List.of("noReturn"),
            "anyOf", List.of(Map.of("required", List.of("address")), Map.of("required", List.of("name"))));
    }

    @Override public boolean isMutating() { return true; }

    @Override public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) {
        boolean noReturn = FunctionEditSupport.booleanValue(arguments.get("noReturn"), "noReturn");
        Function function = FunctionEditSupport.resolve(arguments, program, "address", "name");
        Function target = function.isThunk() ? function.getThunkedFunction(true) : function;
        boolean previous = target.hasNoReturn();
        target.setNoReturn(noReturn);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", function.getName(true));
        result.put("address", function.getEntryPoint().toString());
        result.put("targetFunction", target.getName(true));
        result.put("targetAddress", target.getEntryPoint().toString());
        result.put("oldNoReturn", previous);
        result.put("noReturn", target.hasNoReturn());
        result.put("status", previous == noReturn ? "unchanged" : "updated");
        return result;
    }
}
