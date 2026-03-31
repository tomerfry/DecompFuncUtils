package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class GetCallGraphTool implements McpTool {

    @Override public String name() { return "ghidra_get_call_graph"; }

    @Override
    public String description() {
        return "Get the call graph for a function: both callers (who calls this function) and callees (what this function calls), traversed to a configurable depth.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Function address in hex"),
            "name", Map.of("type", "string", "description", "Function name"),
            "depth", Map.of("type", "integer", "description", "Maximum traversal depth (default 2, max 5)")
        ));
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Function func = DecompileFunctionTool.resolveFunction(arguments, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        int depth = Math.min(((Number) arguments.getOrDefault("depth", 2)).intValue(), 5);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("address", func.getEntryPoint().toString());

        // Build callee tree
        Set<String> visited = new HashSet<>();
        result.put("callees", buildCalleeTree(func, depth, visited, program));

        // Build caller tree
        visited.clear();
        result.put("callers", buildCallerTree(func, depth, visited, program));

        return result;
    }

    private Map<String, Object> buildCalleeTree(Function func, int depth, Set<String> visited, Program program) {
        Map<String, Object> node = new LinkedHashMap<>();
        node.put("name", func.getName());
        node.put("address", func.getEntryPoint().toString());

        String key = func.getEntryPoint().toString();
        if (depth <= 0 || visited.contains(key)) {
            if (visited.contains(key)) node.put("recursive", true);
            return node;
        }
        visited.add(key);

        List<Map<String, Object>> children = new ArrayList<>();
        for (Function called : func.getCalledFunctions(TaskMonitor.DUMMY)) {
            children.add(buildCalleeTree(called, depth - 1, visited, program));
        }
        if (!children.isEmpty()) {
            node.put("calls", children);
        }

        return node;
    }

    private Map<String, Object> buildCallerTree(Function func, int depth, Set<String> visited, Program program) {
        Map<String, Object> node = new LinkedHashMap<>();
        node.put("name", func.getName());
        node.put("address", func.getEntryPoint().toString());

        String key = func.getEntryPoint().toString();
        if (depth <= 0 || visited.contains(key)) {
            if (visited.contains(key)) node.put("recursive", true);
            return node;
        }
        visited.add(key);

        List<Map<String, Object>> parents = new ArrayList<>();
        for (Function caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            parents.add(buildCallerTree(caller, depth - 1, visited, program));
        }
        if (!parents.isEmpty()) {
            node.put("calledBy", parents);
        }

        return node;
    }
}
