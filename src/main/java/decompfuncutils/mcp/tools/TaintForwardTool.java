package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;

import java.util.*;

public class TaintForwardTool implements McpTool {

    private final DecompInterfacePool decompPool;

    public TaintForwardTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override public String name() { return "ghidra_taint_forward"; }

    @Override
    public String description() {
        return "Run forward inter-procedural taint analysis from a variable. Shows where tainted data flows to (e.g., from user input to dangerous sinks).";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Address of the function in hex"),
            "functionName", Map.of("type", "string", "description", "Function name"),
            "variableName", Map.of("type", "string", "description", "Name of the variable to taint"),
            "maxDepth", Map.of("type", "integer", "description", "Maximum call depth to follow (default 3)"),
            "decompileTimeout", Map.of("type", "integer", "description",
                "Per-function decompile timeout in seconds. Pass -1 (or 0) to disable the timeout — useful when running this tool over many large functions in a batch.")
        ));
        schema.put("required", List.of("variableName"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        return TaintBackwardTool.runTaintAnalysis(arguments, program, tool, true, decompPool);
    }
}
