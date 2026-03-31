package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class RenameFunctionTool implements McpTool {

    @Override public String name() { return "ghidra_rename_function"; }

    @Override
    public String description() {
        return "Rename a function. The rename is recorded as a Ghidra transaction (undoable).";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Function address in hex"),
            "name", Map.of("type", "string", "description", "Function name (if address not provided)"),
            "newName", Map.of("type", "string", "description", "New name for the function")
        ));
        schema.put("required", List.of("newName"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Function func = DecompileFunctionTool.resolveFunction(arguments, program);
        if (func == null) {
            throw new IllegalArgumentException("Function not found");
        }

        String oldName = func.getName();
        String newName = (String) arguments.get("newName");
        func.setName(newName, SourceType.USER_DEFINED);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", func.getEntryPoint().toString());
        result.put("oldName", oldName);
        result.put("newName", newName);
        result.put("status", "renamed");
        return result;
    }
}
