package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class RenameVariableTool implements McpTool {

    @Override public String name() { return "ghidra_rename_variable"; }

    @Override
    public String description() {
        return "Rename a local variable or parameter within a function.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Address of the containing function in hex"),
            "functionName", Map.of("type", "string", "description", "Name of the containing function"),
            "oldName", Map.of("type", "string", "description", "Current variable name"),
            "newName", Map.of("type", "string", "description", "New variable name")
        ));
        schema.put("required", List.of("oldName", "newName"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        // Resolve function using address or name
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) {
            throw new IllegalArgumentException("Function not found");
        }

        String oldName = (String) arguments.get("oldName");
        String newName = (String) arguments.get("newName");

        // Search parameters
        for (Parameter param : func.getParameters()) {
            if (param.getName().equals(oldName)) {
                param.setName(newName, SourceType.USER_DEFINED);
                return successResult(func, oldName, newName, "parameter");
            }
        }

        // Search local variables
        for (Variable var : func.getLocalVariables()) {
            if (var.getName().equals(oldName)) {
                var.setName(newName, SourceType.USER_DEFINED);
                return successResult(func, oldName, newName, "local_variable");
            }
        }

        throw new IllegalArgumentException("Variable '" + oldName + "' not found in function " + func.getName());
    }

    private Map<String, Object> successResult(Function func, String oldName, String newName, String varType) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("oldName", oldName);
        result.put("newName", newName);
        result.put("variableType", varType);
        result.put("status", "renamed");
        return result;
    }
}
