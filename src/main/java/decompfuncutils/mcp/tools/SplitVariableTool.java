package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class SplitVariableTool implements McpTool {

    @Override public String name() { return "ghidra_split_variable"; }

    @Override
    public String description() {
        return "Split a local variable into multiple sub-variables at specified offsets with types. " +
               "Useful for decomposing a large buffer or struct-like local into individual fields.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Address of the containing function in hex"),
            "functionName", Map.of("type", "string", "description", "Name of the containing function"),
            "variableName", Map.of("type", "string", "description", "Name of the variable to split"),
            "splitPoints", Map.of("type", "array", "description", "Array of split definitions: [{name, type, offset}]",
                "items", Map.of("type", "object", "properties", Map.of(
                    "name", Map.of("type", "string"),
                    "type", Map.of("type", "string"),
                    "offset", Map.of("type", "integer")
                )))
        ));
        schema.put("required", List.of("variableName", "splitPoints"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        String varName = (String) arguments.get("variableName");
        List<Map<String, Object>> splitPoints = (List<Map<String, Object>>) arguments.get("splitPoints");

        // Find the variable
        Variable targetVar = null;
        for (Variable var : func.getLocalVariables()) {
            if (var.getName().equals(varName)) {
                targetVar = var;
                break;
            }
        }
        if (targetVar == null) {
            throw new IllegalArgumentException("Variable '" + varName + "' not found in function " + func.getName());
        }

        // Get the base stack offset
        int baseOffset = (int) targetVar.getVariableStorage().getFirstVarnode().getOffset();

        // Remove the original variable
        func.removeVariable(targetVar);

        // Create new variables at each split point
        List<Map<String, Object>> created = new ArrayList<>();
        for (Map<String, Object> split : splitPoints) {
            String newName = (String) split.get("name");
            String typeName = (String) split.get("type");
            int offset = ((Number) split.get("offset")).intValue();

            DataType dt = RetypeVariableTool.resolveDataType(typeName, program);
            if (dt == null) throw new IllegalArgumentException("Unknown type: " + typeName);

            int stackOffset = baseOffset + offset;
            Variable newVar = new LocalVariableImpl(newName, dt,
                stackOffset, program);
            func.addLocalVariable(newVar, SourceType.USER_DEFINED);

            Map<String, Object> c = new LinkedHashMap<>();
            c.put("name", newName);
            c.put("type", dt.getDisplayName());
            c.put("stackOffset", stackOffset);
            created.add(c);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("originalVariable", varName);
        result.put("createdVariables", created);
        result.put("status", "variable_split");
        return result;
    }
}
