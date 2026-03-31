package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.util.*;

public class CreateStructTool implements McpTool {

    @Override public String name() { return "ghidra_create_struct"; }

    @Override
    public String description() {
        return "Create a new structure data type with specified fields. Each field needs a name, type, and optionally a size/offset.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "name", Map.of("type", "string", "description", "Structure name"),
            "category", Map.of("type", "string", "description", "Category path (e.g. '/MyTypes'). Default: '/'"),
            "fields", Map.of("type", "array", "description", "Array of fields: [{name, type, size?}]",
                "items", Map.of("type", "object", "properties", Map.of(
                    "name", Map.of("type", "string"),
                    "type", Map.of("type", "string"),
                    "size", Map.of("type", "integer")
                )))
        ));
        schema.put("required", List.of("name", "fields"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String name = (String) arguments.get("name");
        String categoryPath = (String) arguments.getOrDefault("category", "/");
        List<Map<String, Object>> fields = (List<Map<String, Object>>) arguments.get("fields");

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(categoryPath);

        StructureDataType struct = new StructureDataType(catPath, name, 0, dtm);

        for (Map<String, Object> field : fields) {
            String fieldName = (String) field.get("name");
            String fieldTypeName = (String) field.get("type");

            DataType fieldType = RetypeVariableTool.resolveDataType(fieldTypeName, program);
            if (fieldType == null) {
                throw new IllegalArgumentException("Unknown field type: " + fieldTypeName);
            }

            if (field.containsKey("size")) {
                int size = ((Number) field.get("size")).intValue();
                struct.add(fieldType, size, fieldName, null);
            } else {
                struct.add(fieldType, fieldName, null);
            }
        }

        DataType resolved = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", resolved.getName());
        result.put("category", resolved.getCategoryPath().getPath());
        result.put("size", resolved.getLength());
        result.put("fieldCount", fields.size());
        result.put("status", "created");
        return result;
    }
}
