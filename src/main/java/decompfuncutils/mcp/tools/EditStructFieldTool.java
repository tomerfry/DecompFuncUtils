package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.Iterator;

public class EditStructFieldTool implements McpTool {

    @Override public String name() { return "ghidra_edit_struct_field"; }

    @Override
    public String description() {
        return "Edit a structure field: rename, retype, add, or remove a field. Actions: 'rename', 'retype', 'add', 'remove'.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "structName", Map.of("type", "string", "description", "Name of the structure"),
            "action", Map.of("type", "string", "description", "Action: rename, retype, add, remove"),
            "fieldName", Map.of("type", "string", "description", "Existing field name (for rename/retype/remove)"),
            "newName", Map.of("type", "string", "description", "New field name (for rename/add)"),
            "newType", Map.of("type", "string", "description", "New data type (for retype/add)"),
            "offset", Map.of("type", "integer", "description", "Offset for add (appends if not specified)")
        ));
        schema.put("required", List.of("structName", "action"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String structName = (String) arguments.get("structName");
        String action = (String) arguments.get("action");

        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = findStruct(structName, dtm);
        if (struct == null) {
            throw new IllegalArgumentException("Structure not found: " + structName);
        }

        switch (action.toLowerCase()) {
            case "rename": return doRename(arguments, struct);
            case "retype": return doRetype(arguments, struct, program);
            case "add": return doAdd(arguments, struct, program);
            case "remove": return doRemove(arguments, struct);
            default: throw new IllegalArgumentException("Unknown action: " + action);
        }
    }

    private Structure findStruct(String name, DataTypeManager dtm) {
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof Structure && dt.getName().equals(name)) {
                return (Structure) dt;
            }
        }
        return null;
    }

    private DataTypeComponent findField(Structure struct, String fieldName) {
        for (DataTypeComponent comp : struct.getDefinedComponents()) {
            if (fieldName.equals(comp.getFieldName())) {
                return comp;
            }
        }
        return null;
    }

    private Object doRename(Map<String, Object> args, Structure struct) throws Exception {
        String fieldName = (String) args.get("fieldName");
        String newName = (String) args.get("newName");
        if (fieldName == null || newName == null) throw new IllegalArgumentException("rename requires fieldName and newName");

        DataTypeComponent comp = findField(struct, fieldName);
        if (comp == null) throw new IllegalArgumentException("Field not found: " + fieldName);

        comp.setFieldName(newName);

        return Map.of("struct", struct.getName(), "action", "rename",
            "oldName", fieldName, "newName", newName, "status", "field_renamed");
    }

    private Object doRetype(Map<String, Object> args, Structure struct, Program program) {
        String fieldName = (String) args.get("fieldName");
        String newTypeName = (String) args.get("newType");
        if (fieldName == null || newTypeName == null) throw new IllegalArgumentException("retype requires fieldName and newType");

        DataTypeComponent comp = findField(struct, fieldName);
        if (comp == null) throw new IllegalArgumentException("Field not found: " + fieldName);

        DataType newType = RetypeVariableTool.resolveDataType(newTypeName, program);
        if (newType == null) throw new IllegalArgumentException("Unknown type: " + newTypeName);

        int ordinal = comp.getOrdinal();
        struct.replace(ordinal, newType, newType.getLength(), comp.getFieldName(), comp.getComment());

        return Map.of("struct", struct.getName(), "action", "retype",
            "field", fieldName, "newType", newType.getDisplayName(), "status", "field_retyped");
    }

    private Object doAdd(Map<String, Object> args, Structure struct, Program program) {
        String newName = (String) args.getOrDefault("newName", "field_" + struct.getNumDefinedComponents());
        String newTypeName = (String) args.get("newType");
        if (newTypeName == null) throw new IllegalArgumentException("add requires newType");

        DataType newType = RetypeVariableTool.resolveDataType(newTypeName, program);
        if (newType == null) throw new IllegalArgumentException("Unknown type: " + newTypeName);

        if (args.containsKey("offset")) {
            int offset = ((Number) args.get("offset")).intValue();
            struct.insertAtOffset(offset, newType, newType.getLength(), newName, null);
        } else {
            struct.add(newType, newName, null);
        }

        return Map.of("struct", struct.getName(), "action", "add",
            "field", newName, "type", newType.getDisplayName(),
            "newSize", struct.getLength(), "status", "field_added");
    }

    private Object doRemove(Map<String, Object> args, Structure struct) {
        String fieldName = (String) args.get("fieldName");
        if (fieldName == null) throw new IllegalArgumentException("remove requires fieldName");

        DataTypeComponent comp = findField(struct, fieldName);
        if (comp == null) throw new IllegalArgumentException("Field not found: " + fieldName);

        struct.delete(comp.getOrdinal());

        return Map.of("struct", struct.getName(), "action", "remove",
            "field", fieldName, "newSize", struct.getLength(), "status", "field_removed");
    }
}
