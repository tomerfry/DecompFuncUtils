package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.Iterator;

public class CreateClassTool implements McpTool {

    @Override public String name() { return "ghidra_create_class"; }

    @Override
    public String description() {
        return "Create a new class: a namespace + associated structure data type. Optionally specify parent class and fields.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "name", Map.of("type", "string", "description", "Class name"),
            "namespace", Map.of("type", "string", "description", "Parent namespace (e.g. 'MyLib'). Default: global"),
            "parentClass", Map.of("type", "string", "description", "Parent class name to inherit from (optional)"),
            "fields", Map.of("type", "array", "description", "Structure fields: [{name, type}]",
                "items", Map.of("type", "object", "properties", Map.of(
                    "name", Map.of("type", "string"),
                    "type", Map.of("type", "string")
                )))
        ));
        schema.put("required", List.of("name"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String className = (String) arguments.get("name");
        String namespaceName = (String) arguments.getOrDefault("namespace", null);
        String parentClassName = (String) arguments.getOrDefault("parentClass", null);
        List<Map<String, Object>> fields = (List<Map<String, Object>>) arguments.getOrDefault("fields", null);

        SymbolTable st = program.getSymbolTable();

        // Resolve parent namespace
        Namespace parentNs;
        if (namespaceName != null) {
            parentNs = st.getNamespace(namespaceName, program.getGlobalNamespace());
            if (parentNs == null) {
                parentNs = st.createNameSpace(program.getGlobalNamespace(), namespaceName, SourceType.USER_DEFINED);
            }
        } else {
            parentNs = program.getGlobalNamespace();
        }

        // Create the class namespace
        Namespace ghidraClass = st.createClass(parentNs, className, SourceType.USER_DEFINED);

        // Create associated structure
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath("/" + className);
        StructureDataType struct = new StructureDataType(catPath, className, 0, dtm);

        // If parent class, add parent struct as first field
        if (parentClassName != null) {
            DataType parentType = null;
            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            while (dtIter.hasNext()) {
                DataType dt = dtIter.next();
                if (dt instanceof Structure && dt.getName().equals(parentClassName)) {
                    parentType = dt;
                    break;
                }
            }
            if (parentType != null) {
                struct.add(parentType, "base_" + parentClassName, "Inherited from " + parentClassName);
            }
        }

        // Add fields
        if (fields != null) {
            for (Map<String, Object> field : fields) {
                String fieldName = (String) field.get("name");
                String fieldTypeName = (String) field.get("type");
                DataType fieldType = RetypeVariableTool.resolveDataType(fieldTypeName, program);
                if (fieldType == null) throw new IllegalArgumentException("Unknown type: " + fieldTypeName);
                struct.add(fieldType, fieldName, null);
            }
        }

        DataType resolved = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("className", className);
        result.put("namespace", ghidraClass.getName(true));
        result.put("structSize", resolved.getLength());
        result.put("status", "class_created");
        return result;
    }
}
