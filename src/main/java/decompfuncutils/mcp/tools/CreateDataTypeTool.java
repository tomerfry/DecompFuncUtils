package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.util.*;

public class CreateDataTypeTool implements McpTool {

    @Override public String name() { return "ghidra_create_data_type"; }

    @Override
    public String description() {
        return "Create a new data type. Supported kinds: 'funcptr' (function pointer), 'typedef', 'enum', 'union'.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("kind", Map.of("type", "string", "description", "Type kind: funcptr, typedef, enum, union"));
        props.put("name", Map.of("type", "string", "description", "Name for the new data type"));
        props.put("category", Map.of("type", "string", "description", "Category path (e.g. '/MyTypes'). Default: '/'"));

        // For funcptr
        props.put("returnType", Map.of("type", "string", "description", "(funcptr) Return type"));
        props.put("parameters", Map.of("type", "array", "description", "(funcptr) Parameters: [{name, type}]",
            "items", Map.of("type", "object")));
        props.put("callingConvention", Map.of("type", "string", "description", "(funcptr) Calling convention (default: __cdecl)"));

        // For typedef
        props.put("baseType", Map.of("type", "string", "description", "(typedef) Base data type name"));

        // For enum
        props.put("size", Map.of("type", "integer", "description", "(enum) Size in bytes (1, 2, 4, or 8). Default: 4"));
        props.put("members", Map.of("type", "object", "description", "(enum/union) Members. For enum: {name: value, ...}. For union: [{name, type}]"));

        schema.put("properties", props);
        schema.put("required", List.of("kind", "name"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String kind = (String) arguments.get("kind");
        String name = (String) arguments.get("name");
        String categoryStr = (String) arguments.getOrDefault("category", "/");
        CategoryPath catPath = new CategoryPath(categoryStr);
        DataTypeManager dtm = program.getDataTypeManager();

        DataType created;
        switch (kind.toLowerCase()) {
            case "funcptr": created = createFuncPtr(arguments, name, catPath, program, dtm); break;
            case "typedef": created = createTypedef(arguments, name, catPath, program, dtm); break;
            case "enum": created = createEnum(arguments, name, catPath, dtm); break;
            case "union": created = createUnion(arguments, name, catPath, program, dtm); break;
            default: throw new IllegalArgumentException("Unknown kind: " + kind + ". Use: funcptr, typedef, enum, union");
        }

        DataType resolved = dtm.addDataType(created, DataTypeConflictHandler.REPLACE_HANDLER);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", resolved.getName());
        result.put("kind", kind);
        result.put("category", resolved.getCategoryPath().getPath());
        result.put("size", resolved.getLength());
        result.put("status", "created");
        return result;
    }

    @SuppressWarnings("unchecked")
    private DataType createFuncPtr(Map<String, Object> args, String name, CategoryPath catPath,
                                    Program program, DataTypeManager dtm) {
        String retTypeName = (String) args.getOrDefault("returnType", "void");
        DataType retType = RetypeVariableTool.resolveDataType(retTypeName, program);
        if (retType == null) throw new IllegalArgumentException("Unknown return type: " + retTypeName);

        // Give the underlying FunctionDefinition a distinct internal name so the user-
        // supplied name applies to the final typedef (e.g. handler_fn_t) rather than
        // the auto-generated pointer name ("handler_fn_t *64").
        String funcDefName = name.endsWith("_fn") ? name + "_def" : name + "_fn";
        FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(catPath, funcDefName, dtm);
        funcDef.setReturnType(retType);

        List<Map<String, Object>> params = (List<Map<String, Object>>) args.getOrDefault("parameters", List.of());
        ParameterDefinition[] paramDefs = new ParameterDefinition[params.size()];
        for (int i = 0; i < params.size(); i++) {
            Map<String, Object> p = params.get(i);
            String pName = (String) p.getOrDefault("name", "param" + i);
            String pTypeName = (String) p.get("type");
            DataType pType = RetypeVariableTool.resolveDataType(pTypeName, program);
            if (pType == null) throw new IllegalArgumentException("Unknown parameter type: " + pTypeName);
            paramDefs[i] = new ParameterDefinitionImpl(pName, pType, null);
        }
        funcDef.setArguments(paramDefs);

        String cc = (String) args.getOrDefault("callingConvention", null);
        if (cc != null) {
            try {
                funcDef.setCallingConvention(cc);
            } catch (ghidra.util.exception.InvalidInputException e) {
                throw new IllegalArgumentException("Invalid calling convention: " + cc, e);
            }
        }

        DataType resolvedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
        PointerDataType ptr = new PointerDataType(resolvedFuncDef, program.getDefaultPointerSize(), dtm);
        return new TypedefDataType(catPath, name, ptr, dtm);
    }

    private DataType createTypedef(Map<String, Object> args, String name, CategoryPath catPath,
                                    Program program, DataTypeManager dtm) {
        String baseTypeName = (String) args.get("baseType");
        if (baseTypeName == null) throw new IllegalArgumentException("typedef requires 'baseType'");

        DataType baseType = RetypeVariableTool.resolveDataType(baseTypeName, program);
        if (baseType == null) throw new IllegalArgumentException("Unknown base type: " + baseTypeName);

        return new TypedefDataType(catPath, name, baseType, dtm);
    }

    @SuppressWarnings("unchecked")
    private DataType createEnum(Map<String, Object> args, String name, CategoryPath catPath,
                                 DataTypeManager dtm) {
        int size = ((Number) args.getOrDefault("size", 4)).intValue();
        EnumDataType enumDt = new EnumDataType(catPath, name, size, dtm);

        Map<String, Object> members = (Map<String, Object>) args.getOrDefault("members", Map.of());
        for (Map.Entry<String, Object> entry : members.entrySet()) {
            long value = ((Number) entry.getValue()).longValue();
            enumDt.add(entry.getKey(), value);
        }

        return enumDt;
    }

    @SuppressWarnings("unchecked")
    private DataType createUnion(Map<String, Object> args, String name, CategoryPath catPath,
                                  Program program, DataTypeManager dtm) {
        UnionDataType unionDt = new UnionDataType(catPath, name, dtm);

        List<Map<String, Object>> members = (List<Map<String, Object>>) args.getOrDefault("members", List.of());
        for (Map<String, Object> member : members) {
            String mName = (String) member.get("name");
            String mTypeName = (String) member.get("type");
            DataType mType = RetypeVariableTool.resolveDataType(mTypeName, program);
            if (mType == null) throw new IllegalArgumentException("Unknown member type: " + mTypeName);
            unionDt.add(mType, mName, null);
        }

        return unionDt;
    }
}
