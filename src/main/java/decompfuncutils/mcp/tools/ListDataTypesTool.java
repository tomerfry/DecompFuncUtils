package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.util.*;

public class ListDataTypesTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_data_types"; }

    @Override
    public String description() {
        return "List data types (structs, enums, typedefs, function pointers, etc.) in the program's data type manager. Filter by name or category path.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("filter", Map.of("type", "string", "description", "Substring filter on data type name (case-insensitive)"));
        props.put("category", Map.of("type", "string", "description", "Category path filter (e.g. '/MyTypes')"));
        props.put("limit", Map.of("type", "integer", "description", "Maximum results (default 100, max 500)"));
        schema.put("properties", props);

        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filter = (String) arguments.getOrDefault("filter", null);
        String category = (String) arguments.getOrDefault("category", null);
        int limit = Math.min(((Number) arguments.getOrDefault("limit", 100)).intValue(), 500);

        if (filter != null) filter = filter.toLowerCase();

        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> iter = dtm.getAllDataTypes();

        List<Map<String, Object>> types = new ArrayList<>();
        while (iter.hasNext() && types.size() < limit) {
            DataType dt = iter.next();

            if (filter != null && !dt.getName().toLowerCase().contains(filter)) continue;
            if (category != null && !dt.getCategoryPath().getPath().contains(category)) continue;

            Map<String, Object> t = new LinkedHashMap<>();
            t.put("name", dt.getName());
            t.put("category", dt.getCategoryPath().getPath());
            t.put("size", dt.getLength());
            t.put("kind", getKind(dt));
            t.put("displayName", dt.getDisplayName());

            // Extra detail for structs
            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                List<Map<String, Object>> fields = new ArrayList<>();
                for (DataTypeComponent comp : struct.getDefinedComponents()) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("name", comp.getFieldName());
                    f.put("offset", comp.getOffset());
                    f.put("dataType", comp.getDataType().getDisplayName());
                    f.put("size", comp.getLength());
                    fields.add(f);
                }
                t.put("fields", fields);
            }

            // Extra detail for enums
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
                Map<String, Long> values = new LinkedHashMap<>();
                for (String name : enumDt.getNames()) {
                    values.put(name, enumDt.getValue(name));
                }
                t.put("values", values);
            }

            types.add(t);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("dataTypes", types);
        result.put("count", types.size());
        return result;
    }

    private String getKind(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof FunctionDefinition) return "function_pointer";
        if (dt instanceof Pointer) return "pointer";
        if (dt instanceof Array) return "array";
        return "builtin";
    }
}
