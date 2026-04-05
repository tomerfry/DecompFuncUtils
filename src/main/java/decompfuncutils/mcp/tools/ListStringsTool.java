package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;

import java.util.*;

public class ListStringsTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_strings"; }

    @Override
    public String description() {
        return "List defined strings in the program with optional filtering. Returns address, value, and length.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("filter", Map.of("type", "string", "description", "Substring filter on string value (case-insensitive)"));
        props.put("limit", Map.of("type", "integer", "description", "Maximum number of strings to return (default 100, max 1000)"));
        schema.put("properties", props);

        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filter = (String) arguments.getOrDefault("filter", null);
        int limit = Math.min(((Number) arguments.getOrDefault("limit", 100)).intValue(), 1000);

        if (filter != null) {
            filter = filter.toLowerCase();
        }

        List<Map<String, Object>> strings = new ArrayList<>();

        DataIterator iter = program.getListing().getDefinedData(true);
        while (iter.hasNext() && strings.size() < limit) {
            Data data = iter.next();
            if (!data.hasStringValue()) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null) continue;

            if (filter != null && !value.toLowerCase().contains(filter)) {
                continue;
            }

            Map<String, Object> s = new LinkedHashMap<>();
            s.put("address", data.getAddress().toString());
            s.put("value", value.length() > 500 ? value.substring(0, 500) + "..." : value);
            s.put("length", value.length());
            s.put("dataType", data.getDataType().getDisplayName());
            strings.add(s);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("strings", strings);
        result.put("count", strings.size());
        return result;
    }
}
