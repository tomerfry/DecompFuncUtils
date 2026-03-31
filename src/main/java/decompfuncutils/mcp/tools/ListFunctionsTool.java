package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class ListFunctionsTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_functions"; }

    @Override
    public String description() {
        return "List functions in the program with optional name filtering and pagination. Returns name, address, size, and signature.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("filter", Map.of("type", "string", "description", "Substring filter on function name (case-insensitive)"));
        props.put("offset", Map.of("type", "integer", "description", "Number of functions to skip (default 0)"));
        props.put("limit", Map.of("type", "integer", "description", "Maximum number of functions to return (default 100, max 500)"));
        schema.put("properties", props);

        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filter = (String) arguments.getOrDefault("filter", null);
        int offset = ((Number) arguments.getOrDefault("offset", 0)).intValue();
        int limit = Math.min(((Number) arguments.getOrDefault("limit", 100)).intValue(), 500);

        if (filter != null) {
            filter = filter.toLowerCase();
        }

        FunctionManager fm = program.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);

        List<Map<String, Object>> functions = new ArrayList<>();
        int skipped = 0;
        int total = 0;

        while (iter.hasNext() && functions.size() < limit) {
            Function func = iter.next();
            String funcName = func.getName();

            if (filter != null && !funcName.toLowerCase().contains(filter)) {
                continue;
            }

            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }

            Map<String, Object> f = new LinkedHashMap<>();
            f.put("name", funcName);
            f.put("address", func.getEntryPoint().toString());
            f.put("size", func.getBody().getNumAddresses());
            f.put("signature", func.getPrototypeString(false, false));
            f.put("isThunk", func.isThunk());
            f.put("isExternal", func.isExternal());
            f.put("callingConvention", func.getCallingConventionName());

            // Source type indicates if user-defined or auto-analysis
            SourceType src = func.getSymbol().getSource();
            f.put("source", src.toString());

            functions.add(f);
        }

        // Count remaining if we stopped early
        while (iter.hasNext()) {
            Function func = iter.next();
            if (filter == null || func.getName().toLowerCase().contains(filter)) {
                total++;
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("functions", functions);
        result.put("totalMatching", total);
        result.put("offset", offset);
        result.put("limit", limit);
        return result;
    }
}
