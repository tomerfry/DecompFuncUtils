package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

import java.util.*;

public class ListSymbolsTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_symbols"; }

    @Override
    public String description() {
        return "List symbols in the program with optional name filter and type filter. Types: FUNCTION, LABEL, CLASS, NAMESPACE, PARAMETER, LOCAL_VAR, GLOBAL_VAR, LIBRARY.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("filter", Map.of("type", "string", "description", "Substring filter on symbol name (case-insensitive)"));
        props.put("type", Map.of("type", "string", "description", "Symbol type filter (e.g. FUNCTION, LABEL, CLASS)"));
        props.put("limit", Map.of("type", "integer", "description", "Maximum results (default 100, max 500)"));
        schema.put("properties", props);

        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filter = (String) arguments.getOrDefault("filter", null);
        String typeFilter = (String) arguments.getOrDefault("type", null);
        int limit = Math.min(((Number) arguments.getOrDefault("limit", 100)).intValue(), 500);

        if (filter != null) filter = filter.toLowerCase();

        SymbolType symType = null;
        if (typeFilter != null) {
            symType = parseSymbolType(typeFilter);
        }

        SymbolTable st = program.getSymbolTable();
        SymbolIterator iter = st.getAllSymbols(true);

        List<Map<String, Object>> symbols = new ArrayList<>();
        while (iter.hasNext() && symbols.size() < limit) {
            Symbol sym = iter.next();

            if (symType != null && sym.getSymbolType() != symType) continue;
            if (filter != null && !sym.getName().toLowerCase().contains(filter)) continue;

            Map<String, Object> s = new LinkedHashMap<>();
            s.put("name", sym.getName());
            s.put("address", sym.getAddress().toString());
            s.put("type", sym.getSymbolType().toString());
            s.put("source", sym.getSource().toString());
            s.put("namespace", sym.getParentNamespace().getName());
            s.put("isPrimary", sym.isPrimary());
            symbols.add(s);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("symbols", symbols);
        result.put("count", symbols.size());
        return result;
    }

    private SymbolType parseSymbolType(String type) {
        switch (type.toUpperCase()) {
            case "FUNCTION": return SymbolType.FUNCTION;
            case "LABEL": return SymbolType.LABEL;
            case "CLASS": return SymbolType.CLASS;
            case "NAMESPACE": return SymbolType.NAMESPACE;
            case "PARAMETER": return SymbolType.PARAMETER;
            case "LOCAL_VAR": return SymbolType.LOCAL_VAR;
            case "GLOBAL_VAR": return SymbolType.GLOBAL_VAR;
            case "LIBRARY": return SymbolType.LIBRARY;
            default: return null;
        }
    }
}
