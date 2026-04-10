package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

import java.util.*;

public class RenameLabelTool implements McpTool {

    @Override public String name() { return "ghidra_rename_label"; }

    @Override
    public String description() {
        return "Rename a label (non-function symbol) at a given address. If multiple labels exist at the address, oldName disambiguates.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address in hex"),
            "oldName", Map.of("type", "string", "description", "Current label name (optional disambiguator)"),
            "newName", Map.of("type", "string", "description", "New label name")
        ));
        schema.put("required", List.of("address", "newName"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String oldName = (String) arguments.get("oldName");
        String newName = (String) arguments.get("newName");

        Address addr = McpUtil.parseAddress(addrStr, program);
        SymbolTable st = program.getSymbolTable();
        Symbol[] symbols = st.getSymbols(addr);

        Symbol target = null;
        for (Symbol s : symbols) {
            if (s.getSymbolType() == SymbolType.FUNCTION) continue;
            if (oldName != null && !oldName.isEmpty()) {
                if (s.getName().equals(oldName)) { target = s; break; }
            } else if (target == null) {
                target = s;
            }
        }

        if (target == null) {
            throw new IllegalArgumentException("No matching label at " + addrStr);
        }

        String previous = target.getName();
        target.setName(newName, SourceType.USER_DEFINED);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("oldName", previous);
        result.put("newName", newName);
        result.put("status", "renamed");
        return result;
    }
}
