package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

import java.util.*;

public class ClearListingTool implements McpTool {

    @Override public String name() { return "ghidra_clear_listing"; }

    @Override
    public String description() {
        return "Clear code/data definitions at an address range, reverting bytes to undefined. This removes instructions and data definitions but preserves the raw bytes.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Start address in hex"),
            "length", Map.of("type", "integer", "description", "Number of bytes to clear")
        ));
        schema.put("required", List.of("address", "length"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        int length = ((Number) arguments.get("length")).intValue();

        Address start = McpUtil.parseAddress(addrStr, program);
        Address end = start.add(length - 1);
        AddressSet range = new AddressSet(start, end);

        program.getListing().clearCodeUnits(start, end, false);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("start", start.toString());
        result.put("end", end.toString());
        result.put("bytesCleared", length);
        result.put("status", "listing_cleared");
        return result;
    }
}
