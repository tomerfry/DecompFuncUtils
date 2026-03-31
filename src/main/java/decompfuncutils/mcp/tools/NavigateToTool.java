package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.*;

public class NavigateToTool implements McpTool {

    @Override public String name() { return "ghidra_navigate_to"; }

    @Override
    public String description() {
        return "Navigate Ghidra's UI to a specific address. Moves the cursor in the listing and decompiler views.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Target address in hex")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean isMutating() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        Address addr = McpUtil.parseAddress(addrStr, program);

        GoToService goToService = tool.getService(GoToService.class);
        if (goToService != null) {
            boolean success = goToService.goTo(addr);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addr.toString());
            result.put("navigated", success);
            result.put("status", success ? "navigated" : "navigation_failed");
            return result;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("navigated", false);
        result.put("status", "no_goto_service");
        return result;
    }
}
