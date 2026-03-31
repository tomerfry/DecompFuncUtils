package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.*;

public class CreateBookmarkTool implements McpTool {

    @Override public String name() { return "ghidra_create_bookmark"; }

    @Override
    public String description() {
        return "Create a bookmark at a given address with a category and comment.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address in hex"),
            "category", Map.of("type", "string", "description", "Bookmark category (e.g. 'AI Analysis')"),
            "comment", Map.of("type", "string", "description", "Bookmark comment text")
        ));
        schema.put("required", List.of("address", "category", "comment"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String category = (String) arguments.get("category");
        String comment = (String) arguments.get("comment");

        Address addr = McpUtil.parseAddress(addrStr, program);

        program.getBookmarkManager().setBookmark(addr, "Note", category, comment);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("category", category);
        result.put("comment", comment);
        result.put("status", "bookmark_created");
        return result;
    }
}
