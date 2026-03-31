package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.util.*;

public class SetCommentTool implements McpTool {

    @Override public String name() { return "ghidra_set_comment"; }

    @Override
    public String description() {
        return "Set a comment at a given address. Comment types: EOL (end of line), PRE (before), POST (after), PLATE (block header), REPEATABLE.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address in hex"),
            "comment", Map.of("type", "string", "description", "Comment text"),
            "type", Map.of("type", "string", "description", "Comment type: EOL, PRE, POST, PLATE, REPEATABLE (default EOL)")
        ));
        schema.put("required", List.of("address", "comment"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String comment = (String) arguments.get("comment");
        String typeStr = ((String) arguments.getOrDefault("type", "EOL")).toUpperCase();

        Address addr = McpUtil.parseAddress(addrStr, program);

        int commentType;
        switch (typeStr) {
            case "EOL": commentType = CodeUnit.EOL_COMMENT; break;
            case "PRE": commentType = CodeUnit.PRE_COMMENT; break;
            case "POST": commentType = CodeUnit.POST_COMMENT; break;
            case "PLATE": commentType = CodeUnit.PLATE_COMMENT; break;
            case "REPEATABLE": commentType = CodeUnit.REPEATABLE_COMMENT; break;
            default: throw new IllegalArgumentException("Invalid comment type: " + typeStr);
        }

        CodeUnit cu = program.getListing().getCodeUnitAt(addr);
        if (cu == null) {
            cu = program.getListing().getCodeUnitContaining(addr);
        }
        if (cu == null) {
            throw new IllegalArgumentException("No code unit at address: " + addrStr);
        }

        cu.setComment(commentType, comment);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("commentType", typeStr);
        result.put("comment", comment);
        result.put("status", "comment_set");
        return result;
    }
}
