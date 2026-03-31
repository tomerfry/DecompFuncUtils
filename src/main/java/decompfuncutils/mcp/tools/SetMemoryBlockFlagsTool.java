package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class SetMemoryBlockFlagsTool implements McpTool {

    @Override public String name() { return "ghidra_set_memory_block_flags"; }

    @Override
    public String description() {
        return "Change memory block permission flags (read/write/execute/volatile/constant) for the block containing the given address.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Any address within the target memory block (hex)"),
            "read", Map.of("type", "boolean", "description", "Set read permission"),
            "write", Map.of("type", "boolean", "description", "Set write permission"),
            "execute", Map.of("type", "boolean", "description", "Set execute permission"),
            "volatile", Map.of("type", "boolean", "description", "Set volatile flag"),
            "constant", Map.of("type", "boolean", "description", "Set constant flag (sets write=false when true)")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        Address addr = McpUtil.parseAddress(addrStr, program);

        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) {
            throw new IllegalArgumentException("No memory block at address: " + addrStr);
        }

        Map<String, Object> oldFlags = Map.of(
            "read", block.isRead(), "write", block.isWrite(),
            "execute", block.isExecute(), "volatile", block.isVolatile()
        );

        if (arguments.containsKey("read")) block.setRead((Boolean) arguments.get("read"));
        if (arguments.containsKey("write")) block.setWrite((Boolean) arguments.get("write"));
        if (arguments.containsKey("execute")) block.setExecute((Boolean) arguments.get("execute"));
        if (arguments.containsKey("volatile")) block.setVolatile((Boolean) arguments.get("volatile"));

        // Constant: setting constant=true means write=false
        if (arguments.containsKey("constant")) {
            boolean isConstant = (Boolean) arguments.get("constant");
            if (isConstant) {
                block.setWrite(false);
            }
        }

        Map<String, Object> newFlags = Map.of(
            "read", block.isRead(), "write", block.isWrite(),
            "execute", block.isExecute(), "volatile", block.isVolatile()
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("blockName", block.getName());
        result.put("start", block.getStart().toString());
        result.put("end", block.getEnd().toString());
        result.put("oldFlags", oldFlags);
        result.put("newFlags", newFlags);
        result.put("status", "flags_updated");
        return result;
    }
}
