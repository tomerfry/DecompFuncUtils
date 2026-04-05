package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import java.util.*;

public class ReadMemoryTool implements McpTool {

    @Override
    public String name() { return "ghidra_read_memory"; }

    @Override
    public String description() {
        return "Read raw bytes from memory at a given address. Returns hex dump and ASCII representation. Max 4096 bytes per read.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Start address in hex"),
            "length", Map.of("type", "integer", "description", "Number of bytes to read (default 256, max 4096)")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        int length = Math.min(((Number) arguments.getOrDefault("length", 256)).intValue(), 4096);

        Address addr = McpUtil.parseAddress(addrStr, program);

        Memory memory = program.getMemory();
        byte[] bytes = new byte[length];
        int bytesRead = memory.getBytes(addr, bytes);

        // Build hex dump
        StringBuilder hexDump = new StringBuilder();
        StringBuilder asciiLine = new StringBuilder();
        for (int i = 0; i < bytesRead; i++) {
            if (i > 0 && i % 16 == 0) {
                hexDump.append("  ").append(asciiLine).append("\n");
                asciiLine.setLength(0);
            }
            if (i % 16 == 0) {
                hexDump.append(String.format("%s: ", addr.add(i).toString()));
            }
            hexDump.append(String.format("%02x ", bytes[i] & 0xFF));
            char c = (char) (bytes[i] & 0xFF);
            asciiLine.append(c >= 32 && c < 127 ? c : '.');
        }
        // Pad last line
        int remainder = bytesRead % 16;
        if (remainder != 0) {
            for (int i = remainder; i < 16; i++) {
                hexDump.append("   ");
            }
        }
        hexDump.append("  ").append(asciiLine);

        // Also provide raw hex string
        StringBuilder rawHex = new StringBuilder();
        for (int i = 0; i < bytesRead; i++) {
            rawHex.append(String.format("%02x", bytes[i] & 0xFF));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("bytesRead", bytesRead);
        result.put("hexDump", hexDump.toString());
        result.put("rawHex", rawHex.toString());
        return result;
    }
}
