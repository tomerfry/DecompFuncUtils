package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class SearchMemoryTool implements McpTool {

    @Override public String name() { return "ghidra_search_memory"; }

    @Override
    public String description() {
        return "Search program memory for a byte pattern or string. Returns all matching addresses. " +
               "Encoding: 'hex' for hex bytes (e.g. '90 90 cc'), 'ascii' for ASCII string, 'utf16' for UTF-16 string.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "pattern", Map.of("type", "string", "description", "Search pattern"),
            "encoding", Map.of("type", "string", "description", "Pattern encoding: hex, ascii, utf16 (default: ascii)"),
            "maxResults", Map.of("type", "integer", "description", "Maximum number of results (default 50)")
        ));
        schema.put("required", List.of("pattern"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String pattern = (String) arguments.get("pattern");
        String encoding = ((String) arguments.getOrDefault("encoding", "ascii")).toLowerCase();
        int maxResults = ((Number) arguments.getOrDefault("maxResults", 50)).intValue();

        byte[] searchBytes;
        switch (encoding) {
            case "hex":
                searchBytes = hexToBytes(pattern);
                break;
            case "utf16":
                searchBytes = pattern.getBytes(StandardCharsets.UTF_16LE);
                break;
            case "ascii":
            default:
                searchBytes = pattern.getBytes(StandardCharsets.US_ASCII);
                break;
        }

        Memory memory = program.getMemory();
        Address start = memory.getMinAddress();
        List<Map<String, Object>> matches = new ArrayList<>();

        while (start != null && matches.size() < maxResults) {
            Address found = memory.findBytes(start, searchBytes, null, true, null);
            if (found == null) break;

            Map<String, Object> match = new LinkedHashMap<>();
            match.put("address", found.toString());

            // Try to find containing function
            Function func = program.getFunctionManager().getFunctionContaining(found);
            if (func != null) {
                match.put("function", func.getName());
                match.put("functionAddress", func.getEntryPoint().toString());
            }

            // Context: show surrounding bytes
            byte[] context = new byte[Math.min(32, (int) (memory.getMaxAddress().getOffset() - found.getOffset()))];
            try {
                memory.getBytes(found, context);
                StringBuilder hex = new StringBuilder();
                for (byte b : context) hex.append(String.format("%02x ", b & 0xFF));
                match.put("contextHex", hex.toString().trim());
            } catch (Exception ignored) {}

            matches.add(match);
            start = found.add(1);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("pattern", pattern);
        result.put("encoding", encoding);
        result.put("matches", matches);
        result.put("matchCount", matches.size());
        return result;
    }

    private byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("Hex string must have even length");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
