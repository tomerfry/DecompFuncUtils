package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

import java.util.*;

public class ScanVtableTool implements McpTool {

    @Override public String name() { return "ghidra_scan_vtable"; }

    @Override
    public String description() {
        return "Scan for a virtual table (vtable) at a given address. Reads consecutive pointer-sized entries and resolves them to functions. By default stops at the first entry that does not point to a function (null, RTTI, or the next vtable).";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address of the vtable in hex"),
            "maxEntries", Map.of("type", "integer", "description", "Maximum entries to scan (default 100)"),
            "tolerateMisses", Map.of("type", "integer", "description", "Number of consecutive non-function entries to skip over before stopping. Default 0 (stop at first miss). Increase only if you know the vtable has embedded data.")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        int maxEntries = ((Number) arguments.getOrDefault("maxEntries", 100)).intValue();
        int tolerateMisses = ((Number) arguments.getOrDefault("tolerateMisses", 0)).intValue();

        Address addr = McpUtil.parseAddress(addrStr, program);

        int ptrSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager fm = program.getFunctionManager();

        List<Map<String, Object>> entries = new ArrayList<>();
        Address current = addr;
        int consecutiveMisses = 0;

        for (int i = 0; i < maxEntries; i++) {
            long value;
            try {
                if (ptrSize == 8) {
                    value = memory.getLong(current);
                } else {
                    value = memory.getInt(current) & 0xFFFFFFFFL;
                }
            } catch (Exception e) {
                break; // Out of bounds
            }

            Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            Function func = fm.getFunctionAt(targetAddr);

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("vtableOffset", i * ptrSize);
            entry.put("address", current.toString());
            entry.put("targetAddress", targetAddr.toString());

            if (func != null) {
                entry.put("functionName", func.getName());
                entry.put("signature", func.getPrototypeString(false, false));
                entry.put("isResolved", true);
                consecutiveMisses = 0;
                entries.add(entry);
            } else {
                entry.put("isResolved", false);
                consecutiveMisses++;
                if (consecutiveMisses > tolerateMisses) break;
                entries.add(entry);
            }

            current = current.add(ptrSize);
        }

        // Remove trailing unresolved entries
        while (!entries.isEmpty() && !(Boolean) entries.get(entries.size() - 1).get("isResolved")) {
            entries.remove(entries.size() - 1);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("vtableAddress", addr.toString());
        result.put("entries", entries);
        result.put("entryCount", entries.size());
        result.put("pointerSize", ptrSize);
        return result;
    }
}
