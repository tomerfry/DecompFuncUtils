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
        return "Scan a virtual table at a given address. Reads consecutive pointer-sized entries and resolves them to functions. Auto-skips the standard Itanium ABI header (offset-to-top + RTTI typeinfo) when scanning from a vtable base; stops at the first non-function entry after the methods begin.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address of the vtable in hex. Can be the canonical base (offset-to-top) or the first virtual method slot — header is auto-detected."),
            "maxEntries", Map.of("type", "integer", "description", "Maximum entries to scan (default 100)"),
            "tolerateMisses", Map.of("type", "integer", "description", "Extra consecutive non-function entries to skip after the methods begin. Default 0."),
            "skipHeader", Map.of("type", "string", "description", "Itanium ABI header handling: 'auto' (default; skip up to 2 leading non-function slots if real methods follow), 'always' (force-skip 2 slots), 'never'.")
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
        String skipHeader = ((String) arguments.getOrDefault("skipHeader", "auto")).toLowerCase();

        Address addr = McpUtil.parseAddress(addrStr, program);

        int ptrSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager fm = program.getFunctionManager();

        // Detect Itanium ABI header (offset-to-top + RTTI typeinfo). The standard
        // layout puts those two non-function slots immediately before the first
        // virtual method. If the caller pointed at the canonical base, the first
        // 1–2 entries won't resolve to functions — peek ahead and skip them.
        int skip = 0;
        if (skipHeader.equals("always")) {
            skip = 2;
        } else if (skipHeader.equals("auto")) {
            for (int i = 0; i < 2; i++) {
                Address peek = addr.add((long) i * ptrSize);
                if (resolveFunctionAt(peek, ptrSize, memory, fm, program) != null) break;
                Address afterPeek = addr.add((long) (i + 1) * ptrSize);
                if (resolveFunctionAt(afterPeek, ptrSize, memory, fm, program) != null) {
                    skip = i + 1;
                    break;
                }
            }
        }

        List<Map<String, Object>> entries = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();
        Address current = addr;
        int consecutiveMisses = 0;

        // Record skipped header slots for transparency
        for (int i = 0; i < skip; i++) {
            long value;
            try {
                value = (ptrSize == 8) ? memory.getLong(current) : memory.getInt(current) & 0xFFFFFFFFL;
            } catch (Exception e) {
                break;
            }
            Map<String, Object> hdr = new LinkedHashMap<>();
            hdr.put("address", current.toString());
            hdr.put("rawValue", "0x" + Long.toHexString(value));
            hdr.put("role", i == 0 ? "offset_to_top" : "typeinfo_ptr");
            skipped.add(hdr);
            current = current.add(ptrSize);
        }

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
            entry.put("vtableOffset", (skip + i) * ptrSize);
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
        if (!skipped.isEmpty()) result.put("skippedHeader", skipped);
        result.put("entries", entries);
        result.put("entryCount", entries.size());
        result.put("pointerSize", ptrSize);
        return result;
    }

    private static Function resolveFunctionAt(Address slot, int ptrSize, Memory memory,
                                              FunctionManager fm, Program program) {
        try {
            long value = (ptrSize == 8) ? memory.getLong(slot) : memory.getInt(slot) & 0xFFFFFFFFL;
            Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            return fm.getFunctionAt(target);
        } catch (Exception e) {
            return null;
        }
    }
}
