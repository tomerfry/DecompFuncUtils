package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.util.*;

public class DisassembleTool implements McpTool {

    @Override public String name() { return "ghidra_disassemble"; }

    @Override
    public String description() {
        return "Disassemble undefined bytes as code instructions starting at the given address. If no length is specified, follows flow to determine extent.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Start address in hex"),
            "length", Map.of("type", "integer", "description", "Number of bytes to disassemble (optional, follows flow if omitted)")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        Address start = McpUtil.parseAddress(addrStr, program);

        AddressSet restrictedSet = null;
        if (arguments.containsKey("length")) {
            int length = ((Number) arguments.get("length")).intValue();
            Address end = start.add(length - 1);
            restrictedSet = new AddressSet(start, end);
        }

        DisassembleCommand cmd = new DisassembleCommand(start, restrictedSet, true);
        boolean success = cmd.applyTo(program);

        // Count new instructions
        int instructionCount = 0;
        Listing listing = program.getListing();
        InstructionIterator iter = listing.getInstructions(start, true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            if (restrictedSet != null && !restrictedSet.contains(inst.getAddress())) break;
            instructionCount++;
            if (restrictedSet == null && instructionCount > 10000) break; // safety limit
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("startAddress", start.toString());
        result.put("instructionsCreated", instructionCount);
        result.put("success", success);
        if (!success) {
            result.put("message", cmd.getStatusMsg());
        }
        result.put("status", "disassembled");
        return result;
    }
}
