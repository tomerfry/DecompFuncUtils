package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.util.*;

public class ClearAndRepairTool implements McpTool {

    @Override public String name() { return "ghidra_clear_and_repair"; }

    @Override
    public String description() {
        return "Clear code at an address range and re-disassemble with flow following. Useful for fixing bad disassembly or misaligned instructions.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Start address in hex"),
            "length", Map.of("type", "integer", "description", "Number of bytes to clear and re-disassemble")
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

        // Step 1: Clear existing code units
        program.getListing().clearCodeUnits(start, end, false);

        // Step 2: Re-disassemble
        AddressSet range = new AddressSet(start, end);
        DisassembleCommand cmd = new DisassembleCommand(start, range, true);
        boolean success = cmd.applyTo(program);

        // Count new instructions
        int instructionCount = 0;
        InstructionIterator iter = program.getListing().getInstructions(start, true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            if (!range.contains(inst.getAddress())) break;
            instructionCount++;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("startAddress", start.toString());
        result.put("endAddress", end.toString());
        result.put("bytesProcessed", length);
        result.put("instructionsCreated", instructionCount);
        result.put("success", success);
        if (!success) {
            result.put("message", cmd.getStatusMsg());
        }
        result.put("status", "cleared_and_repaired");
        return result;
    }
}
