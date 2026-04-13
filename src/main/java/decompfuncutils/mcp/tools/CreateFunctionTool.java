package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class CreateFunctionTool implements McpTool {

    @Override public String name() { return "ghidra_create_function"; }

    @Override
    public String description() {
        return "Define a function starting at an address. If the bytes are undefined, they will be disassembled first. Optionally specify a name and end address.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Function entry point address in hex"),
            "name", Map.of("type", "string", "description", "Function name (optional, auto-generated if omitted)"),
            "endAddress", Map.of("type", "string", "description", "Function end address in hex (optional, auto-detected if omitted)"),
            "overwrite", Map.of("type", "boolean", "description", "If true and a function already exists at this address, remove it first (then recreate with the requested name/body). Default false.")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String name = (String) arguments.getOrDefault("name", null);
        String endAddrStr = (String) arguments.getOrDefault("endAddress", null);
        boolean overwrite = (Boolean) arguments.getOrDefault("overwrite", Boolean.FALSE);

        Address entryPoint = McpUtil.parseAddress(addrStr, program);

        // Check if function already exists
        Function existing = program.getFunctionManager().getFunctionAt(entryPoint);
        if (existing != null) {
            if (!overwrite) {
                throw new IllegalArgumentException("Function already exists at " + addrStr + ": " +
                    existing.getName() + ". Pass overwrite=true to replace it, or use rename_function to rename.");
            }
            program.getFunctionManager().removeFunction(entryPoint);
        }

        AddressSet body = null;
        if (endAddrStr != null) {
            Address endAddr = McpUtil.parseAddress(endAddrStr, program);
            body = new AddressSet(entryPoint, endAddr);
        }

        CreateFunctionCmd cmd;
        if (body != null) {
            cmd = new CreateFunctionCmd(name, entryPoint, body, SourceType.USER_DEFINED);
        } else {
            cmd = new CreateFunctionCmd(entryPoint);
        }

        boolean success = cmd.applyTo(program);
        if (!success) {
            throw new RuntimeException("Failed to create function: " + cmd.getStatusMsg());
        }

        Function func = program.getFunctionManager().getFunctionAt(entryPoint);
        if (func == null) {
            throw new RuntimeException("Function creation succeeded but function not found at entry point");
        }

        // Set name if provided and not already set by cmd
        if (name != null && !name.isEmpty() && !func.getName().equals(name)) {
            func.setName(name, SourceType.USER_DEFINED);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("size", func.getBody().getNumAddresses());
        result.put("status", "function_created");
        return result;
    }
}
