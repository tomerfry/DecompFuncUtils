package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class DecompileFunctionTool implements McpTool {

    private final DecompInterfacePool decompPool;

    public DecompileFunctionTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override
    public String name() { return "ghidra_decompile_function"; }

    @Override
    public String description() {
        return "Decompile a function and return C pseudocode. Specify by address (hex) or function name.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("address", Map.of("type", "string", "description", "Function address in hex (e.g. '0x401000' or '00401000')"));
        props.put("name", Map.of("type", "string", "description", "Function name (if address is not provided)"));
        schema.put("properties", props);

        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Function func = resolveFunction(arguments, program);
        if (func == null) {
            throw new IllegalArgumentException("Function not found. Provide a valid 'address' or 'name'.");
        }

        DecompInterface decomp = decompPool.acquire(program);
        try {
            DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);

            if (!results.decompileCompleted()) {
                throw new RuntimeException("Decompilation failed: " + results.getErrorMessage());
            }

            String cCode = results.getDecompiledFunction().getC();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("address", func.getEntryPoint().toString());
            result.put("decompilation", cCode);
            return result;
        } finally {
            decompPool.release(program, decomp);
        }
    }

    static Function resolveFunction(Map<String, Object> arguments, Program program) {
        String addressStr = (String) arguments.get("address");
        String nameStr = (String) arguments.get("name");

        FunctionManager fm = program.getFunctionManager();

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = McpUtil.parseAddress(addressStr, program);
            Function func = fm.getFunctionAt(addr);
            if (func == null) {
                func = fm.getFunctionContaining(addr);
            }
            return func;
        }

        if (nameStr != null && !nameStr.isEmpty()) {
            for (Function func : fm.getFunctions(true)) {
                if (func.getName().equals(nameStr)) {
                    return func;
                }
            }
            // Try case-insensitive
            for (Function func : fm.getFunctions(true)) {
                if (func.getName().equalsIgnoreCase(nameStr)) {
                    return func;
                }
            }
        }

        return null;
    }
}
