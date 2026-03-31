package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;

import java.util.*;

/**
 * Placeholder for fuzzer generation integration.
 * The full LibAFLFuzzerGeneratorPlugin requires extensive UI interaction
 * (stub configuration, architecture selection, etc.). This tool provides
 * basic info needed for fuzzer generation and delegates to the main plugin.
 */
public class GenerateFuzzerTool implements McpTool {

    @Override public String name() { return "ghidra_generate_fuzzer"; }

    @Override
    public String description() {
        return "Get information needed to generate a LibAFL fuzzer for a target function. " +
               "Returns function details, architecture, external dependencies, and memory map. " +
               "Use this info to configure and generate a fuzzer harness.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Target function address in hex"),
            "functionName", Map.of("type", "string", "description", "Target function name")
        ));
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("functionName", func.getName());
        result.put("functionAddress", func.getEntryPoint().toString());
        result.put("signature", func.getPrototypeString(true, true));

        // Architecture info
        result.put("processor", program.getLanguage().getProcessor().toString());
        result.put("pointerSize", program.getDefaultPointerSize());
        result.put("endianness", program.getLanguage().isBigEndian() ? "big" : "little");

        // External function calls
        List<Map<String, Object>> externalCalls = new ArrayList<>();
        for (Function called : func.getCalledFunctions(null)) {
            if (called.isExternal() || called.isThunk()) {
                Map<String, Object> ext = new LinkedHashMap<>();
                ext.put("name", called.getName());
                ext.put("address", called.getEntryPoint().toString());
                ext.put("isExternal", called.isExternal());
                ext.put("isThunk", called.isThunk());
                externalCalls.add(ext);
            }
        }
        result.put("externalCalls", externalCalls);

        // Parameters for harness input
        List<Map<String, Object>> params = new ArrayList<>();
        for (Parameter param : func.getParameters()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("name", param.getName());
            p.put("type", param.getDataType().getDisplayName());
            p.put("size", param.getLength());
            params.add(p);
        }
        result.put("parameters", params);

        result.put("hint", "Use the LibAFL Fuzzer Generator plugin in Ghidra for full interactive generation, " +
                           "or use this info to manually create a fuzzer harness.");
        return result;
    }
}
