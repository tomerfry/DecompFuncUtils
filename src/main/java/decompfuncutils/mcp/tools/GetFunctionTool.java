package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class GetFunctionTool implements McpTool {

    @Override
    public String name() { return "ghidra_get_function"; }

    @Override
    public String description() {
        return "Get detailed info about a function: signature, parameters, local variables, stack frame, calling convention, and cross-references count.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("address", Map.of("type", "string", "description", "Function address in hex"));
        props.put("name", Map.of("type", "string", "description", "Function name"));
        schema.put("properties", props);

        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Function func = DecompileFunctionTool.resolveFunction(arguments, program);
        if (func == null) {
            throw new IllegalArgumentException("Function not found. Provide a valid 'address' or 'name'.");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("signature", func.getPrototypeString(true, true));
        result.put("callingConvention", func.getCallingConventionName());
        result.put("isThunk", func.isThunk());
        result.put("isExternal", func.isExternal());
        result.put("size", func.getBody().getNumAddresses());

        // Parameters
        List<Map<String, Object>> params = new ArrayList<>();
        for (Parameter param : func.getParameters()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("name", param.getName());
            p.put("dataType", param.getDataType().getDisplayName());
            p.put("size", param.getLength());
            p.put("storage", param.getVariableStorage().toString());
            p.put("ordinal", param.getOrdinal());
            params.add(p);
        }
        result.put("parameters", params);

        // Return type
        result.put("returnType", func.getReturnType().getDisplayName());

        // Local variables
        List<Map<String, Object>> locals = new ArrayList<>();
        for (Variable var : func.getLocalVariables()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("name", var.getName());
            v.put("dataType", var.getDataType().getDisplayName());
            v.put("size", var.getLength());
            v.put("storage", var.getVariableStorage().toString());
            locals.add(v);
        }
        result.put("localVariables", locals);

        // Stack frame
        if (func.getStackFrame() != null) {
            Map<String, Object> frame = new LinkedHashMap<>();
            frame.put("frameSize", func.getStackFrame().getFrameSize());
            frame.put("localSize", func.getStackFrame().getLocalSize());
            frame.put("parameterSize", func.getStackFrame().getParameterSize());
            result.put("stackFrame", frame);
        }

        // Xref counts
        ReferenceManager refMgr = program.getReferenceManager();
        int xrefsTo = refMgr.getReferenceCountTo(func.getEntryPoint());
        result.put("xrefsToCount", xrefsTo);

        return result;
    }
}
