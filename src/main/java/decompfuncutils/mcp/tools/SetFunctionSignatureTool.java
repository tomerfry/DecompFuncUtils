package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class SetFunctionSignatureTool implements McpTool {

    @Override public String name() { return "ghidra_set_function_signature"; }

    @Override
    public String description() {
        return "Set the full function signature/prototype (return type, name, parameters). Example: 'int myFunc(char *buf, int size)'";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Function address in hex"),
            "name", Map.of("type", "string", "description", "Function name (if address not provided)"),
            "signature", Map.of("type", "string", "description", "Full C-style function signature, e.g. 'int myFunc(char *buf, int size)'")
        ));
        schema.put("required", List.of("signature"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Function func = DecompileFunctionTool.resolveFunction(arguments, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        String signature = (String) arguments.get("signature");
        String oldSig = func.getPrototypeString(true, false);

        FunctionSignatureParser parser = new FunctionSignatureParser(
            program.getDataTypeManager(), null);
        FunctionDefinitionDataType funcDef = parser.parse(func.getSignature(), signature);

        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
            func.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
        if (!cmd.applyTo(program)) {
            throw new RuntimeException("Failed to apply signature: " + cmd.getStatusMsg());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", func.getEntryPoint().toString());
        result.put("oldSignature", oldSig);
        result.put("newSignature", func.getPrototypeString(true, false));
        result.put("status", "signature_updated");
        return result;
    }
}
