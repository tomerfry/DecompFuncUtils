package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.TypedefDataType;
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

        // FunctionSignatureParser only consults the program's DataTypeManager —
        // it doesn't know about built-in aliases like uint64_t / size_t. Inject
        // any referenced stdint aliases as typedefs so the parser can resolve them.
        ensureStdintTypedefs(signature, program);

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

    /**
     * Names of stdint / posix aliases that callers commonly use in C signatures
     * but that aren't in the program's DataTypeManager by default. We resolve
     * each via {@link RetypeVariableTool#resolveDataType} (which knows the
     * platform-correct backing type) and add it as a typedef so the signature
     * parser will accept it.
     */
    private static final String[] STDINT_NAMES = {
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "s8", "s16", "s32", "s64",
        "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "off_t", "usize", "isize"
    };

    static void ensureStdintTypedefs(String signature, Program program) {
        if (signature == null) return;
        DataTypeManager dtm = program.getDataTypeManager();
        for (String alias : STDINT_NAMES) {
            if (!containsWord(signature, alias)) continue;
            // Already present in program DTM? skip.
            Iterator<DataType> it = dtm.getAllDataTypes();
            boolean present = false;
            while (it.hasNext()) {
                DataType dt = it.next();
                if (dt.getName().equals(alias)) { present = true; break; }
            }
            if (present) continue;

            DataType resolved = RetypeVariableTool.resolveDataType(alias, program);
            if (resolved == null) continue;
            try {
                TypedefDataType td = new TypedefDataType(new CategoryPath("/stdint"), alias, resolved, dtm);
                dtm.addDataType(td, DataTypeConflictHandler.KEEP_HANDLER);
            } catch (Exception ignored) {
                // Best-effort: if the typedef can't be installed we'll fall through
                // and the parser will surface the original error.
            }
        }
    }

    private static boolean containsWord(String text, String word) {
        int idx = 0;
        while ((idx = text.indexOf(word, idx)) >= 0) {
            boolean leftOk = idx == 0 || !isIdentChar(text.charAt(idx - 1));
            int end = idx + word.length();
            boolean rightOk = end == text.length() || !isIdentChar(text.charAt(end));
            if (leftOk && rightOk) return true;
            idx = end;
        }
        return false;
    }

    private static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
}
