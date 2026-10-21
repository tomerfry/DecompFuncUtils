package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.math.BigDecimal;
import java.util.*;

/** Replaces intersecting persisted stack locals in one MCP transaction. */
public class ReplaceStackVariablesTool implements McpTool {
    private static final int MAX_VARIABLES = 1000;

    @Override public String name() { return "ghidra_replace_stack_variables"; }

    @Override public String description() {
        return "Bulk-create typed stack locals, removing every persisted local whose storage overlaps " +
            "a requested byte range, including partial overlaps and different first-use offsets. " +
            "Use this to replace fragmented locals with arrays or structs. Offsets are Ghidra stack " +
            "offsets, not raw SP/FP displacements; new locals have firstUseOffset 0. " +
            "Parameters and compound storage are protected. The batch is atomic. " +
            "dryRun previews removed/created variables without changing the database. " +
            "Decompiler-only locals need not be committed first.";
    }

    @Override public Map<String, Object> inputSchema() {
        Map<String, Object> variable = Map.of("type", "object", "properties", Map.of(
            "name", Map.of("type", "string", "description", "New local variable name"),
            "dataType", Map.of("type", "string", "description", "Fixed-size type, e.g. char[64], MyStruct, or MyStruct *"),
            "stackOffset", Map.of("oneOf", List.of(Map.of("type", "integer"), Map.of("type", "string")),
                "description", "Signed 32-bit Ghidra stack offset: integer, decimal string, or signed 0x hex string")),
            "required", List.of("name", "dataType", "stackOffset"), "additionalProperties", false);
        return Map.of("type", "object", "properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Function address in hex (takes precedence)"),
            "functionName", Map.of("type", "string", "description", "Exact unique function name, optionally namespace-qualified"),
            "variables", Map.of("type", "array", "minItems", 1, "maxItems", MAX_VARIABLES, "items", variable),
            "dryRun", Map.of("type", "boolean", "default", false)),
            "required", List.of("variables"),
            "anyOf", List.of(Map.of("required", List.of("functionAddress")), Map.of("required", List.of("functionName"))));
    }

    @Override public boolean isMutating() { return true; }

    @Override public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        boolean dryRun = arguments.containsKey("dryRun")
            ? FunctionEditSupport.booleanValue(arguments.get("dryRun"), "dryRun") : false;
        Function function = FunctionEditSupport.resolve(arguments, program, "functionAddress", "functionName");
        if (function.isExternal() || function.isThunk()) {
            throw new IllegalArgumentException("Stack locals require a non-external, non-thunk function");
        }
        Object raw = arguments.get("variables");
        if (!(raw instanceof List<?>) || ((List<?>) raw).isEmpty() || ((List<?>) raw).size() > MAX_VARIABLES) {
            throw new IllegalArgumentException("variables must contain 1 to " + MAX_VARIABLES + " entries");
        }

        // Build and validate the entire replacement layout before removing anything.
        List<Variable> replacements = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (Object item : (List<?>) raw) {
            McpUtil.activeMonitor().checkCancelled();
            if (!(item instanceof Map<?, ?>)) throw new IllegalArgumentException("Each variable must be an object");
            Map<?, ?> entry = (Map<?, ?>) item;
            for (Object key : entry.keySet()) {
                if (!Set.of("name", "dataType", "stackOffset").contains(key)) {
                    throw new IllegalArgumentException("Unknown variable property: " + key);
                }
            }
            String name = FunctionEditSupport.requiredString(entry.get("name"), "name");
            SymbolUtilities.validateName(name);
            if (!names.add(name)) throw new IllegalArgumentException("Duplicate replacement name: " + name);
            String typeName = FunctionEditSupport.requiredString(entry.get("dataType"), "dataType");
            DataType type = RetypeVariableTool.resolveDataType(typeName, program);
            if (type == null) throw new IllegalArgumentException("Unknown data type: " + typeName);
            // Clone before sizing: built-in C types depend on the program's data organization.
            type = type.clone(program.getDataTypeManager());
            if (type.getLength() <= 0) throw new IllegalArgumentException("Type must have fixed positive size: " + typeName);
            int offset = parseOffset(entry.get("stackOffset"));
            long last = (long) offset + type.getLength() - 1;
            if (last > Integer.MAX_VALUE || (offset < 0 && last >= 0)) {
                throw new IllegalArgumentException("Stack range overflows or crosses zero: " + name);
            }
            if (function.getStackFrame().isParameterOffset(offset) ||
                    function.getStackFrame().isParameterOffset((int) last)) {
                throw new IllegalArgumentException("Stack range enters parameter area: " + name);
            }
            Variable replacement = new LocalVariableImpl(name, type, offset, program, SourceType.USER_DEFINED);
            for (Variable other : replacements) {
                if (replacement.getVariableStorage().intersects(other.getVariableStorage())) {
                    throw new IllegalArgumentException("Replacement ranges overlap: " + other.getName() + " and " + name);
                }
            }
            replacements.add(replacement);
        }

        Set<Variable> removed = new LinkedHashSet<>();
        for (Variable existing : function.getAllVariables()) {
            for (Variable replacement : replacements) {
                if (!existing.getVariableStorage().intersects(replacement.getVariableStorage())) continue;
                if (existing instanceof Parameter || !existing.getVariableStorage().isStackStorage()) {
                    throw new IllegalArgumentException("Replacement overlaps protected parameter or compound storage: " + existing.getName());
                }
                removed.add(existing);
            }
        }
        for (Variable existing : function.getAllVariables()) {
            if (!removed.contains(existing) && names.contains(existing.getName())) {
                throw new IllegalArgumentException("Name belongs to an unaffected variable: " + existing.getName());
            }
        }

        List<Map<String, Object>> removedInfo = new ArrayList<>();
        for (Variable variable : removed) removedInfo.add(describe(variable));
        List<Map<String, Object>> createdInfo = new ArrayList<>();
        if (dryRun) {
            for (Variable variable : replacements) createdInfo.add(describe(variable));
        } else {
            // The MCP dispatcher owns the transaction and rolls back every deletion/addition on error.
            for (Variable variable : removed) {
                McpUtil.activeMonitor().checkCancelled();
                function.removeVariable(variable);
            }
            for (Variable variable : replacements) {
                McpUtil.activeMonitor().checkCancelled();
                createdInfo.add(describe(function.addLocalVariable(variable, SourceType.USER_DEFINED)));
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", function.getName(true));
        result.put("functionAddress", function.getEntryPoint().toString());
        result.put("dryRun", dryRun);
        result.put("removedVariables", removedInfo);
        result.put("createdVariables", createdInfo);
        result.put("status", dryRun ? "preview" : "replaced");
        return result;
    }

    private static int parseOffset(Object value) {
        try {
            if (value instanceof Number) return new BigDecimal(value.toString()).intValueExact();
            if (value instanceof String) {
                String text = ((String) value).trim();
                if (text.matches("[+-]?0[xX][0-9a-fA-F]+")) return Math.toIntExact(Long.decode(text));
                if (text.matches("[+-]?[0-9]+")) return Integer.parseInt(text);
            }
        } catch (ArithmeticException | NumberFormatException ignored) {
            // Report the same actionable error for fractional and out-of-range inputs.
        }
        throw new IllegalArgumentException("stackOffset must be a signed 32-bit integer or decimal/0x hex string");
    }

    private static Map<String, Object> describe(Variable variable) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", variable.getName());
        info.put("dataType", variable.getDataType().getDisplayName());
        info.put("stackOffset", variable.getStackOffset());
        info.put("size", variable.getLength());
        info.put("firstUseOffset", variable.getFirstUseOffset());
        info.put("comment", variable.getComment());
        return info;
    }
}
