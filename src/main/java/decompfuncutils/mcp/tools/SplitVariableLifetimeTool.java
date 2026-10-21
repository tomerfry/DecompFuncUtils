package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class SplitVariableLifetimeTool implements McpTool {
    public String name() { return "ghidra_split_variable_lifetime"; }
    public String description() {
        return "Split the selected decompiler merge group into a named, type-locked local, like Split Out As New Variable. " +
            "Use selectors from ghidra_get_variable_uses. Splits inferred lifetimes, not arbitrary instruction ranges or storage fields.";
    }
    public boolean isMutating() { return true; }
    public Map<String, Object> inputSchema() {
        var props = DecompilerEditSupport.properties(true);
        props.put("newName", Map.of("type", "string"));
        props.put("newType", Map.of("type", "string", "description", "Optional same-sized data type"));
        return Map.of("type", "object", "properties", props,
            "required", List.of("functionAddress", "operationAddress", "operationTime", "slot", "newName"));
    }
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        String name = DecompilerEditSupport.string(args, "newName");
        try (var edit = new DecompilerEditSupport(args, program)) {
            PcodeOpAST op = edit.operation(args, program);
            int slot = DecompilerEditSupport.integer(args.get("slot"), "slot", -1, op.getNumInputs() - 1);
            Varnode vn = DecompilerEditSupport.varnode(op, slot);
            DecompilerEditSupport.guard(args, vn);
            if (!DecompilerEditSupport.canSplit(vn)) {
                throw new IllegalArgumentException("Selected local has no separable merge group; inspect uses with canSplit=true");
            }
            HighVariable original = vn.getHigh();
            HighSymbol symbol = original.getSymbol();
            if (name.equals(original.getName()) && symbol.isNameLocked() &&
                    vn.getMergeGroup() != original.getRepresentative().getMergeGroup()) {
                throw new IllegalArgumentException("Name is attached to another instance; choose a newName");
            }
            DataType type = symbol.getDataType();
            if (args.containsKey("newType")) {
                type = RetypeVariableTool.resolveDataType(DecompilerEditSupport.string(args, "newType"), program);
                if (type == null) throw new IllegalArgumentException("Unknown newType");
            }
            type = type.clone(program.getDataTypeManager());
            if (type.getLength() != original.getSize()) throw new IllegalArgumentException("newType must match the selected variable size");
            if (Undefined.isUndefined(type)) {
                type = AbstractIntegerDataType.getUnsignedDataType(type.getLength(), program.getDataTypeManager());
            }
            HighVariable split = edit.high.splitOutMergeGroup(original, vn);
            HighFunctionDBUtil.updateDBVariable(split.getSymbol(), name, type, SourceType.USER_DEFINED);
            return Map.of("status", "lifetime_split", "functionAddress", edit.function.getEntryPoint().toString(),
                "originalVariable", original.getName(), "name", name, "dataType", type.getPathName(),
                "mergeGroup", vn.getMergeGroup(), "instances", split.getInstances().length);
        }
    }
}
