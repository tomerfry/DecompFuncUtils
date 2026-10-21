package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import java.util.*;

/** Exposes selectors that GUI actions normally obtain from a clicked decompiler token. */
public class GetVariableUsesTool implements McpTool {
    public String name() { return "ghidra_get_variable_uses"; }
    public String description() {
        return "Inspect decompiler variable uses, merge groups and union fields. Returns exact operationAddress, " +
            "operationTime and slot selectors for lifetime splitting and union selection. Refresh after each edit.";
    }
    public boolean requiresEdt() { return false; }
    public Map<String, Object> inputSchema() {
        var props = DecompilerEditSupport.properties(false);
        props.put("variableName", Map.of("type", "string", "description", "Optional exact high variable name filter"));
        props.put("operationAddress", Map.of("type", "string", "description", "Optional instruction address filter"));
        props.put("offset", Map.of("type", "integer", "minimum", 0, "default", 0));
        props.put("limit", Map.of("type", "integer", "minimum", 1, "maximum", 500, "default", 100));
        return Map.of("type", "object", "properties", props, "required", List.of("functionAddress"));
    }
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        int offset = DecompilerEditSupport.integer(args.getOrDefault("offset", 0), "offset", 0, Integer.MAX_VALUE);
        int limit = DecompilerEditSupport.integer(args.getOrDefault("limit", 100), "limit", 1, 500);
        String name = args.containsKey("variableName") ? DecompilerEditSupport.string(args, "variableName") : null;
        var address = args.containsKey("operationAddress") ? McpUtil.parseAddress(
            DecompilerEditSupport.string(args, "operationAddress"), program) : null;
        try (var edit = new DecompilerEditSupport(args, program)) {
            List<Map<String, Object>> uses = new ArrayList<>();
            int count = 0;
            Iterator<PcodeOpAST> ops = address == null ? edit.high.getPcodeOps() : edit.high.getPcodeOps(address);
            while (ops.hasNext()) {
                McpUtil.activeMonitor().checkCancelled();
                PcodeOpAST op = ops.next();
                for (int slot = -1; slot < op.getNumInputs(); slot++) {
                    Varnode vn = slot == -1 ? op.getOutput() : op.getInput(slot);
                    if (vn == null || vn.getHigh() == null || vn.isConstant()) continue;
                    HighVariable high = vn.getHigh();
                    if (name != null && !name.equals(high.getName())) continue;
                    if (count++ < offset || uses.size() >= limit) continue;
                    Map<String, Object> use = new LinkedHashMap<>();
                    use.put("operationAddress", op.getSeqnum().getTarget().toString());
                    use.put("operationTime", op.getSeqnum().getTime());
                    use.put("opcode", op.getMnemonic());
                    use.put("slot", slot);
                    use.put("variable", high.getName());
                    use.put("dataType", high.getDataType().getPathName());
                    use.put("storage", vn.getAddress().toString());
                    use.put("size", vn.getSize());
                    use.put("mergeGroup", vn.getMergeGroup());
                    use.put("canSplit", DecompilerEditSupport.canSplit(vn));
                    DataType parent = DecompilerEditSupport.unionParent(op, slot);
                    Union union = DecompilerEditSupport.union(parent);
                    if (union != null) {
                        use.put("unionType", union.getPathName());
                        List<Map<String, Object>> fields = new ArrayList<>();
                        for (DataTypeComponent field : union.getDefinedComponents()) {
                            fields.add(Map.of("ordinal", field.getOrdinal(), "name", field.getFieldName() == null ?
                                field.getDefaultFieldName() : field.getFieldName(), "dataType", field.getDataType().getPathName()));
                        }
                        use.put("unionFields", fields);
                    }
                    uses.add(use);
                }
            }
            return Map.of("functionAddress", edit.function.getEntryPoint().toString(), "uses", uses,
                "total", count, "offset", offset, "hasMore", (long) offset + uses.size() < count);
        }
    }
}
