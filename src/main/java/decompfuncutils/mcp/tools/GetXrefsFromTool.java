package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class GetXrefsFromTool implements McpTool {

    @Override
    public String name() { return "ghidra_get_xrefs_from"; }

    @Override
    public String description() {
        return "Get all cross-references FROM a given address. Shows what this address references.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Source address in hex")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        Address addr = McpUtil.parseAddress(addrStr, program);

        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        List<Map<String, Object>> xrefs = new ArrayList<>();
        for (Reference ref : refs) {
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("fromAddress", ref.getFromAddress().toString());
            x.put("toAddress", ref.getToAddress().toString());
            x.put("refType", ref.getReferenceType().getName());
            x.put("isCall", ref.getReferenceType().isCall());
            x.put("isData", ref.getReferenceType().isData());

            Function toFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
            if (toFunc != null) {
                x.put("toFunction", toFunc.getName());
            }
            xrefs.add(x);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addr.toString());
        result.put("xrefs", xrefs);
        result.put("count", xrefs.size());
        return result;
    }
}
