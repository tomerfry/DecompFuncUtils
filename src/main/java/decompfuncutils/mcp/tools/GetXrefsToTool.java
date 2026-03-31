package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.*;

public class GetXrefsToTool implements McpTool {

    @Override
    public String name() { return "ghidra_get_xrefs_to"; }

    @Override
    public String description() {
        return "Get all cross-references TO a given address. Shows where this address is referenced from.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Target address in hex")
        ));
        schema.put("required", List.of("address"));
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        Address addr = McpUtil.parseAddress(addrStr, program);

        ReferenceManager refMgr = program.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(addr);

        List<Map<String, Object>> xrefs = new ArrayList<>();
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("fromAddress", ref.getFromAddress().toString());
            x.put("toAddress", ref.getToAddress().toString());
            x.put("refType", ref.getReferenceType().getName());
            x.put("isCall", ref.getReferenceType().isCall());
            x.put("isData", ref.getReferenceType().isData());

            // Try to find the containing function
            Function fromFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (fromFunc != null) {
                x.put("fromFunction", fromFunc.getName());
                x.put("fromFunctionAddress", fromFunc.getEntryPoint().toString());
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
