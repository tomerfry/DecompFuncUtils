package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class AssignNamespaceTool implements McpTool {

    @Override public String name() { return "ghidra_assign_namespace"; }

    @Override
    public String description() {
        return "Assign a function or symbol to a namespace. Creates the namespace if it does not exist.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Address of the function or symbol in hex"),
            "namespace", Map.of("type", "string", "description", "Target namespace (use '::' for nested, e.g. 'MyLib::MyClass')"),
            "createIfMissing", Map.of("type", "boolean", "description", "Create namespace if it doesn't exist (default true)")
        ));
        schema.put("required", List.of("address", "namespace"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String namespacePath = (String) arguments.get("namespace");
        boolean createIfMissing = (Boolean) arguments.getOrDefault("createIfMissing", true);

        Address addr = McpUtil.parseAddress(addrStr, program);

        SymbolTable st = program.getSymbolTable();

        // Find the symbol at the address
        Symbol sym = st.getPrimarySymbol(addr);
        if (sym == null) {
            throw new IllegalArgumentException("No symbol at address: " + addrStr);
        }

        // Resolve or create namespace hierarchy (supports "::" separator)
        String[] parts = namespacePath.split("::");
        Namespace current = program.getGlobalNamespace();

        for (String part : parts) {
            part = part.trim();
            Namespace child = st.getNamespace(part, current);
            if (child == null) {
                if (!createIfMissing) {
                    throw new IllegalArgumentException("Namespace not found: " + part + " (under " + current.getName(true) + ")");
                }
                child = st.createNameSpace(current, part, SourceType.USER_DEFINED);
            }
            current = child;
        }

        // Move the symbol to the namespace
        String oldNamespace = sym.getParentNamespace().getName(true);
        sym.setNamespace(current);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("symbol", sym.getName());
        result.put("address", addr.toString());
        result.put("oldNamespace", oldNamespace);
        result.put("newNamespace", current.getName(true));
        result.put("status", "namespace_assigned");
        return result;
    }
}
