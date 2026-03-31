package decompfuncutils.mcp;

import java.util.*;

/**
 * Registry mapping tool names to McpTool implementations.
 */
public class McpToolRegistry {

    private final Map<String, McpTool> tools = new LinkedHashMap<>();

    public void register(McpTool tool) {
        tools.put(tool.name(), tool);
    }

    public McpTool get(String name) {
        return tools.get(name);
    }

    public Collection<McpTool> all() {
        return Collections.unmodifiableCollection(tools.values());
    }

    public boolean has(String name) {
        return tools.containsKey(name);
    }

    public int size() {
        return tools.size();
    }
}
