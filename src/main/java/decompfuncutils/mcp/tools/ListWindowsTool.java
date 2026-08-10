package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpServerPlugin;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpWorkspaceRegistry;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lists the tool windows of this Ghidra process — the parallel work lanes.
 *
 * <p>Each window has its own active program and its own MCP port, so this is how a
 * session learns which lane it is in ({@code self: true}) and what the other
 * sessions are holding.
 */
public class ListWindowsTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_windows"; }

    @Override
    public String description() {
        return "List the Ghidra tool windows (CodeBrowser instances) running in this Ghidra process, "
             + "with each one's MCP port, active program and open programs. Every window is an "
             + "independent lane: one agent session per port, each with its own active program. "
             + "The entry with self=true is the window this session is attached to. Use "
             + "ghidra_open_in_new_window to add a lane.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", new LinkedHashMap<>());
        return schema;
    }

    @Override
    public boolean requiresEdt() {
        // Reads Swing-managed tool/window state.
        return true;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        List<Map<String, Object>> windows = new ArrayList<>();
        List<PluginTool> served = new ArrayList<>();

        for (McpServerPlugin server : McpWorkspaceRegistry.servers()) {
            windows.add(McpWorkspaceRegistry.describe(server, tool));
            served.add(server.getTool());
        }

        // Windows without our plugin are still lanes the operator can see on screen;
        // listing them explains why they are not reachable over MCP.
        Project project = tool.getProject();
        if (project != null && project.getToolManager() != null) {
            for (PluginTool running : project.getToolManager().getRunningTools()) {
                if (!served.contains(running)) {
                    windows.add(McpWorkspaceRegistry.describeUnserved(running, tool));
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("windows", windows);
        result.put("count", windows.size());
        result.put("project", project != null ? project.getName() : null);
        result.put("pid", ProcessHandle.current().pid());
        result.put("hint", "Each window is driven by its own agent session. Attach one with "
            + "./tools/ghidra-claude.ps1 -Port <port> (Claude) or -Client codex -Port <port>.");
        return result;
    }
}
