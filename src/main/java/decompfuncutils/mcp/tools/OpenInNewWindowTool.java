package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpServerPlugin;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpWorkspaceRegistry;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Opens a program in a <em>new</em> Ghidra tool window with its own MCP server,
 * creating a second work lane instead of hijacking this session's window.
 *
 * <p>This is the multitasking primitive: a Ghidra project is locked to one process,
 * so parallel work on several binaries of one project means several tool windows
 * inside that process, each on its own port.
 */
public class OpenInNewWindowTool implements McpTool {

    @Override
    public String name() { return "ghidra_open_in_new_window"; }

    @Override
    public String description() {
        return "Open a program from the current project in a NEW Ghidra tool window that gets its own "
             + "MCP server and port, without disturbing this window. Use this to work on several "
             + "binaries in parallel: the returned port is a separate lane that a second agent session "
             + "attaches to (./tools/ghidra-claude.ps1 -Port <port>). The program must already be in the "
             + "project — import it first with ghidra_open_program if needed. Omit both arguments to open "
             + "an empty window. Note that this tool call returns the new window's port; it does not "
             + "move this session, which stays attached to its own window.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("name", Map.of("type", "string",
            "description", "Name of the program to open in the new window (as shown by "
                + "ghidra_list_open_programs)"));
        props.put("domainFile", Map.of("type", "string",
            "description", "Project path of the program instead of its name (e.g. '/bins/libfoo.so')"));
        props.put("closeHere", Map.of("type", "boolean",
            "description", "Also close the program in THIS window (default false), so the two lanes "
                + "do not edit the same program from both sides"));
        schema.put("properties", props);

        return schema;
    }

    @Override
    public boolean requiresEdt() {
        // Launching a tool window and opening programs into it is Swing work.
        return true;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String targetName = trimmed(arguments.get("name"));
        String targetPath = trimmed(arguments.get("domainFile"));
        boolean closeHere = arguments.get("closeHere") != null
            && Boolean.parseBoolean(String.valueOf(arguments.get("closeHere")));

        DomainFile file = null;
        if (targetName != null || targetPath != null) {
            file = McpWorkspaceRegistry.findProgramFile(tool, targetName, targetPath);
            if (file == null) {
                throw new IllegalArgumentException("No program named '" +
                    (targetName != null ? targetName : targetPath) + "' in project '" +
                    (tool.getProject() != null ? tool.getProject().getName() : "?") +
                    "'. Import it first with ghidra_open_program, or check ghidra_list_open_programs.");
            }
        }

        PluginTool newTool = McpWorkspaceRegistry.launchWindow(tool, file, null);
        McpServerPlugin server = McpWorkspaceRegistry.ensureServer(newTool);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("window", newTool.getName());
        result.put("opened", file != null ? file.getName() : null);

        if (server == null || !server.isServerRunning()) {
            result.put("mcpRunning", false);
            result.put("warning", "The new window opened but its MCP server did not start. Start it "
                + "from that window: Tools -> MCP Server -> Start.");
            return result;
        }

        int port = server.getRunningPort();
        result.put("mcpRunning", true);
        result.put("port", port);
        result.put("sseUrl", "http://127.0.0.1:" + port + "/sse");
        result.put("mcpUrl", "http://127.0.0.1:" + port + "/mcp");
        result.put("attachClaude", "./tools/ghidra-claude.ps1 -Port " + port);
        result.put("attachCodex", "./tools/ghidra-claude.ps1 -Client codex -Port " + port);

        if (closeHere && file != null) {
            result.put("closedHere", closeInThisWindow(tool, file));
        }

        result.put("hint", "Tell the operator to run the attach command in a second terminal; that "
            + "session will drive the new window while this one keeps its own program.");
        return result;
    }

    /**
     * Release the program from the calling window so the two lanes do not both hold
     * it. Returns false when Ghidra refused (e.g. unsaved changes need a decision).
     */
    private boolean closeInThisWindow(PluginTool tool, DomainFile file) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return false;
        }
        for (Program p : pm.getAllOpenPrograms()) {
            if (p.getDomainFile() != null && p.getDomainFile().getPathname().equals(file.getPathname())) {
                boolean closed = pm.closeProgram(p, false);
                if (!closed) {
                    Msg.info(this, "Kept " + p.getName() + " open in " + tool.getName() +
                        " — Ghidra declined the close (likely unsaved changes).");
                }
                return closed;
            }
        }
        return false;
    }

    private static String trimmed(Object raw) {
        if (raw == null) {
            return null;
        }
        String s = String.valueOf(raw).trim();
        return s.isEmpty() ? null : s;
    }
}
