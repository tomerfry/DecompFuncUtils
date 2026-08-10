package decompfuncutils.mcp;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolChest;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.model.Workspace;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Process-wide registry of MCP-serving Ghidra windows, and the machinery for
 * spawning new ones.
 *
 * <p>A single Ghidra process can host several tool instances (CodeBrowser,
 * CodeBrowser(2), ...) side by side, each with its own active program, its own
 * {@link McpServerPlugin} and therefore its own MCP port. That is the only way
 * to work on several binaries of the <em>same</em> project at once, because a
 * Ghidra project is locked to one process.
 *
 * <p>Each window is an independent lane: one agent session ⇄ one port ⇄ one
 * window ⇄ that window's active program. This registry is what lets a session
 * see its siblings ({@code ghidra_list_windows}) and open new ones
 * ({@code ghidra_open_in_new_window}) instead of the operator having to wire up
 * every window by hand.
 */
public final class McpWorkspaceRegistry {

    private McpWorkspaceRegistry() {
    }

    /** Every {@link McpServerPlugin} alive in this JVM, in creation order. */
    private static final CopyOnWriteArrayList<McpServerPlugin> SERVERS = new CopyOnWriteArrayList<>();

    static void register(McpServerPlugin server) {
        SERVERS.addIfAbsent(server);
    }

    static void unregister(McpServerPlugin server) {
        SERVERS.remove(server);
    }

    /** All MCP server plugins in this Ghidra process (running or not). */
    public static List<McpServerPlugin> servers() {
        return new ArrayList<>(SERVERS);
    }

    /** The MCP server plugin installed in {@code tool}, or null if it has none. */
    public static McpServerPlugin serverFor(PluginTool tool) {
        for (McpServerPlugin server : SERVERS) {
            if (server.getTool() == tool) {
                return server;
            }
        }
        return null;
    }

    /**
     * Whether a server in <em>this</em> process is currently listening on the given
     * port. Used to tell a live sibling's discovery file from one left behind by a
     * window that has since closed (both carry our pid).
     */
    static boolean isLocalRunningPort(int port) {
        for (McpServerPlugin server : SERVERS) {
            if (server.isServerRunning() && server.getRunningPort() == port) {
                return true;
            }
        }
        return false;
    }

    // ---- description ----

    /**
     * Describe one window for an MCP client: its identity, its MCP endpoints and
     * the programs <em>that window</em> has open (each window has its own set).
     *
     * @param server the window's MCP server plugin
     * @param self   the tool the calling session is attached to, for the {@code self} flag
     */
    public static Map<String, Object> describe(McpServerPlugin server, PluginTool self) {
        PluginTool windowTool = server.getTool();
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("window", windowTool.getName());
        info.put("tool", windowTool.getToolName());
        info.put("self", windowTool == self);

        boolean running = server.isServerRunning();
        int port = server.getRunningPort();
        info.put("mcpRunning", running);
        if (running && port > 0) {
            info.put("port", port);
            info.put("sseUrl", "http://127.0.0.1:" + port + "/sse");
            info.put("mcpUrl", "http://127.0.0.1:" + port + "/mcp");
            info.put("attachClaude", "./tools/ghidra-claude.ps1 -Port " + port);
            info.put("attachCodex", "./tools/ghidra-claude.ps1 -Client codex -Port " + port);
        }

        addProgramFields(info, windowTool);
        return info;
    }

    /** Describe a tool window that has no MCP server installed. */
    public static Map<String, Object> describeUnserved(PluginTool windowTool, PluginTool self) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("window", windowTool.getName());
        info.put("tool", windowTool.getToolName());
        info.put("self", windowTool == self);
        info.put("mcpRunning", false);
        info.put("hint", "This window has no MCP server. Start one from its "
            + "Tools -> MCP Server -> Start menu, or open a new served window with "
            + "ghidra_open_in_new_window.");
        addProgramFields(info, windowTool);
        return info;
    }

    private static void addProgramFields(Map<String, Object> info, PluginTool windowTool) {
        ProgramManager pm = windowTool.getService(ProgramManager.class);
        if (pm == null) {
            info.put("activeProgram", null);
            info.put("programs", List.of());
            return;
        }
        Program active = pm.getCurrentProgram();
        info.put("activeProgram", active != null ? active.getName() : null);
        List<String> names = new ArrayList<>();
        for (Program p : pm.getAllOpenPrograms()) {
            names.add(p.getName());
        }
        info.put("programs", names);
    }

    // ---- launching new windows ----

    /**
     * Launch a new tool window in the active workspace and, if given, open a
     * program in it.
     *
     * <p>Deliberately bypasses {@code ToolServices.launchTool}, which reuses an
     * already-running window when the launch mode says to — here a <em>new</em>
     * window is the whole point.
     *
     * <p>Must be called on the Swing thread.
     *
     * @param source       the window requesting the launch (supplies project + template)
     * @param file         program to open in the new window, or null for an empty one
     * @param templateName tool template to instantiate, or null for {@code source}'s own
     * @return the new tool
     */
    public static PluginTool launchWindow(PluginTool source, DomainFile file, String templateName) {
        Project project = source.getProject();
        if (project == null) {
            throw new IllegalStateException("No Ghidra project is open, so no new window can be launched.");
        }

        String preferred = (templateName != null && !templateName.isEmpty())
            ? templateName : source.getToolName();
        ToolTemplate template = resolveTemplate(project, preferred);
        if (template == null) {
            throw new IllegalStateException("No tool template named '" + preferred +
                "' (or 'CodeBrowser') in the project tool chest, so no new window can be launched.");
        }

        Workspace workspace = project.getToolManager().getActiveWorkspace();
        if (workspace == null) {
            throw new IllegalStateException("No active workspace to launch a window into.");
        }

        PluginTool newTool = workspace.runTool(template);
        if (newTool == null) {
            throw new IllegalStateException("Ghidra failed to launch a new '" + template.getName() + "' window.");
        }
        newTool.setVisible(true);

        if (file != null && !newTool.acceptDomainFiles(new DomainFile[] { file })) {
            Msg.warn(McpWorkspaceRegistry.class,
                "New window " + newTool.getName() + " did not accept " + file.getPathname());
        }
        return newTool;
    }

    private static ToolTemplate resolveTemplate(Project project, String preferred) {
        ToolChest chest = project.getLocalToolChest();
        if (chest == null) {
            return null;
        }
        if (preferred != null && !preferred.isEmpty()) {
            ToolTemplate template = chest.getToolTemplate(preferred);
            if (template != null) {
                return template;
            }
        }
        ToolTemplate codeBrowser = chest.getToolTemplate("CodeBrowser");
        if (codeBrowser != null) {
            return codeBrowser;
        }
        for (ToolTemplate template : chest.getToolTemplates()) {
            String name = template.getName();
            if (name != null && name.toLowerCase().contains("codebrowser")) {
                return template;
            }
        }
        return null;
    }

    /**
     * Make sure {@code windowTool} has a running MCP server, installing the plugin
     * if the tool template did not carry it, and return it.
     *
     * <p>Must be called on the Swing thread.
     *
     * @return the window's server plugin, or null if the plugin could not be installed
     */
    public static McpServerPlugin ensureServer(PluginTool windowTool) throws PluginException {
        McpServerPlugin server = serverFor(windowTool);
        if (server == null) {
            windowTool.addPlugin(McpServerPlugin.class.getName());
            server = serverFor(windowTool);
        }
        if (server != null && !server.isServerRunning()) {
            server.startServer();
        }
        return server;
    }

    // ---- project file lookup ----

    /**
     * Find a program file in the project by name or by full path. Open programs are
     * consulted first so the common "the binary I'm looking at" case is exact; a
     * bounded recursive walk of the project folders handles the rest.
     *
     * @param tool  any tool of the project to search
     * @param name  program name (e.g. {@code libfoo.so}), or null
     * @param path  domain file path (e.g. {@code /bins/libfoo.so}), or null
     * @return the matching file, or null
     */
    public static DomainFile findProgramFile(PluginTool tool, String name, String path) {
        Project project = tool.getProject();
        if (project == null) {
            return null;
        }

        if (path != null && !path.isEmpty()) {
            DomainFile byPath = project.getProjectData().getFile(path);
            if (byPath != null) {
                return byPath;
            }
        }

        if (name == null || name.isEmpty()) {
            return null;
        }

        // Already-open programs know their own DomainFile — cheapest and most exact.
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            for (Program p : pm.getAllOpenPrograms()) {
                if (p.getName().equals(name) && p.getDomainFile() != null) {
                    return p.getDomainFile();
                }
            }
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        DomainFile direct = root.getFile(name);
        if (direct != null) {
            return direct;
        }
        return searchFolder(root, name, 0);
    }

    /** Depth-limited search so a pathological project tree cannot stall the EDT. */
    private static DomainFile searchFolder(DomainFolder folder, String name, int depth) {
        if (depth > 12) {
            return null;
        }
        for (DomainFile file : folder.getFiles()) {
            if (file.getName().equals(name)) {
                return file;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile hit = searchFolder(sub, name, depth + 1);
            if (hit != null) {
                return hit;
            }
        }
        return null;
    }
}
