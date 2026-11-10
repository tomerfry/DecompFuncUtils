package decompfuncutils.mcp;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs the MCP session manager from the Ghidra <em>Project window</em>, so one
 * fixed port is listening from the moment Ghidra starts — before any CodeBrowser
 * is open, and no matter how many open later.
 *
 * <p>Agent sessions all connect to this one port. The manager opens CodeBrowser
 * windows on demand and gives each session its own (see {@link McpSessionRouter}).
 * The per-window servers of {@link McpServerPlugin} keep their own direct ports
 * for clients that want to pin one window.
 *
 * <p>The plugin sits in Ghidra's "Utility" package on purpose. The Project window
 * restores its plugins by package, and Utility is part of every saved Project
 * window configuration, so a released plugin in it loads on the next start with
 * no "File -> Configure" step. A plugin in the extension's own package would stay
 * off until the user found and ticked it.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "MCP Session Manager (DecompFuncUtils)",
    description = "Serves the Model Context Protocol on one fixed port for the whole Ghidra " +
                  "process. Agent sessions connect here; the manager opens CodeBrowser windows " +
                  "on demand and routes each session to a window of its own."
)
//@formatter:on
public class McpSessionManagerPlugin extends Plugin
        implements ApplicationLevelOnlyPlugin, OptionsChangeListener, McpWindowDirectory {

    private static final String OPTIONS_CATEGORY = "MCP Session Manager";
    private static final String OPTION_PORT = "Session Manager Port";
    private static final String OPTION_AUTH_TOKEN = "Auth Token";
    private static final String OPTION_AUTO_START = "Start With Ghidra";

    /** The fixed, well-known port agent configs point at. */
    public static final int DEFAULT_PORT = 13100;
    private static final String DEFAULT_AUTH_TOKEN = "";
    private static final boolean DEFAULT_AUTO_START = true;

    private static final String MENU_GROUP = "MCP Session Manager";

    private static final long LAUNCH_TIMEOUT_SECONDS = 45;
    private static final String LAUNCH_STUCK =
        "Ghidra did not finish opening a window within " + LAUNCH_TIMEOUT_SECONDS + " seconds. It is "
        + "most likely waiting on a dialog, for example 'New Plugins Found!' after an extension "
        + "update. Ask the operator to answer the dialog in Ghidra. The window then finishes "
        + "opening and the next ghidra_* call can use it; do not open another one meanwhile.";

    private McpSessionRouter router;
    private volatile McpHttpTransport transport;
    private final Semaphore launchPermit = new Semaphore(1);

    private int port = DEFAULT_PORT;
    private String authToken = DEFAULT_AUTH_TOKEN;
    private boolean autoStart = DEFAULT_AUTO_START;

    public McpSessionManagerPlugin(PluginTool tool) {
        super(tool);
        setupOptions();
        setupActions();

        // This runs while Ghidra is starting. Nothing here may stop the Project
        // window from coming up, so a failure only leaves the manager off.
        try {
            McpToolRegistry catalog = new McpToolRegistry();
            McpServerPlugin.registerStandardTools(catalog, new DecompInterfacePool());
            router = new McpSessionRouter(this, catalog);
            if (autoStart) {
                startManager(false);
            }
        } catch (Throwable t) {
            Msg.error(this, "MCP session manager could not be set up: " + t, t);
        }
    }

    private void setupOptions() {
        ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
        options.registerOption(OPTION_PORT, DEFAULT_PORT, null,
            "Fixed port of the MCP session manager (localhost only). Agent configs point here.");
        options.registerOption(OPTION_AUTH_TOKEN, DEFAULT_AUTH_TOKEN, null,
            "Bearer token for authentication (leave empty to disable)");
        options.registerOption(OPTION_AUTO_START, DEFAULT_AUTO_START, null,
            "Start the MCP session manager as soon as Ghidra starts");

        port = options.getInt(OPTION_PORT, DEFAULT_PORT);
        authToken = options.getString(OPTION_AUTH_TOKEN, DEFAULT_AUTH_TOKEN);
        autoStart = options.getBoolean(OPTION_AUTO_START, DEFAULT_AUTO_START);
        options.addOptionsChangeListener(this);
    }

    private void setupActions() {
        DockingAction start = new DockingAction("Start MCP Session Manager", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                startManager(true);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return !isRunning();
            }
        };
        start.setMenuBarData(new MenuData(new String[] { "Tools", MENU_GROUP, "Start" }));
        start.setDescription("Start the MCP session manager on its fixed port");
        tool.addAction(start);

        DockingAction stop = new DockingAction("Stop MCP Session Manager", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopManager();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isRunning();
            }
        };
        stop.setMenuBarData(new MenuData(new String[] { "Tools", MENU_GROUP, "Stop" }));
        stop.setDescription("Stop the MCP session manager. Windows keep their own direct ports.");
        tool.addAction(stop);

        DockingAction status = new DockingAction("MCP Session Manager Status", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showStatus();
            }
        };
        status.setMenuBarData(new MenuData(new String[] { "Tools", MENU_GROUP, "Status" }));
        status.setDescription("Show the session manager's port and the windows it routes to");
        tool.addAction(status);
    }

    public boolean isRunning() {
        McpHttpTransport t = transport;
        return t != null && t.isRunning();
    }

    /**
     * Bind the manager to its configured port. Unlike a window's server it never
     * moves to another port: the point of the manager is a stable address.
     *
     * @param interactive report a failure in a dialog (menu action) rather than
     *                    only in the log (Ghidra startup)
     */
    private boolean startManager(boolean interactive) {
        if (isRunning()) {
            return true;
        }
        if (router == null) {
            return false;
        }
        McpHttpTransport t = new McpHttpTransport(port, authToken, router);
        t.setDiscoveryInfoSupplier(this::discoveryInfo);
        try {
            t.start();
            transport = t;
            Msg.info(this, "MCP session manager listening on http://127.0.0.1:" + port
                + " (/sse and /mcp)");
            return true;
        } catch (Exception e) {
            String message = "MCP session manager could not listen on 127.0.0.1:" + port + " ("
                + e.getMessage() + "). Another Ghidra, or another program, probably holds the port. "
                + "Windows are still reachable on their own ports. Change the port under Edit -> "
                + "Tool Options -> " + OPTIONS_CATEGORY + ", or free it and use Tools -> "
                + MENU_GROUP + " -> Start.";
            if (interactive) {
                Msg.showError(this, tool.getToolFrame(), "MCP Session Manager", message);
            } else {
                Msg.error(this, message);
            }
            return false;
        }
    }

    private void stopManager() {
        McpHttpTransport t = transport;
        transport = null;
        if (t != null) {
            t.stop();
            Msg.info(this, "MCP session manager stopped");
        }
    }

    private void showStatus() {
        StringBuilder sb = new StringBuilder();
        if (isRunning()) {
            sb.append("Listening on http://127.0.0.1:").append(port).append("\n")
              .append("  Claude Code (SSE):  http://127.0.0.1:").append(port).append("/sse\n")
              .append("  Codex (HTTP):       http://127.0.0.1:").append(port).append("/mcp\n");
        } else {
            sb.append("Not running (configured port ").append(port).append(").\n");
        }
        String project = projectName();
        sb.append("\nProject: ").append(project != null ? project : "(none open)").append("\n");

        List<Map<String, Object>> windows = router != null ? router.describeWindows() : List.of();
        if (windows.isEmpty()) {
            sb.append("\nNo CodeBrowser window is serving MCP. One opens on an agent's first call.");
        } else {
            sb.append("\nWindows:\n");
            for (Map<String, Object> w : windows) {
                sb.append("  ").append(w.get("window"))
                  .append("  program: ").append(w.get("activeProgram") != null ? w.get("activeProgram") : "-")
                  .append("  sessions: ").append(w.get("sessions")).append("\n");
            }
        }
        Msg.showInfo(this, tool.getToolFrame(), "MCP Session Manager", sb.toString());
    }

    private Map<String, Object> discoveryInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("role", "session-manager");
        info.put("pid", ProcessHandle.current().pid());
        info.put("project", projectName());
        info.put("windows", router.describeWindows());
        return info;
    }

    // ---- McpWindowDirectory ----

    @Override
    public List<Window> windows() {
        List<Window> open = new ArrayList<>();
        for (McpServerPlugin server : McpWorkspaceRegistry.servers()) {
            if (server.isOpen()) {
                open.add(server);
            }
        }
        return open;
    }

    @Override
    public String projectName() {
        Project project = AppInfo.getActiveProject();
        return project != null ? project.getName() : null;
    }

    @Override
    public Window open(String programName, String domainFile) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return openOnSwing(programName, domainFile);
        }

        // Launching a tool can stop on a modal Ghidra dialog — most often the
        // "New Plugins Found!" prompt a tool shows once after an extension update.
        // The launch then sits inside that dialog's event loop until someone
        // answers it, so the wait here is bounded: the agent gets told what Ghidra
        // is waiting for instead of hanging with it. One launch at a time, because
        // a second one would only stack another dialog on top of the first.
        if (!launchPermit.tryAcquire(LAUNCH_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new IllegalStateException(LAUNCH_STUCK);
        }
        CompletableFuture<Window> result = new CompletableFuture<>();
        SwingUtilities.invokeLater(() -> {
            try {
                result.complete(openOnSwing(programName, domainFile));
            } catch (Throwable t) {
                result.completeExceptionally(t);
            } finally {
                launchPermit.release();
            }
        });

        try {
            return result.get(LAUNCH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new IllegalStateException(LAUNCH_STUCK);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            throw cause instanceof Exception ? (Exception) cause : new IllegalStateException(cause);
        }
    }

    private Window openOnSwing(String programName, String domainFile) throws Exception {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            throw new IllegalStateException("no Ghidra project is open. Open or create a project "
                + "in the Ghidra Project window first.");
        }

        DomainFile file = null;
        if (programName != null || domainFile != null) {
            file = McpWorkspaceRegistry.findProgramFile(project, programName, domainFile);
            if (file == null) {
                throw new IllegalArgumentException("no program '"
                    + (programName != null ? programName : domainFile) + "' in project '"
                    + project.getName() + "'. Open an empty window and import the binary with "
                    + "ghidra_open_program.");
            }
        }

        // Reuse the tool type the operator already works in, so a custom tool
        // chest entry is respected; a bare Ghidra gets a CodeBrowser.
        String template = "CodeBrowser";
        List<McpServerPlugin> existing = McpWorkspaceRegistry.servers();
        if (!existing.isEmpty()) {
            template = existing.get(0).getTool().getToolName();
        }

        PluginTool newTool = McpWorkspaceRegistry.launchWindow(project, file, template);
        McpServerPlugin server = McpWorkspaceRegistry.ensureServer(newTool);
        if (server == null || !server.isServerRunning()) {
            throw new IllegalStateException("window '" + newTool.getName() + "' opened but its MCP "
                + "server did not start. Start it from that window: Tools -> MCP Server -> Start.");
        }
        return server;
    }

    // ---- lifecycle ----

    @Override
    protected void dispose() {
        stopManager();
        super.dispose();
    }

    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
                               Object newValue) {
        switch (optionName) {
            case OPTION_PORT:
                port = (int) newValue;
                break;
            case OPTION_AUTH_TOKEN:
                authToken = (String) newValue;
                break;
            case OPTION_AUTO_START:
                autoStart = (boolean) newValue;
                return;
            default:
                return;
        }
        if (isRunning()) {
            Msg.info(this, "MCP session manager config changed, restarting...");
            stopManager();
            startManager(true);
        }
    }
}
