package decompfuncutils.mcp;

import com.google.gson.Gson;
import decompfuncutils.mcp.tools.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.Options;
import ghidra.util.Msg;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.COMMON,
    shortDescription = "MCP Server for AI Integration",
    description = "Exposes Ghidra analysis capabilities via the Model Context Protocol (MCP) " +
                  "for integration with AI agents like Claude Code. One server per tool window, " +
                  "so several windows can be driven by several agent sessions in parallel."
)
//@formatter:on
public class McpServerPlugin extends ProgramPlugin implements OptionsChangeListener {

    private static final String OPTION_PORT = "MCP Server Port";
    private static final String OPTION_AUTH_TOKEN = "MCP Auth Token";
    private static final String OPTION_AUTO_START = "MCP Auto Start";

    private static final int DEFAULT_PORT = 13100;
    private static final String DEFAULT_AUTH_TOKEN = "";
    // On by default: every window that carries this plugin claims its own port, so
    // opening a second CodeBrowser is all it takes to get a second agent lane.
    private static final boolean DEFAULT_AUTO_START = true;

    /** Shared directory where every running MCP server advertises its port for client discovery. */
    private static final Path PORT_DIR = Paths.get(System.getProperty("user.home"), ".ghidra-mcp");

    private static final Gson GSON = new Gson();

    private McpHttpTransport transport;
    private McpToolRegistry toolRegistry;
    private McpProtocolHandler protocolHandler;
    private DecompInterfacePool decompPool;
    private Path portFile;
    private int runningPort = -1;
    private String startedAt;

    private int port = DEFAULT_PORT;
    private String authToken = DEFAULT_AUTH_TOKEN;
    private boolean autoStart = DEFAULT_AUTO_START;

    private DockingAction startAction;
    private DockingAction stopAction;
    private DockingAction newWindowAction;

    public McpServerPlugin(PluginTool tool) {
        super(tool);
        McpWorkspaceRegistry.register(this);
        setupOptions();
        setupActions();
        setupToolRegistry();

        // Auto-start the server immediately so MCP clients can import binaries
        // even before a program is manually opened in the CodeBrowser.
        if (autoStart) {
            startServer();
        }
    }

    /** Identifies this window in logs and discovery output, e.g. {@code CodeBrowser(2)}. */
    private String windowName() {
        return tool.getName();
    }

    /** The port this window's server is listening on, or -1 when it is stopped. */
    public int getRunningPort() {
        return runningPort;
    }

    /** Whether this window's server is currently accepting MCP connections. */
    public boolean isServerRunning() {
        return transport != null && transport.isRunning();
    }

    private void setupOptions() {
        ToolOptions options = tool.getOptions("MCP Server");
        options.registerOption(OPTION_PORT, DEFAULT_PORT, null,
            "Port for the MCP HTTP+SSE server (localhost only)");
        options.registerOption(OPTION_AUTH_TOKEN, DEFAULT_AUTH_TOKEN, null,
            "Bearer token for authentication (leave empty to disable)");
        options.registerOption(OPTION_AUTO_START, DEFAULT_AUTO_START, null,
            "Automatically start the MCP server when a program is opened");

        port = options.getInt(OPTION_PORT, DEFAULT_PORT);
        authToken = options.getString(OPTION_AUTH_TOKEN, DEFAULT_AUTH_TOKEN);
        autoStart = options.getBoolean(OPTION_AUTO_START, DEFAULT_AUTO_START);

        options.addOptionsChangeListener(this);
    }

    private void setupActions() {
        startAction = new DockingAction("Start MCP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                startServer();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return transport == null || !transport.isRunning();
            }
        };
        startAction.setMenuBarData(new MenuData(new String[] { "Tools", "MCP Server", "Start" }));
        startAction.setDescription("Start the MCP server for AI agent integration");
        tool.addAction(startAction);

        stopAction = new DockingAction("Stop MCP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return transport != null && transport.isRunning();
            }
        };
        stopAction.setMenuBarData(new MenuData(new String[] { "Tools", "MCP Server", "Stop" }));
        stopAction.setDescription("Stop the MCP server");
        tool.addAction(stopAction);

        newWindowAction = new DockingAction("New MCP Window", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                openNewWindow();
            }
        };
        newWindowAction.setMenuBarData(
            new MenuData(new String[] { "Tools", "MCP Server", "New MCP Window" }));
        newWindowAction.setDescription("Open another tool window with its own MCP server, " +
            "so a second agent session can work on a second binary in parallel");
        tool.addAction(newWindowAction);
    }

    /**
     * Open a sibling window with its own MCP server and tell the operator which
     * port to point the next agent session at.
     */
    private void openNewWindow() {
        try {
            DomainFile file = currentProgram != null ? currentProgram.getDomainFile() : null;
            PluginTool newTool = McpWorkspaceRegistry.launchWindow(tool, file, null);
            McpServerPlugin server = McpWorkspaceRegistry.ensureServer(newTool);

            if (server == null || !server.isServerRunning()) {
                Msg.showWarn(this, null, "MCP Server",
                    "Opened window '" + newTool.getName() + "', but its MCP server did not start. " +
                    "Start it from that window: Tools -> MCP Server -> Start.");
                return;
            }
            int newPort = server.getRunningPort();
            Msg.showInfo(this, null, "MCP Server",
                "Window '" + newTool.getName() + "' is serving MCP on port " + newPort + ".\n\n" +
                "Attach an agent session to it with:\n" +
                "  ./tools/ghidra-claude.ps1 -Port " + newPort);
        } catch (Exception e) {
            Msg.showError(this, null, "MCP Server",
                "Could not open a new MCP window: " + e.getMessage(), e);
        }
    }

    private void setupToolRegistry() {
        toolRegistry = new McpToolRegistry();
        decompPool = new DecompInterfacePool();

        // P0 — Core RE Operations (read-only)
        toolRegistry.register(new GetProgramInfoTool());
        toolRegistry.register(new ListFunctionsTool());
        toolRegistry.register(new DecompileFunctionTool(decompPool));
        toolRegistry.register(new GetFunctionTool());
        toolRegistry.register(new GetXrefsToTool());
        toolRegistry.register(new GetXrefsFromTool());
        toolRegistry.register(new ListStringsTool());
        toolRegistry.register(new ListSymbolsTool());
        toolRegistry.register(new ReadMemoryTool());
        toolRegistry.register(new ListDataTypesTool());

        // P1 — Mutation Operations
        toolRegistry.register(new RenameFunctionTool());
        toolRegistry.register(new RenameVariableTool());
        toolRegistry.register(new RenameLabelTool());
        toolRegistry.register(new RetypeVariableTool());
        toolRegistry.register(new SetFunctionSignatureTool());
        toolRegistry.register(new SetCommentTool());
        toolRegistry.register(new CreateStructTool());
        toolRegistry.register(new AutoCreateStructTool());
        toolRegistry.register(new EditStructFieldTool());
        toolRegistry.register(new SplitVariableTool());
        toolRegistry.register(new CommitVariablesTool(decompPool));
        toolRegistry.register(new SetMemoryBlockFlagsTool());
        toolRegistry.register(new CreateClassTool());
        toolRegistry.register(new AssignNamespaceTool());
        toolRegistry.register(new CreateDataTypeTool());
        toolRegistry.register(new ClearListingTool());
        toolRegistry.register(new DisassembleTool());
        toolRegistry.register(new ClearAndRepairTool());
        toolRegistry.register(new CreateFunctionTool());
        toolRegistry.register(new CreateBookmarkTool());

        // Program Management
        toolRegistry.register(new ListOpenProgramsTool());
        toolRegistry.register(new OpenProgramTool());
        toolRegistry.register(new SwitchProgramTool());

        // Multi-window (parallel work) management
        toolRegistry.register(new ListWindowsTool());
        toolRegistry.register(new OpenInNewWindowTool());

        // P2 — Advanced Analysis
        toolRegistry.register(new TaintForwardTool(decompPool));
        toolRegistry.register(new TaintBackwardTool(decompPool));
        toolRegistry.register(new TaintQueryTool());
        toolRegistry.register(new ScanVtableTool());
        toolRegistry.register(new CreateVtableStructTool());
        toolRegistry.register(new GenerateFuzzerTool());
        toolRegistry.register(new GetCallGraphTool());
        toolRegistry.register(new NavigateToTool());
        toolRegistry.register(new SearchMemoryTool());

        // Emulation
        toolRegistry.register(new EmulateFunctionTool(decompPool));

        // Constraint / symbolic-lite analysis
        toolRegistry.register(new PathConstraintsTool(decompPool));
        toolRegistry.register(new SuggestBranchFlipTool(decompPool));
        toolRegistry.register(new FindIntegerTruncationTool(decompPool));

        // GUI
        toolRegistry.register(new ScreenshotTool());

        protocolHandler = new McpProtocolHandler(
            toolRegistry,
            this::getCurrentProgram,
            () -> this.tool
        );
        // Tell each connecting session which window it landed in — with several
        // windows served from one Ghidra, "the active program" is ambiguous
        // otherwise.
        protocolHandler.setInstructionsSupplier(this::sessionInstructions);
    }

    /** Orientation text handed to a client in the initialize response. */
    private String sessionInstructions() {
        StringBuilder sb = new StringBuilder();
        sb.append("You are attached to Ghidra tool window '").append(windowName()).append('\'');
        if (runningPort > 0) {
            sb.append(" (MCP port ").append(runningPort).append(')');
        }
        sb.append(". Tool calls act on this window's active program");
        Program active = getCurrentProgram();
        if (active != null) {
            sb.append(" (currently ").append(active.getName()).append(')');
        }
        sb.append(". ");

        int others = 0;
        for (McpServerPlugin server : McpWorkspaceRegistry.servers()) {
            if (server != this && server.isServerRunning()) {
                others++;
            }
        }
        if (others > 0) {
            sb.append(others).append(" other MCP-served window(s) are open in this Ghidra, each with its ")
              .append("own active program and port; they are separate sessions' lanes. ");
        }
        sb.append("Use ghidra_list_windows to see them and ghidra_open_in_new_window to open ")
          .append("another binary in a fresh window instead of switching this one.");
        return sb.toString();
    }

    /**
     * Bind this window's MCP server to a free port.
     *
     * @return true if the server is running when this returns
     */
    public boolean startServer() {
        if (transport != null && transport.isRunning()) {
            Msg.showInfo(this, null, "MCP Server",
                "MCP server is already running on port " + transport.getPort());
            return true;
        }

        // Clear out advertisements left behind by Ghidra instances that crashed
        // without running their shutdown hook, so discovery only sees live servers.
        pruneStalePortFiles();

        // Try configured port first, then scan up to 50 ports for a free one.
        // Every tool window keeps the same configured default, so this scan is what
        // lets a second, third, ... window each claim a port of its own.
        int actualPort = port;
        Exception lastError = null;
        for (int attempt = 0; attempt < 50; attempt++) {
            transport = new McpHttpTransport(actualPort, authToken, protocolHandler);
            transport.setDiscoveryInfoSupplier(this::discoveryInfo);
            try {
                transport.start();
                runningPort = actualPort;
                startedAt = Instant.now().toString();
                Msg.info(this, "MCP server for window '" + windowName() + "' started on http://127.0.0.1:" +
                    actualPort + " with " + toolRegistry.size() + " tools");
                if (actualPort != port) {
                    Msg.info(this, "Configured port " + port + " was busy, window '" + windowName() +
                        "' is using " + actualPort);
                }
                writePortFile(actualPort);
                return true;
            } catch (Exception e) {
                lastError = e;
                transport = null;
                actualPort++;
            }
        }

        Msg.error(this, "Failed to start MCP server on ports " + port + "-" + (actualPort - 1), lastError);
        SwingUtilities.invokeLater(() ->
            JOptionPane.showMessageDialog(null,
                "Failed to start MCP server.\nAll ports " + port + "-" + (port + 49) + " are in use.",
                "MCP Server Error",
                JOptionPane.ERROR_MESSAGE));
        return false;
    }

    public void stopServer() {
        if (transport != null) {
            transport.stop();
            transport = null;
            Msg.info(this, "MCP server for window '" + windowName() + "' stopped");
        }
        runningPort = -1;
        startedAt = null;
        if (decompPool != null) {
            decompPool.disposeAll();
        }
        deletePortFile();
    }

    /**
     * Advertise this window's server so a launcher can route a session to it.
     *
     * <p>The file name carries the port as well as the pid, because one Ghidra
     * process hosts one server <em>per tool window</em> — keying on the pid alone
     * would make each new window silently overwrite its siblings' advertisement,
     * leaving only one window discoverable.
     */
    private void writePortFile(int actualPort) {
        try {
            Files.createDirectories(PORT_DIR);
            long pid = ProcessHandle.current().pid();
            portFile = PORT_DIR.resolve("server-" + pid + "-" + actualPort + ".json");
            Files.writeString(portFile, GSON.toJson(discoveryInfo()));
            portFile.toFile().deleteOnExit();
            Msg.info(this, "Port file written: " + portFile);
        } catch (Exception e) {
            Msg.warn(this, "Failed to write port file: " + e.getMessage());
        }
    }

    /**
     * The advertisement for this window: which port, which window, which binaries.
     * Served both from the discovery file and from the {@code /discovery} endpoint.
     */
    private Map<String, Object> discoveryInfo() {
        int advertisedPort = runningPort > 0 ? runningPort
            : (transport != null ? transport.getPort() : port);

        Program active = getCurrentProgram();
        List<String> openNames = new ArrayList<>();
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            for (Program p : pm.getAllOpenPrograms()) {
                openNames.add(p.getName());
            }
        } else if (active != null) {
            openNames.add(active.getName());
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("port", advertisedPort);
        info.put("pid", ProcessHandle.current().pid());
        info.put("started", startedAt != null ? startedAt : Instant.now().toString());
        info.put("project", tool.getProject() != null ? tool.getProject().getName() : "unknown");
        // Window identity: several of these files can share a pid, one per window.
        info.put("window", windowName());
        info.put("toolName", tool.getToolName());
        info.put("program", active != null ? active.getName() : null);
        info.put("programs", openNames);
        info.put("url", "http://127.0.0.1:" + advertisedPort + "/sse");
        info.put("mcpUrl", "http://127.0.0.1:" + advertisedPort + "/mcp");
        return info;
    }

    /** Re-advertise the loaded binary after the active program changes, if the server is up. */
    private void refreshPortFile() {
        if (transport != null && transport.isRunning() && runningPort > 0) {
            writePortFile(runningPort);
        }
    }

    /**
     * Delete discovery files that no longer describe a live server. The normal
     * {@code deleteOnExit} hook does not run on a crash/kill, so stale files
     * accumulate and would otherwise mislead a client into connecting to a dead port.
     *
     * <p>Two kinds of staleness, since files are named {@code server-<pid>-<port>.json}:
     * another pid that is gone, and our own pid on a port no window here is serving
     * (a window that was closed hard, or a recycled pid).
     */
    private void pruneStalePortFiles() {
        if (!Files.isDirectory(PORT_DIR)) {
            return;
        }
        long selfPid = ProcessHandle.current().pid();
        List<Path> candidates;
        try (Stream<Path> files = Files.list(PORT_DIR)) {
            candidates = files.filter(p -> {
                String fn = p.getFileName().toString();
                return fn.startsWith("server-") && fn.endsWith(".json");
            }).toList();
        } catch (IOException e) {
            Msg.debug(this, "Failed to scan MCP discovery dir: " + e.getMessage());
            return;
        }

        for (Path p : candidates) {
            String fn = p.getFileName().toString();
            String stem = fn.substring("server-".length(), fn.length() - ".json".length());
            String[] parts = stem.split("-");
            try {
                long pid = Long.parseLong(parts[0]);
                // Legacy pid-only names carry no port; treat them as unclaimed.
                int filePort = parts.length > 1 ? Integer.parseInt(parts[1]) : -1;

                boolean stale = (pid == selfPid)
                    ? !(filePort > 0 && McpWorkspaceRegistry.isLocalRunningPort(filePort))
                    : ProcessHandle.of(pid).isEmpty();

                if (stale) {
                    Files.deleteIfExists(p);
                    Msg.info(this, "Pruned stale MCP discovery file: " + fn);
                }
            } catch (NumberFormatException nfe) {
                // unrecognised name — leave it alone
            } catch (Exception e) {
                Msg.debug(this, "Could not prune " + fn + ": " + e.getMessage());
            }
        }
    }

    private void deletePortFile() {
        if (portFile != null) {
            try {
                Files.deleteIfExists(portFile);
            } catch (Exception e) {
                Msg.debug(this, "Failed to delete port file: " + e.getMessage());
            }
            portFile = null;
        }
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        if (autoStart && (transport == null || !transport.isRunning())) {
            startServer();
        }
        // Keep the discovery file's advertised binary in sync so a launcher can
        // route by target even after the user opens/switches programs.
        refreshPortFile();
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        if (decompPool != null && program != null) {
            decompPool.invalidate(program);
        }
        refreshPortFile();
    }

    @Override
    protected void dispose() {
        stopServer();
        McpWorkspaceRegistry.unregister(this);
        super.dispose();
    }

    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
        switch (optionName) {
            case OPTION_PORT:
                port = (int) newValue;
                break;
            case OPTION_AUTH_TOKEN:
                authToken = (String) newValue;
                break;
            case OPTION_AUTO_START:
                autoStart = (boolean) newValue;
                break;
        }
        if ((OPTION_PORT.equals(optionName) || OPTION_AUTH_TOKEN.equals(optionName))
                && transport != null && transport.isRunning()) {
            Msg.info(this, "MCP server config changed, restarting...");
            stopServer();
            startServer();
        }
    }
}
