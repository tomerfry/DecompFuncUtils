package decompfuncutils.mcp;

import decompfuncutils.mcp.tools.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
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

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.COMMON,
    shortDescription = "MCP Server for AI Integration",
    description = "Exposes Ghidra analysis capabilities via the Model Context Protocol (MCP) " +
                  "for integration with AI agents like Claude Code."
)
//@formatter:on
public class McpServerPlugin extends ProgramPlugin implements OptionsChangeListener {

    private static final String OPTION_PORT = "MCP Server Port";
    private static final String OPTION_AUTH_TOKEN = "MCP Auth Token";
    private static final String OPTION_AUTO_START = "MCP Auto Start";

    private static final int DEFAULT_PORT = 13100;
    private static final String DEFAULT_AUTH_TOKEN = "";
    private static final boolean DEFAULT_AUTO_START = false;

    private McpHttpTransport transport;
    private McpToolRegistry toolRegistry;
    private McpProtocolHandler protocolHandler;
    private DecompInterfacePool decompPool;
    private Path portFile;

    private int port = DEFAULT_PORT;
    private String authToken = DEFAULT_AUTH_TOKEN;
    private boolean autoStart = DEFAULT_AUTO_START;

    private DockingAction startAction;
    private DockingAction stopAction;

    public McpServerPlugin(PluginTool tool) {
        super(tool);
        setupOptions();
        setupActions();
        setupToolRegistry();

        // Auto-start the server immediately so MCP clients can import binaries
        // even before a program is manually opened in the CodeBrowser.
        if (autoStart) {
            startServer();
        }
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

        protocolHandler = new McpProtocolHandler(
            toolRegistry,
            this::getCurrentProgram,
            () -> this.tool
        );
    }

    public void startServer() {
        if (transport != null && transport.isRunning()) {
            Msg.showInfo(this, null, "MCP Server",
                "MCP server is already running on port " + transport.getPort());
            return;
        }

        // Try configured port first, then scan up to 50 ports for a free one.
        // This allows multiple CodeBrowser instances to coexist.
        int actualPort = port;
        Exception lastError = null;
        for (int attempt = 0; attempt < 50; attempt++) {
            transport = new McpHttpTransport(actualPort, authToken, protocolHandler);
            try {
                transport.start();
                Msg.info(this, "MCP server started on http://127.0.0.1:" + actualPort +
                    " with " + toolRegistry.size() + " tools");
                if (actualPort != port) {
                    Msg.info(this, "Configured port " + port + " was busy, using " + actualPort);
                }
                writePortFile(actualPort);
                return;
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
    }

    public void stopServer() {
        if (transport != null) {
            transport.stop();
            transport = null;
            Msg.info(this, "MCP server stopped");
        }
        if (decompPool != null) {
            decompPool.disposeAll();
        }
        deletePortFile();
    }

    private void writePortFile(int actualPort) {
        try {
            Path portDir = Paths.get(System.getProperty("user.home"), ".ghidra-mcp");
            Files.createDirectories(portDir);

            long pid = ProcessHandle.current().pid();
            portFile = portDir.resolve("server-" + pid + ".json");

            String projectName = tool.getProject() != null ? tool.getProject().getName() : "unknown";
            String json = String.format(
                "{\"port\": %d, \"pid\": %d, \"started\": \"%s\", \"project\": \"%s\", \"url\": \"http://127.0.0.1:%d/sse\"}",
                actualPort, pid, Instant.now().toString(), projectName, actualPort
            );
            Files.writeString(portFile, json);
            portFile.toFile().deleteOnExit();
            Msg.info(this, "Port file written: " + portFile);
        } catch (Exception e) {
            Msg.warn(this, "Failed to write port file: " + e.getMessage());
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
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        if (decompPool != null && program != null) {
            decompPool.invalidate(program);
        }
    }

    @Override
    protected void dispose() {
        stopServer();
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
