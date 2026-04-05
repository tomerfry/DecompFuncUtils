package decompfuncutils.mcp;

import com.google.gson.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Handles MCP JSON-RPC 2.0 protocol messages.
 *
 * Supports: initialize, notifications/initialized, ping, tools/list, tools/call
 */
public class McpProtocolHandler {

    private static final Set<String> TOOLS_WITHOUT_PROGRAM = Set.of(
        "ghidra_get_program_info",
        "ghidra_list_open_programs",
        "ghidra_open_program",
        "ghidra_switch_program"
    );

    private static final String PROTOCOL_VERSION = "2024-11-05";
    private static final String SERVER_NAME = "ghidra-mcp";
    private static final String SERVER_VERSION = "1.0.0";

    private final Gson gson = new GsonBuilder().create();
    private final McpToolRegistry toolRegistry;
    private final Supplier<Program> programSupplier;
    private final Supplier<PluginTool> toolSupplier;

    // Per-session active program tracking: sessionId -> program name
    private final ConcurrentHashMap<String, String> sessionPrograms = new ConcurrentHashMap<>();

    // Serialize EDT access with timeout to prevent agents from hanging indefinitely
    private static final long EDT_TIMEOUT_MS = 60_000;
    private final Semaphore edtSemaphore = new Semaphore(1);

    public McpProtocolHandler(McpToolRegistry toolRegistry,
                              Supplier<Program> programSupplier,
                              Supplier<PluginTool> toolSupplier) {
        this.toolRegistry = toolRegistry;
        this.programSupplier = programSupplier;
        this.toolSupplier = toolSupplier;
    }

    /**
     * Handle a JSON-RPC 2.0 request string, returning the response string.
     * Returns null for notifications (no response expected).
     *
     * @param requestJson the JSON-RPC request body
     * @param sessionId   the SSE session ID (used for per-session program context)
     */
    public String handleRequest(String requestJson, String sessionId) {
        JsonObject request;
        try {
            request = JsonParser.parseString(requestJson).getAsJsonObject();
        } catch (Exception e) {
            return errorResponse(null, -32700, "Parse error: " + e.getMessage());
        }

        JsonElement idElement = request.get("id");
        String method = request.has("method") ? request.get("method").getAsString() : null;
        JsonObject params = request.has("params") ? request.getAsJsonObject("params") : new JsonObject();

        if (method == null) {
            return errorResponse(idElement, -32600, "Invalid Request: missing method");
        }

        // Notifications (no id) — don't send a response
        if (idElement == null) {
            handleNotification(method, params);
            return null;
        }

        try {
            Object result = dispatch(method, params, sessionId);
            return successResponse(idElement, result);
        } catch (McpError e) {
            return errorResponse(idElement, e.code, e.getMessage());
        } catch (Exception e) {
            Msg.warn(this, "Error handling " + method + ": " + e.getMessage());
            return errorResponse(idElement, -32603, "Internal error: " + e.getMessage());
        }
    }

    /**
     * Remove session state when an SSE connection is closed.
     */
    public void removeSession(String sessionId) {
        if (sessionId != null) {
            sessionPrograms.remove(sessionId);
        }
    }

    private void handleNotification(String method, JsonObject params) {
        switch (method) {
            case "notifications/initialized":
                Msg.info(this, "MCP client initialized");
                break;
            case "notifications/cancelled":
                Msg.info(this, "MCP client cancelled request");
                break;
            default:
                Msg.debug(this, "Unknown notification: " + method);
        }
    }

    private Object dispatch(String method, JsonObject params, String sessionId) throws Exception {
        switch (method) {
            case "initialize":
                return handleInitialize(params);
            case "ping":
                return new JsonObject(); // empty result
            case "tools/list":
                return handleToolsList(params);
            case "tools/call":
                return handleToolsCall(params, sessionId);
            default:
                throw new McpError(-32601, "Method not found: " + method);
        }
    }

    // ---- initialize ----

    private Object handleInitialize(JsonObject params) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protocolVersion", PROTOCOL_VERSION);

        Map<String, Object> capabilities = new LinkedHashMap<>();
        Map<String, Object> toolsCap = new LinkedHashMap<>();
        toolsCap.put("listChanged", false);
        capabilities.put("tools", toolsCap);
        result.put("capabilities", capabilities);

        Map<String, Object> serverInfo = new LinkedHashMap<>();
        serverInfo.put("name", SERVER_NAME);
        serverInfo.put("version", SERVER_VERSION);
        result.put("serverInfo", serverInfo);

        return result;
    }

    // ---- tools/list ----

    private Object handleToolsList(JsonObject params) {
        List<Map<String, Object>> toolList = new ArrayList<>();
        for (McpTool tool : toolRegistry.all()) {
            Map<String, Object> toolDef = new LinkedHashMap<>();
            toolDef.put("name", tool.name());
            toolDef.put("description", tool.description());
            toolDef.put("inputSchema", tool.inputSchema());
            toolList.add(toolDef);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tools", toolList);
        return result;
    }

    // ---- tools/call ----

    // Tools that change the active program for a session
    private static final Set<String> PROGRAM_SWITCHING_TOOLS = Set.of(
        "ghidra_open_program",
        "ghidra_switch_program"
    );

    @SuppressWarnings("unchecked")
    private Object handleToolsCall(JsonObject params, String sessionId) throws Exception {
        if (!params.has("name")) {
            throw new McpError(-32602, "Missing required parameter: name");
        }
        String toolName = params.get("name").getAsString();

        McpTool mcpTool = toolRegistry.get(toolName);
        if (mcpTool == null) {
            throw new McpError(-32602, "Unknown tool: " + toolName);
        }

        // Parse arguments
        Map<String, Object> arguments = new HashMap<>();
        if (params.has("arguments") && !params.get("arguments").isJsonNull()) {
            arguments = gson.fromJson(params.get("arguments"), Map.class);
        }

        // Resolve program: per-session context first, then global fallback
        Program program = resolveSessionProgram(sessionId);
        PluginTool pluginTool = toolSupplier.get();

        if (program == null && !TOOLS_WITHOUT_PROGRAM.contains(toolName)) {
            throw new McpError(-32603, "No program is currently open in Ghidra. " +
                "Use ghidra_open_program to import and open a binary first.");
        }

        // Execute: off-EDT for thread-safe read-only tools, EDT for mutations and Swing-dependent tools
        Object result;
        if (mcpTool.isMutating()) {
            result = executeOnEdtWithTransaction(mcpTool, arguments, program, pluginTool);
        } else if (mcpTool.requiresEdt()) {
            result = executeOnEdt(mcpTool, arguments, program, pluginTool);
        } else {
            // Safe to execute on current HTTP worker thread — enables concurrent multi-agent access
            result = mcpTool.execute(arguments, program, pluginTool);
        }

        // After program-switching tools, update session context
        if (sessionId != null && PROGRAM_SWITCHING_TOOLS.contains(toolName) && result instanceof Map) {
            Map<String, Object> resultMap = (Map<String, Object>) result;
            String progName = (String) resultMap.get("name");
            if (progName == null) {
                progName = (String) resultMap.get("switched_to");
            }
            if (progName != null) {
                sessionPrograms.put(sessionId, progName);
                Msg.info(this, "Session " + sessionId + " active program set to: " + progName);
            }
        }

        // Format as MCP tool result
        Map<String, Object> callResult = new LinkedHashMap<>();
        List<Map<String, Object>> content = new ArrayList<>();

        Map<String, Object> textContent = new LinkedHashMap<>();
        textContent.put("type", "text");
        if (result instanceof String) {
            textContent.put("text", result);
        } else {
            textContent.put("text", gson.toJson(result));
        }
        content.add(textContent);

        callResult.put("content", content);
        return callResult;
    }

    /**
     * Resolve the active program for a session.
     * Checks per-session override first, then falls back to global active program.
     */
    private Program resolveSessionProgram(String sessionId) {
        PluginTool pluginTool = toolSupplier.get();
        ProgramManager pm = pluginTool != null ? pluginTool.getService(ProgramManager.class) : null;

        // Check per-session program override
        if (sessionId != null && pm != null) {
            String sessionProg = sessionPrograms.get(sessionId);
            if (sessionProg != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p.getName().equals(sessionProg)) {
                        return p;
                    }
                }
                // Session program no longer open — clear stale mapping
                Msg.warn(this, "Session " + sessionId + " program '" + sessionProg +
                    "' is no longer open, falling back to global active program");
                sessionPrograms.remove(sessionId);
            }
        }

        // Fallback to globally active program
        return programSupplier.get();
    }

    private Object executeOnEdt(McpTool tool, Map<String, Object> arguments,
                                 Program program, PluginTool pluginTool) throws Exception {
        if (!edtSemaphore.tryAcquire(EDT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            throw new McpError(-32603, "Server busy: another EDT operation is in progress. Try again shortly.");
        }
        try {
            AtomicReference<Object> resultRef = new AtomicReference<>();
            AtomicReference<Exception> errorRef = new AtomicReference<>();

            SwingUtilities.invokeAndWait(() -> {
                try {
                    resultRef.set(tool.execute(arguments, program, pluginTool));
                } catch (Exception e) {
                    errorRef.set(e);
                }
            });

            if (errorRef.get() != null) {
                throw errorRef.get();
            }
            return resultRef.get();
        } finally {
            edtSemaphore.release();
        }
    }

    private Object executeOnEdtWithTransaction(McpTool tool, Map<String, Object> arguments,
                                                Program program, PluginTool pluginTool) throws Exception {
        if (!edtSemaphore.tryAcquire(EDT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            throw new McpError(-32603, "Server busy: another EDT operation is in progress. Try again shortly.");
        }
        try {
            AtomicReference<Object> resultRef = new AtomicReference<>();
            AtomicReference<Exception> errorRef = new AtomicReference<>();

            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("MCP: " + tool.name());
                boolean success = false;
                try {
                    resultRef.set(tool.execute(arguments, program, pluginTool));
                    success = true;
                } catch (Exception e) {
                    errorRef.set(e);
                } finally {
                    program.endTransaction(txId, success);
                }
            });

            if (errorRef.get() != null) {
                throw errorRef.get();
            }
            return resultRef.get();
        } finally {
            edtSemaphore.release();
        }
    }

    // ---- JSON-RPC response helpers ----

    private String successResponse(JsonElement id, Object result) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        response.put("id", gson.fromJson(id, Object.class));
        response.put("result", result);
        return gson.toJson(response);
    }

    private String errorResponse(JsonElement id, int code, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        if (id != null) {
            response.put("id", gson.fromJson(id, Object.class));
        } else {
            response.put("id", null);
        }
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", code);
        error.put("message", message);
        response.put("error", error);
        return gson.toJson(response);
    }

    // ---- Error type ----

    static class McpError extends Exception {
        final int code;

        McpError(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}
