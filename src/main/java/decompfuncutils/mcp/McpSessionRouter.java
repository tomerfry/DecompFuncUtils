package decompfuncutils.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import decompfuncutils.mcp.McpProtocolHandler.McpError;
import decompfuncutils.mcp.McpWindowDirectory.Window;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The MCP session manager: one fixed endpoint in front of every tool window.
 *
 * <p>Each window still runs its own {@link McpProtocolHandler}. This router sits
 * above them and gives every connecting agent session a window of its own, so
 * any number of sessions can use the same URL without knowing a per-window port:
 *
 * <ul>
 *   <li>{@code initialize} and {@code tools/list} are answered here, so a client
 *       can connect before any CodeBrowser exists.</li>
 *   <li>The {@code ghidra_session_*} tools open, list, attach to, release and
 *       close windows.</li>
 *   <li>Every other tool call is forwarded, in process, to the window the session
 *       is bound to. An unbound session is bound on its first call: to a window no
 *       other session is using, or to a freshly opened one when none exists.</li>
 * </ul>
 *
 * <p>A session is never moved between windows behind its back. If its window
 * closes, calls fail until it attaches or opens a window explicitly, because a
 * silent move would aim the session's next edit at a different binary.
 */
public final class McpSessionRouter implements McpRequestHandler {

    public static final String TOOL_STATUS = "ghidra_session_status";
    public static final String TOOL_OPEN_WINDOW = "ghidra_session_open_window";
    public static final String TOOL_ATTACH = "ghidra_session_attach";
    public static final String TOOL_RELEASE = "ghidra_session_release";
    public static final String TOOL_CLOSE_WINDOW = "ghidra_session_close_window";

    /**
     * Optional argument accepted by every forwarded tool: run this one call in the
     * named window instead of the session's bound one. It exists for sub-agents,
     * which share their parent's MCP connection and so share one binding; each
     * sub-agent names its own window and they work side by side.
     */
    public static final String WINDOW_ARG = "window";

    // Per-window lane tools that hand out ports and attach commands. Through the
    // manager a session changes window with ghidra_session_*, so these would mislead.
    private static final Set<String> HIDDEN_WINDOW_TOOLS =
        Set.of("ghidra_list_windows", "ghidra_open_in_new_window");

    private static final String SERVER_NAME = "ghidra-mcp";
    private static final String SERVER_VERSION = "1.0.0";
    private static final String ANONYMOUS = "<no-session>";

    // A session that has been silent this long no longer keeps other sessions out
    // of its window. It stays bound; only the exclusivity lapses. Needed because a
    // Streamable HTTP client that exits without DELETE never tells us it is gone.
    private static final long DEFAULT_CLAIM_IDLE_MS = 30L * 60 * 1000;
    private static final long FORGET_AFTER_MS = 24L * 60 * 60 * 1000;

    private final Gson gson = new GsonBuilder().serializeNulls().create();
    private final McpWindowDirectory directory;
    private final McpToolRegistry catalog;

    private final Object lock = new Object();
    private final Map<String, Binding> bindings = new HashMap<>(); // guarded by lock
    private volatile long claimIdleMs = DEFAULT_CLAIM_IDLE_MS;

    private static final class Binding {
        Window window;
        String lostWindow;
        long lastActivity;
        // Windows this session reaches with the per-call window argument, and when
        // it last did. They count as in use, so no other session is bound into them.
        final Map<Window, Long> perCall = new HashMap<>();

        List<Window> allWindows() {
            List<Window> all = new ArrayList<>(perCall.keySet());
            if (window != null && !all.contains(window)) {
                all.add(window);
            }
            return all;
        }
    }

    /** Where a routed call goes, plus a note when the session was bound just now. */
    private static final class Route {
        final Window window;
        final String note;

        Route(Window window, String note) {
            this.window = window;
            this.note = note;
        }
    }

    /**
     * @param directory the windows this manager can route to and open
     * @param catalog   the per-window tool set, used to answer {@code tools/list}
     *                  without needing a window to exist
     */
    public McpSessionRouter(McpWindowDirectory directory, McpToolRegistry catalog) {
        this.directory = directory;
        this.catalog = catalog;
    }

    /** Override how long a silent session keeps its window to itself. */
    public void setClaimIdleMillis(long millis) {
        this.claimIdleMs = millis;
    }

    // ---- McpRequestHandler ----

    @Override
    public String handleRequest(String requestJson, String sessionId) {
        JsonObject request;
        try {
            request = JsonParser.parseString(requestJson).getAsJsonObject();
        } catch (Exception e) {
            return errorResponse(null, -32700, "Parse error: " + e.getMessage());
        }

        JsonElement id = request.get("id");
        String method = request.has("method") && request.get("method").isJsonPrimitive()
            ? request.get("method").getAsString() : null;
        JsonObject params = request.has("params") && request.get("params").isJsonObject()
            ? request.getAsJsonObject("params") : new JsonObject();

        if (method == null) {
            return errorResponse(id, -32600, "Invalid Request: missing method");
        }

        String session = sessionId != null ? sessionId : ANONYMOUS;

        if (id == null) {
            handleNotification(method, requestJson, session, sessionId);
            return null;
        }

        try {
            switch (method) {
                case "initialize":
                    return successResponse(id, initializeResult(params));
                case "ping":
                    return successResponse(id, new JsonObject());
                case "tools/list":
                    return successResponse(id, toolsListResult());
                case "tools/call":
                    return toolsCall(id, params, requestJson, session, sessionId);
                default:
                    throw new McpError(-32601, "Method not found: " + method);
            }
        } catch (McpError e) {
            return errorResponse(id, e.code, e.getMessage());
        } catch (Exception e) {
            Msg.warn(this, "Session manager error handling " + method + ": " + e.getMessage());
            return errorResponse(id, -32603, "Internal error: " + e.getMessage());
        }
    }

    @Override
    public void removeSession(String sessionId) {
        if (sessionId == null) {
            return;
        }
        Binding removed;
        synchronized (lock) {
            removed = bindings.remove(sessionId);
        }
        if (removed != null) {
            for (Window w : removed.allWindows()) {
                w.handler().removeSession(sessionId);
            }
        }
    }

    private void handleNotification(String method, String requestJson, String session,
                                    String sessionId) {
        // Cancellation targets a request that is running inside a window, so it
        // has to reach that window's handler. Never bind a session for this.
        if ("notifications/cancelled".equals(method)) {
            // The request may be running in the bound window or in one reached per
            // call; a window that does not know the request id ignores the notice.
            List<Window> windows;
            synchronized (lock) {
                Binding b = bindings.get(session);
                windows = b != null ? b.allWindows() : List.of();
            }
            for (Window window : windows) {
                if (window.isOpen()) {
                    window.handler().handleRequest(requestJson, sessionId);
                }
            }
        }
    }

    // ---- initialize / tools/list ----

    private Object initializeResult(JsonObject params) {
        String requested = params.has("protocolVersion") && params.get("protocolVersion").isJsonPrimitive()
            ? params.get("protocolVersion").getAsString() : null;
        String negotiated = requested != null
            && McpProtocolHandler.SUPPORTED_PROTOCOL_VERSIONS.contains(requested)
            ? requested : McpProtocolHandler.LATEST_PROTOCOL_VERSION;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protocolVersion", negotiated);
        result.put("capabilities", Map.of("tools", Map.of("listChanged", false)));
        result.put("serverInfo", Map.of("name", SERVER_NAME, "version", SERVER_VERSION));
        result.put("instructions",
            "This is the Ghidra MCP session manager: one fixed endpoint in front of every Ghidra "
            + "CodeBrowser window. Each agent session works in a window of its own. Your first "
            + "ghidra_* call binds this session to a window no other session is using, or opens one "
            + "if none exists; call " + TOOL_STATUS + " to see which window you are in. Use "
            + TOOL_OPEN_WINDOW + " to open another window (optionally on a program of the project) "
            + "and move into it, " + TOOL_ATTACH + " to switch to an existing window, and "
            + TOOL_RELEASE + " to give yours up while leaving it open, and " + TOOL_CLOSE_WINDOW
            + " to save its programs and close it. ghidra_save_program saves without closing; "
            + "programs imported with ghidra_open_program are writable and are saved "
            + "automatically when auto-analysis finishes. Every other ghidra_* tool acts on the window this "
            + "session is bound to. To work in several windows at once (for example from parallel "
            + "sub-agents, which share this one session), open them with " + TOOL_OPEN_WINDOW
            + " bind=false and pass the window name as the '" + WINDOW_ARG + "' argument on each "
            + "ghidra_* call; such a call runs in the named window and leaves the binding alone.");
        return result;
    }

    private Object toolsListResult() {
        List<Map<String, Object>> tools = new ArrayList<>(sessionToolDefinitions());
        for (McpTool tool : catalog.all()) {
            if (HIDDEN_WINDOW_TOOLS.contains(tool.name())) {
                continue;
            }
            Map<String, Object> def = new LinkedHashMap<>();
            def.put("name", tool.name());
            def.put("description", tool.description());
            def.put("inputSchema", withWindowArg(tool.inputSchema()));
            tools.add(def);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tools", tools);
        return result;
    }

    /** Copy of a window tool's schema with the optional per-call window argument added. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> withWindowArg(Map<String, Object> schema) {
        Map<String, Object> copy = new LinkedHashMap<>(schema);
        Map<String, Object> properties = new LinkedHashMap<>();
        if (schema.get("properties") instanceof Map) {
            properties.putAll((Map<String, Object>) schema.get("properties"));
        }
        if (!properties.containsKey(WINDOW_ARG)) {
            properties.put(WINDOW_ARG, Map.of("type", "string",
                "description", "Optional. Run this call in the named Ghidra window (as listed by "
                    + TOOL_STATUS + ") instead of the window this session is bound to. Lets "
                    + "parallel sub-agents each work in their own window."));
        }
        copy.put("properties", properties);
        return copy;
    }

    private static List<Map<String, Object>> sessionToolDefinitions() {
        List<Map<String, Object>> defs = new ArrayList<>();

        defs.add(toolDef(TOOL_STATUS,
            "Show which Ghidra window this session is bound to and list every open CodeBrowser "
            + "window with its programs and how many sessions are using it. All other ghidra_* "
            + "tools act on the bound window.",
            Map.of()));

        Map<String, Object> openProps = new LinkedHashMap<>();
        openProps.put("name", Map.of("type", "string",
            "description", "Name of a program in the project to open in the new window. Omit for "
                + "an empty window, then import a binary into it with ghidra_open_program."));
        openProps.put("domainFile", Map.of("type", "string",
            "description", "Project path of the program instead of its name (e.g. '/bins/libfoo.so')"));
        openProps.put("bind", Map.of("type", "boolean",
            "description", "Move this session into the new window (default true). Pass false to "
                + "open a window for another session and stay where you are."));
        defs.add(toolDef(TOOL_OPEN_WINDOW,
            "Open a NEW Ghidra CodeBrowser window and, by default, move this session into it. Use "
            + "it to get a window of your own when the others are in use, or to work on another "
            + "binary without disturbing the window you were in.",
            openProps));

        Map<String, Object> attachProps = new LinkedHashMap<>();
        attachProps.put("window", Map.of("type", "string",
            "description", "Window name as listed by " + TOOL_STATUS + ", e.g. 'CodeBrowser(2)'"));
        attachProps.put("port", Map.of("type", "integer",
            "description", "The window's direct MCP port instead of its name"));
        defs.add(toolDef(TOOL_ATTACH,
            "Bind this session to an existing Ghidra window, leaving the one it was in. Sharing a "
            + "window with another session is allowed but the two will overwrite each other's "
            + "renames and types.",
            attachProps));

        defs.add(toolDef(TOOL_RELEASE,
            "Unbind this session from its Ghidra window so another session can take it. The window "
            + "and its programs stay open.",
            Map.of()));

        Map<String, Object> closeProps = new LinkedHashMap<>();
        closeProps.put("window", Map.of("type", "string",
            "description", "Window to close, as listed by " + TOOL_STATUS + ". Defaults to the "
                + "window this session is bound to."));
        closeProps.put("save", Map.of("type", "boolean",
            "description", "Save every changed program before closing (default true). Pass false "
                + "to close and DISCARD unsaved changes."));
        closeProps.put("force", Map.of("type", "boolean",
            "description", "Close the window even though other sessions are using it "
                + "(default false)."));
        defs.add(toolDef(TOOL_CLOSE_WINDOW,
            "Save the programs open in a Ghidra CodeBrowser window to the project and close the "
            + "window. By default it closes the window this session is bound to and saves first, so "
            + "no work is lost; the programs stay in the project and can be reopened with "
            + TOOL_OPEN_WINDOW + ". Fails, leaving the window open, while auto-analysis is running "
            + "or if a program cannot be saved.",
            closeProps));

        return defs;
    }

    private static Map<String, Object> toolDef(String name, String description,
                                               Map<String, Object> properties) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        Map<String, Object> def = new LinkedHashMap<>();
        def.put("name", name);
        def.put("description", description);
        def.put("inputSchema", schema);
        return def;
    }

    // ---- tools/call ----

    @SuppressWarnings("unchecked")
    private String toolsCall(JsonElement id, JsonObject params, String requestJson,
                             String session, String sessionId) throws Exception {
        if (!params.has("name") || !params.get("name").isJsonPrimitive()) {
            throw new McpError(-32602, "Missing required parameter: name");
        }
        String toolName = params.get("name").getAsString();

        Map<String, Object> args = new HashMap<>();
        if (params.has("arguments") && params.get("arguments").isJsonObject()) {
            args = gson.fromJson(params.get("arguments"), Map.class);
        }

        switch (toolName) {
            case TOOL_STATUS:
                return successResponse(id, textResult(status(session)));
            case TOOL_OPEN_WINDOW:
                return successResponse(id, textResult(openWindow(args, session)));
            case TOOL_ATTACH:
                return successResponse(id, textResult(attach(args, session)));
            case TOOL_RELEASE:
                return successResponse(id, textResult(release(session, sessionId)));
            case TOOL_CLOSE_WINDOW:
                return successResponse(id, textResult(closeWindow(args, session, sessionId)));
            default:
                break;
        }

        if (HIDDEN_WINDOW_TOOLS.contains(toolName)) {
            throw new McpError(-32602, toolName + " is not available through the session manager. "
                + "Use " + TOOL_STATUS + " to list windows and " + TOOL_OPEN_WINDOW + " to open one.");
        }
        if (!catalog.has(toolName)) {
            throw new McpError(-32602, "Unknown tool: " + toolName);
        }

        String target = text(args.get(WINDOW_ARG));
        if (target != null) {
            Window window = perCallWindow(session, target);
            return window.handler().handleRequest(withoutWindowArg(requestJson), sessionId);
        }

        Route route = route(session);
        String response = route.window.handler().handleRequest(requestJson, sessionId);
        return route.note != null ? appendNote(response, route.note) : response;
    }

    /**
     * Resolve the window named on a single call and record that this session is
     * using it. The session's binding is left exactly as it was.
     */
    private Window perCallWindow(String session, String target) throws McpError {
        List<Window> windows = directory.windows();
        Window window = findWindow(windows, target);
        if (window == null) {
            throw new McpError(-32602, "No open Ghidra window matches '" + target + "' (the '"
                + WINDOW_ARG + "' argument). Open windows: " + names(windows) + ". Open one with "
                + TOOL_OPEN_WINDOW + ".");
        }
        long now = System.currentTimeMillis();
        synchronized (lock) {
            Binding b = bindings.computeIfAbsent(session, k -> new Binding());
            b.lastActivity = now;
            b.perCall.keySet().removeIf(w -> !w.isOpen());
            b.perCall.put(window, now);
        }
        return window;
    }

    /** Match a window by name (ignoring case) or by its direct port. */
    private static Window findWindow(List<Window> windows, String target) {
        for (Window w : windows) {
            if (w.name().equalsIgnoreCase(target)) {
                return w;
            }
        }
        try {
            int port = (int) Double.parseDouble(target);
            for (Window w : windows) {
                if (w.port() == port) {
                    return w;
                }
            }
        } catch (NumberFormatException e) {
            // not a port
        }
        return null;
    }

    private static List<String> names(List<Window> windows) {
        List<String> names = new ArrayList<>();
        for (Window w : windows) {
            names.add(w.name());
        }
        return names;
    }

    /** The request as the window should see it: without the routing argument. */
    private String withoutWindowArg(String requestJson) {
        JsonObject request = JsonParser.parseString(requestJson).getAsJsonObject();
        request.getAsJsonObject("params").getAsJsonObject("arguments").remove(WINDOW_ARG);
        return new Gson().toJson(request);
    }

    /** Find the window a session's tool call goes to, binding the session if needed. */
    private Route route(String session) throws McpError {
        long now = System.currentTimeMillis();
        synchronized (lock) {
            forgetIdleBindings(now);
            Binding b = bindings.computeIfAbsent(session, k -> new Binding());
            b.lastActivity = now;

            if (b.window != null) {
                if (b.window.isOpen()) {
                    return new Route(b.window, null);
                }
                b.lostWindow = b.window.name();
                b.window = null;
            }
            if (b.lostWindow != null) {
                throw new McpError(-32603, "Ghidra window '" + b.lostWindow + "', which this session "
                    + "was working in, has closed or stopped serving MCP. The session was not moved to "
                    + "another window. Call " + TOOL_STATUS + " to see the open windows, then "
                    + TOOL_ATTACH + " or " + TOOL_OPEN_WINDOW + ".");
            }

            List<Window> windows = directory.windows();
            Window pick = null;
            for (Window w : windows) {
                if (othersUsing(w, session, now) > 0) {
                    continue;
                }
                if (pick == null) {
                    pick = w;
                }
                if (w.activeProgram() != null) {
                    pick = w; // prefer a window that already has a binary loaded
                    break;
                }
            }
            if (pick != null) {
                b.window = pick;
                return new Route(pick, boundNote(pick, false));
            }
            if (!windows.isEmpty()) {
                List<String> names = new ArrayList<>();
                for (Window w : windows) {
                    names.add(w.name());
                }
                throw new McpError(-32603, "Every open Ghidra window is in use by another session "
                    + names + ". Call " + TOOL_OPEN_WINDOW + " to get a window of your own (pass a "
                    + "program name to open it there), or " + TOOL_ATTACH + " to share one.");
            }
        }

        // No window exists at all. Open one outside the lock: launching a tool
        // waits on the Swing thread, which must never wait on this lock in turn.
        Window opened;
        try {
            opened = directory.open(null, null);
        } catch (Exception e) {
            throw new McpError(-32603, "No Ghidra CodeBrowser window is open and one could not be "
                + "opened: " + e.getMessage());
        }
        bind(session, opened);
        return new Route(opened, boundNote(opened, true));
    }

    private static String boundNote(Window window, boolean opened) {
        String program = window.activeProgram();
        return "[ghidra session manager] " + (opened ? "Opened window '" : "This session is now bound to window '")
            + window.name() + "'" + (opened ? " for this session" : "")
            + (program != null ? " (active program: " + program + ")"
                               : " (no program loaded; open one with ghidra_open_program)")
            + ". " + TOOL_STATUS + " lists all windows.";
    }

    private void bind(String session, Window window) {
        synchronized (lock) {
            Binding b = bindings.computeIfAbsent(session, k -> new Binding());
            b.window = window;
            b.lostWindow = null;
            b.lastActivity = System.currentTimeMillis();
        }
    }

    /** Number of other sessions actively holding a window. Caller holds the lock. */
    private int othersUsing(Window window, String session, long now) {
        int count = 0;
        for (Map.Entry<String, Binding> e : bindings.entrySet()) {
            Binding b = e.getValue();
            if (e.getKey().equals(session)) {
                continue;
            }
            Long perCallUse = b.perCall.get(window);
            boolean bound = b.window == window && now - b.lastActivity < claimIdleMs;
            boolean perCall = perCallUse != null && now - perCallUse < claimIdleMs;
            if (bound || perCall) {
                count++;
            }
        }
        return count;
    }

    private void forgetIdleBindings(long now) {
        for (Iterator<Binding> it = bindings.values().iterator(); it.hasNext();) {
            if (now - it.next().lastActivity > FORGET_AFTER_MS) {
                it.remove();
            }
        }
    }

    // ---- ghidra_session_* tools ----

    private Object status(String session) {
        long now = System.currentTimeMillis();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("role", "ghidra-session-manager");
        result.put("project", directory.projectName());

        List<Window> windows = directory.windows();
        synchronized (lock) {
            Binding b = bindings.get(session);
            Window mine = b != null ? b.window : null;
            if (b != null) {
                b.lastActivity = now;
            }

            Map<String, Object> self = new LinkedHashMap<>();
            self.put("window", mine != null && mine.isOpen() ? mine.name() : null);
            if (b != null && b.lostWindow != null) {
                self.put("lostWindow", b.lostWindow);
            }
            result.put("session", self);

            List<Map<String, Object>> list = new ArrayList<>();
            for (Window w : windows) {
                Map<String, Object> info = describe(w);
                info.put("otherSessions", othersUsing(w, session, now));
                info.put("thisSession", w == mine);
                if (b != null && b.perCall.containsKey(w)) {
                    info.put("usedPerCall", true);
                }
                list.add(info);
            }
            result.put("windows", list);
        }

        result.put("hint", windows.isEmpty()
            ? "No CodeBrowser window is open. Any ghidra_* tool call opens one, or call "
                + TOOL_OPEN_WINDOW + "."
            : "Tool calls act on the window marked thisSession. " + TOOL_OPEN_WINDOW
                + " opens another; " + TOOL_ATTACH + " switches to an existing one; "
                + TOOL_CLOSE_WINDOW + " saves and closes one.");
        return result;
    }

    private Object openWindow(Map<String, Object> args, String session) throws McpError {
        String name = text(args.get("name"));
        String domainFile = text(args.get("domainFile"));
        boolean bind = args.get("bind") == null || Boolean.parseBoolean(String.valueOf(args.get("bind")));

        Window opened;
        try {
            opened = directory.open(name, domainFile);
        } catch (Exception e) {
            throw new McpError(-32603, "Could not open a new Ghidra window: " + e.getMessage());
        }
        if (bind) {
            bind(session, opened);
        }

        Map<String, Object> result = describe(opened);
        result.put("bound", bind);
        result.put("hint", bind
            ? "This session's ghidra_* calls now act on '" + opened.name() + "'."
                + (opened.activeProgram() == null
                    ? " It has no program yet; import one with ghidra_open_program." : "")
            : "Window opened but this session stayed where it was. Pass " + WINDOW_ARG + "='"
                + opened.name() + "' on ghidra_* calls to work in it without moving (give each "
                + "parallel sub-agent its own window this way). Otherwise another session picks it "
                + "up on its first call.");
        return result;
    }

    private Object attach(Map<String, Object> args, String session) throws McpError {
        String name = text(args.get("window"));
        Integer port = null;
        if (args.get("port") != null) {
            try {
                port = (int) Double.parseDouble(String.valueOf(args.get("port")));
            } catch (NumberFormatException e) {
                throw new McpError(-32602, "port must be a number");
            }
        }
        if (name == null && port == null) {
            throw new McpError(-32602, "Give the window name or its port. " + TOOL_STATUS + " lists them.");
        }

        List<Window> windows = directory.windows();
        Window target = null;
        for (Window w : windows) {
            boolean match = name != null ? w.name().equalsIgnoreCase(name) : w.port() == port;
            if (match) {
                target = w;
                break;
            }
        }
        if (target == null) {
            List<String> names = new ArrayList<>();
            for (Window w : windows) {
                names.add(w.name());
            }
            throw new McpError(-32602, "No open Ghidra window matches "
                + (name != null ? "'" + name + "'" : "port " + port) + ". Open windows: " + names);
        }

        bind(session, target);
        int others;
        synchronized (lock) {
            others = othersUsing(target, session, System.currentTimeMillis());
        }
        Map<String, Object> result = describe(target);
        result.put("bound", true);
        result.put("otherSessions", others);
        if (others > 0) {
            result.put("warning", others + " other session(s) are using this window. Edits from "
                + "both sides land in the same program and can overwrite each other.");
        }
        return result;
    }

    private Object release(String session, String sessionId) {
        Window was;
        List<Window> held;
        synchronized (lock) {
            Binding b = bindings.remove(session);
            was = b != null ? b.window : null;
            held = b != null ? b.allWindows() : List.of();
        }
        if (sessionId != null) {
            for (Window w : held) {
                w.handler().removeSession(sessionId);
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("released", was != null ? was.name() : null);
        result.put("hint", "This session is unbound. Its next ghidra_* call binds it to a free "
            + "window again.");
        return result;
    }

    private Object closeWindow(Map<String, Object> args, String session, String sessionId)
            throws McpError {
        String name = text(args.get(WINDOW_ARG));
        boolean save = args.get("save") == null || Boolean.parseBoolean(String.valueOf(args.get("save")));
        boolean force = args.get("force") != null && Boolean.parseBoolean(String.valueOf(args.get("force")));

        Window target;
        int others;
        synchronized (lock) {
            if (name != null) {
                List<Window> windows = directory.windows();
                target = findWindow(windows, name);
                if (target == null) {
                    throw new McpError(-32602, "No open Ghidra window matches '" + name
                        + "'. Open windows: " + names(windows));
                }
            } else {
                Binding b = bindings.get(session);
                target = b != null ? b.window : null;
                if (target == null || !target.isOpen()) {
                    throw new McpError(-32602, "This session is not bound to an open Ghidra window, "
                        + "so there is nothing to close. Name one with the '" + WINDOW_ARG
                        + "' argument; " + TOOL_STATUS + " lists them.");
                }
            }
            others = othersUsing(target, session, System.currentTimeMillis());
        }
        if (others > 0 && !force) {
            throw new McpError(-32603, others + " other session(s) are using window '" + target.name()
                + "'. Closing it would pull it out from under them. Pass force=true to close it "
                + "anyway" + (save ? " (its programs are saved first)." : "."));
        }

        // Closing waits on saves and on the Swing thread, so it runs outside the lock.
        List<Map<String, Object>> programs;
        try {
            programs = target.close(save);
        } catch (Exception e) {
            throw new McpError(-32603, "Window '" + target.name() + "' was not closed: "
                + e.getMessage());
        }

        // This session asked for the close, so it is simply unbound: its next call
        // picks a window again. Other sessions that were in the window find out on
        // their next call, as for any window that closes.
        synchronized (lock) {
            Binding b = bindings.get(session);
            if (b != null) {
                b.perCall.remove(target);
                if (b.window == target) {
                    b.window = null;
                    b.lostWindow = null;
                }
            }
        }
        if (sessionId != null) {
            target.handler().removeSession(sessionId);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("closed", target.name());
        result.put("saved", save);
        result.put("programs", programs);
        result.put("hint", "The window is closed" + (save ? " and its programs are saved in the "
            + "project" : "; unsaved changes were discarded") + ". Reopen a program with "
            + TOOL_OPEN_WINDOW + " name=<program>. This session's next ghidra_* call binds it to "
            + "a free window, or opens a new one.");
        return result;
    }

    private static Map<String, Object> describe(Window w) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("window", w.name());
        if (w.port() > 0) {
            info.put("directPort", w.port());
        }
        info.put("activeProgram", w.activeProgram());
        info.put("programs", w.programs());
        return info;
    }

    /** Windows and how many sessions hold each, for the manager's /discovery output. */
    public List<Map<String, Object>> describeWindows() {
        long now = System.currentTimeMillis();
        List<Window> windows = directory.windows();
        List<Map<String, Object>> list = new ArrayList<>();
        synchronized (lock) {
            for (Window w : windows) {
                Map<String, Object> info = describe(w);
                info.put("sessions", othersUsing(w, null, now));
                list.add(info);
            }
        }
        return list;
    }

    private static String text(Object raw) {
        if (raw == null) {
            return null;
        }
        String s = String.valueOf(raw).trim();
        return s.isEmpty() ? null : s;
    }

    // ---- response helpers ----

    private Object textResult(Object payload) {
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("type", "text");
        block.put("text", payload instanceof String ? payload : gson.toJson(payload));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", List.of(block));
        return result;
    }

    /** Add a text block to a window's tool result telling the session where it landed. */
    private String appendNote(String response, String note) {
        try {
            JsonObject obj = JsonParser.parseString(response).getAsJsonObject();
            if (obj.has("error") && obj.get("error").isJsonObject()) {
                // The call failed (e.g. no program loaded yet) but the session was
                // still bound, so it needs to learn where it landed all the same.
                JsonObject error = obj.getAsJsonObject("error");
                String message = error.has("message") ? error.get("message").getAsString() : "";
                error.addProperty("message", message + " " + note);
                return new Gson().toJson(obj);
            }
            JsonObject result = obj.has("result") && obj.get("result").isJsonObject()
                ? obj.getAsJsonObject("result") : null;
            if (result == null || !result.has("content") || !result.get("content").isJsonArray()) {
                return response;
            }
            JsonArray content = result.getAsJsonArray("content");
            JsonObject block = new JsonObject();
            block.addProperty("type", "text");
            block.addProperty("text", note);
            content.add(block);
            return new Gson().toJson(obj);
        } catch (Exception e) {
            return response;
        }
    }

    // The request's id element is echoed verbatim, as in McpProtocolHandler:
    // strictly typed clients reject an integer id that comes back as 1.0.
    private String successResponse(JsonElement id, Object result) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id == null ? JsonNull.INSTANCE : id);
        response.add("result", gson.toJsonTree(result));
        return gson.toJson(response);
    }

    private String errorResponse(JsonElement id, int code, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        response.add("id", id == null ? JsonNull.INSTANCE : id);
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        response.add("error", error);
        return gson.toJson(response);
    }
}
