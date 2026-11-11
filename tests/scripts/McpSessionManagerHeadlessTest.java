import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpHttpTransport;
import decompfuncutils.mcp.McpProtocolHandler;
import decompfuncutils.mcp.McpRequestHandler;
import decompfuncutils.mcp.McpServerPlugin;
import decompfuncutils.mcp.McpSessionRouter;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpToolRegistry;
import decompfuncutils.mcp.McpWindowDirectory;
import decompfuncutils.mcp.tools.GetProgramInfoTool;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Headless test for the MCP session manager (McpSessionRouter): the fixed
 * endpoint that gives every agent session a tool window of its own.
 *
 * Real tool windows need the Ghidra GUI, so the router is driven here with fake
 * windows, each backed by a real McpProtocolHandler on the loaded program. That
 * covers everything the router decides: binding, isolation between sessions,
 * opening, attaching, releasing, closed windows and idle claims. Launching an
 * actual CodeBrowser from the Project window is not covered.
 *
 * Prints CHECK lines and HEADLESS_TEST_RESULT PASS/FAIL for the runner to parse.
 */
public class McpSessionManagerHeadlessTest extends GhidraScript {

    private static final String WHO = "test_window_name";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private int passed = 0;
    private int failed = 0;
    private int nextId = 100;

    private void check(String name, boolean ok, String detail) {
        if (ok) { passed++; println("CHECK " + name + ": PASS"); }
        else    { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }

    /** Answers with the name of the window that executed it. */
    private static final class WhoTool implements McpTool {
        private final String window;
        WhoTool(String window) { this.window = window; }
        @Override public String name() { return WHO; }
        @Override public String description() { return "Name of the window that ran this call"; }
        @Override public Map<String, Object> inputSchema() {
            Map<String, Object> schema = new LinkedHashMap<>();
            schema.put("type", "object");
            schema.put("properties", new LinkedHashMap<>());
            return schema;
        }
        @Override public boolean requiresEdt() { return false; }
        @Override public Object execute(Map<String, Object> args, Program program, PluginTool tool) {
            // The manager's routing argument must never reach the window's tool.
            return args.containsKey("window") ? window + "!leaked-window-arg" : window;
        }
    }

    private final class FakeWindow implements McpWindowDirectory.Window {
        final String name;
        final int port;
        final McpProtocolHandler handler;
        volatile boolean open = true;
        volatile boolean hasProgram;

        FakeWindow(String name, int port, boolean hasProgram) {
            this.name = name;
            this.port = port;
            this.hasProgram = hasProgram;
            McpToolRegistry registry = new McpToolRegistry();
            registry.register(new GetProgramInfoTool());
            registry.register(new WhoTool(name));
            this.handler = new McpProtocolHandler(registry, () -> currentProgram, () -> null);
        }

        @Override public String name() { return name; }
        @Override public int port() { return port; }
        @Override public String activeProgram() { return hasProgram ? currentProgram.getName() : null; }
        @Override public List<String> programs() {
            return hasProgram ? List.of(currentProgram.getName()) : List.of();
        }
        @Override public boolean isOpen() { return open; }
        @Override public McpRequestHandler handler() { return handler; }

        volatile boolean busy;
        volatile Boolean closedWithSave;

        @Override public List<Map<String, Object>> close(boolean save) {
            if (busy) {
                throw new IllegalStateException("auto-analysis is still running");
            }
            closedWithSave = save;
            open = false;
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", "prog");
            entry.put("status", save ? "saved" : "discarded");
            return hasProgram ? List.of(entry) : List.of();
        }
    }

    private final class FakeDirectory implements McpWindowDirectory {
        final List<FakeWindow> all = new ArrayList<>();
        boolean canOpen = true;
        String lastOpenedProgram;

        @Override public List<Window> windows() {
            List<Window> open = new ArrayList<>();
            for (FakeWindow w : all) {
                if (w.open) open.add(w);
            }
            return open;
        }

        @Override public Window open(String programName, String domainFile) {
            if (!canOpen) {
                throw new IllegalStateException("no Ghidra project is open");
            }
            lastOpenedProgram = programName;
            FakeWindow w = new FakeWindow("Fake(" + (all.size() + 1) + ")", 13200 + all.size(),
                programName != null);
            all.add(w);
            return w;
        }

        @Override public String projectName() { return "HeadlessProject"; }
    }

    private McpSessionRouter newRouter(FakeDirectory dir) {
        McpToolRegistry catalog = new McpToolRegistry();
        McpServerPlugin.registerStandardTools(catalog, new DecompInterfacePool());
        catalog.register(new WhoTool("catalog"));
        return new McpSessionRouter(dir, catalog);
    }

    // ---- JSON-RPC helpers (direct, no HTTP) ----

    private JsonObject call(McpSessionRouter router, String session, String tool, String argsJson) {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + (nextId++) + ",\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"" + tool + "\",\"arguments\":" + argsJson + "}}";
        return JsonParser.parseString(router.handleRequest(body, session)).getAsJsonObject();
    }

    private static boolean isError(JsonObject response) {
        return response.has("error");
    }

    private static String errorText(JsonObject response) {
        return isError(response) ? response.getAsJsonObject("error").get("message").getAsString() : "";
    }

    /** Text of content block {@code index} of a successful tool result. */
    private static String text(JsonObject response, int index) {
        if (isError(response)) {
            return "<error: " + errorText(response) + ">";
        }
        JsonArray content = response.getAsJsonObject("result").getAsJsonArray("content");
        return index < content.size() ? content.get(index).getAsJsonObject().get("text").getAsString() : null;
    }

    private static JsonObject payload(JsonObject response) {
        return JsonParser.parseString(text(response, 0)).getAsJsonObject();
    }

    private static JsonObject windowEntry(JsonObject status, String window) {
        for (var e : status.getAsJsonArray("windows")) {
            if (window.equals(e.getAsJsonObject().get("window").getAsString())) {
                return e.getAsJsonObject();
            }
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START mcp_session_manager prog=" + currentProgram.getName());

        runHttpChecks();
        runBindingChecks();
        runPerCallWindowChecks();
        runClosedWindowChecks();
        runEdgeChecks();
        runCloseWindowChecks();

        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    // ---- ghidra_session_close_window: save and close ----

    private void runCloseWindowChecks() {
        FakeDirectory dir = new FakeDirectory();
        FakeWindow one = new FakeWindow("One", 13301, true);
        FakeWindow two = new FakeWindow("Two", 13302, true);
        FakeWindow three = new FakeWindow("Three", 13303, true);
        dir.all.add(one);
        dir.all.add(two);
        dir.all.add(three);
        McpSessionRouter router = newRouter(dir);

        JsonObject unbound = call(router, "A", "ghidra_session_close_window", "{}");
        check("close_unbound_session_rejected", isError(unbound) && one.open && two.open,
            unbound.toString());

        call(router, "A", "ghidra_session_attach", "{\"window\":\"One\"}");
        call(router, "B", "ghidra_session_attach", "{\"window\":\"Two\"}");

        // A busy window stays open and the session stays bound to it.
        one.busy = true;
        JsonObject busy = call(router, "A", "ghidra_session_close_window", "{}");
        check("close_busy_window_reported", isError(busy) && errorText(busy).contains("analysis")
            && one.open && "One".equals(text(call(router, "A", WHO, "{}"), 0)), busy.toString());
        one.busy = false;

        JsonObject closed = call(router, "A", "ghidra_session_close_window", "{}");
        check("close_bound_window_saves", !isError(closed) && !one.open
            && Boolean.TRUE.equals(one.closedWithSave)
            && "One".equals(payload(closed).get("closed").getAsString())
            && "saved".equals(payload(closed).getAsJsonArray("programs").get(0).getAsJsonObject()
                .get("status").getAsString()), closed.toString());

        // The closer is unbound, not stranded: its next call takes a free window.
        check("closer_rebinds_to_free_window", "Three".equals(text(call(router, "A", WHO, "{}"), 0)),
            "A did not move to the free window");

        JsonObject shared = call(router, "A", "ghidra_session_close_window", "{\"window\":\"Two\"}");
        check("close_window_in_use_rejected", isError(shared) && two.open
            && errorText(shared).contains("force"), shared.toString());

        JsonObject forced = call(router, "A", "ghidra_session_close_window",
            "{\"window\":\"Two\",\"force\":true,\"save\":false}");
        check("close_named_window_discarding", !isError(forced) && !two.open
            && Boolean.FALSE.equals(two.closedWithSave)
            && "Three".equals(text(call(router, "A", WHO, "{}"), 0)), forced.toString());

        JsonObject lost = call(router, "B", WHO, "{}");
        check("other_session_told_window_closed", isError(lost) && errorText(lost).contains("Two"),
            lost.toString());

        JsonObject missing = call(router, "A", "ghidra_session_close_window", "{\"window\":\"Nope\"}");
        check("close_unknown_window_rejected", isError(missing) && three.open, missing.toString());
    }

    // ---- over the real transport: connect before any window exists ----

    private void runHttpChecks() throws Exception {
        FakeDirectory dir = new FakeDirectory();
        McpSessionRouter router = newRouter(dir);

        McpHttpTransport transport = null;
        int port = -1;
        for (int p = 13130; p < 13140 && transport == null; p++) {
            McpHttpTransport t = new McpHttpTransport(p, null, router);
            t.setDiscoveryInfoSupplier(() -> Map.of("role", "session-manager",
                "windows", router.describeWindows()));
            try {
                t.start();
                transport = t;
                port = p;
            } catch (Exception e) {
                // port busy — try the next one
            }
        }
        check("manager_transport_start", transport != null, "no free port in 13130-13139");
        if (transport == null) {
            return;
        }

        String base = "http://127.0.0.1:" + port;
        HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        try {
            HttpResponse<String> init = http.send(post(base + "/mcp",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
                + "\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},"
                + "\"clientInfo\":{\"name\":\"headless-test\",\"version\":\"0\"}}}", null),
                HttpResponse.BodyHandlers.ofString());
            String sessionId = init.headers().firstValue("Mcp-Session-Id").orElse(null);
            JsonObject initJson = JsonParser.parseString(init.body()).getAsJsonObject();
            JsonObject initResult = initJson.getAsJsonObject("result");
            check("manager_initialize_without_windows", init.statusCode() == 200 && sessionId != null
                && initResult != null
                && "2025-03-26".equals(initResult.get("protocolVersion").getAsString())
                && initResult.get("instructions").getAsString().contains("session manager"),
                "status=" + init.statusCode() + " body=" + init.body());
            check("manager_id_integer_fidelity", initJson.get("id").toString().equals("1"),
                "id serialized as " + initJson.get("id"));

            HttpResponse<String> list = http.send(post(base + "/mcp",
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", sessionId),
                HttpResponse.BodyHandlers.ofString());
            List<String> names = new ArrayList<>();
            for (var t : JsonParser.parseString(list.body()).getAsJsonObject()
                    .getAsJsonObject("result").getAsJsonArray("tools")) {
                names.add(t.getAsJsonObject().get("name").getAsString());
            }
            check("manager_lists_session_tools", names.contains("ghidra_session_status")
                && names.contains("ghidra_session_open_window")
                && names.contains("ghidra_session_attach")
                && names.contains("ghidra_session_release")
                && names.contains("ghidra_session_close_window")
                && names.contains("ghidra_save_program"), "tools=" + names);
            check("manager_lists_window_tools", names.contains("ghidra_decompile_function")
                && names.contains("ghidra_open_program") && names.size() > 40,
                "count=" + names.size());
            check("manager_hides_lane_tools", !names.contains("ghidra_open_in_new_window")
                && !names.contains("ghidra_list_windows"), "tools=" + names);

            // No window exists yet: the first tool call has to open one and run there.
            HttpResponse<String> first = http.send(post(base + "/mcp",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{"
                + "\"name\":\"ghidra_get_program_info\",\"arguments\":{}}}", sessionId),
                HttpResponse.BodyHandlers.ofString());
            JsonObject firstJson = JsonParser.parseString(first.body()).getAsJsonObject();
            check("first_call_opens_window", dir.all.size() == 1 && !isError(firstJson)
                && text(firstJson, 0).contains(currentProgram.getName()),
                "windows=" + dir.all.size() + " body=" + first.body());
            String note = text(firstJson, 1);
            check("first_call_reports_window", note != null && note.contains("Fake(1)"),
                "note=" + note);

            HttpResponse<String> second = http.send(post(base + "/mcp",
                "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{"
                + "\"name\":\"" + WHO + "\",\"arguments\":{}}}", sessionId),
                HttpResponse.BodyHandlers.ofString());
            JsonObject secondJson = JsonParser.parseString(second.body()).getAsJsonObject();
            check("later_calls_stay_in_window", dir.all.size() == 1
                && "Fake(1)".equals(text(secondJson, 0)) && text(secondJson, 1) == null,
                "body=" + second.body());

            HttpResponse<String> disc = http.send(
                HttpRequest.newBuilder(URI.create(base + "/discovery")).timeout(TIMEOUT).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            JsonObject discJson = JsonParser.parseString(disc.body()).getAsJsonObject();
            check("manager_discovery", disc.statusCode() == 200
                && "session-manager".equals(discJson.get("role").getAsString())
                && discJson.getAsJsonArray("windows").size() == 1
                && discJson.getAsJsonArray("windows").get(0).getAsJsonObject().get("sessions").getAsInt() == 1,
                "body=" + disc.body());
        } finally {
            transport.stop();
        }
    }

    private HttpRequest post(String url, String body, String sessionId) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (sessionId != null) {
            b.header("Mcp-Session-Id", sessionId);
        }
        return b.build();
    }

    // ---- several sessions, one window each ----

    private void runBindingChecks() {
        FakeDirectory dir = new FakeDirectory();
        McpSessionRouter router = newRouter(dir);

        // A operator-opened window with a binary, and an empty one.
        FakeWindow empty = new FakeWindow("Empty", 13201, false);
        FakeWindow loaded = new FakeWindow("Loaded", 13202, true);
        dir.all.add(empty);
        dir.all.add(loaded);

        JsonObject a1 = call(router, "A", WHO, "{}");
        check("unbound_session_prefers_loaded_window", "Loaded".equals(text(a1, 0))
            && text(a1, 1) != null && text(a1, 1).contains("Loaded"), a1.toString());

        JsonObject b1 = call(router, "B", WHO, "{}");
        check("second_session_gets_other_window", "Empty".equals(text(b1, 0)), b1.toString());

        JsonObject c1 = call(router, "C", WHO, "{}");
        check("third_session_told_windows_in_use", isError(c1)
            && errorText(c1).contains("in use") && errorText(c1).contains("ghidra_session_open_window")
            && dir.all.size() == 2, c1.toString());

        JsonObject cOpen = call(router, "C", "ghidra_session_open_window", "{\"name\":\"libfoo.so\"}");
        check("open_window_binds_session", !isError(cOpen)
            && payload(cOpen).get("bound").getAsBoolean()
            && "Fake(3)".equals(payload(cOpen).get("window").getAsString())
            && "libfoo.so".equals(dir.lastOpenedProgram), cOpen.toString());

        check("sessions_are_isolated", "Loaded".equals(text(call(router, "A", WHO, "{}"), 0))
            && "Empty".equals(text(call(router, "B", WHO, "{}"), 0))
            && "Fake(3)".equals(text(call(router, "C", WHO, "{}"), 0)), "cross-talk between sessions");

        JsonObject status = payload(call(router, "B", "ghidra_session_status", "{}"));
        JsonObject mine = windowEntry(status, "Empty");
        JsonObject theirs = windowEntry(status, "Loaded");
        check("status_reports_binding", "Empty".equals(status.getAsJsonObject("session").get("window").getAsString())
            && mine != null && mine.get("thisSession").getAsBoolean()
            && mine.get("otherSessions").getAsInt() == 0
            && theirs != null && !theirs.get("thisSession").getAsBoolean()
            && theirs.get("otherSessions").getAsInt() == 1
            && status.getAsJsonArray("windows").size() == 3, status.toString());

        JsonObject dOpen = call(router, "D", "ghidra_session_open_window", "{\"bind\":false}");
        check("open_window_without_bind", !isError(dOpen) && !payload(dOpen).get("bound").getAsBoolean()
            && dir.all.size() == 4, dOpen.toString());
        check("unbound_window_is_picked_up", "Fake(4)".equals(text(call(router, "D", WHO, "{}"), 0)),
            "D did not land in the free window");

        JsonObject eAttach = call(router, "E", "ghidra_session_attach", "{\"window\":\"loaded\"}");
        check("attach_shares_with_warning", !isError(eAttach)
            && payload(eAttach).get("otherSessions").getAsInt() == 1
            && payload(eAttach).has("warning")
            && "Loaded".equals(text(call(router, "E", WHO, "{}"), 0)), eAttach.toString());

        JsonObject ePort = call(router, "E", "ghidra_session_attach", "{\"port\":13201}");
        check("attach_by_port", !isError(ePort)
            && "Empty".equals(text(call(router, "E", WHO, "{}"), 0)), ePort.toString());

        JsonObject bad = call(router, "E", "ghidra_session_attach", "{\"window\":\"Nope\"}");
        check("attach_unknown_window_rejected", isError(bad) && errorText(bad).contains("Loaded")
            && "Empty".equals(text(call(router, "E", WHO, "{}"), 0)), bad.toString());

        // A leaves; its window becomes free for the next unbound session.
        JsonObject rel = call(router, "A", "ghidra_session_release", "{}");
        call(router, "E", "ghidra_session_release", "{}");
        check("release_reports_window", !isError(rel)
            && "Loaded".equals(payload(rel).get("released").getAsString()), rel.toString());
        check("released_window_is_reused", "Loaded".equals(text(call(router, "F", WHO, "{}"), 0)),
            "F did not get the released window");

        // A transport session ending frees its window the same way.
        router.removeSession("F");
        check("ended_session_frees_window", "Loaded".equals(text(call(router, "G", WHO, "{}"), 0)),
            "G did not get the window of the ended session");
    }

    // ---- one session, several windows at once (parallel sub-agents) ----

    private void runPerCallWindowChecks() throws Exception {
        FakeDirectory dir = new FakeDirectory();
        McpSessionRouter router = newRouter(dir);
        dir.all.add(new FakeWindow("W1", 13231, true));
        dir.all.add(new FakeWindow("W2", 13232, true));
        dir.all.add(new FakeWindow("W3", 13233, false));

        check("percall_setup", "W1".equals(text(call(router, "P", WHO, "{}"), 0)), "P not in W1");

        JsonObject w2 = call(router, "P", WHO, "{\"window\":\"W2\"}");
        check("percall_routes_to_named_window", "W2".equals(text(w2, 0)) && text(w2, 1) == null,
            w2.toString());
        check("percall_name_ignores_case", "W3".equals(text(call(router, "P", WHO, "{\"window\":\"w3\"}"), 0)),
            "w3 did not reach W3");
        check("percall_by_port", "W2".equals(text(call(router, "P", WHO, "{\"window\":\"13232\"}"), 0))
            && "W3".equals(text(call(router, "P", WHO, "{\"window\":13233}"), 0)), "port did not match");
        check("percall_leaves_binding_alone", "W1".equals(text(call(router, "P", WHO, "{}"), 0)),
            "binding moved");

        // Three "sub-agents" on one session hammer three windows at the same time.
        String[] targets = { "W1", "W2", "W3" };
        java.util.concurrent.atomic.AtomicInteger wrong = new java.util.concurrent.atomic.AtomicInteger();
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < targets.length; t++) {
            final String target = targets[t];
            final int base = 10_000 * (t + 1);
            Thread th = new Thread(() -> {
                for (int i = 0; i < 60; i++) {
                    String body = "{\"jsonrpc\":\"2.0\",\"id\":" + (base + i) + ",\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"" + WHO + "\",\"arguments\":{\"window\":\"" + target + "\"}}}";
                    JsonObject r = JsonParser.parseString(router.handleRequest(body, "P")).getAsJsonObject();
                    if (!target.equals(text(r, 0)) || r.get("id").getAsInt() != base + i) {
                        wrong.incrementAndGet();
                    }
                }
            });
            threads.add(th);
            th.start();
        }
        for (Thread th : threads) {
            th.join(30_000);
        }
        check("percall_parallel_no_crosstalk", wrong.get() == 0, wrong.get() + " misrouted calls");

        JsonObject other = call(router, "Q", WHO, "{}");
        check("percall_windows_count_as_in_use", isError(other) && errorText(other).contains("in use"),
            other.toString());

        JsonObject status = payload(call(router, "P", "ghidra_session_status", "{}"));
        JsonObject w2Entry = windowEntry(status, "W2");
        check("status_reports_percall_use", w2Entry != null && w2Entry.has("usedPerCall")
            && !w2Entry.get("thisSession").getAsBoolean()
            && windowEntry(status, "W1").get("thisSession").getAsBoolean(), status.toString());

        JsonObject missing = call(router, "P", WHO, "{\"window\":\"Nope\"}");
        check("percall_unknown_window_rejected", isError(missing) && errorText(missing).contains("W2"),
            missing.toString());

        // An unbound session can work purely per call, without being bound anywhere.
        JsonObject unbound = call(router, "R", WHO, "{\"window\":\"W3\"}");
        JsonObject rStatus = payload(call(router, "R", "ghidra_session_status", "{}"));
        check("percall_needs_no_binding", "W3".equals(text(unbound, 0))
            && rStatus.getAsJsonObject("session").get("window").isJsonNull(), rStatus.toString());

        String list = router.handleRequest("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", "P");
        boolean windowTool = false;
        boolean sessionTool = true;
        for (var t : JsonParser.parseString(list).getAsJsonObject().getAsJsonObject("result").getAsJsonArray("tools")) {
            JsonObject def = t.getAsJsonObject();
            boolean has = def.getAsJsonObject("inputSchema").getAsJsonObject("properties").has("window");
            String name = def.get("name").getAsString();
            if ("ghidra_decompile_function".equals(name)) {
                windowTool = has && def.getAsJsonObject("inputSchema").getAsJsonObject("properties").size() > 1;
            }
            if ("ghidra_session_status".equals(name) || "ghidra_session_release".equals(name)) {
                sessionTool &= !has;
            }
        }
        check("tools_advertise_window_arg", windowTool && sessionTool,
            "windowTool=" + windowTool + " sessionTool=" + sessionTool);

        call(router, "P", "ghidra_session_release", "{}");
        call(router, "R", "ghidra_session_release", "{}");
        check("release_frees_percall_windows", "W1".equals(text(call(router, "Q", WHO, "{}"), 0)),
            "Q still kept out after release");
    }

    // ---- a window closing under a session ----

    private void runClosedWindowChecks() {
        FakeDirectory dir = new FakeDirectory();
        McpSessionRouter router = newRouter(dir);
        FakeWindow first = new FakeWindow("First", 13211, true);
        FakeWindow second = new FakeWindow("Second", 13212, true);
        dir.all.add(first);
        dir.all.add(second);

        check("closed_setup", "First".equals(text(call(router, "A", WHO, "{}"), 0)), "A not in First");
        first.open = false;

        JsonObject lost = call(router, "A", WHO, "{}");
        check("closed_window_is_an_error", isError(lost) && errorText(lost).contains("First")
            && errorText(lost).contains("closed"), lost.toString());
        JsonObject again = call(router, "A", WHO, "{}");
        check("closed_window_never_silently_moves", isError(again), again.toString());

        JsonObject status = payload(call(router, "A", "ghidra_session_status", "{}"));
        check("status_reports_lost_window", status.getAsJsonObject("session").get("window").isJsonNull()
            && "First".equals(status.getAsJsonObject("session").get("lostWindow").getAsString())
            && status.getAsJsonArray("windows").size() == 1, status.toString());

        call(router, "A", "ghidra_session_attach", "{\"window\":\"Second\"}");
        check("explicit_attach_recovers", "Second".equals(text(call(router, "A", WHO, "{}"), 0)),
            "A did not recover in Second");
    }

    // ---- edges ----

    private void runEdgeChecks() {
        FakeDirectory dir = new FakeDirectory();
        McpSessionRouter router = newRouter(dir);

        dir.canOpen = false;
        JsonObject noProject = call(router, "A", WHO, "{}");
        check("no_window_and_cannot_open", isError(noProject)
            && errorText(noProject).contains("could not be opened")
            && errorText(noProject).contains("no Ghidra project is open"), noProject.toString());
        dir.canOpen = true;

        JsonObject hidden = call(router, "A", "ghidra_open_in_new_window", "{}");
        check("lane_tool_rejected", isError(hidden)
            && errorText(hidden).contains("ghidra_session_open_window") && dir.all.isEmpty(),
            hidden.toString());

        JsonObject unknown = call(router, "A", "ghidra_no_such_tool", "{}");
        check("unknown_tool_rejected", isError(unknown) && dir.all.isEmpty(), unknown.toString());

        // A window whose only session has gone quiet is no longer reserved.
        FakeWindow only = new FakeWindow("Only", 13221, true);
        dir.all.add(only);
        check("idle_setup", "Only".equals(text(call(router, "A", WHO, "{}"), 0)), "A not in Only");
        JsonObject busy = call(router, "B", WHO, "{}");
        check("active_claim_keeps_others_out", isError(busy), busy.toString());
        router.setClaimIdleMillis(0);
        check("idle_claim_lapses", "Only".equals(text(call(router, "B", WHO, "{}"), 0)),
            "B was kept out by an idle session");
        check("idle_session_keeps_its_binding", "Only".equals(text(call(router, "A", WHO, "{}"), 0)),
            "A lost its window");

        String ping = router.handleRequest("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}", "A");
        check("ping", JsonParser.parseString(ping).getAsJsonObject().has("result"), ping);
        check("notification_has_no_response",
            router.handleRequest("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", "A") == null,
            "notification answered");
    }
}
