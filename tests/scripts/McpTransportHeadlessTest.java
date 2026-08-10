import ghidra.app.script.GhidraScript;

import decompfuncutils.mcp.McpHttpTransport;
import decompfuncutils.mcp.McpProtocolHandler;
import decompfuncutils.mcp.McpToolRegistry;
import decompfuncutils.mcp.tools.GetProgramInfoTool;
import decompfuncutils.mcp.tools.ListFunctionsTool;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Headless handshake test for both MCP transports served by McpHttpTransport.
 * Boots the transport in-process on a test port (13140-13149), then verifies:
 *   - Streamable HTTP (/mcp): initialize -> 200 + Mcp-Session-Id, initialized
 *     notification -> 202, tools/list, tools/call, GET -> 405, bogus session -> 404.
 *   - Legacy HTTP+SSE (/sse + /message): endpoint event, initialize + tools/list
 *     answered over the SSE stream.
 * Prints CHECK lines and HEADLESS_TEST_RESULT PASS/FAIL for the runner to parse.
 */
public class McpTransportHeadlessTest extends GhidraScript {

    private int passed = 0;
    private int failed = 0;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private void check(String name, boolean ok, String detail) {
        if (ok) { passed++; println("CHECK " + name + ": PASS"); }
        else    { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START mcp_transport prog=" + currentProgram.getName());

        McpToolRegistry registry = new McpToolRegistry();
        registry.register(new GetProgramInfoTool());
        registry.register(new ListFunctionsTool());
        McpProtocolHandler handler = new McpProtocolHandler(
            registry, () -> currentProgram, () -> null);
        // Window identity is what tells sibling servers of one Ghidra apart.
        handler.setInstructionsSupplier(() -> "attached to window 'HeadlessWindow'");

        McpHttpTransport transport = null;
        int port = -1;
        for (int p = 13140; p < 13150 && transport == null; p++) {
            McpHttpTransport t = new McpHttpTransport(p, null, handler);
            t.setDiscoveryInfoSupplier(() -> Map.of("window", "HeadlessWindow"));
            try {
                t.start();
                transport = t;
                port = p;
            } catch (Exception e) {
                // port busy — try the next one
            }
        }
        if (transport == null) {
            println("CHECK transport_start: FAIL (no free port in 13140-13149)");
            println("HEADLESS_TEST_RESULT FAIL");
            return;
        }
        println("CHECK transport_start: PASS");

        String base = "http://127.0.0.1:" + port;
        HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        try {
            runDiscoveryChecks(http, base, port);
            runStreamableChecks(http, base);
            runLegacySseChecks(http, base);
        } finally {
            transport.stop();
        }

        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    // ---- /discovery (window routing) ----

    /**
     * Launchers route a session to one window out of several served by one Ghidra
     * process, so /discovery must carry the window identity alongside the port.
     */
    private void runDiscoveryChecks(HttpClient http, String base, int port) throws Exception {
        HttpResponse<String> disc = http.send(
            HttpRequest.newBuilder(URI.create(base + "/discovery")).timeout(TIMEOUT).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        boolean ok = false;
        if (disc.statusCode() == 200) {
            JsonObject body = JsonParser.parseString(disc.body()).getAsJsonObject();
            ok = body.has("window")
                && "HeadlessWindow".equals(body.get("window").getAsString())
                && body.get("port").getAsInt() == port;
        }
        check("discovery_reports_window", ok, "status=" + disc.statusCode() + " body=" + disc.body());
    }

    // ---- Streamable HTTP (/mcp) ----

    private void runStreamableChecks(HttpClient http, String base) throws Exception {
        String initBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{" +
            "\"protocolVersion\":\"2025-03-26\",\"capabilities\":{}," +
            "\"clientInfo\":{\"name\":\"headless-test\",\"version\":\"0\"}}}";
        HttpResponse<String> init = http.send(post(base + "/mcp", initBody, null),
            HttpResponse.BodyHandlers.ofString());

        check("http_initialize_status", init.statusCode() == 200,
            "expected 200, got " + init.statusCode());
        String sessionId = init.headers().firstValue("Mcp-Session-Id").orElse(null);
        check("http_initialize_session_header", sessionId != null, "Mcp-Session-Id missing");

        JsonObject initJson = JsonParser.parseString(init.body()).getAsJsonObject();
        JsonObject initResult = initJson.getAsJsonObject("result");
        check("http_initialize_result", initResult != null
            && "2025-03-26".equals(initResult.get("protocolVersion").getAsString())
            && "ghidra-mcp".equals(initResult.getAsJsonObject("serverInfo").get("name").getAsString()),
            "body=" + init.body());
        // Clients learn which window they landed in from initialize.
        check("http_initialize_instructions", initResult != null
            && initResult.has("instructions")
            && initResult.get("instructions").getAsString().contains("HeadlessWindow"),
            "body=" + init.body());
        // Integer ids must round-trip untouched — "id":1.0 breaks typed clients.
        check("http_id_integer_fidelity",
            initJson.get("id").toString().equals("1"),
            "id serialized as " + initJson.get("id"));

        HttpResponse<String> initialized = http.send(
            post(base + "/mcp", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", sessionId),
            HttpResponse.BodyHandlers.ofString());
        check("http_initialized_notification", initialized.statusCode() == 202,
            "expected 202, got " + initialized.statusCode());

        HttpResponse<String> toolsList = http.send(
            post(base + "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", sessionId),
            HttpResponse.BodyHandlers.ofString());
        boolean toolsOk = false;
        int toolCount = -1;
        if (toolsList.statusCode() == 200) {
            JsonArray tools = JsonParser.parseString(toolsList.body()).getAsJsonObject()
                .getAsJsonObject("result").getAsJsonArray("tools");
            toolCount = tools.size();
            for (var t : tools) {
                if ("ghidra_get_program_info".equals(t.getAsJsonObject().get("name").getAsString())) {
                    toolsOk = true;
                }
            }
        }
        check("http_tools_list", toolsOk,
            "status=" + toolsList.statusCode() + " tools=" + toolCount);

        HttpResponse<String> call = http.send(
            post(base + "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"," +
                "\"params\":{\"name\":\"ghidra_get_program_info\",\"arguments\":{}}}", sessionId),
            HttpResponse.BodyHandlers.ofString());
        check("http_tools_call", call.statusCode() == 200
            && call.body().contains("\"content\"")
            && call.body().contains(currentProgram.getName()),
            "status=" + call.statusCode());

        HttpResponse<String> get = http.send(
            HttpRequest.newBuilder(URI.create(base + "/mcp")).timeout(TIMEOUT).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        check("http_get_returns_405", get.statusCode() == 405,
            "expected 405, got " + get.statusCode());

        HttpResponse<String> bogus = http.send(
            post(base + "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\"}",
                "00000000-dead-beef-0000-000000000000"),
            HttpResponse.BodyHandlers.ofString());
        check("http_unknown_session_404", bogus.statusCode() == 404,
            "expected 404, got " + bogus.statusCode());

        HttpResponse<String> del = http.send(
            HttpRequest.newBuilder(URI.create(base + "/mcp")).timeout(TIMEOUT)
                .header("Mcp-Session-Id", sessionId).DELETE().build(),
            HttpResponse.BodyHandlers.ofString());
        check("http_delete_session", del.statusCode() == 204,
            "expected 204, got " + del.statusCode());
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

    // ---- Legacy HTTP+SSE (/sse + /message) ----

    /** One parsed SSE event. */
    private static final class SseEvent {
        final String event;
        final String data;
        SseEvent(String event, String data) { this.event = event; this.data = data; }
    }

    private void runLegacySseChecks(HttpClient http, String base) throws Exception {
        HttpResponse<java.io.InputStream> sse = http.send(
            HttpRequest.newBuilder(URI.create(base + "/sse")).timeout(TIMEOUT)
                .header("Accept", "text/event-stream").GET().build(),
            HttpResponse.BodyHandlers.ofInputStream());
        check("sse_stream_opens", sse.statusCode() == 200
            && sse.headers().firstValue("Content-Type").orElse("").startsWith("text/event-stream"),
            "status=" + sse.statusCode());

        BlockingQueue<SseEvent> events = new ArrayBlockingQueue<>(64);
        Thread reader = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(sse.body(), StandardCharsets.UTF_8))) {
                String event = null;
                StringBuilder data = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.isEmpty()) {
                        if (event != null) {
                            events.offer(new SseEvent(event, data.toString()));
                        }
                        event = null;
                        data.setLength(0);
                    } else if (line.startsWith("event: ")) {
                        event = line.substring(7);
                    } else if (line.startsWith("data: ")) {
                        if (data.length() > 0) data.append('\n');
                        data.append(line.substring(6));
                    } // ": keepalive" comments are ignored
                }
            } catch (Exception ignored) {
                // stream closed at end of test
            }
        }, "sse-test-reader");
        reader.setDaemon(true);
        reader.start();

        SseEvent endpoint = events.poll(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        boolean endpointOk = endpoint != null && "endpoint".equals(endpoint.event)
            && endpoint.data.contains("/message?sessionId=");
        check("sse_endpoint_event", endpointOk,
            endpoint == null ? "no event within timeout" : endpoint.event + " " + endpoint.data);
        if (!endpointOk) {
            return;
        }
        String messageUrl = endpoint.data;

        HttpResponse<String> init = http.send(
            post(messageUrl, "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"initialize\",\"params\":{" +
                "\"protocolVersion\":\"2024-11-05\",\"capabilities\":{}," +
                "\"clientInfo\":{\"name\":\"headless-test\",\"version\":\"0\"}}}", null),
            HttpResponse.BodyHandlers.ofString());
        check("sse_initialize_accepted", init.statusCode() == 202,
            "expected 202, got " + init.statusCode());

        JsonObject initMsg = awaitMessage(events, 10);
        check("sse_initialize_response", initMsg != null
            && "2024-11-05".equals(initMsg.getAsJsonObject("result").get("protocolVersion").getAsString()),
            initMsg == null ? "no response within timeout" : initMsg.toString());

        http.send(post(messageUrl, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", null),
            HttpResponse.BodyHandlers.ofString());

        HttpResponse<String> tools = http.send(
            post(messageUrl, "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/list\"}", null),
            HttpResponse.BodyHandlers.ofString());
        check("sse_tools_list_accepted", tools.statusCode() == 202,
            "expected 202, got " + tools.statusCode());

        JsonObject toolsMsg = awaitMessage(events, 11);
        check("sse_tools_list_response", toolsMsg != null
            && toolsMsg.getAsJsonObject("result").getAsJsonArray("tools").size() >= 2,
            toolsMsg == null ? "no response within timeout" : toolsMsg.toString());
    }

    /** Wait for the SSE "message" event whose JSON-RPC id matches, skipping others. */
    private JsonObject awaitMessage(BlockingQueue<SseEvent> events, int id) throws Exception {
        long deadline = System.currentTimeMillis() + TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            SseEvent e = events.poll(500, TimeUnit.MILLISECONDS);
            if (e == null || !"message".equals(e.event)) {
                continue;
            }
            JsonObject msg = JsonParser.parseString(e.data).getAsJsonObject();
            if (msg.has("id") && msg.get("id").getAsInt() == id) {
                return msg;
            }
        }
        return null;
    }
}
