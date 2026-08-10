package decompfuncutils.mcp;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Supplier;

/**
 * HTTP transport for the MCP protocol. Both supported MCP transports are
 * served on the same port:
 *
 * Legacy HTTP+SSE (2024-11-05) — used by Claude Code's "sse" client:
 *   GET  /sse     — SSE event stream (long-lived connection; staying open is
 *                   normal, not a hang). First event advertises the /message URL.
 *   POST /message — JSON-RPC 2.0 requests; always answered 202, responses are
 *                   pushed over the SSE stream.
 *
 * Streamable HTTP (2025-03-26+) — used by Codex and other modern clients:
 *   POST /mcp     — JSON-RPC 2.0 request in, JSON response body out (200).
 *                   Notifications are answered 202. The initialize response
 *                   carries an Mcp-Session-Id header the client echoes back.
 *   DELETE /mcp   — explicit session termination.
 */
public class McpHttpTransport {

    // Uses Ghidra's Msg for logging

    private static final Gson GSON = new Gson();

    private final int port;
    private final String authToken; // null = no auth
    private final McpProtocolHandler protocolHandler;
    private HttpServer server;

    // Optional owner-supplied facts (which tool window, which programs) merged into
    // /discovery so a probe can tell sibling servers of one Ghidra process apart.
    private volatile Supplier<Map<String, Object>> discoveryInfoSupplier;

    // Active SSE connections: sessionId -> output stream
    private final ConcurrentHashMap<String, SseConnection> sseConnections = new ConcurrentHashMap<>();

    // Sessions minted by the Streamable HTTP endpoint (no persistent connection)
    private final Set<String> streamableSessions = ConcurrentHashMap.newKeySet();

    // Scheduled executor for keepalive pings
    private ScheduledExecutorService keepaliveExecutor;

    public McpHttpTransport(int port, String authToken, McpProtocolHandler protocolHandler) {
        this.port = port;
        this.authToken = authToken;
        this.protocolHandler = protocolHandler;
    }

    /** Supply extra identity fields for the {@code /discovery} response. */
    public void setDiscoveryInfoSupplier(Supplier<Map<String, Object>> supplier) {
        this.discoveryInfoSupplier = supplier;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "mcp-http-worker");
            t.setDaemon(true);
            return t;
        }));

        server.createContext("/sse", new SseHandler());
        server.createContext("/message", new MessageHandler());
        server.createContext("/mcp", new StreamableHttpHandler());
        server.createContext("/discovery", new DiscoveryHandler());

        server.start();
        Msg.info(this,"MCP server started on http://127.0.0.1:" + port);

        // Start keepalive: send comment every 30s to keep SSE connections alive
        keepaliveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "mcp-keepalive");
            t.setDaemon(true);
            return t;
        });
        keepaliveExecutor.scheduleAtFixedRate(this::sendKeepalives, 30, 30, TimeUnit.SECONDS);
    }

    public void stop() {
        if (keepaliveExecutor != null) {
            keepaliveExecutor.shutdownNow();
            keepaliveExecutor = null;
        }
        // Close all SSE connections and clean up session state
        for (Map.Entry<String, SseConnection> entry : sseConnections.entrySet()) {
            entry.getValue().close();
            protocolHandler.removeSession(entry.getKey());
        }
        sseConnections.clear();

        for (String sid : streamableSessions) {
            protocolHandler.removeSession(sid);
        }
        streamableSessions.clear();

        if (server != null) {
            server.stop(1);
            server = null;
            Msg.info(this,"MCP server stopped");
        }
    }

    public boolean isRunning() {
        return server != null;
    }

    public int getPort() {
        return port;
    }

    private boolean checkAuth(HttpExchange exchange) {
        if (authToken == null || authToken.isEmpty()) {
            return true;
        }
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null) {
            return false;
        }
        return header.equals("Bearer " + authToken);
    }

    private void sendError(HttpExchange exchange, int code, String message) throws IOException {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(code, body.length);
        exchange.getResponseBody().write(body);
        exchange.getResponseBody().close();
    }

    private void sendKeepalives() {
        for (Map.Entry<String, SseConnection> entry : sseConnections.entrySet()) {
            SseConnection conn = entry.getValue();
            try {
                conn.sendComment("keepalive");
            } catch (IOException e) {
                String sid = entry.getKey();
                Msg.debug(this,"SSE connection " + sid + " lost during keepalive");
                conn.close();
                sseConnections.remove(sid);
                protocolHandler.removeSession(sid);
            }
        }
    }

    /**
     * Sends an SSE event to all connected clients.
     */
    private void broadcastSseEvent(String event, String data) {
        for (Map.Entry<String, SseConnection> entry : sseConnections.entrySet()) {
            try {
                entry.getValue().sendEvent(event, data);
            } catch (IOException e) {
                String sid = entry.getKey();
                Msg.debug(this,"SSE connection " + sid + " lost during broadcast");
                entry.getValue().close();
                sseConnections.remove(sid);
                protocolHandler.removeSession(sid);
            }
        }
    }

    // ---- SSE Handler ----

    private class SseHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method Not Allowed");
                return;
            }
            if (!checkAuth(exchange)) {
                sendError(exchange, 401, "Unauthorized");
                return;
            }

            String sessionId = UUID.randomUUID().toString();

            // Set SSE headers
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, 0); // chunked

            OutputStream os = exchange.getResponseBody();
            SseConnection conn = new SseConnection(os, exchange);
            sseConnections.put(sessionId, conn);

            Msg.info(this,"SSE client connected: " + sessionId);

            // Send the endpoint event — derive host from the request's Host header
            String host = exchange.getRequestHeaders().getFirst("Host");
            if (host == null || host.isEmpty()) {
                host = "localhost:" + port;
            }
            String messageUrl = "http://" + host + "/message?sessionId=" + sessionId;
            conn.sendEvent("endpoint", messageUrl);

            // Keep the connection open — it will be held by the HTTP server thread.
            // The connection stays alive until the client disconnects or we close it.
        }
    }

    // ---- Message Handler ----

    private class MessageHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Handle CORS preflight
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method Not Allowed");
                return;
            }
            if (!checkAuth(exchange)) {
                sendError(exchange, 401, "Unauthorized");
                return;
            }

            // Read request body
            String requestBody;
            try (InputStream is = exchange.getRequestBody()) {
                requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            // Extract sessionId from query
            String query = exchange.getRequestURI().getQuery();
            String sessionId = null;
            if (query != null) {
                for (String param : query.split("&")) {
                    if (param.startsWith("sessionId=")) {
                        sessionId = param.substring("sessionId=".length());
                        break;
                    }
                }
            }

            Msg.debug(this,"Received message from session " + sessionId + ": " + requestBody);

            // Process the JSON-RPC request (with session context for per-session program tracking)
            String response = protocolHandler.handleRequest(requestBody, sessionId);

            // Send 202 Accepted to the POST
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(202, -1);
            exchange.close();

            // If we have a response and a session, push it via SSE
            if (response != null && sessionId != null) {
                SseConnection conn = sseConnections.get(sessionId);
                if (conn != null) {
                    try {
                        conn.sendEvent("message", response);
                    } catch (IOException e) {
                        Msg.warn(this,"Failed to send SSE response to session " + sessionId);
                        conn.close();
                        sseConnections.remove(sessionId);
                        protocolHandler.removeSession(sessionId);
                    }
                }
            }
        }
    }

    // ---- Streamable HTTP Handler ----

    /**
     * Modern MCP Streamable HTTP endpoint (spec rev 2025-03-26 and later).
     * Unlike the legacy pair above, the JSON-RPC response is returned directly
     * in the POST response body — no SSE channel is required.
     */
    private class StreamableHttpHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            if ("OPTIONS".equals(method)) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers",
                    "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version");
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            if (!checkAuth(exchange)) {
                sendError(exchange, 401, "Unauthorized");
                return;
            }

            String sessionId = exchange.getRequestHeaders().getFirst("Mcp-Session-Id");

            if ("DELETE".equals(method)) {
                if (sessionId != null) {
                    streamableSessions.remove(sessionId);
                    protocolHandler.removeSession(sessionId);
                    Msg.info(this, "Streamable HTTP session terminated: " + sessionId);
                }
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            if (!"POST".equals(method)) {
                // The spec allows GET to open a server-initiated stream; we don't
                // offer one, and 405 is the mandated reply in that case.
                exchange.getResponseHeaders().set("Allow", "POST, DELETE, OPTIONS");
                sendError(exchange, 405, "Method Not Allowed");
                return;
            }

            String requestBody;
            try (InputStream is = exchange.getRequestBody()) {
                requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            boolean isInitialize = false;
            boolean isNotification = false;
            try {
                JsonElement parsed = JsonParser.parseString(requestBody);
                if (parsed.isJsonObject()) {
                    JsonObject obj = parsed.getAsJsonObject();
                    isInitialize = obj.has("method")
                        && "initialize".equals(obj.get("method").getAsString());
                    isNotification = !obj.has("id") || obj.get("id").isJsonNull();
                }
            } catch (Exception ignored) {
                // Malformed JSON falls through; the protocol handler answers with
                // a JSON-RPC parse error, which we still deliver as 200.
            }

            if (isInitialize) {
                // Mint a fresh session; the client echoes it in Mcp-Session-Id.
                sessionId = UUID.randomUUID().toString();
                streamableSessions.add(sessionId);
                exchange.getResponseHeaders().set("Mcp-Session-Id", sessionId);
                Msg.info(this, "Streamable HTTP client connected: " + sessionId);
            } else if (sessionId != null && !streamableSessions.contains(sessionId)) {
                // Unknown/expired session (e.g. server restarted). 404 tells the
                // client to re-initialize rather than retry forever.
                sendError(exchange, 404, "Unknown Mcp-Session-Id");
                return;
            }

            String response = protocolHandler.handleRequest(requestBody, sessionId);

            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            if (response == null || isNotification) {
                // Notification: accepted, nothing to return.
                exchange.sendResponseHeaders(202, -1);
                exchange.close();
                return;
            }
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        }
    }

    // ---- Discovery Handler ----

    private class DiscoveryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Method Not Allowed");
                return;
            }
            // activeSessions counts live SSE connections only (keepalive-pruned);
            // streamable sessions have no connection to probe, so a client that
            // exits without DELETE would otherwise inflate the count forever.
            Map<String, Object> info = new LinkedHashMap<>();
            Supplier<Map<String, Object>> supplier = discoveryInfoSupplier;
            if (supplier != null) {
                try {
                    Map<String, Object> extra = supplier.get();
                    if (extra != null) {
                        info.putAll(extra);
                    }
                } catch (Exception e) {
                    Msg.debug(this, "Discovery info supplier failed: " + e.getMessage());
                }
            }
            info.put("port", port);
            info.put("activeSessions", sseConnections.size());
            info.put("streamableSessions", streamableSessions.size());
            info.put("sseUrl", "http://127.0.0.1:" + port + "/sse");
            info.put("mcpUrl", "http://127.0.0.1:" + port + "/mcp");

            byte[] body = GSON.toJson(info).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        }
    }

    // ---- SSE Connection wrapper ----

    static class SseConnection {
        private final OutputStream outputStream;
        private final HttpExchange exchange;
        private volatile boolean closed = false;

        SseConnection(OutputStream outputStream, HttpExchange exchange) {
            this.outputStream = outputStream;
            this.exchange = exchange;
        }

        synchronized void sendEvent(String event, String data) throws IOException {
            if (closed) throw new IOException("Connection closed");
            StringBuilder sb = new StringBuilder();
            sb.append("event: ").append(event).append("\n");
            // Data may be multi-line; each line needs "data: " prefix
            for (String line : data.split("\n", -1)) {
                sb.append("data: ").append(line).append("\n");
            }
            sb.append("\n");
            outputStream.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
        }

        synchronized void sendComment(String comment) throws IOException {
            if (closed) throw new IOException("Connection closed");
            outputStream.write((": " + comment + "\n\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
        }

        synchronized void close() {
            if (closed) return;
            closed = true;
            try {
                outputStream.close();
            } catch (IOException ignored) {
            }
            exchange.close();
        }
    }
}
