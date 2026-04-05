package decompfuncutils.mcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * HTTP+SSE transport for MCP protocol.
 *
 * Exposes two endpoints:
 *   GET  /sse     — SSE event stream (long-lived connection)
 *   POST /message — JSON-RPC 2.0 requests from the client
 */
public class McpHttpTransport {

    // Uses Ghidra's Msg for logging

    private final int port;
    private final String authToken; // null = no auth
    private final McpProtocolHandler protocolHandler;
    private HttpServer server;

    // Active SSE connections: sessionId -> output stream
    private final ConcurrentHashMap<String, SseConnection> sseConnections = new ConcurrentHashMap<>();

    // Scheduled executor for keepalive pings
    private ScheduledExecutorService keepaliveExecutor;

    public McpHttpTransport(int port, String authToken, McpProtocolHandler protocolHandler) {
        this.port = port;
        this.authToken = authToken;
        this.protocolHandler = protocolHandler;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        server.createContext("/sse", new SseHandler());
        server.createContext("/message", new MessageHandler());

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
