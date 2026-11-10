package decompfuncutils.mcp;

/**
 * Something that answers MCP JSON-RPC requests for {@link McpHttpTransport}.
 *
 * <p>Two implementations exist: {@link McpProtocolHandler} serves one Ghidra tool
 * window, and {@link McpSessionRouter} is the session manager that fronts every
 * window from a single fixed port.
 */
public interface McpRequestHandler {

    /**
     * Handle one JSON-RPC 2.0 request.
     *
     * @param requestJson the request body
     * @param sessionId   the transport session the request arrived on (may be null)
     * @return the JSON-RPC response, or null for a notification
     */
    String handleRequest(String requestJson, String sessionId);

    /** Drop any state held for a transport session that has ended. */
    void removeSession(String sessionId);
}
