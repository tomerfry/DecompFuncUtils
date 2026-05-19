package decompfuncutils.mcp;

/**
 * Result type for tools that return an image rather than text/JSON.
 *
 * When {@link McpProtocolHandler} sees a tool return this type, it emits an
 * MCP {@code image} content block ({@code {type:"image", data, mimeType}})
 * instead of stuffing the bytes into a text block.
 */
public class McpImageContent {

    /** Base64-encoded image bytes (no data-URI prefix). */
    public final String base64Data;

    /** MIME type, e.g. {@code image/png}. */
    public final String mimeType;

    /** Optional human-readable caption emitted as a preceding text block (may be null). */
    public final String caption;

    public McpImageContent(String base64Data, String mimeType, String caption) {
        this.base64Data = base64Data;
        this.mimeType = mimeType;
        this.caption = caption;
    }
}
