package decompfuncutils.mcp;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.Map;

/**
 * Interface for MCP tools that expose Ghidra operations to external agents.
 */
public interface McpTool {

    /** Unique tool name (e.g. "ghidra_decompile_function"). */
    String name();

    /** Human-readable description of what this tool does. */
    String description();

    /** JSON Schema describing the input parameters (as nested Maps). */
    Map<String, Object> inputSchema();

    /**
     * Execute the tool with the given arguments.
     *
     * @param arguments  parsed JSON arguments matching the input schema
     * @param program    the currently open Ghidra program (may be null)
     * @param tool       the Ghidra PluginTool for accessing services
     * @return result object (will be serialized to JSON)
     * @throws Exception on failure
     */
    Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception;

    /**
     * Whether this tool modifies the program (requires a transaction).
     * Default is false (read-only).
     */
    default boolean isMutating() {
        return false;
    }

    /**
     * Whether this tool must execute on the Swing EDT.
     * Tools that only read Program data and don't touch Swing services
     * can return false to enable concurrent execution across agents.
     * Default is true (safe fallback — EDT serialized).
     */
    default boolean requiresEdt() {
        return true;
    }
}
