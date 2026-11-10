package decompfuncutils.mcp;

import java.util.List;

/**
 * The session manager's view of the Ghidra tool windows it can route to.
 *
 * <p>Kept as an interface so {@link McpSessionRouter} holds no Swing or project
 * code: the Project window supplies the real implementation, and the headless
 * tests supply fake windows.
 */
public interface McpWindowDirectory {

    /** One MCP-served tool window (a CodeBrowser instance). */
    interface Window {

        /** Window name as Ghidra shows it, e.g. {@code CodeBrowser(2)}. */
        String name();

        /** The window's own direct MCP port, or -1 if it has none. */
        int port();

        /** Name of the window's active program, or null. */
        String activeProgram();

        /** Names of every program the window has open. */
        List<String> programs();

        /** False once the window has closed or stopped serving MCP. */
        boolean isOpen();

        /** Handler that executes tool calls against this window. */
        McpRequestHandler handler();
    }

    /** Every window currently serving MCP, in creation order. */
    List<Window> windows();

    /**
     * Open a new window, optionally with a program from the project.
     *
     * @param programName name of a project program to open, or null
     * @param domainFile  project path of the program instead of its name, or null
     * @return the new window, already serving MCP
     * @throws Exception if no project is open, the program is unknown, or the launch failed
     */
    Window open(String programName, String domainFile) throws Exception;

    /** Name of the open Ghidra project, or null when none is open. */
    String projectName();
}
