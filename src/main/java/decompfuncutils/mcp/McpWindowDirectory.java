package decompfuncutils.mcp;

import java.util.List;
import java.util.Map;

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

        /**
         * Close the window without asking the operator anything.
         *
         * @param save true to save every changed program first; false to discard
         *             unsaved changes
         * @return one entry per program the window had open: {@code name} and
         *         {@code status} ({@code saved}, {@code unchanged},
         *         {@code added_to_project} or {@code discarded})
         * @throws Exception if a program could not be saved or the window is busy;
         *                   the window is then left open
         */
        List<Map<String, Object>> close(boolean save) throws Exception;
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
