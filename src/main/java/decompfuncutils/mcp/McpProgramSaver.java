package decompfuncutils.mcp;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Saves programs to the Ghidra project without any dialog, so an agent's work
 * (and the auto-analysis it waited for) survives the window being closed.
 *
 * <p>Ghidra's own save path ({@code ProgramManager.saveProgram}) asks the operator
 * what to do when the program is busy. Nothing here ever prompts: a save that
 * cannot happen right now fails with a message the agent can act on.
 */
public final class McpProgramSaver {

    public static final String STATUS_SAVED = "saved";
    public static final String STATUS_UNCHANGED = "unchanged";
    /** The program had no project file (it was never saved) and now has one. */
    public static final String STATUS_ADDED_TO_PROJECT = "added_to_project";

    private static final int AUTOSAVE_ATTEMPTS = 20;
    private static final long AUTOSAVE_RETRY_MS = 500;

    private McpProgramSaver() {
    }

    /** Whether auto-analysis is running on the program right now. */
    public static boolean isAnalyzing(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }
        try {
            return AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * True when the program is backed by a placeholder instead of a project file:
     * it was created or imported but never saved, so Ghidra shows it read-only.
     */
    public static boolean isUnsavedToProject(Program program) {
        DomainFile file = program.getDomainFile();
        return file == null || file.getParent() == null;
    }

    /**
     * Save a program to the project. May be called from any thread; it must not be
     * called inside an open transaction on the program.
     *
     * @param tool    the window the program is open in, or null (headless)
     * @param program the program to save
     * @param monitor progress/cancel monitor
     * @return {@code name}, {@code projectPath} and {@code status} (one of the
     *         {@code STATUS_*} values)
     * @throws IllegalStateException if the program cannot be saved right now; the
     *                               message says why
     */
    public static Map<String, Object> save(PluginTool tool, Program program, TaskMonitor monitor)
            throws Exception {
        return save(tool != null ? tool.getProject() : null, tool, program, monitor);
    }

    /**
     * As {@link #save(PluginTool, Program, TaskMonitor)}, naming the project a
     * never-saved program goes into. For callers without a tool window.
     */
    public static Map<String, Object> save(Project project, PluginTool tool, Program program,
                                           TaskMonitor monitor) throws Exception {
        if (program == null || program.isClosed()) {
            throw new IllegalStateException("The program is closed.");
        }
        String name = program.getName();
        if (isAnalyzing(program)) {
            throw new IllegalStateException("Auto-analysis is still running on '" + name
                + "', so it cannot be saved yet. Wait for analysis to finish and try again.");
        }

        String status;
        if (isUnsavedToProject(program)) {
            if (project == null) {
                throw new IllegalStateException("'" + name + "' has no project file and no project "
                    + "is open to save it into.");
            }
            prepare(tool, program);
            createInProject(project, program, monitor);
            status = STATUS_ADDED_TO_PROJECT;
        } else if (!program.isChanged()) {
            status = STATUS_UNCHANGED;
        } else if (!program.canSave()) {
            throw new IllegalStateException("'" + name + "' is open read-only (a read-only project, "
                + "or a versioned file that is not checked out), so its changes cannot be saved.");
        } else {
            prepare(tool, program);
            try {
                program.getDomainFile().save(monitor);
            } catch (IOException e) {
                throw new IllegalStateException("Could not save '" + name + "': " + e.getMessage()
                    + ". Another operation is probably still modifying it; try again shortly.", e);
            }
            status = STATUS_SAVED;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", program.getName());
        DomainFile file = program.getDomainFile();
        result.put("projectPath", file != null ? file.getPathname() : null);
        result.put("status", status);
        return result;
    }

    /** Let the window's plugins flush cached edits into the program before a save. */
    private static void prepare(PluginTool tool, Program program) {
        if (tool != null) {
            Swing.runNow(() -> tool.prepareToSave(program));
        }
    }

    private static void createInProject(Project project, Program program, TaskMonitor monitor)
            throws Exception {
        DomainFolder root = project.getProjectData().getRootFolder();
        String base = program.getName();
        String candidate = base;
        for (int i = 0; i < 1000; i++) {
            try {
                root.createFile(candidate, program, monitor);
                return;
            } catch (DuplicateFileException e) {
                candidate = base + "." + i;
            }
        }
        throw new IOException("No free name for '" + base + "' in the project root.");
    }

    /**
     * Save the program once its auto-analysis finishes, so the analysis is not lost
     * if the window is closed or Ghidra exits before anyone saves by hand.
     */
    public static void saveWhenAnalysisEnds(PluginTool tool, Program program) {
        AutoAnalysisManager manager;
        try {
            manager = AutoAnalysisManager.getAnalysisManager(program);
        } catch (Exception e) {
            return;
        }
        manager.addListener(new AutoAnalysisManagerListener() {
            @Override
            public void analysisEnded(AutoAnalysisManager mgr, boolean isCancelled) {
                mgr.removeListener(this);
                if (isCancelled) {
                    return;
                }
                // The notification arrives on the analysis thread, which still holds
                // the program; save from a thread of our own once it lets go.
                Thread saver = new Thread(() -> autosave(tool, program), "MCP-analysis-autosave");
                saver.setDaemon(true);
                saver.start();
            }
        });
    }

    private static void autosave(PluginTool tool, Program program) {
        Exception last = null;
        for (int attempt = 0; attempt < AUTOSAVE_ATTEMPTS; attempt++) {
            if (program.isClosed()) {
                return;
            }
            try {
                save(tool, program, TaskMonitor.DUMMY);
                Msg.info(McpProgramSaver.class, "Saved '" + program.getName() + "' after auto-analysis");
                return;
            } catch (Exception e) {
                last = e;
            }
            try {
                Thread.sleep(AUTOSAVE_RETRY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        Msg.warn(McpProgramSaver.class, "Could not save '" + program.getName()
            + "' after auto-analysis: " + (last != null ? last.getMessage() : "unknown error")
            + ". Save it with ghidra_save_program.");
    }
}
