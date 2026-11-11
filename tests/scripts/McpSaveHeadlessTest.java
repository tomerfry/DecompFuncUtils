import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import decompfuncutils.mcp.McpProgramSaver;

import java.io.File;
import java.util.Map;

/**
 * Headless test for McpProgramSaver: the dialog-free save behind
 * ghidra_save_program, ghidra_session_close_window and the import path of
 * ghidra_open_program.
 *
 * Loads the test binary a second time without saving it, which is the state the
 * MCP import used to leave programs in (no project file, shown read-only), and
 * checks that saving puts it in the project, makes it writable and persists later
 * edits. Closing a real tool window needs the Ghidra GUI and is not covered.
 *
 * Prints CHECK lines and HEADLESS_TEST_RESULT PASS/FAIL for the runner to parse.
 */
public class McpSaveHeadlessTest extends GhidraScript {

    private static final String COMMENT = "mcp save test";

    private int passed = 0;
    private int failed = 0;

    private void check(String name, boolean ok, String detail) {
        if (ok) { passed++; println("CHECK " + name + ": PASS"); }
        else    { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START mcp_save prog=" + currentProgram.getName());

        Project project = state.getProject();
        String path = currentProgram.getExecutablePath();
        if (path.length() > 2 && path.charAt(0) == '/' && path.charAt(2) == ':') {
            path = path.substring(1);
        }
        File binary = new File(path);
        check("fixture_binary_found", binary.isFile(), path);

        Object consumer = new Object();
        String projectPath = null;
        Program loaded;
        try (LoadResults<Program> results = ProgramLoader.builder()
                .source(binary)
                .project(project)
                .projectFolderPath("/")
                .log(new MessageLog())
                .monitor(TaskMonitor.DUMMY)
                .load()) {
            loaded = results.getPrimaryDomainObject(consumer);
        }

        try {
            check("unsaved_import_is_read_only", McpProgramSaver.isUnsavedToProject(loaded)
                && loaded.getDomainFile().isReadOnly(), "readOnly=" + loaded.getDomainFile().isReadOnly());

            Map<String, Object> first = McpProgramSaver.save(project, null, loaded, TaskMonitor.DUMMY);
            projectPath = (String) first.get("projectPath");
            check("save_adds_program_to_project",
                McpProgramSaver.STATUS_ADDED_TO_PROJECT.equals(first.get("status"))
                    && projectPath != null && project.getProjectData().getFile(projectPath) != null,
                String.valueOf(first));
            check("saved_program_is_writable", !McpProgramSaver.isUnsavedToProject(loaded)
                && loaded.canSave() && !loaded.getDomainFile().isReadOnly(),
                "canSave=" + loaded.canSave());

            Map<String, Object> again = McpProgramSaver.save(project, null, loaded, TaskMonitor.DUMMY);
            check("save_without_changes_is_noop",
                McpProgramSaver.STATUS_UNCHANGED.equals(again.get("status")), String.valueOf(again));

            int tx = loaded.startTransaction("edit");
            boolean refusedInTransaction = false;
            try {
                loaded.getListing().setComment(loaded.getMinAddress(), CodeUnit.PLATE_COMMENT, COMMENT);
                try {
                    McpProgramSaver.save(project, null, loaded, TaskMonitor.DUMMY);
                } catch (IllegalStateException e) {
                    refusedInTransaction = true;
                }
            } finally {
                loaded.endTransaction(tx, true);
            }
            check("save_refused_while_program_is_being_modified",
                refusedInTransaction && loaded.isChanged(), "changed=" + loaded.isChanged());

            Map<String, Object> edited = McpProgramSaver.save(project, null, loaded, TaskMonitor.DUMMY);
            check("save_persists_edits", McpProgramSaver.STATUS_SAVED.equals(edited.get("status"))
                && !loaded.isChanged(), String.valueOf(edited));
        } finally {
            loaded.release(consumer);
        }

        // Reopen from the project: the edit must have reached disk.
        DomainFile file = projectPath != null ? project.getProjectData().getFile(projectPath) : null;
        if (file != null) {
            Program reopened = (Program) file.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
            try {
                String comment = reopened.getListing().getComment(CodeUnit.PLATE_COMMENT,
                    reopened.getMinAddress());
                check("edit_survives_reopen", COMMENT.equals(comment), "comment=" + comment);
            } finally {
                reopened.release(consumer);
            }
        } else {
            check("edit_survives_reopen", false, "no project file");
        }

        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }
}
