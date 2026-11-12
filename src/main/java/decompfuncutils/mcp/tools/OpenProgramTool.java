package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpProgramSaver;
import decompfuncutils.mcp.McpTool;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.*;

public class OpenProgramTool implements McpTool {

    @Override
    public String name() { return "ghidra_open_program"; }

    @Override
    public String description() {
        return "Import and open a binary file for analysis in Ghidra. " +
               "Provide the filesystem path to the binary. " +
               "Ghidra will auto-detect the format and architecture. " +
               "The program is saved into the project and opened writable, and it is saved " +
               "again automatically once auto-analysis finishes. " +
               "The imported program becomes the active program.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("filePath", Map.of("type", "string",
            "description", "Absolute filesystem path to the binary file to import and analyze"));
        props.put("programName", Map.of("type", "string",
            "description", "Optional name for the program in the project (defaults to filename)"));
        props.put("analyze", Map.of("type", "boolean",
            "description", "Run auto-analysis after import (default: true). " +
                "Analysis discovers functions, data types, and cross-references."));
        schema.put("properties", props);
        schema.put("required", List.of("filePath"));

        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filePath = (String) arguments.get("filePath");
        String programName = (String) arguments.get("programName");
        Object analyzeObj = arguments.get("analyze");
        boolean analyze = analyzeObj == null || Boolean.parseBoolean(analyzeObj.toString());

        if (filePath == null || filePath.isEmpty()) {
            throw new IllegalArgumentException("'filePath' is required");
        }

        filePath = filePath.replace('/', File.separatorChar).replace('\\', File.separatorChar);

        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("File not found: " + filePath);
        }
        if (!file.isFile()) {
            throw new IllegalArgumentException("Path is not a file: " + filePath);
        }

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            throw new RuntimeException("ProgramManager service not available");
        }

        // Check if this binary is already open
        String absPath = file.getAbsolutePath();
        for (Program p : pm.getAllOpenPrograms()) {
            if (absPath.equals(p.getExecutablePath()) ||
                    p.getName().equals(file.getName()) ||
                    (programName != null && p.getName().equals(programName))) {
                pm.setCurrentProgram(p);
                return buildResult("already_open", p);
            }
        }

        // Check if already imported in the project
        Project project = tool.getProject();
        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        String targetName = (programName != null && !programName.isEmpty()) ? programName : file.getName();
        DomainFile existing = rootFolder.getFile(targetName);

        if (existing != null) {
            // Load the program ourselves via DomainFile.getDomainObject, then hand to ProgramManager.
            // This avoids DomainFileProxy issues with pm.openProgram(DomainFile).
            Program loaded = (Program) existing.getDomainObject(this, false, false, TaskMonitor.DUMMY);
            if (loaded == null) {
                throw new RuntimeException("Failed to load existing program from project: " + targetName);
            }
            pm.openProgram(loaded);
            pm.setCurrentProgram(loaded);
            loaded.release(this);

            if (analyze && !GhidraProgramUtilities.isAnalyzed(loaded)) {
                triggerAutoAnalysis(loaded, tool);
            }

            return buildResult("opened_from_project", loaded);
        }

        // Import the binary and save it into the project. Without the save the
        // program has no project file: Ghidra then shows it read-only and nothing
        // done to it can ever be saved.
        Msg.info(this, "Importing binary: " + absPath);
        MessageLog log = new MessageLog();
        Program imported;
        ProgramLoader.Builder loader = ProgramLoader.builder()
            .source(file)
            .project(project)
            .projectFolderPath(rootFolder.getPathname())
            .log(log)
            .monitor(TaskMonitor.DUMMY);
        if (programName != null && !programName.isEmpty()) {
            loader.name(programName);
        }
        try (LoadResults<Program> loadResults = loader.load()) {
            loadResults.save(TaskMonitor.DUMMY);
            // Our own reference, so the program outlives the load results.
            imported = loadResults.getPrimaryDomainObject(this);
        } catch (Exception e) {
            String logMsg = log.toString();
            throw new RuntimeException("Import failed for: " + filePath + " — " + e.getMessage() +
                (logMsg.isEmpty() ? "" : "\nImport log: " + logMsg), e);
        }

        try {
            pm.openProgram(imported);
            pm.setCurrentProgram(imported);
        } finally {
            // ProgramManager now holds the program.
            imported.release(this);
        }

        if (analyze) {
            triggerAutoAnalysis(imported, tool);
        }

        Msg.info(this, "Successfully imported and opened: " + imported.getName());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "imported");
        result.put("name", imported.getName());
        result.put("projectPath", imported.getDomainFile().getPathname());
        result.put("writable", imported.canSave());
        result.put("executablePath", imported.getExecutablePath());
        result.put("processor", imported.getLanguage().getProcessor().toString());
        result.put("pointerSize", imported.getDefaultPointerSize());
        result.put("analyzing", analyze);
        result.put("hint", analyze
            ? "The program is saved in the project and auto-analysis has been started; it is saved "
                + "again automatically when analysis finishes. Use ghidra_get_program_info to check "
                + "functionCount before decompiling, and ghidra_save_program to save later edits."
            : "The program is saved in the project. Use ghidra_save_program to save later edits.");
        String logMsg = log.toString();
        if (!logMsg.isEmpty()) {
            result.put("importLog", logMsg);
        }
        return result;
    }

    private Map<String, Object> buildResult(String status, Program p) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", status);
        result.put("name", p.getName());
        result.put("writable", p.canSave());
        if (McpProgramSaver.isUnsavedToProject(p)) {
            result.put("warning", "This program was never saved to the project, so Ghidra shows it "
                + "read-only. Call ghidra_save_program to add it to the project.");
        }
        result.put("executablePath", p.getExecutablePath());
        result.put("processor", p.getLanguage().getProcessor().toString());
        result.put("analyzed", GhidraProgramUtilities.isAnalyzed(p));
        result.put("functionCount", p.getFunctionManager().getFunctionCount());
        return result;
    }

    private void triggerAutoAnalysis(Program program, PluginTool tool) {
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            // Registered before analysis is scheduled so the end is never missed.
            McpProgramSaver.saveWhenAnalysisEnds(tool, program);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            Msg.info(this, "Auto-analysis triggered for: " + program.getName());
        } catch (Exception e) {
            Msg.warn(this, "Failed to trigger auto-analysis: " + e.getMessage());
        }
    }
}
