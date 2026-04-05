package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
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
                triggerAutoAnalysis(loaded);
            }

            return buildResult("opened_from_project", loaded);
        }

        // Import the binary
        Msg.info(this, "Importing binary: " + absPath);
        MessageLog log = new MessageLog();
        LoadResults<Program> loadResults;
        try {
            loadResults = AutoImporter.importByUsingBestGuess(file, project,
                rootFolder.getPathname(), this, log, TaskMonitor.DUMMY);
        } catch (Exception e) {
            String logMsg = log.toString();
            throw new RuntimeException("Import failed for: " + filePath + " — " + e.getMessage() +
                (logMsg.isEmpty() ? "" : "\nImport log: " + logMsg), e);
        }

        if (loadResults == null) {
            String logMsg = log.toString();
            throw new RuntimeException("Import returned no results for: " + filePath +
                (logMsg.isEmpty() ? "" : "\nImport log: " + logMsg));
        }

        Program imported = loadResults.getPrimaryDomainObject();
        if (imported == null) {
            loadResults.release(this);
            String logMsg = log.toString();
            throw new RuntimeException("Failed to import binary: " + filePath +
                (logMsg.isEmpty() ? "" : "\nImport log: " + logMsg));
        }

        loadResults.releaseNonPrimary(this);

        // Rename if a custom name was provided
        if (programName != null && !programName.isEmpty() && !imported.getName().equals(programName)) {
            try {
                imported.getDomainFile().setName(programName);
            } catch (Exception e) {
                Msg.warn(this, "Could not rename to " + programName + ": " + e.getMessage());
            }
        }

        // Use pm.openProgram(Program) to hand the imported program directly to ProgramManager.
        // This bypasses the DomainFileProxy entirely — ProgramManager acquires its own reference.
        pm.openProgram(imported);
        pm.setCurrentProgram(imported);

        // Release our consumer lock — ProgramManager now owns the program
        imported.release(this);

        // Trigger auto-analysis
        if (analyze) {
            triggerAutoAnalysis(imported);
        }

        Msg.info(this, "Successfully imported and opened: " + imported.getName());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "imported");
        result.put("name", imported.getName());
        result.put("executablePath", imported.getExecutablePath());
        result.put("processor", imported.getLanguage().getProcessor().toString());
        result.put("pointerSize", imported.getDefaultPointerSize());
        result.put("analyzing", analyze);
        result.put("hint", "Auto-analysis has been started. Use ghidra_get_program_info to check " +
            "functionCount and confirm analysis progress before decompiling.");
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
        result.put("executablePath", p.getExecutablePath());
        result.put("processor", p.getLanguage().getProcessor().toString());
        result.put("analyzed", GhidraProgramUtilities.isAnalyzed(p));
        result.put("functionCount", p.getFunctionManager().getFunctionCount());
        return result;
    }

    private void triggerAutoAnalysis(Program program) {
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            Msg.info(this, "Auto-analysis triggered for: " + program.getName());
        } catch (Exception e) {
            Msg.warn(this, "Failed to trigger auto-analysis: " + e.getMessage());
        }
    }
}
