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

        // Normalize path separators for cross-platform compatibility
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
                // Already open — just switch to it
                pm.setCurrentProgram(p);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "already_open");
                result.put("name", p.getName());
                result.put("executablePath", p.getExecutablePath());
                result.put("processor", p.getLanguage().getProcessor().toString());
                result.put("analyzed", GhidraProgramUtilities.isAnalyzed(p));
                result.put("functionCount", p.getFunctionManager().getFunctionCount());
                return result;
            }
        }

        // Check if already imported in the project
        Project project = tool.getProject();
        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        String targetName = (programName != null && !programName.isEmpty()) ? programName : file.getName();
        DomainFile existing = rootFolder.getFile(targetName);

        if (existing != null) {
            // Already in project — open it
            Program opened = pm.openProgram(existing);
            if (opened == null) {
                throw new RuntimeException("Failed to open existing program from project: " + targetName);
            }
            pm.setCurrentProgram(opened);

            // Trigger analysis if not yet analyzed
            if (analyze && !GhidraProgramUtilities.isAnalyzed(opened)) {
                triggerAutoAnalysis(opened);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "opened_from_project");
            result.put("name", opened.getName());
            result.put("executablePath", opened.getExecutablePath());
            result.put("processor", opened.getLanguage().getProcessor().toString());
            result.put("analyzed", GhidraProgramUtilities.isAnalyzed(opened));
            result.put("functionCount", opened.getFunctionManager().getFunctionCount());
            return result;
        }

        // Import the binary
        Msg.info(this, "Importing binary: " + absPath);
        MessageLog log = new MessageLog();
        LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(file, project,
            rootFolder.getPathname(), this, log, TaskMonitor.DUMMY);

        Program imported = loadResults.getPrimaryDomainObject();
        if (imported == null) {
            loadResults.release(this);
            String logMsg = log.toString();
            throw new RuntimeException("Failed to import binary: " + filePath +
                (logMsg.isEmpty() ? "" : "\nImport log: " + logMsg));
        }

        // Release non-primary loaded objects
        loadResults.releaseNonPrimary(this);

        // Rename if a custom name was provided
        if (programName != null && !programName.isEmpty() && !imported.getName().equals(programName)) {
            imported.getDomainFile().setName(programName);
        }

        // Save and release the domain object so ProgramManager can open it properly
        DomainFile domainFile = imported.getDomainFile();
        imported.save("Initial import", TaskMonitor.DUMMY);
        imported.release(this);

        // Open via ProgramManager (this triggers UI integration)
        Program opened = pm.openProgram(domainFile);
        if (opened == null) {
            throw new RuntimeException("Imported but failed to open program in tool");
        }
        pm.setCurrentProgram(opened);

        // Explicitly trigger auto-analysis so functions and data are discovered
        if (analyze) {
            triggerAutoAnalysis(opened);
        }

        Msg.info(this, "Successfully imported and opened: " + opened.getName());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "imported");
        result.put("name", opened.getName());
        result.put("executablePath", opened.getExecutablePath());
        result.put("processor", opened.getLanguage().getProcessor().toString());
        result.put("pointerSize", opened.getDefaultPointerSize());
        result.put("analyzing", true);
        result.put("hint", "Auto-analysis has been started. Use ghidra_get_program_info to check " +
            "functionCount and confirm analysis progress before decompiling.");
        String logMsg = log.toString();
        if (!logMsg.isEmpty()) {
            result.put("importLog", logMsg);
        }
        return result;
    }

    /**
     * Trigger Ghidra's auto-analysis on the program.
     * Analysis runs asynchronously in the background.
     */
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
