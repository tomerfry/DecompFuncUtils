package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
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
        schema.put("properties", props);
        schema.put("required", List.of("filePath"));

        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String filePath = (String) arguments.get("filePath");
        String programName = (String) arguments.get("programName");

        if (filePath == null || filePath.isEmpty()) {
            throw new IllegalArgumentException("'filePath' is required");
        }

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
        for (Program p : pm.getAllOpenPrograms()) {
            if (p.getExecutablePath().equals(filePath) ||
                    p.getName().equals(file.getName()) ||
                    (programName != null && p.getName().equals(programName))) {
                // Already open — just switch to it
                pm.setCurrentProgram(p);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "already_open");
                result.put("name", p.getName());
                result.put("executablePath", p.getExecutablePath());
                result.put("processor", p.getLanguage().getProcessor().toString());
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
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "opened_from_project");
            result.put("name", opened.getName());
            result.put("executablePath", opened.getExecutablePath());
            result.put("processor", opened.getLanguage().getProcessor().toString());
            return result;
        }

        // Import the binary
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

        // Open via ProgramManager (this triggers analysis and proper UI integration)
        Program opened = pm.openProgram(domainFile);
        if (opened == null) {
            throw new RuntimeException("Imported but failed to open program in tool");
        }
        pm.setCurrentProgram(opened);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "imported");
        result.put("name", opened.getName());
        result.put("executablePath", opened.getExecutablePath());
        result.put("processor", opened.getLanguage().getProcessor().toString());
        result.put("pointerSize", opened.getDefaultPointerSize());
        String logMsg = log.toString();
        if (!logMsg.isEmpty()) {
            result.put("importLog", logMsg);
        }
        return result;
    }
}
