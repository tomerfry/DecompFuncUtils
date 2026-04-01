package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;

public class ListOpenProgramsTool implements McpTool {

    @Override
    public String name() { return "ghidra_list_open_programs"; }

    @Override
    public String description() {
        return "List all programs currently open in Ghidra, indicating which one is active.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", new LinkedHashMap<>());
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            throw new RuntimeException("ProgramManager service not available");
        }

        Program currentProgram = pm.getCurrentProgram();
        Program[] allPrograms = pm.getAllOpenPrograms();

        List<Map<String, Object>> programs = new ArrayList<>();
        for (Program p : allPrograms) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", p.getName());
            entry.put("executablePath", p.getExecutablePath());
            entry.put("domainFile", p.getDomainFile() != null ? p.getDomainFile().getPathname() : null);
            entry.put("languageId", p.getLanguageID().toString());
            entry.put("processor", p.getLanguage().getProcessor().toString());
            entry.put("active", p == currentProgram);
            programs.add(entry);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("programs", programs);
        result.put("count", programs.size());
        return result;
    }
}
