package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;

public class SwitchProgramTool implements McpTool {

    @Override
    public String name() { return "ghidra_switch_program"; }

    @Override
    public String description() {
        return "Switch the active program in Ghidra to a different one that is already open. " +
               "Specify by program name or domain file path. All subsequent tool calls will operate on the switched program.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> props = new LinkedHashMap<>();
        props.put("name", Map.of("type", "string",
            "description", "Name of the program to switch to (as shown in ghidra_list_open_programs)"));
        props.put("domainFile", Map.of("type", "string",
            "description", "Domain file path of the program (e.g. '/program.exe')"));
        schema.put("properties", props);

        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            throw new RuntimeException("ProgramManager service not available");
        }

        String targetName = (String) arguments.get("name");
        String targetPath = (String) arguments.get("domainFile");

        if ((targetName == null || targetName.isEmpty()) && (targetPath == null || targetPath.isEmpty())) {
            throw new IllegalArgumentException("Provide either 'name' or 'domainFile' to identify the program");
        }

        Program[] allPrograms = pm.getAllOpenPrograms();
        Program target = null;

        for (Program p : allPrograms) {
            if (targetName != null && !targetName.isEmpty() && p.getName().equals(targetName)) {
                target = p;
                break;
            }
            if (targetPath != null && !targetPath.isEmpty()
                    && p.getDomainFile() != null
                    && p.getDomainFile().getPathname().equals(targetPath)) {
                target = p;
                break;
            }
        }

        if (target == null) {
            List<String> available = new ArrayList<>();
            for (Program p : allPrograms) {
                available.add(p.getName());
            }
            throw new IllegalArgumentException(
                "Program not found among open programs. Available: " + available);
        }

        pm.setCurrentProgram(target);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("switched_to", target.getName());
        result.put("executablePath", target.getExecutablePath());
        result.put("processor", target.getLanguage().getProcessor().toString());
        return result;
    }
}
