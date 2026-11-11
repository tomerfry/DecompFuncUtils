package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpProgramSaver;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Saves the active program (or every program in the window) to the Ghidra project. */
public class SaveProgramTool implements McpTool {

    @Override
    public String name() { return "ghidra_save_program"; }

    @Override
    public String description() {
        return "Save the active program to the Ghidra project so renames, types, comments and "
             + "analysis results survive closing the window. Pass all=true to save every program "
             + "open in this window. Fails while auto-analysis is still running; retry once it is "
             + "done. To save and close the whole window use ghidra_session_close_window.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("all", Map.of("type", "boolean",
            "description", "Save every program open in this window, not just the active one "
                + "(default false)"));
        schema.put("properties", props);
        return schema;
    }

    // Not "mutating": a save needs the program free of open transactions, and the
    // mutating path would wrap this call in one.
    @Override
    public boolean requiresEdt() {
        return false;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        boolean all = arguments.get("all") != null
            && Boolean.parseBoolean(String.valueOf(arguments.get("all")));

        List<Program> targets = new ArrayList<>();
        ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
        if (all && pm != null) {
            targets.addAll(List.of(pm.getAllOpenPrograms()));
        } else if (program != null) {
            targets.add(program);
        }

        TaskMonitor monitor = McpUtil.activeMonitor();
        if (monitor == null) {
            monitor = TaskMonitor.DUMMY;
        }

        if (!all) {
            return McpProgramSaver.save(tool, program, monitor);
        }

        // Saving several: report each one, so a single busy program does not hide
        // that the others were saved.
        List<Map<String, Object>> results = new ArrayList<>();
        int failures = 0;
        for (Program p : targets) {
            try {
                results.add(McpProgramSaver.save(tool, p, monitor));
            } catch (Exception e) {
                failures++;
                Map<String, Object> failed = new LinkedHashMap<>();
                failed.put("name", p.getName());
                failed.put("status", "failed");
                failed.put("error", e.getMessage());
                results.add(failed);
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("programs", results);
        result.put("failed", failures);
        return result;
    }
}
