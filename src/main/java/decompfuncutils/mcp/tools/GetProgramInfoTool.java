package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class GetProgramInfoTool implements McpTool {

    @Override
    public String name() { return "ghidra_get_program_info"; }

    @Override
    public String description() {
        return "Get program metadata: name, architecture, compiler, image base, memory layout, entry points, and analysis state.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", new LinkedHashMap<>());
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "no_program_open");
            return result;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", program.getName());
        result.put("executablePath", program.getExecutablePath());
        result.put("executableFormat", program.getExecutableFormat());
        result.put("languageId", program.getLanguageID().toString());
        result.put("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().toString());
        result.put("processor", program.getLanguage().getProcessor().toString());
        result.put("pointerSize", program.getDefaultPointerSize());
        result.put("imageBase", program.getImageBase().toString());

        // Memory blocks
        List<Map<String, Object>> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("name", block.getName());
            b.put("start", block.getStart().toString());
            b.put("end", block.getEnd().toString());
            b.put("size", block.getSize());
            b.put("read", block.isRead());
            b.put("write", block.isWrite());
            b.put("execute", block.isExecute());
            b.put("volatile", block.isVolatile());
            b.put("initialized", block.isInitialized());
            blocks.add(b);
        }
        result.put("memoryBlocks", blocks);

        // Counts
        result.put("functionCount", program.getFunctionManager().getFunctionCount());
        result.put("symbolCount", program.getSymbolTable().getNumSymbols());

        return result;
    }
}
