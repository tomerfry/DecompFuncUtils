package decompfuncutils.mcp.tools;

import decompfuncutils.InterproceduralTaintAnalyzer;
import decompfuncutils.InterproceduralTaintAnalyzer.TaintPath;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.StringTaintLog;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class TaintBackwardTool implements McpTool {

    @Override public String name() { return "ghidra_taint_backward"; }

    @Override
    public String description() {
        return "Run backward inter-procedural taint analysis to a variable. Shows what data reaches the target variable (e.g., what influences a comparison or buffer pointer).";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Address of the function in hex"),
            "functionName", Map.of("type", "string", "description", "Function name"),
            "variableName", Map.of("type", "string", "description", "Name of the variable to trace"),
            "maxDepth", Map.of("type", "integer", "description", "Maximum call depth to follow (default 3)")
        ));
        schema.put("required", List.of("variableName"));
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        return runTaintAnalysis(arguments, program, tool, false);
    }

    /**
     * Shared implementation for forward and backward taint analysis.
     */
    static Object runTaintAnalysis(Map<String, Object> arguments, Program program,
                                    PluginTool tool, boolean forward) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        String varName = (String) arguments.get("variableName");
        int maxDepth = ((Number) arguments.getOrDefault("maxDepth", 3)).intValue();

        // Decompile to get HighFunction
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
        if (!results.decompileCompleted()) {
            decomp.dispose();
            throw new RuntimeException("Decompilation failed: " + results.getErrorMessage());
        }
        HighFunction highFunc = results.getHighFunction();

        // Find the varnode by name
        Varnode targetVarnode = null;
        Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.getName().equals(varName)) {
                targetVarnode = sym.getHighVariable().getRepresentative();
                break;
            }
        }

        if (targetVarnode == null) {
            decomp.dispose();
            throw new IllegalArgumentException("Variable '" + varName + "' not found in decompiled function " + func.getName());
        }

        // Run taint analysis
        StringTaintLog logPanel = new StringTaintLog(tool);
        InterproceduralTaintAnalyzer analyzer = new InterproceduralTaintAnalyzer(program, logPanel);
        analyzer.setMaxDepth(maxDepth);
        analyzer.analyze(highFunc, targetVarnode, forward, TaskMonitor.DUMMY);

        decomp.dispose();

        // Build result
        List<Map<String, Object>> paths = new ArrayList<>();
        for (TaintPath path : analyzer.getFoundPaths()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("chain", path.functionChain);
            p.put("sink", path.sinkName);
            p.put("sinkFunction", path.sinkFunction);
            p.put("taintLevel", path.finalTaint);
            paths.add(p);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("variable", varName);
        result.put("direction", forward ? "forward" : "backward");
        result.put("maxDepth", maxDepth);
        result.put("dangerousPaths", paths);
        result.put("pathCount", paths.size());
        result.put("log", logPanel.getOutput());
        return result;
    }
}
