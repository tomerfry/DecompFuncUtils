package decompfuncutils.mcp.tools;

import decompfuncutils.InterproceduralTaintAnalyzer;
import decompfuncutils.InterproceduralTaintAnalyzer.TaintPath;
import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import decompfuncutils.mcp.StringTaintLog;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class TaintBackwardTool implements McpTool {

    private final DecompInterfacePool decompPool;

    public TaintBackwardTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

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
            "maxDepth", Map.of("type", "integer", "description", "Maximum call depth to follow (default 3)"),
            "decompileTimeout", Map.of("type", "integer", "description",
                "Per-function decompile timeout in seconds. Pass -1 (or 0) to disable the timeout — useful when running this tool over many large functions in a batch.")
        ));
        schema.put("required", List.of("variableName"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        return runTaintAnalysis(arguments, program, tool, false, decompPool);
    }

    /**
     * Shared implementation for forward and backward taint analysis.
     */
    static Object runTaintAnalysis(Map<String, Object> arguments, Program program,
                                    PluginTool tool, boolean forward,
                                    DecompInterfacePool decompPool) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        String varName = (String) arguments.get("variableName");
        int maxDepth = ((Number) arguments.getOrDefault("maxDepth", 3)).intValue();
        int decompileTimeout = McpUtil.resolveDecompileTimeout(arguments.get("decompileTimeout"), 30);
        TaskMonitor monitor = McpUtil.activeMonitor();

        // Decompile to get HighFunction
        DecompInterface decomp = decompPool.acquire(program);
        HighFunction highFunc;
        try {
            DecompileResults results = decomp.decompileFunction(func, decompileTimeout, monitor);
            if (!results.decompileCompleted()) {
                throw new RuntimeException("Decompilation failed: " + results.getErrorMessage());
            }
            highFunc = results.getHighFunction();
        } finally {
            decompPool.release(program, decomp);
        }

        // Find the varnode by name. Match against high symbols (locals + params),
        // then fall back to scanning all HighVariable names reachable via the
        // function's p-code (catches split/merged variables that no longer have
        // a matching HighSymbol). On failure, surface the full list of valid
        // names so callers know exactly what this engine recognizes.
        LinkedHashSet<String> availableNames = new LinkedHashSet<>();
        Varnode targetVarnode = null;

        Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            String n = sym.getName();
            availableNames.add(n);
            if (targetVarnode == null && n.equals(varName) && sym.getHighVariable() != null) {
                targetVarnode = sym.getHighVariable().getRepresentative();
            }
        }

        if (targetVarnode == null) {
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                collectHighNames(op.getOutput(), availableNames);
                for (int i = 0; i < op.getNumInputs(); i++) {
                    collectHighNames(op.getInput(i), availableNames);
                }
            }
            for (String n : availableNames) {
                if (n.equals(varName)) {
                    Iterator<PcodeOpAST> ops2 = highFunc.getPcodeOps();
                    while (ops2.hasNext() && targetVarnode == null) {
                        PcodeOpAST op = ops2.next();
                        targetVarnode = firstMatchingHigh(op.getOutput(), varName);
                        if (targetVarnode != null) break;
                        for (int i = 0; i < op.getNumInputs() && targetVarnode == null; i++) {
                            targetVarnode = firstMatchingHigh(op.getInput(i), varName);
                        }
                    }
                    break;
                }
            }
        }

        if (targetVarnode == null) {
            throw new IllegalArgumentException("Variable '" + varName + "' not found in decompiled function "
                + func.getName() + ". Known variables: " + String.join(", ", availableNames));
        }

        // Run taint analysis
        StringTaintLog logPanel = new StringTaintLog(tool);
        InterproceduralTaintAnalyzer analyzer = new InterproceduralTaintAnalyzer(program, logPanel);
        analyzer.setMaxDepth(maxDepth);
        analyzer.setDecompileTimeout(decompileTimeout);
        analyzer.analyze(highFunc, targetVarnode, forward, monitor);

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
        result.put("decompileTimeout", decompileTimeout == Integer.MAX_VALUE ? "disabled" : decompileTimeout);
        result.put("cancelled", monitor.isCancelled());
        result.put("dangerousPaths", paths);
        result.put("pathCount", paths.size());
        result.put("log", logPanel.getOutput());
        return result;
    }

    private static void collectHighNames(Varnode vn, LinkedHashSet<String> out) {
        if (vn == null) return;
        HighVariable hv = vn.getHigh();
        if (hv == null) return;
        String n = hv.getName();
        if (n != null && !n.isEmpty()) out.add(n);
    }

    private static Varnode firstMatchingHigh(Varnode vn, String name) {
        if (vn == null) return null;
        HighVariable hv = vn.getHigh();
        if (hv == null) return null;
        return name.equals(hv.getName()) ? hv.getRepresentative() : null;
    }
}
