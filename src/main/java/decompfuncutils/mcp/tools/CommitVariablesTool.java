package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Commits decompiler-recovered local variables, parameters, and (optionally) the
 * return type of a function into the program database.
 *
 * <p>The decompiler recovers locals into an in-memory {@link HighFunction}; those
 * recovered variables are <em>not</em> persisted unless committed. Uncommitted
 * locals are re-derived on every decompile and can drift between runs, so the
 * operator's CodeBrowser view diverges from what the agent analyzed. Committing
 * locks the variable layout into the database so re-decompilation is stable.
 *
 * <p>This is the MCP-exposed equivalent of the decompiler's right-click
 * "Commit Locals" / "Commit Params/Return" actions.
 */
public class CommitVariablesTool implements McpTool {

    private final DecompInterfacePool decompPool;

    public CommitVariablesTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override public String name() { return "ghidra_commit_variables"; }

    @Override
    public String description() {
        return "Commit the decompiler-recovered local variables (and optionally parameters/return type) " +
               "of a function into the program database. Use this when decompiled output drifts between " +
               "runs because recovered locals were never persisted — committing locks the variable layout " +
               "so re-decompilation and the operator's CodeBrowser view stay aligned with the agent's " +
               "analysis. Pass 'variableNames' to commit only specific locals for fine-grained control.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description",
                "Address of the target function in hex"),
            "functionName", Map.of("type", "string", "description",
                "Name of the target function (if address is not provided)"),
            "commitParams", Map.of("type", "boolean", "description",
                "Also commit parameters with their recovered data types (default true)"),
            "commitReturn", Map.of("type", "boolean", "description",
                "Also commit the recovered return type (default false). Ignored when commitParams is false."),
            "variableNames", Map.of("type", "array", "items", Map.of("type", "string"),
                "description", "Optional: commit only these specific recovered locals by name. " +
                "If omitted, every recovered local is committed."),
            "decompileTimeout", Map.of("type", "integer", "description",
                "Decompile timeout in seconds. Pass -1 (or 0) to disable for very large functions.")
        ));
        schema.put("required", List.of());
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) {
            throw new IllegalArgumentException(
                "Function not found. Provide a valid 'functionAddress' or 'functionName'.");
        }

        boolean commitParams = toBool(arguments.get("commitParams"), true);
        boolean commitReturn = toBool(arguments.get("commitReturn"), false);
        int decompileTimeout = McpUtil.resolveDecompileTimeout(arguments.get("decompileTimeout"), 30);
        TaskMonitor monitor = McpUtil.activeMonitor();

        List<String> requested = null;
        Object rawNames = arguments.get("variableNames");
        if (rawNames instanceof List) {
            requested = new ArrayList<>();
            for (Object o : (List<?>) rawNames) {
                if (o != null) requested.add(o.toString());
            }
        }

        // Decompile to recover the HighFunction. This is a single function, so
        // running it inside the mutating-tool EDT transaction is acceptable.
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
        if (highFunc == null) {
            throw new RuntimeException("Decompiler returned no high-level function for " + func.getName());
        }

        List<Map<String, Object>> committedLocals = new ArrayList<>();
        List<String> notFound = new ArrayList<>();

        if (requested != null && !requested.isEmpty()) {
            // Fine-grained: persist only the named recovered locals. Passing null
            // for name/dataType keeps the decompiler-recovered values as-is.
            Map<String, HighSymbol> byName = new LinkedHashMap<>();
            Iterator<HighSymbol> it = highFunc.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                byName.putIfAbsent(sym.getName(), sym);
            }
            for (String want : requested) {
                HighSymbol sym = byName.get(want);
                if (sym == null) {
                    notFound.add(want);
                    continue;
                }
                HighFunctionDBUtil.updateDBVariable(sym, null, null, SourceType.USER_DEFINED);
                committedLocals.add(describe(sym));
            }
        } else {
            // Commit every recovered local name/storage in one shot.
            HighFunctionDBUtil.commitLocalNamesToDatabase(highFunc, SourceType.USER_DEFINED);
            Iterator<HighSymbol> it = highFunc.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                if (sym.isParameter() || sym.isGlobal()) continue;
                committedLocals.add(describe(sym));
            }
        }

        int paramsCommitted = 0;
        if (commitParams) {
            ReturnCommitOption returnOpt = commitReturn
                ? ReturnCommitOption.COMMIT : ReturnCommitOption.NO_COMMIT;
            HighFunctionDBUtil.commitParamsToDatabase(highFunc, true, returnOpt, SourceType.USER_DEFINED);
            paramsCommitted = highFunc.getLocalSymbolMap().getNumParams();
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("functionAddress", func.getEntryPoint().toString());
        result.put("localsCommitted", committedLocals.size());
        result.put("locals", committedLocals);
        result.put("paramsCommitted", paramsCommitted);
        result.put("returnCommitted", commitParams && commitReturn);
        if (!notFound.isEmpty()) {
            result.put("notFound", notFound);
        }
        result.put("status", "committed");
        result.put("note", "Variable layout persisted to the program database. Re-decompilation and " +
            "the operator's CodeBrowser view will now reflect these names, types, and storage.");
        return result;
    }

    private static Map<String, Object> describe(HighSymbol sym) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", sym.getName());
        m.put("type", sym.getDataType() != null ? sym.getDataType().getDisplayName() : "undefined");
        m.put("storage", sym.getStorage() != null ? sym.getStorage().toString() : null);
        m.put("isParameter", sym.isParameter());
        return m;
    }

    private static boolean toBool(Object v, boolean def) {
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return Boolean.parseBoolean(((String) v).trim());
        return def;
    }
}
