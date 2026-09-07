package decompfuncutils.mcp.tools;

import decompfuncutils.TaintQueryParser;
import decompfuncutils.TaintQueryMatcher;
import decompfuncutils.TaintQueryMatcher.QueryMatch;
import decompfuncutils.TaintQuery;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import decompfuncutils.mcp.StringTaintLog;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class TaintQueryTool implements McpTool {

    private static final Map<String, String> PRESETS = TaintQueryParser.getRecommendedPatterns();

    @Override public String name() { return "ghidra_taint_query"; }

    @Override
    public String description() {
        return "Execute a taint query using the built-in DSL to find vulnerability patterns. " +
               "Syntax: PATTERN name { <C-like pattern> } WHERE <constraints>. " +
               "Constraints: tainted($var), flows_to($src, $dst), is_constant($var), function_is($func, \"free\"), etc. " +
               "Provide query OR preset. Presets share the UI built-in catalog, including tainted_copy_length, tainted_format, use_after_free, double_free. " +
               "Use startAfter from nextStartAfter to resume bounded scans. Results are heuristic candidates, not confirmed vulnerabilities.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "preset", Map.of("type", "string", "enum", new TreeSet<>(PRESETS.keySet()),
                "description", "Ready-to-use query; mutually exclusive with query"),
            "startAfter", Map.of("type", "string", "description", "Resume after this function entry address, returned as nextStartAfter"),
            "query", Map.of("type", "string", "description",
                "Taint query DSL string. Example: PATTERN buf_overflow { memcpy($dst, $src, $len); } WHERE tainted($len)"),
            "functionAddress", Map.of("type", "string", "description", "Restrict search to a single function (address in hex). If omitted, scans all functions."),
            "functionName", Map.of("type", "string", "description", "Restrict search to a single function by name."),
            "maxFunctions", Map.of("type", "integer", "minimum", 1, "maximum", 10000, "description", "Maximum functions per page (default 1000)"),
            "decompileTimeout", Map.of("type", "integer", "description",
                "Per-function decompile timeout in seconds. Pass -1 (or 0) to disable the timeout — useful for batch scans across many large functions where the 30s default truncates and silently drops matches.")
        ));
        schema.put("oneOf", List.of(Map.of("required", List.of("query"), "not", Map.of("required", List.of("preset"))),
            Map.of("required", List.of("preset"), "not", Map.of("required", List.of("query")))));
        return schema;
    }

    // Read-only analysis: creates a private DecompInterface, only reads Program
    // data, and logs to a headless StringTaintLog. Running off the EDT keeps the
    // Ghidra UI responsive while long multi-function scans execute.
    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (arguments.containsKey("query") == arguments.containsKey("preset")) {
            throw new IllegalArgumentException("Provide exactly one of query or preset");
        }
        String queryStr = arguments.containsKey("preset") ? PRESETS.get(arguments.get("preset")) : (String) arguments.get("query");
        if (queryStr == null || queryStr.isBlank()) {
            throw new IllegalArgumentException("Provide a non-empty query or a preset from: " + new TreeSet<>(PRESETS.keySet()));
        }
        Object limit = arguments.getOrDefault("maxFunctions", 1000);
        if (!(limit instanceof Number) || !Double.isFinite(((Number) limit).doubleValue())
                || ((Number) limit).doubleValue() != ((Number) limit).intValue()
                || ((Number) limit).intValue() < 1 || ((Number) limit).intValue() > 10000) {
            throw new IllegalArgumentException("maxFunctions must be an integer from 1 to 10000");
        }
        int maxFunctions = ((Number) limit).intValue();
        boolean singleFunction = arguments.containsKey("functionAddress") || arguments.containsKey("functionName");
        ghidra.program.model.address.Address startAfter = null;
        if (arguments.containsKey("startAfter")) {
            if (singleFunction) throw new IllegalArgumentException("startAfter cannot be combined with a single function selector");
            startAfter = program.getAddressFactory().getAddress((String) arguments.get("startAfter"));
            if (startAfter == null) throw new IllegalArgumentException("Invalid startAfter address");
        }
        int decompileTimeout = McpUtil.resolveDecompileTimeout(arguments.get("decompileTimeout"), 30);
        TaskMonitor monitor = McpUtil.activeMonitor();

        // Parse the query
        TaintQueryParser parser = new TaintQueryParser();
        TaintQuery query = parser.parse(queryStr);

        // Create matcher with headless log panel
        StringTaintLog logPanel = new StringTaintLog(tool);
        TaintQueryMatcher matcher = new TaintQueryMatcher(program, logPanel);

        // Set up decompiler for the matcher
        DecompInterface decomp = new DecompInterface();

        try {
            if (!decomp.openProgram(program)) throw new IllegalStateException("Unable to open program in decompiler");
            // Determine target functions
            List<Function> functions = new ArrayList<>();
            boolean hasMore = false;
            if (arguments.containsKey("functionAddress") || arguments.containsKey("functionName")) {
                Map<String, Object> funcArgs = new HashMap<>();
                if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
                if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
                Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
                if (func == null) throw new IllegalArgumentException("Function not found");
                functions.add(func);
            } else {
                FunctionIterator iter = program.getFunctionManager().getFunctions(true);
                while (iter.hasNext()) {
                    monitor.checkCancelled();
                    Function candidate = iter.next();
                    if (startAfter != null && candidate.getEntryPoint().compareTo(startAfter) <= 0) continue;
                    if (functions.size() == maxFunctions) { hasMore = true; break; }
                    functions.add(candidate);
                }
            }

            // Execute the query per function
            List<Map<String, Object>> matches = new ArrayList<>();
            int functionsScanned = 0;
            int functionsAnalyzed = 0;
            String lastAddress = null;
            List<Map<String, Object>> failures = new ArrayList<>();

            for (Function func : functions) {
                if (monitor.isCancelled()) break;
                functionsScanned++;
                lastAddress = func.getEntryPoint().toString();

                // Decompile once to get both the HighFunction and the C markup the
                // matcher needs. Reusing results.getCCodeMarkup() avoids a second
                // decompile pass per function (matchInFunction would otherwise spin
                // up a fresh DecompInterface and re-decompile just for the markup).
                DecompileResults results = decomp.decompileFunction(func, decompileTimeout, monitor);
                HighFunction highFunc = results == null ? null : results.getHighFunction();
                ClangTokenGroup markup = results == null ? null : results.getCCodeMarkup();
                if (results == null || !results.decompileCompleted() || highFunc == null || markup == null) {
                    failures.add(Map.of("function", func.getName(), "functionAddress", lastAddress,
                        "reason", results == null ? "No decompiler result" :
                            "Missing or incomplete decompilation: " + results.getErrorMessage()));
                    continue;
                }

                List<QueryMatch> queryMatches = matcher.matchInFunctionWithMarkup(query, highFunc, markup, true);
                functionsAnalyzed++;
                for (QueryMatch match : queryMatches) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("function", func.getName());
                    m.put("functionAddress", func.getEntryPoint().toString());
                    m.put("matchAddress", match.address != null ? match.address.toString() : null);
                    m.put("matchedCode", match.matchedCode);
                    m.put("bindings", stringifyBindings(match.bindings));
                    m.put("confidence", match.confidence);
                    matches.add(m);
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("query", queryStr);
            result.put("functionsScanned", functionsScanned);
            result.put("functionsAnalyzed", functionsAnalyzed);
            result.put("failures", failures);
            boolean truncated = hasMore || functionsScanned < functions.size();
            result.put("truncated", truncated);
            result.put("nextStartAfter", truncated ? lastAddress : null);
            result.put("complete", !truncated && failures.isEmpty() && !monitor.isCancelled());
            result.put("confidenceMeaning", "Structural match score, not a probability of exploitability.");
            result.put("limitations", List.of("Heuristic pattern and taint matching; findings require manual validation.",
                "Direct input buffers are modeled; arbitrary pointer writes, overwrites and aliases remain approximate.",
                "CFG reachability does not prove branch feasibility, missing sanitization or insufficient destination capacity.",
                "Wrapper return-source analysis is bounded to three nested callees; unknown call returns remain conservative.",
                "complete describes scan coverage for this scope, not proof that the program is safe."));
            result.put("decompileTimeout", decompileTimeout == Integer.MAX_VALUE ? "disabled" : decompileTimeout);
            result.put("cancelled", monitor.isCancelled());
            result.put("matches", matches);
            result.put("matchCount", matches.size());
            return result;
        } finally {
            decomp.dispose();
        }
    }

    /**
     * Bindings values may hold Varnode / PcodeOp / HighVariable — objects that
     * contain WeakReferences and pull in non-exported java.lang.ref internals
     * when Gson walks them reflectively. Flatten to safe primitives/strings.
     */
    private static Map<String, Object> stringifyBindings(Map<String, Object> raw) {
        if (raw == null) return Collections.emptyMap();
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : raw.entrySet()) {
            out.put(e.getKey(), stringifyValue(e.getValue()));
        }
        return out;
    }

    private static Object stringifyValue(Object v) {
        if (v == null) return null;
        if (v instanceof String || v instanceof Number || v instanceof Boolean) return v;
        // Everything else (Varnode, PcodeOp, HighVariable, etc.) — use toString().
        try {
            return v.toString();
        } catch (Exception e) {
            return v.getClass().getSimpleName();
        }
    }
}
