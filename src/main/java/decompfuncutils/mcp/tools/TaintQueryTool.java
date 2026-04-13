package decompfuncutils.mcp.tools;

import decompfuncutils.TaintQueryParser;
import decompfuncutils.TaintQueryMatcher;
import decompfuncutils.TaintQueryMatcher.QueryMatch;
import decompfuncutils.TaintQuery;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.StringTaintLog;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class TaintQueryTool implements McpTool {

    @Override public String name() { return "ghidra_taint_query"; }

    @Override
    public String description() {
        return "Execute a taint query using the built-in DSL to find vulnerability patterns. " +
               "Syntax: PATTERN name { <C-like pattern> } WHERE <constraints>. " +
               "Constraints: tainted($var), flows_to($src, $dst), is_constant($var), calls($func), etc. " +
               "Optionally restrict to a single function.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "query", Map.of("type", "string", "description",
                "Taint query DSL string. Example: PATTERN buf_overflow { memcpy($dst, $src, $len); } WHERE tainted($len)"),
            "functionAddress", Map.of("type", "string", "description", "Restrict search to a single function (address in hex). If omitted, scans all functions."),
            "functionName", Map.of("type", "string", "description", "Restrict search to a single function by name."),
            "maxFunctions", Map.of("type", "integer", "description", "Maximum number of functions to scan when searching all (default 1000)")
        ));
        schema.put("required", List.of("query"));
        return schema;
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String queryStr = (String) arguments.get("query");
        int maxFunctions = ((Number) arguments.getOrDefault("maxFunctions", 1000)).intValue();

        // Parse the query
        TaintQueryParser parser = new TaintQueryParser();
        TaintQuery query = parser.parse(queryStr);

        // Create matcher with headless log panel
        StringTaintLog logPanel = new StringTaintLog(tool);
        TaintQueryMatcher matcher = new TaintQueryMatcher(program, logPanel);

        // Set up decompiler for the matcher
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        try {
            // Determine target functions
            List<Function> functions = new ArrayList<>();
            if (arguments.containsKey("functionAddress") || arguments.containsKey("functionName")) {
                Map<String, Object> funcArgs = new HashMap<>();
                if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
                if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
                Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
                if (func == null) throw new IllegalArgumentException("Function not found");
                functions.add(func);
            } else {
                FunctionIterator iter = program.getFunctionManager().getFunctions(true);
                while (iter.hasNext() && functions.size() < maxFunctions) {
                    functions.add(iter.next());
                }
            }

            // Execute the query per function
            List<Map<String, Object>> matches = new ArrayList<>();
            int functionsScanned = 0;

            for (Function func : functions) {
                functionsScanned++;

                // Decompile to get HighFunction
                DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) continue;
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) continue;

                List<QueryMatch> queryMatches = matcher.matchInFunction(query, highFunc);
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
