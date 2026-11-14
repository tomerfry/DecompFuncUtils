package decompfuncutils.mcp.tools;

import com.google.gson.Gson;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.RefineEngine;
import decompfuncutils.refine.RefineResult;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP face of the refinement engine: the same pipeline and configuration the Refined Decompiler
 * view uses, for an agent.
 */
public class RefineFunctionTool implements McpTool {
    /** One engine per program, so its decompiler and helper-pattern caches survive between calls. */
    private static final int MAX_ENGINES = 4;
    private static final Map<Program, RefineEngine> ENGINES = new LinkedHashMap<>();
    private static final Gson GSON = new Gson();

    @Override public String name() { return "ghidra_refine_function"; }

    @Override public String description() {
        return "Refined decompilation: run the second-layer analysis over a function's decompiler output and return C with "
            + "compiler optimizations and inlining undone -- loop rotation (if + do-while back to while / for), conditional "
            + "moves (back to ?: / MIN / MAX / abs), open-coded strlen / memset / memcpy loops, merged constant stores "
            + "(back to strcpy / strncpy / memset), rotate / sign / range-check / power-of-two-division idioms, opaque "
            + "predicates, inlined helper functions (the call is put back), and calls with constant arguments (evaluated "
            + "by emulation). Every rewrite is listed with how it was justified: 'proven' (Z3, all inputs), 'tested' "
            + "(original and replacement agreed on concrete runs), 'structural', 'assumed' (unchecked) or 'refuted' (not "
            + "applied). 'validation' reports whether the function's machine code under the emulator and the refined C "
            + "agree on the same inputs. Use it instead of ghidra_decompile_function when the plain output is dominated by "
            + "such artifacts; trust 'proven' and an 'agrees' validation, read 'assumed' with care. Pass describe=true to "
            + "list the passes, their parameters and the rule groups. The configuration is fully adjustable per call: "
            + "'disable' / 'enable' pass ids, 'ruleGroups', your own 'rules' "
            + "(e.g. \"my-rule: ($x << 1) + $x => $x * 3\"), or a whole 'config' object.";
    }

    @Override public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("address", Map.of("type", "string", "description", "Function address in hex"));
        props.put("name", Map.of("type", "string", "description", "Function name (if address is not provided)"));
        props.put("describe", Map.of("type", "boolean", "description",
            "Return the catalog of passes, parameters, rule groups and the default configuration instead of refining."));
        props.put("disable", Map.of("type", "array", "items", Map.of("type", "string"), "description",
            "Pass ids to switch off (see describe). Example: [\"inline\", \"const-calls\"]"));
        props.put("enable", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Pass ids to switch on."));
        props.put("only", Map.of("type", "array", "items", Map.of("type", "string"), "description",
            "Run exactly these passes, in the default order, and no others."));
        props.put("ruleGroups", Map.of("type", "object", "description",
            "Rule groups to switch on or off, e.g. {\"strength\": true, \"range\": false}."));
        props.put("rules", Map.of("type", "string", "description",
            "Extra rewrite rules, one per line: 'name: pattern => replacement where guard'. $x matches any expression, "
                + "$c:const a constant. Each match is verified before it is applied; a rule that is wrong somewhere is refused there."));
        props.put("verification", Map.of("type", "string", "enum", List.of("prove", "test", "off"), "description",
            "prove (default): test, then prove with Z3. test: concrete differential testing only. off: apply unchecked."));
        props.put("rejectUnverified", Map.of("type", "boolean", "description",
            "Drop rewrites that could be neither proved nor tested instead of applying them as 'assumed'. Default false."));
        props.put("validate", Map.of("type", "boolean", "description",
            "Compare the refined code with the machine code under the emulator. Default true."));
        props.put("trace", Map.of("type", "boolean", "description",
            "Explain, for code a pass looked at and left alone, why it declined. Default false."));
        props.put("includeOriginal", Map.of("type", "boolean", "description", "Also return the plain decompiler output. Default false."));
        props.put("config", Map.of("type", "object", "description",
            "A complete or partial configuration object as returned by describe (fields not given keep their defaults). "
                + "The other arguments are applied on top of it."));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", props);
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (Boolean.TRUE.equals(arguments.get("describe"))) return RefineEngine.catalog();
        Function function = DecompileFunctionTool.resolveFunction(arguments, program);
        if (function == null) throw new IllegalArgumentException("Function not found. Provide a valid 'address' or 'name'.");
        if (function.isExternal()) throw new IllegalArgumentException(function.getName() + " is an external function; there is no code to refine.");
        RefineConfig config = configure(arguments);
        RefineEngine engine = engine(program);
        RefineResult result;
        synchronized (engine) {
            result = engine.refine(function, config, TaskMonitor.DUMMY);
        }
        return result.toMap(Boolean.TRUE.equals(arguments.get("includeOriginal")));
    }

    static RefineConfig configure(Map<String, Object> arguments) {
        Object whole = arguments.get("config");
        if (whole != null && !(whole instanceof Map)) throw new IllegalArgumentException("config must be an object");
        RefineConfig config = whole == null ? RefineConfig.defaults() : RefineConfig.fromJson(GSON.toJson(whole));
        List<String> only = strings(arguments.get("only"), "only");
        if (!only.isEmpty()) {
            for (String id : only) requirePass(config, id);
            for (RefineConfig.PassSetting p : config.passes) p.enabled = only.contains(p.id);
        }
        for (String id : strings(arguments.get("enable"), "enable")) requirePass(config, id).enabled = true;
        for (String id : strings(arguments.get("disable"), "disable")) requirePass(config, id).enabled = false;
        Object groups = arguments.get("ruleGroups");
        if (groups != null) {
            if (!(groups instanceof Map<?, ?> m)) throw new IllegalArgumentException("ruleGroups must be an object of booleans");
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!(e.getValue() instanceof Boolean b)) throw new IllegalArgumentException("ruleGroups." + e.getKey() + " must be a boolean");
                config.ruleGroups.put(String.valueOf(e.getKey()), b);
            }
        }
        if (arguments.get("rules") != null) {
            if (!(arguments.get("rules") instanceof String text)) throw new IllegalArgumentException("rules must be a string");
            config.userRules = config.userRules.isBlank() ? text : config.userRules + "\n" + text;
        }
        if (arguments.get("verification") != null) {
            String v = String.valueOf(arguments.get("verification"));
            if (!List.of("prove", "test", "off").contains(v)) throw new IllegalArgumentException("verification must be prove, test or off");
            config.verification = v;
        }
        config.rejectUnverified = flag(arguments, "rejectUnverified", config.rejectUnverified);
        config.validate = flag(arguments, "validate", config.validate);
        config.trace = flag(arguments, "trace", config.trace);
        return config.normalized();
    }

    private static RefineConfig.PassSetting requirePass(RefineConfig config, String id) {
        RefineConfig.PassSetting p = config.pass(id);
        if (p == null) {
            StringBuilder known = new StringBuilder();
            for (RefineConfig.PassSetting s : config.passes) known.append(known.length() > 0 ? ", " : "").append(s.id);
            throw new IllegalArgumentException("Unknown pass '" + id + "'. Passes: " + known);
        }
        return p;
    }

    private static boolean flag(Map<String, Object> arguments, String key, boolean byDefault) {
        Object v = arguments.get(key);
        if (v == null) return byDefault;
        if (!(v instanceof Boolean b)) throw new IllegalArgumentException(key + " must be a boolean");
        return b;
    }

    private static List<String> strings(Object value, String key) {
        if (value == null) return List.of();
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException(key + " must be an array of strings");
        for (Object o : list) if (!(o instanceof String)) throw new IllegalArgumentException(key + " must be an array of strings");
        @SuppressWarnings("unchecked") List<String> out = (List<String>) list;
        return out;
    }

    private static RefineEngine engine(Program program) {
        synchronized (ENGINES) {
            for (Iterator<Map.Entry<Program, RefineEngine>> it = ENGINES.entrySet().iterator(); it.hasNext();) {
                Map.Entry<Program, RefineEngine> e = it.next();
                if (e.getKey().isClosed()) {
                    e.getValue().close();
                    it.remove();
                }
            }
            RefineEngine engine = ENGINES.remove(program);
            if (engine == null) engine = new RefineEngine(program);
            ENGINES.put(program, engine);   // most recently used last
            while (ENGINES.size() > MAX_ENGINES) {
                Iterator<Map.Entry<Program, RefineEngine>> it = ENGINES.entrySet().iterator();
                Map.Entry<Program, RefineEngine> oldest = it.next();
                synchronized (oldest.getValue()) {
                    oldest.getValue().close();
                }
                it.remove();
            }
            return engine;
        }
    }
}
