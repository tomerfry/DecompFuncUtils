package decompfuncutils.refine;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import decompfuncutils.refine.pass.RefinePass;
import decompfuncutils.refine.pass.RefinePasses;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything that shapes a refinement run: which passes run, in what order, with what parameters,
 * which rewrite rules are active, how changes are verified and how the result is printed. Plain
 * data, serialized as JSON, so the same configuration drives the view, the MCP tool and a saved
 * preset.
 */
public final class RefineConfig {
    public static final class PassSetting {
        public String id;
        public boolean enabled = true;
        public Map<String, Object> params = new LinkedHashMap<>();

        public PassSetting() {}
        public PassSetting(String id, boolean enabled) { this.id = id; this.enabled = enabled; }
    }

    /** Passes in execution order. */
    public List<PassSetting> passes = new ArrayList<>();
    /** How many times the pipeline repeats while passes keep changing the code. */
    public int maxRounds = 4;
    /** "off": apply rewrites unchecked. "test": differential testing. "prove": testing, then Z3. */
    public String verification = "prove";
    /** Drop rewrites that could be neither proved nor tested, instead of applying them as "assumed". */
    public boolean rejectUnverified = false;
    public int solverTimeoutMs = 800;
    public int trials = 32;
    /** Step budget of one concrete trial. */
    public int maxSteps = 5000;
    /** Enabled state of built-in rule groups, by group name. Groups not listed use their default. */
    public Map<String, Boolean> ruleGroups = new LinkedHashMap<>();
    /** Extra rewrite rules in rule syntax, applied after the built-in ones. */
    public String userRules = "";
    /** After refining, run the machine code under the emulator and the refined code side by side. */
    public boolean validate = true;
    public int validateTrials = 12;
    public int validateMaxInstructions = 20000;
    /** Report, for each place a pass looked at and left alone, why it declined. */
    public boolean trace = false;
    // --- printing
    public boolean clarifyParens = true;
    /** "auto", "hex" or "dec": how constants the engine computed are written. */
    public String literals = "auto";
    public boolean dropUnusedLocals = true;

    public static RefineConfig defaults() {
        RefineConfig c = new RefineConfig();
        for (RefinePass p : RefinePasses.all()) c.passes.add(new PassSetting(p.id(), p.enabledByDefault()));
        return c;
    }

    /** A configuration that changes nothing: the plain decompiler output through the same pipeline. */
    public static RefineConfig passthrough() {
        RefineConfig c = defaults();
        for (PassSetting p : c.passes) p.enabled = false;
        c.validate = false;
        return c;
    }

    public PassSetting pass(String id) {
        for (PassSetting p : passes) if (p.id.equals(id)) return p;
        return null;
    }

    public boolean groupEnabled(String group, boolean byDefault) {
        Boolean b = ruleGroups.get(group);
        return b == null ? byDefault : b;
    }

    /**
     * Make a configuration loaded from elsewhere usable: drop unknown passes, append passes it
     * does not mention (so an old saved configuration picks up new passes), clamp the limits.
     */
    public RefineConfig normalized() {
        List<PassSetting> known = new ArrayList<>();
        if (passes == null) passes = new ArrayList<>();
        for (PassSetting p : passes) {
            if (p == null || p.id == null || RefinePasses.byId(p.id) == null || containsId(known, p.id)) continue;
            if (p.params == null) p.params = new LinkedHashMap<>();
            // JSON has one number type; whole numbers are meant as integers.
            for (Map.Entry<String, Object> e : p.params.entrySet()) {
                if (e.getValue() instanceof Double d && d == Math.rint(d) && Math.abs(d) < Integer.MAX_VALUE) e.setValue(d.intValue());
            }
            known.add(p);
        }
        for (RefinePass p : RefinePasses.all()) {
            if (!containsId(known, p.id())) known.add(new PassSetting(p.id(), p.enabledByDefault()));
        }
        passes = known;
        if (ruleGroups == null) ruleGroups = new LinkedHashMap<>();
        if (userRules == null) userRules = "";
        if (verification == null || !List.of("off", "test", "prove").contains(verification)) verification = "prove";
        if (literals == null || !List.of("auto", "hex", "dec").contains(literals)) literals = "auto";
        maxRounds = clamp(maxRounds, 1, 16);
        solverTimeoutMs = clamp(solverTimeoutMs, 10, 30000);
        trials = clamp(trials, 1, 1000);
        maxSteps = clamp(maxSteps, 100, 5_000_000);
        validateTrials = clamp(validateTrials, 1, 500);
        validateMaxInstructions = clamp(validateMaxInstructions, 100, 5_000_000);
        return this;
    }

    private static boolean containsId(List<PassSetting> list, String id) {
        for (PassSetting p : list) if (p.id.equals(id)) return true;
        return false;
    }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public String toJson() { return GSON.toJson(this); }

    public static RefineConfig fromJson(String json) {
        RefineConfig c = json == null || json.isBlank() ? null : GSON.fromJson(json, RefineConfig.class);
        return (c == null ? defaults() : c).normalized();
    }

    public RefineConfig copy() { return fromJson(toJson()); }
}
