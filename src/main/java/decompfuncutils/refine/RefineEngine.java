package decompfuncutils.refine;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.pass.PassContext;
import decompfuncutils.refine.pass.RefinePass;
import decompfuncutils.refine.pass.RefinePasses;
import decompfuncutils.refine.rules.RuleSet;
import decompfuncutils.refine.sem.CSym;
import decompfuncutils.refine.sem.Verifier;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import decompfuncutils.refine.rules.Rule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The second-layer analysis: takes what the decompiler produced for a function and works it back
 * toward what the source said, using every view of the code Ghidra has.
 *
 * <ul>
 * <li><b>Decompiler output and AST</b> -- the token markup is parsed into a typed C syntax tree;
 *     all rewriting happens on that tree.</li>
 * <li><b>P-code</b> -- gives each node its width and signedness, so reasoning matches the machine.</li>
 * <li><b>Disassembly</b> -- decides questions the C cannot (was this 'if' a conditional move?),
 *     and is kept as evidence next to each rewrite.</li>
 * <li><b>Symbolic execution</b> -- Z3 proves a rewritten expression equal to the original, decides
 *     conditions that can only go one way, and relates loop exits to loop guards.</li>
 * <li><b>Emulation</b> -- the refined code and the machine code are run on the same inputs and
 *     compared; concrete runs also test every rewrite the solver cannot settle.</li>
 * </ul>
 *
 * The pipeline is data ({@link RefineConfig}); running it again with a different configuration is
 * cheap, which is what lets a view refine as the user edits the configuration.
 *
 * <p>An engine belongs to one program and is used from one thread at a time.
 */
public final class RefineEngine implements AutoCloseable {
    private final Program program;
    private final Map<String, RuleSet> userRules = new HashMap<>();
    private final Map<Function, CFunction> bodies = new LinkedHashMap<>();
    private long bodiesModification = -1;
    private DecompInterface decompiler;

    public RefineEngine(Program program) { this.program = program; }

    public Program program() { return program; }

    /**
     * Everything that can be configured, as plain data: the passes with their parameters, the
     * built-in rule groups with their rules, and the default configuration.
     */
    public static Map<String, Object> catalog() {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> passes = new ArrayList<>();
        for (RefinePass p : RefinePasses.all()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", p.id());
            m.put("title", p.title());
            m.put("description", p.description());
            m.put("enabledByDefault", p.enabledByDefault());
            List<Map<String, Object>> params = new ArrayList<>();
            for (RefinePass.Param param : p.params()) {
                Map<String, Object> pm = new LinkedHashMap<>();
                pm.put("key", param.key);
                pm.put("label", param.label);
                pm.put("type", param.type.name().toLowerCase());
                pm.put("default", param.defaultValue);
                if (param.type == RefinePass.Param.Type.CHOICE) pm.put("choices", param.choices);
                if (param.type == RefinePass.Param.Type.INT) {
                    pm.put("min", param.min);
                    pm.put("max", param.max);
                }
                pm.put("help", param.help);
                params.add(pm);
            }
            m.put("params", params);
            passes.add(m);
        }
        out.put("passes", passes);
        List<Map<String, Object>> groups = new ArrayList<>();
        for (RuleSet.Group g : RuleSet.builtin().groups.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", g.name);
            m.put("enabledByDefault", g.enabledByDefault);
            m.put("description", g.description);
            List<String> rules = new ArrayList<>();
            for (Rule r : g.rules) rules.add(r.source);
            m.put("rules", rules);
            groups.add(m);
        }
        out.put("ruleGroups", groups);
        out.put("ruleSyntax", "name: pattern => replacement where guard. $x matches any expression, $c:const a constant, "
            + "$v:var a variable; (_)e matches a cast to any type. Guards: integer arithmetic on bound constants, bits($x), "
            + "signed($x), unsigned($x), is_ptr($x), is_const($x), pure($x), sval($c), is_pow2(n), log2(n), mask(n), signed_op(), "
            + "unsigned_op(). In a replacement, eval(expr) becomes a constant; abs, MIN, MAX, rotl, rotr, bswap have known meaning "
            + "and can be proved, any other function name is applied as 'assumed'.");
        out.put("defaultConfig", new com.google.gson.Gson().fromJson(RefineConfig.defaults().toJson(), Map.class));
        return out;
    }

    /** A decompiler set up the way the engine needs it: with syntax tree and token markup. */
    public static DecompInterface openDecompiler(Program program) {
        DecompInterface d = new DecompInterface();
        d.setOptions(new DecompileOptions());
        d.toggleSyntaxTree(true);
        d.toggleCCode(true);
        d.setSimplificationStyle("decompile");
        if (!d.openProgram(program)) {
            String why = d.getLastMessage();
            d.dispose();
            throw new IllegalStateException("Cannot start the decompiler: " + why);
        }
        return d;
    }

    private DecompInterface decompiler() {
        if (decompiler == null) decompiler = openDecompiler(program);
        return decompiler;
    }

    @Override public void close() {
        if (decompiler != null) decompiler.dispose();
        decompiler = null;
        bodies.clear();
    }

    /** Parsed user rules; cached by text because the view re-runs on every keystroke pause. */
    public RuleSet userRules(String text) {
        if (userRules.size() > 16) userRules.clear();
        return userRules.computeIfAbsent(text, t -> RuleSet.parse(t, "user"));
    }

    /**
     * The unrefined AST of another function of this program, for passes and checks that need to
     * know what a callee does. Null when it cannot be decompiled.
     */
    public CFunction body(Function callee, TaskMonitor monitor) {
        if (callee == null || callee.isExternal() || callee.isThunk()) return null;
        long now = program.getModificationNumber();
        if (now != bodiesModification) {
            bodies.clear();
            bodiesModification = now;
        }
        if (bodies.containsKey(callee)) return bodies.get(callee);
        CFunction f = null;
        try {
            DecompileResults r = decompiler().decompileFunction(callee, 30, monitor == null ? TaskMonitor.DUMMY : monitor);
            if (r.decompileCompleted() && r.getCCodeMarkup() != null) f = new ClangAstBuilder(program).build(r);
        } catch (RuntimeException e) {
            Msg.debug(this, "Could not build a body for " + callee.getName() + ": " + e);
        }
        if (bodies.size() > 256) bodies.clear();
        bodies.put(callee, f);
        return f;
    }

    /** A small function reduced to one expression over its parameters, usable as a pattern. */
    public static final class Helper {
        public Function function;
        /** The body as a pattern; parameter i is the metavariable named by {@code params.get(i)}. */
        public Rule rule;
        public List<String> params = new ArrayList<>();
        public CType returnType;
        public int size;
    }

    private String helperKey;
    private List<Helper> helperCache = List.of();

    /**
     * The small functions of the program as patterns for {@link decompfuncutils.refine.pass.InlinePass}.
     * Each is refined with the configuration in use (minus the passes that would recurse), so
     * that a helper and its inlined copies are compared after the same rewrites. Computed once per
     * program state and configuration.
     */
    public List<Helper> helpers(Function current, RefineConfig config, int maxBytes, int maxCandidates, int minSize, TaskMonitor monitor) {
        RefineConfig sub = config.copy();
        for (RefineConfig.PassSetting p : sub.passes) if (p.id.equals("inline") || p.id.equals("const-calls")) p.enabled = false;
        sub.validate = false;
        String key = program.getModificationNumber() + "|" + maxBytes + "|" + maxCandidates + "|" + minSize + "|" + sub.toJson();
        if (!key.equals(helperKey)) {
            List<Helper> built = new ArrayList<>();
            int considered = 0;
            boolean complete = true;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (monitor != null && monitor.isCancelled()) { complete = false; break; }
                if (f.isExternal() || f.isThunk() || f.getBody().getNumAddresses() > maxBytes) continue;
                if (++considered > maxCandidates) break;
                try {
                    Helper h = helper(f, sub, minSize, monitor);
                    if (h != null) built.add(h);
                } catch (RuntimeException e) {
                    Msg.debug(this, "No helper pattern for " + f.getName() + ": " + e);
                }
            }
            built.sort((a, b) -> Integer.compare(b.size, a.size));
            if (!complete) return List.of();
            helperCache = built;
            helperKey = key;
        }
        List<Helper> out = new ArrayList<>();
        for (Helper h : helperCache) if (!h.function.equals(current)) out.add(h);
        return out;
    }

    private Helper helper(Function f, RefineConfig sub, int minSize, TaskMonitor monitor) {
        DecompileResults results = decompiler().decompileFunction(f, 30, monitor == null ? TaskMonitor.DUMMY : monitor);
        if (!results.decompileCompleted() || results.getCCodeMarkup() == null) return null;
        CFunction fn = refine(results, sub, monitor).function;
        Stmt only = null;
        for (Stmt s : fn.body.body) {
            if (s instanceof Stmt.Comment) continue;
            if (only != null) return null;
            only = s;
        }
        if (!(only instanceof Stmt.Return ret) || ret.e == null || !fn.returnType.isScalarInt() || fn.params.isEmpty()) return null;
        Expr e = ret.e.copy();
        if (AstUtil.size(e) < minSize) return null;
        if (AstUtil.any(e, x -> x instanceof Expr.Raw || x instanceof Expr.Assign
                || (x instanceof Expr.Un u && (u.o.equals("++") || u.o.equals("--"))))) return null;
        Helper h = new Helper();
        h.function = f;
        h.returnType = fn.returnType;
        h.size = AstUtil.size(e);
        Map<String, String> meta = new HashMap<>();
        for (int i = 0; i < fn.params.size(); i++) {
            CFunction.Var p = fn.params.get(i);
            if (!p.type.isScalarInt() || !AstUtil.mentions(e, p.name)) return null;
            meta.put(p.name, "p" + i);
            h.params.add("p" + i);
        }
        // Anything else the body names (a local it could not fold away) is not a function of the parameters alone.
        if (AstUtil.any(e, x -> x instanceof Expr.Id id && id.kind == Expr.Id.Kind.VAR)) return null;
        Expr pattern = AstUtil.rewrite(e, x -> {
            x.note = null;
            if (x instanceof Expr.Id id && id.kind != Expr.Id.Kind.FUNC && meta.containsKey(id.name)) {
                Expr.Id m = new Expr.Id(meta.get(id.name), Expr.Id.Kind.META);
                m.type = id.type;
                return m;
            }
            return x;
        });
        h.rule = new Rule("inlined " + f.getName(), "inline", pattern, pattern, null, CPrinter.text(e), 0);
        return h;
    }

    /**
     * Decompile and refine one function.
     *
     * @throws java.util.concurrent.CancellationException when the monitor is cancelled before there is anything to show
     */
    public RefineResult refine(Function function, RefineConfig config, TaskMonitor monitor) {
        DecompileResults results = decompiler().decompileFunction(function, 60, monitor == null ? TaskMonitor.DUMMY : monitor);
        if (!results.decompileCompleted() || results.getCCodeMarkup() == null) {
            if (monitor != null && monitor.isCancelled()) throw new java.util.concurrent.CancellationException("Refinement was cancelled");
            throw new IllegalStateException("Decompilation of " + function.getName() + " failed: " + results.getErrorMessage());
        }
        return refine(results, config, monitor);
    }

    /** Refine a function from decompiler results the caller already has. */
    public RefineResult refine(DecompileResults results, RefineConfig config, TaskMonitor monitor) {
        long start = System.nanoTime();
        RefineConfig cfg = config.copy();
        RefineResult out = new RefineResult();
        CFunction fn = new ClangAstBuilder(program).build(results);
        out.function = fn;
        out.original = results.getDecompiledFunction() == null ? "" : results.getDecompiledFunction().getC();
        if (fn.rawStatements > 0) {
            out.messages.add(fn.rawStatements + " statement(s) could not be parsed and are shown exactly as the decompiler printed them.");
        }
        if (!cfg.userRules.isBlank()) {
            for (RuleSet.Problem p : userRules(cfg.userRules).problems) out.messages.add("Rule " + p);
        }
        for (RuleSet.Problem p : RuleSet.builtin().problems) out.messages.add("Built-in rule " + p);

        CSym sym = null;
        try {
            sym = new CSym(fn.pointerBits, fn.bigEndian);
            sym.setTimeoutMs(cfg.solverTimeoutMs);
        } catch (Throwable t) {
            // The solver ships as a native library; without it the engine still tests concretely.
            out.messages.add("The Z3 solver is unavailable (" + t + "); rewrites are tested but not proved.");
            if (cfg.verification.equals("prove")) cfg.verification = "test";
        }
        try {
            Verifier verifier = new Verifier(fn, sym, cfg.verification, cfg.trials, cfg.maxSteps, callee -> body(callee, monitor));
            PassContext ctx = new PassContext(fn, cfg, verifier, out.log, monitor, this);
            boolean cancelled = false;
            for (int round = 1; round <= cfg.maxRounds && !cancelled; round++) {
                boolean changed = false;
                out.rounds = round;
                for (RefineConfig.PassSetting setting : cfg.passes) {
                    if (!setting.enabled) continue;
                    if (ctx.cancelled()) { cancelled = true; break; }
                    RefinePass pass = RefinePasses.byId(setting.id);
                    ctx.enter(pass, setting);
                    try {
                        changed |= pass.run(ctx);
                    } catch (RuntimeException e) {
                        // A pass that trips must not cost the user the output of the others.
                        Msg.error(this, "Refinement pass " + setting.id + " failed on " + fn.name, e);
                        out.messages.add("Pass '" + pass.title() + "' failed and was skipped: " + e);
                    }
                }
                if (!changed) break;
            }
            out.messages.addAll(ctx.messages);
            if (cancelled) out.messages.add("Cancelled; the output reflects the passes that had finished.");
            attachEvidence(fn, ctx);
            if (cfg.validate && !cancelled) {
                try {
                    out.validation = Validator.run(fn, this, cfg, monitor);
                } catch (RuntimeException e) {
                    Msg.error(this, "Emulator validation failed on " + fn.name, e);
                    out.messages.add("The emulator check could not run: " + e);
                }
            }
            if (sym != null) out.solverQueries = sym.queries;
            out.proofs = verifier.proofs;
            out.tests = verifier.tests;
        } finally {
            if (sym != null) sym.close();
        }
        CPrinter.Options options = new CPrinter.Options();
        options.clarifyParens = cfg.clarifyParens;
        options.literals = cfg.literals;
        options.dropUnusedLocals = cfg.dropUnusedLocals;
        out.printed = new CPrinter(options).print(fn);
        out.elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        return out;
    }

    /** Give each rewrite the instructions of the statement it sits in, unless a pass already did. */
    private static void attachEvidence(CFunction fn, PassContext ctx) {
        AstUtil.walk(fn.body, s -> {
            if (s.addr == null) return;
            String[] text = new String[1];
            java.util.function.Consumer<Object> give = note -> {
                if (note instanceof Rewrite rw && rw.evidence == null) {
                    if (text[0] == null) text[0] = ctx.disassembly(s.addr, s.maxAddr, 12);
                    rw.evidence = text[0];
                }
            };
            if (!(s instanceof Stmt.Block)) give.accept(s.note);
            for (Expr e : s.exprs()) AstUtil.walk(e, x -> give.accept(x.note));
        });
    }
}
