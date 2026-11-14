package decompfuncutils.refine.pass;

import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.RefineEngine;
import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.Rewrite.Status;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.sem.Verifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** What a pass works with: the function, its parameters, the verifier and the rewrite log. */
public final class PassContext {
    public final CFunction fn;
    public final Program program;
    public final RefineConfig config;
    public final Verifier verifier;
    public final Typer typer;
    public final List<Rewrite> log;
    public final TaskMonitor monitor;
    public final RefineEngine engine;
    private final Set<String> rejected = new HashSet<>();
    private RefinePass pass;
    private RefineConfig.PassSetting setting;

    public PassContext(CFunction fn, RefineConfig config, Verifier verifier, List<Rewrite> log, TaskMonitor monitor, RefineEngine engine) {
        this.fn = fn;
        this.program = fn.program;
        this.config = config;
        this.verifier = verifier;
        this.typer = new Typer(fn.pointerBits);
        this.log = log;
        this.monitor = monitor;
        this.engine = engine;
    }

    public void enter(RefinePass pass, RefineConfig.PassSetting setting) {
        this.pass = pass;
        this.setting = setting;
    }

    public boolean cancelled() { return monitor != null && monitor.isCancelled(); }

    /** Messages for the user; the engine puts them in the result. */
    public final List<String> messages = new java.util.ArrayList<>();

    /** Explain a decision not to rewrite something. Shown only when tracing is switched on. */
    public void trace(String what) {
        if (!config.trace || messages.size() > 400) return;
        String line = pass.id() + ": " + what;
        if (!messages.contains(line)) messages.add(line);
    }

    // ------------------------------------------------------------------ parameters

    private Object param(String key) {
        Object v = setting == null || setting.params == null ? null : setting.params.get(key);
        if (v != null) return v;
        for (RefinePass.Param p : pass.params()) if (p.key.equals(key)) return p.defaultValue;
        throw new IllegalArgumentException("Pass " + pass.id() + " has no parameter " + key);
    }

    public boolean flag(String key) {
        Object v = param(key);
        return v instanceof Boolean b ? b : Boolean.parseBoolean(String.valueOf(v));
    }

    public int integer(String key) {
        Object v = param(key);
        int n = v instanceof Number num ? num.intValue() : Integer.parseInt(String.valueOf(v).trim());
        for (RefinePass.Param p : pass.params()) if (p.key.equals(key)) return Math.max(p.min, Math.min(p.max, n));
        return n;
    }

    public String choice(String key) {
        String v = String.valueOf(param(key));
        for (RefinePass.Param p : pass.params()) {
            if (p.key.equals(key) && !p.choices.isEmpty() && !p.choices.contains(v)) return String.valueOf(p.defaultValue);
        }
        return v;
    }

    // ------------------------------------------------------------------ accepting rewrites

    /** Give a synthesized replacement the exact type of what it replaces, casting if it must. */
    public Expr fit(Expr after, CType want) {
        typer.retype(after);
        if (!want.isScalarInt()) return after;
        if (!after.type.isKnown()) { after.type = want; return after; }
        if (after.type.bits == want.bits && (after.type.signed == want.signed || !after.type.isScalarInt())) return after;
        if (after.type.bits == want.bits && after.type.isPointer() == want.isPointer() && after.type.signed == want.signed) return after;
        if (after instanceof Expr.Lit l && l.isInt()) {
            l.value = decompfuncutils.refine.sem.CEval.convert(l.value, l.type, want.bits);
            l.type = want.isBool() || want.isPointer() ? CType.integer(want.bits, false) : want;
            l.flexible = false;
            l.text = null;
            return l;
        }
        Expr.Cast cast = new Expr.Cast(want, want.name, after);
        cast.addr = after.addr;
        return cast;
    }

    /**
     * Verify that {@code after} can stand in for {@code before} and record the outcome. Returns
     * the expression to substitute (possibly wrapped in a cast), or null when the rewrite was
     * refuted or could not be verified under a configuration that demands verification.
     */
    public Expr accept(String rule, Expr before, Expr after) {
        after = fit(after, before.type);
        String b = CPrinter.text(before), a = CPrinter.text(after);
        if (b.equals(a)) return null;
        String key = pass.id() + "|" + rule + "|" + b + "|" + a;
        if (rejected.contains(key)) return null;
        return acceptChecked(rule, before, after, verifier.check(before, after));
    }

    /** Like {@link #accept(String, Expr, Expr)} for a replacement the caller has already checked. */
    public Expr acceptChecked(String rule, Expr before, Expr after, Verifier.Result r) {
        String b = CPrinter.text(before), a = CPrinter.text(after);
        Rewrite rw = new Rewrite(pass.id(), rule, b, a, r.status, r.detail, before.addr);
        if (!admit(rw, pass.id() + "|" + rule + "|" + b + "|" + a)) return null;
        // The instructions behind the expression being replaced: gone from the tree after this.
        Address[] range = new Address[2];
        AstUtil.walk(before, x -> {
            if (x.addr == null) return;
            if (range[0] == null || x.addr.compareTo(range[0]) < 0) range[0] = x.addr;
            if (range[1] == null || x.addr.compareTo(range[1]) > 0) range[1] = x.addr;
        });
        if (range[0] != null && range[1].subtract(range[0]) < 0x200) rw.evidence = disassembly(range[0], range[1], 12);
        after.note = rw;
        if (after.addr == null) after.addr = before.addr;
        log.add(rw);
        return after;
    }

    /**
     * Statement-level counterpart of {@link #accept(String, Expr, Expr)}: verifies that the
     * statements {@code after} can replace {@code before}, where {@code dead} names variables
     * whose final values nothing reads. On success every statement of {@code after} is marked.
     */
    public boolean accept(String rule, List<Stmt> before, List<Stmt> after, Collection<String> dead) {
        return accept(rule, before, after, dead, null, null);
    }

    /**
     * As above, for a rewrite the pass can vouch for beyond what testing shows: when the trials
     * do not refute it, it is recorded with {@code claim} (and {@code why}) instead of TESTED.
     */
    public boolean accept(String rule, List<Stmt> before, List<Stmt> after, Collection<String> dead, Status claim, String why) {
        String b = text(before), a = text(after);
        String key = pass.id() + "|" + rule + "|" + b + "|" + a;
        if (rejected.contains(key)) return false;
        Verifier.Result r = verifier.check(before, after, dead);
        if (claim != null && r.status != Status.REFUTED) r = verifier.claim(claim, why + (r.status == Status.TESTED ? "; " + r.detail : ""));
        Address addr = null, max = null;
        for (Stmt s : before) {
            if (s.addr != null && (addr == null || s.addr.compareTo(addr) < 0)) addr = s.addr;
            if (s.maxAddr != null && (max == null || s.maxAddr.compareTo(max) > 0)) max = s.maxAddr;
        }
        Rewrite rw = new Rewrite(pass.id(), rule, b, a, r.status, r.detail, addr);
        if (!admit(rw, key)) return false;
        if (addr != null && (max == null || max.subtract(addr) < 0x400)) rw.evidence = disassembly(addr, max, 12);
        for (Stmt s : after) {
            s.note = rw;
            s.span(addr, max);
        }
        log.add(rw);
        return true;
    }

    private boolean admit(Rewrite rw, String key) {
        if (rw.status == Status.REFUTED || (rw.status == Status.ASSUMED && config.rejectUnverified && verifier.enabled())) {
            rejected.add(key);
            if (rw.status == Status.REFUTED) log.add(rw);
            return false;
        }
        return true;
    }

    /** Record a change that needs no semantic check (pure restructuring, or one already justified). */
    public Rewrite record(String rule, String before, String after, Status status, String detail, Address addr) {
        Rewrite rw = new Rewrite(pass.id(), rule, before, after, status, detail, addr);
        log.add(rw);
        return rw;
    }

    private static String text(List<Stmt> stmts) {
        StringBuilder sb = new StringBuilder();
        for (Stmt s : stmts) sb.append(sb.length() > 0 ? " " : "").append(CPrinter.text(s).replaceAll("\\s+", " "));
        return sb.toString();
    }

    // ------------------------------------------------------------------ disassembly

    /** Instructions in [lo, hi], one per line, at most {@code max}. */
    public String disassembly(Address lo, Address hi, int max) {
        if (program == null || lo == null) return "";
        if (hi == null || hi.compareTo(lo) < 0) hi = lo;
        StringBuilder sb = new StringBuilder();
        InstructionIterator it = program.getListing().getInstructions(lo, true);
        int n = 0;
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(hi) > 0) break;
            if (n++ >= max) { sb.append("...\n"); break; }
            sb.append(ins.getAddress()).append("  ").append(ins).append('\n');
        }
        return sb.toString();
    }

    /** Mnemonics of the instructions in [lo, hi]. */
    public Set<String> mnemonics(Address lo, Address hi) {
        Set<String> out = new HashSet<>();
        if (program == null || lo == null) return out;
        if (hi == null || hi.compareTo(lo) < 0) hi = lo;
        InstructionIterator it = program.getListing().getInstructions(lo, true);
        int n = 0;
        while (it.hasNext() && n++ < 256) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(hi) > 0) break;
            out.add(ins.getMnemonicString().toUpperCase());
        }
        return out;
    }
}
