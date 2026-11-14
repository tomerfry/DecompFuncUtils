package decompfuncutils.refine.sem;

import decompfuncutils.refine.Rewrite.Status;
import decompfuncutils.refine.ast.*;
import java.math.BigInteger;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Decides whether a rewrite preserves meaning. Two instruments, used in this order:
 *
 * <ol>
 * <li>differential testing -- run the original and the replacement on the same inputs and memory
 *     and compare everything observable; cheap, and a wrong rule is caught at once with a concrete
 *     counterexample;</li>
 * <li>proof -- ask Z3 whether the two can ever differ.</li>
 * </ol>
 *
 * A proof makes a rewrite PROVEN, agreement on every trial makes it TESTED, a difference makes it
 * REFUTED, and code neither instrument can model leaves it ASSUMED.
 */
public final class Verifier {
    public static final class Result {
        public final Status status;
        public final String detail;

        Result(Status status, String detail) { this.status = status; this.detail = detail; }
    }

    private final CFunction fn;
    private final CSym sym;
    /** "off", "test" or "prove". */
    private final String mode;
    private final int trials;
    private final int maxSteps;
    /** Bodies of program functions, so a rewrite that introduces a call to one can be run. */
    private final CInterp.Resolver resolver;
    public int proofs, tests;

    public Verifier(CFunction fn, CSym sym, String mode, int trials, int maxSteps, CInterp.Resolver resolver) {
        this.resolver = resolver;
        this.fn = fn;
        this.sym = sym;
        this.mode = mode;
        this.trials = Math.max(1, trials);
        this.maxSteps = maxSteps;
    }

    public CSym sym() { return sym; }

    /** A result a pass asserts on grounds of its own (a proof it ran, the code's structure). */
    public Result claim(Status status, String detail) { return new Result(status, detail); }
    public boolean enabled() { return !mode.equals("off"); }

    private Mem memory(long seed, int trial) {
        // Vary how often unknown memory is zero, so loops that stop at a terminator see both
        // short and long runs.
        int[] zero = {0, 3, 9, 40};
        return new Mem(fn.program, seed, zero[trial % zero.length]);
    }

    private static long seedOf(int trial) { return CEval.mix(0x5eedL + trial * 0x9e3779b97f4a7c15L); }

    /** Check that expression {@code after} can replace {@code before}. */
    public Result check(Expr before, Expr after) {
        if (mode.equals("off")) return new Result(Status.ASSUMED, "verification is off");
        String untested = null;
        int ran = 0;
        for (int t = 0; t < trials; t++) {
            long seed = seedOf(t);
            try {
                CInterp a = new CInterp(fn, memory(seed, t), seed, maxSteps, CInterp.Calls.STUB, resolver);
                CInterp b = new CInterp(fn, memory(seed, t), seed, maxSteps, CInterp.Calls.STUB, resolver);
                BigInteger x, y;
                try {
                    x = a.eval(before);
                } catch (CEval.Fault fault) {
                    continue;   // the original traps here: nothing to preserve
                }
                y = b.eval(after);
                if (after.type.isScalarInt() && before.type.isScalarInt() && after.type.bits != before.type.bits) {
                    y = CEval.convert(y, after.type, before.type.bits);
                }
                String unknown = unmodelled(a, b);
                if (unknown != null) {
                    untested = unknown;
                    break;
                }
                tests++;
                ran++;
                String diff = !x.equals(y) ? "value 0x" + x.toString(16) + " became 0x" + y.toString(16) : difference(a, b, Set.of(), seed);
                if (diff != null) return new Result(Status.REFUTED, diff + " with " + inputs(a));
            } catch (CInterp.Unsupported | CEval.Fault | ArithmeticException e) {
                untested = e.getMessage();
                break;
            } catch (CInterp.Budget e) {
                // inconclusive trial
            }
        }
        if (mode.equals("prove") && AstUtil.isPure(before) && AstUtil.isPure(after)) {
            CSym.Verdict v = sym.equivalent(before, after);
            proofs++;
            if (v == CSym.Verdict.PROVEN) return new Result(Status.PROVEN, "");
            if (v == CSym.Verdict.REFUTED) return new Result(Status.REFUTED, sym.detail);
            if (untested == null && ran >= Math.min(trials, 4)) return new Result(Status.TESTED, ran + " trials agree; " + sym.detail);
            return new Result(Status.ASSUMED, sym.detail);
        }
        if (untested == null && ran >= Math.min(trials, 4)) return new Result(Status.TESTED, ran + " trials agree");
        return new Result(Status.ASSUMED, untested == null ? "too few conclusive trials" : "not testable: " + untested);
    }

    /**
     * Check that statements {@code after} can replace statements {@code before}. Everything a
     * later statement could observe is compared: how control leaves, the returned value, memory
     * written, calls made, and every variable either version assigns except those in
     * {@code dead} (which the caller has established are not read afterwards).
     */
    public Result check(List<Stmt> before, List<Stmt> after, Collection<String> dead) {
        if (mode.equals("off")) return new Result(Status.ASSUMED, "verification is off");
        Set<String> ignore = new HashSet<>(dead);
        int ran = 0, budget = 0;
        for (int t = 0; t < trials; t++) {
            long seed = seedOf(t);
            try {
                CInterp a = new CInterp(fn, memory(seed, t), seed, maxSteps, CInterp.Calls.STUB, resolver);
                CInterp b = new CInterp(fn, memory(seed, t), seed, maxSteps, CInterp.Calls.STUB, resolver);
                CInterp.Flow fa, fb;
                try {
                    fa = a.exec(new Stmt.Block(before));
                } catch (CEval.Fault fault) {
                    continue;
                }
                fb = b.exec(new Stmt.Block(after));
                String unknown = unmodelled(a, b);
                if (unknown != null) return new Result(Status.ASSUMED, "not testable: " + unknown);
                tests++;
                ran++;
                String diff = fa != fb ? "control leaves by " + fa + " instead of " + fb : null;
                if (diff == null && fa == CInterp.Flow.RETURN && !java.util.Objects.equals(a.returnValue, b.returnValue)) {
                    diff = "returns " + hex(b.returnValue) + " instead of " + hex(a.returnValue);
                }
                if (diff == null) diff = difference(a, b, ignore, seed);
                if (diff != null) return new Result(Status.REFUTED, diff + " with " + inputs(a));
            } catch (CInterp.Unsupported | CEval.Fault | ArithmeticException e) {
                return new Result(Status.ASSUMED, "not testable: " + e.getMessage());
            } catch (CInterp.Budget e) {
                budget++;
            }
        }
        if (ran >= Math.min(trials, 4)) return new Result(Status.TESTED, ran + " trials agree" + (budget > 0 ? ", " + budget + " ran too long" : ""));
        return new Result(Status.ASSUMED, "too few conclusive trials (" + ran + ")");
    }

    private static String hex(BigInteger v) { return v == null ? "nothing" : "0x" + v.toString(16); }

    /**
     * Calls to functions the engine cannot run are stood in for by an arbitrary function of the
     * arguments. That is enough to compare two versions that make the same calls, and worthless
     * when one version makes a call the other does not: then nothing was tested.
     */
    private static String unmodelled(CInterp a, CInterp b) {
        java.util.List<String> x = names(a), y = names(b);
        if (x.equals(y)) return null;
        java.util.List<String> extra = new java.util.ArrayList<>(y);
        for (String n : x) extra.remove(n);
        if (extra.isEmpty()) {
            extra = new java.util.ArrayList<>(x);
            for (String n : y) extra.remove(n);
        }
        return "it adds or drops a call to " + (extra.isEmpty() ? "a function" : extra.get(0)) + ", which the engine has no model of";
    }

    private static java.util.List<String> names(CInterp run) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String call : run.callLog) out.add(call.substring(0, call.indexOf('(')));
        java.util.Collections.sort(out);
        return out;
    }

    /** First observable difference between two finished runs, or null. */
    private String difference(CInterp a, CInterp b, Set<String> ignore, long seed) {
        if (!a.mem.written.equals(b.mem.written)) {
            for (Map.Entry<Long, Byte> e : a.mem.written.entrySet()) {
                Byte other = b.mem.written.get(e.getKey());
                if (!e.getValue().equals(other)) {
                    return "byte at 0x" + Long.toHexString(e.getKey()) + " is " + (other == null ? "not written" : String.format("0x%02x", other))
                        + " instead of " + String.format("0x%02x", e.getValue());
                }
            }
            for (Long k : b.mem.written.keySet()) {
                if (!a.mem.written.containsKey(k)) return "extra write at 0x" + Long.toHexString(k);
            }
        }
        if (!a.callLog.equals(b.callLog)) return "calls differ: " + a.callLog + " vs " + b.callLog;
        Set<String> names = new TreeSet<>(a.env.keySet());
        names.addAll(b.env.keySet());
        for (String n : names) {
            if (ignore.contains(n)) continue;
            BigInteger x = a.env.get(n), y = b.env.get(n);
            // A variable only one side touched still has its initial value on the other.
            if (x == null || y == null) {
                CType type = fn.typeOf(n);
                if (type == null || !type.isScalarInt()) continue;
                BigInteger initial = CInterp.initial(seed, n, type);
                if (x == null) x = initial; else y = initial;
            }
            if (!x.equals(y)) return n + " ends as 0x" + y.toString(16) + " instead of 0x" + x.toString(16);
        }
        return null;
    }

    private static String inputs(CInterp run) {
        StringBuilder sb = new StringBuilder();
        for (String n : new TreeSet<>(run.inputs.keySet())) {
            if (sb.length() > 120) { sb.append(" ..."); break; }
            sb.append(sb.length() > 0 ? ", " : "").append(n).append("=0x").append(run.inputs.get(n).toString(16));
        }
        return sb.length() == 0 ? "no inputs" : sb.toString();
    }
}
