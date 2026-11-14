package decompfuncutils.refine.pass;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.sem.CEval;
import decompfuncutils.refine.sem.CInterp;
import decompfuncutils.refine.sem.Mem;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * Recognizes loops that are an inlined or open-coded {@code strlen}, {@code memset} or
 * {@code memcpy} -- by what they do, not by how they are written.
 *
 * <p>A candidate loop is run on a series of invented inputs and memories. From what is observed
 * (which bytes it wrote and with what, where its variables ended up) the pass fits a call:
 * the written range as {@code base + k} and a length in terms of the loop's inputs, the fill as a
 * constant or a copy of another range, a counter as the length of a string. A fit is only a
 * hypothesis; it is then handed to the verifier, which runs loop and call side by side on fresh
 * inputs before anything is replaced. Compilers emit these loops in many shapes; behaviour is the
 * one thing the shapes share.
 */
public final class LoopIdiomPass implements RefinePass {
    @Override public String id() { return "loop-idioms"; }
    @Override public String title() { return "Recognize strlen / memset / memcpy loops"; }
    @Override public String description() {
        return "Runs each small call-free loop on sample inputs, fits what it did to strlen, memset or memcpy over the loop's "
            + "inputs, and replaces the loop when loop and call then agree on a fresh set of runs. A byte copy is reported as "
            + "memcpy on the assumption that source and destination do not overlap.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.bool("strlen", "strlen", true, "Loops that scan for a zero byte."),
            Param.bool("memset", "memset", true, "Loops that fill a range with one byte value."),
            Param.bool("memcpy", "memcpy", true, "Loops that copy one range to another."),
            Param.integer("observations", "Runs used to fit a call", 28, 8, 400, "More runs make a coincidental fit less likely."),
            Param.integer("maxBody", "Largest loop to try (statements)", 12, 1, 200, "Library loops are small; bigger loops are skipped."));
    }

    /** What one run of the candidate region did. */
    private static final class Trial {
        long seed;
        int zeroEvery;
        Map<String, BigInteger> inputs, finals;
        TreeMap<Long, Byte> writes;
        long lo, len;

        Mem pristine(PassContext ctx) { return new Mem(ctx.program, seed, zeroEvery); }
    }

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                if (ctx.cancelled()) return changed;
                Stmt s = block.body.get(i);
                if (!isCandidate(s, ctx.integer("maxBody"))) continue;
                // Take the assignments that initialize the loop's own variables along with it.
                Set<String> assigned = AstUtil.assigned(s);
                int start = i;
                while (start > 0 && i - start < 4 && block.body.get(start - 1) instanceof Stmt.ExprStmt es && es.e instanceof Assign a
                        && a.o.equals("=") && a.l instanceof Id x && assigned.contains(x.name) && AstUtil.isPure(a.r)
                        && !AstUtil.readsMemory(a.r)) start--;
                List<Stmt> replacement = null;
                int from = start;
                for (; from <= i && replacement == null; from++) {
                    replacement = recognize(ctx, new ArrayList<>(block.body.subList(from, i + 1)), s);
                }
                if (replacement == null) continue;
                from--;
                for (int k = i; k >= from; k--) block.body.remove(k);
                block.body.addAll(from, replacement);
                changed = true;
                i = from + replacement.size() - 1;
            }
        }
        return changed;
    }

    private static boolean isLoop(Stmt s) { return s instanceof Stmt.While || s instanceof Stmt.DoWhile || s instanceof Stmt.For; }

    private static boolean isCandidate(Stmt s, int maxBody) {
        Stmt loop = s;
        if (s instanceof Stmt.If g) {
            // A guarded loop the loops pass did not (or was not asked to) fold.
            if (g.otherwise != null || g.then.body.isEmpty() || !isLoop(g.then.body.get(g.then.body.size() - 1))) return false;
            loop = g.then.body.get(g.then.body.size() - 1);
        }
        if (!isLoop(loop) || AstUtil.hasCalls(s)) return false;
        int[] n = new int[1];
        boolean[] bad = new boolean[1];
        AstUtil.walk(s, x -> {
            n[0]++;
            if (x instanceof Stmt.Return || x instanceof Stmt.Goto || x instanceof Stmt.Label || x instanceof Stmt.Raw || x instanceof Stmt.Switch) bad[0] = true;
        });
        return !bad[0] && n[0] <= maxBody + 4;
    }

    // ------------------------------------------------------------------ observe

    private static List<Trial> observe(PassContext ctx, List<Stmt> region, int count, String[] why) {
        List<Trial> out = new ArrayList<>();
        int[] zero = {3, 9, 40, 0, 5, 17};
        for (int t = 0; t < count; t++) {
            Trial trial = new Trial();
            trial.seed = CEval.mix(0xf17f17L + t * 0x2545f4914f6cdd1dL);
            trial.zeroEvery = zero[t % zero.length];
            Mem mem = new Mem(ctx.program, trial.seed, trial.zeroEvery);
            CInterp run = new CInterp(ctx.fn, mem, trial.seed, 6000, CInterp.Calls.FAIL, null);
            try {
                if (run.exec(new Stmt.Block(region)) != CInterp.Flow.NORMAL) {
                    why[0] = "control leaves the loop other than by falling out of it";
                    return null;
                }
            } catch (CInterp.Budget | CEval.Fault | ArithmeticException e) {
                continue;
            } catch (CInterp.Unsupported e) {
                why[0] = "the interpreter cannot run it: " + e.getMessage();
                return null;
            }
            trial.inputs = run.inputs;
            trial.finals = run.env;
            trial.writes = new TreeMap<>(mem.written);
            // Writes to the interpreter's own frame are local variables, not the loop's effect.
            trial.writes.keySet().removeIf(a -> a >= 0x7ffd_0000_0000L && a < 0x7ffd_5000_0000L);
            if (!trial.writes.isEmpty()) {
                trial.lo = trial.writes.firstKey();
                trial.len = trial.writes.lastKey() - trial.lo + 1;
                if (trial.len != trial.writes.size()) {
                    why[0] = "it writes more than one contiguous range";
                    return null;
                }
            }
            out.add(trial);
        }
        return out;
    }

    // ------------------------------------------------------------------ recognize

    private List<Stmt> recognize(PassContext ctx, List<Stmt> region, Stmt last) {
        String where = "loop at " + last.addr;
        String[] why = new String[1];
        List<Trial> trials = observe(ctx, region, ctx.integer("observations"), why);
        if (trials == null || trials.size() < 6) {
            ctx.trace(where + ": " + (trials == null ? why[0] : "only " + trials.size() + " sample runs finished within the step budget"));
            return null;
        }
        Set<String> inputs = new LinkedHashSet<>();
        for (Trial t : trials) inputs.addAll(t.inputs.keySet());
        Set<String> assigned = new HashSet<>();
        for (Stmt s : region) assigned.addAll(AstUtil.assigned(s));
        Set<String> liveOut = new LinkedHashSet<>();
        // A variable whose stores may be observed some other way has to keep its final value too.
        for (String v : assigned) if (AstUtil.liveAfter(ctx.fn, last, v) || !ctx.fn.removable(v)) liveOut.add(v);
        // An input the region itself updates is described by its value on entry.
        boolean writes = false;
        for (Trial t : trials) writes |= !t.writes.isEmpty();

        List<Stmt> out = new ArrayList<>();
        String rule;
        if (!writes) {
            if (!ctx.flag("strlen") || liveOut.isEmpty()) {
                ctx.trace(where + ": writes no memory and computes nothing that is read afterwards");
                return null;
            }
            boolean usedStrlen = false;
            for (String v : liveOut) {
                CType type = ctx.fn.typeOf(v);
                if (type == null || !type.isScalarInt()) return null;
                Expr value = fitStrlen(ctx, trials, inputs, v, type);
                if (value != null) usedStrlen = true;
                else value = fitAffine(ctx, trials, inputs, t -> t.finals.get(v), type.bits);
                if (value == null) {
                    ctx.trace(where + ": the final value of " + v + " fits neither strlen of an input nor input + constant");
                    return null;
                }
                out.add(assign(ctx, v, value));
            }
            if (!usedStrlen) {
                ctx.trace(where + ": nothing it computes is a string length");
                return null;
            }
            rule = "strlen";
        } else {
            List<Trial> writing = new ArrayList<>();
            Set<Long> lengths = new HashSet<>();
            for (Trial t : trials) {
                if (!t.writes.isEmpty()) { writing.add(t); lengths.add(t.len); }
            }
            if (writing.size() < 3 || lengths.size() < 2) {
                ctx.trace(where + ": too few sample runs wrote memory, or all wrote the same amount");
                return null;
            }
            int ptr = ctx.fn.pointerBits;
            Expr len = fitAffine(ctx, trials, inputs, t -> BigInteger.valueOf(t.len), ptr);
            Expr base = fitAffine(ctx, writing, inputs, t -> CEval.mask(BigInteger.valueOf(t.lo), ptr), ptr);
            if (len == null || base == null || len instanceof Lit) {
                ctx.trace(where + ": the range it writes is not (input + constant) with a length taken from its inputs");
                return null;
            }
            Expr call = null;
            if (ctx.flag("memset")) {
                Expr fill = fitFill(ctx, writing, inputs);
                if (fill != null) {
                    call = call("memset", pointer(ctx, base, "void"), fill, len);
                    rule = "memset";
                } else rule = null;
            } else rule = null;
            if (call == null && ctx.flag("memcpy")) {
                Expr src = fitSource(ctx, writing, inputs);
                if (src != null) {
                    call = call("memcpy", pointer(ctx, base, "void"), pointer(ctx, src, "void"), len);
                    rule = "memcpy";
                }
            }
            if (call == null) {
                ctx.trace(where + ": the bytes written are neither one repeated value nor a copy of another range");
                return null;
            }
            ctx.typer.retype(call);
            out.add(new Stmt.ExprStmt(call));
            for (String v : liveOut) {
                CType type = ctx.fn.typeOf(v);
                if (type == null || !type.isScalarInt()) return null;
                Expr value = fitAffine(ctx, trials, inputs, t -> t.finals.get(v), type.bits);
                if (value == null) {
                    ctx.trace(where + ": " + v + " is read after the loop and its final value is not input + constant");
                    return null;
                }
                out.add(assign(ctx, v, value));
            }
        }
        Set<String> dead = new HashSet<>(assigned);
        dead.removeAll(liveOut);
        return ctx.accept(rule, region, out, dead) ? out : null;
    }

    // ------------------------------------------------------------------ fitting

    private static BigInteger input(Trial t, String name, CType type, int bits) {
        BigInteger v = t.inputs.get(name);
        return v == null ? null : CEval.convert(v, type, bits);
    }

    /**
     * Express a per-trial target as a constant, {@code a + d}, {@code a * k + d} or
     * {@code a - b + d} over the region's inputs, with one {@code d} for all trials.
     */
    private static Expr fitAffine(PassContext ctx, List<Trial> trials, Set<String> inputs, Function<Trial, BigInteger> target, int bits) {
        BigInteger mod = BigInteger.ONE.shiftLeft(bits);
        List<BigInteger> want = new ArrayList<>();
        for (Trial t : trials) {
            BigInteger v = target.apply(t);
            if (v == null) return null;
            want.add(v.mod(mod));
        }
        if (new HashSet<>(want).size() == 1) return new Lit(want.get(0), CType.integer(bits, false));
        Expr best = null;
        BigInteger bestOffset = null;
        List<String> names = new ArrayList<>(inputs);
        for (String a : names) {
            CType ta = ctx.fn.typeOf(a);
            if (ta == null || !ta.isScalarInt()) continue;
            for (int k : new int[] {1, 2, 4, 8}) {
                BigInteger d = constantOffset(trials, want, mod, t -> {
                    BigInteger x = input(t, a, ta, bits);
                    return x == null ? null : x.multiply(BigInteger.valueOf(k));
                });
                if (d == null) continue;
                BigInteger magnitude = CEval.signed(d, bits).abs();
                if (magnitude.bitLength() > 16 || (bestOffset != null && magnitude.compareTo(bestOffset) >= 0)) continue;
                Expr e = var(ctx, a);
                if (k != 1) e = bin("*", widen(e, bits), new Lit(BigInteger.valueOf(k), CType.integer(bits, false)), bits);
                best = offset(e, d, bits);
                bestOffset = magnitude;
            }
        }
        if (best != null && bestOffset.signum() == 0) return best;
        for (String a : names) {
            for (String b : names) {
                if (a.equals(b)) continue;
                CType ta = ctx.fn.typeOf(a), tb = ctx.fn.typeOf(b);
                if (ta == null || tb == null || !ta.isScalarInt() || !tb.isScalarInt()) continue;
                BigInteger d = constantOffset(trials, want, mod, t -> {
                    BigInteger x = input(t, a, ta, bits), y = input(t, b, tb, bits);
                    return x == null || y == null ? null : x.subtract(y);
                });
                if (d == null) continue;
                BigInteger magnitude = CEval.signed(d, bits).abs();
                if (magnitude.bitLength() > 16 || (bestOffset != null && magnitude.compareTo(bestOffset) >= 0)) continue;
                best = offset(bin("-", widen(var(ctx, a), bits), widen(var(ctx, b), bits), bits), d, bits);
                bestOffset = magnitude;
            }
        }
        return best;
    }

    /** The d with want[i] == term(trial i) + d for every trial, or null. */
    private static BigInteger constantOffset(List<Trial> trials, List<BigInteger> want, BigInteger mod, Function<Trial, BigInteger> term) {
        BigInteger d = null;
        for (int i = 0; i < trials.size(); i++) {
            BigInteger x = term.apply(trials.get(i));
            if (x == null) return null;
            BigInteger di = want.get(i).subtract(x).mod(mod);
            if (d == null) d = di;
            else if (!d.equals(di)) return null;
        }
        return d;
    }

    /** One fill byte for every written range: a constant, or the low byte of an input. */
    private static Expr fitFill(PassContext ctx, List<Trial> writing, Set<String> inputs) {
        Set<Integer> values = new HashSet<>();
        for (Trial t : writing) {
            int first = t.writes.firstEntry().getValue() & 0xff;
            for (Byte b : t.writes.values()) if ((b & 0xff) != first) return null;
            values.add(first);
        }
        if (values.size() == 1) return new Lit(BigInteger.valueOf(values.iterator().next()), CType.integer(32, true));
        for (String a : inputs) {
            boolean all = true;
            for (Trial t : writing) {
                BigInteger v = t.inputs.get(a);
                if (v == null || (v.intValue() & 0xff) != (t.writes.firstEntry().getValue() & 0xff)) { all = false; break; }
            }
            if (all) return var(ctx, a);
        }
        return null;
    }

    /** An input the written bytes are a copy of, as memory stood before the loop ran. */
    private static Expr fitSource(PassContext ctx, List<Trial> writing, Set<String> inputs) {
        for (String a : inputs) {
            CType ta = ctx.fn.typeOf(a);
            if (ta == null || !ta.isScalarInt()) continue;
            boolean all = true;
            int used = 0;
            for (Trial t : writing) {
                BigInteger v = t.inputs.get(a);
                if (v == null) { all = false; break; }
                long src = v.longValue();
                // Where the invented pointers overlap, a byte loop reads what it has just written
                // and the result is not a copy of the original range. Such runs say nothing.
                if (Math.abs(src - t.lo) < t.len) continue;
                used++;
                Mem before = t.pristine(ctx);
                for (long i = 0; i < t.len && all; i++) {
                    if (before.readByte(src + i) != (t.writes.get(t.lo + i) & 0xff)) all = false;
                }
                if (!all) break;
            }
            if (all && used >= 3) return var(ctx, a);
        }
        return null;
    }

    /** {@code v} as strlen of an input (plus a constant), or as a pointer advanced by it. */
    private static Expr fitStrlen(PassContext ctx, List<Trial> trials, Set<String> inputs, String v, CType type) {
        int bits = type.bits;
        BigInteger mod = BigInteger.ONE.shiftLeft(bits);
        for (String a : inputs) {
            CType ta = ctx.fn.typeOf(a);
            if (ta == null || !ta.isScalarInt() || ta.bits != ctx.fn.pointerBits) continue;
            for (int d1 : new int[] {0, 1, -1}) {
                for (boolean pointerForm : new boolean[] {false, true}) {
                    BigInteger d2 = null;
                    Set<Long> seen = new HashSet<>();
                    boolean ok = true;
                    for (Trial t : trials) {
                        BigInteger in = t.inputs.get(a), fin = t.finals.get(v);
                        if (in == null || fin == null) { ok = false; break; }
                        long len = modelStrlen(t.pristine(ctx), in.longValue() + d1);
                        if (len < 0) { ok = false; break; }
                        seen.add(len);
                        BigInteger term = BigInteger.valueOf(len);
                        if (pointerForm) term = term.add(CEval.convert(in, ta, bits));
                        BigInteger di = fin.subtract(term).mod(mod);
                        if (d2 == null) d2 = di;
                        else if (!d2.equals(di)) { ok = false; break; }
                    }
                    if (!ok || d2 == null || seen.size() < 3 || CEval.signed(d2, bits).abs().bitLength() > 8) continue;
                    Expr arg = pointer(ctx, offset(widen(var(ctx, a), ctx.fn.pointerBits), CEval.mask(BigInteger.valueOf(d1), ctx.fn.pointerBits),
                        ctx.fn.pointerBits), "char");
                    Expr value = call("strlen", arg);
                    ctx.typer.retype(value);
                    if (pointerForm) value = bin("+", widen(var(ctx, a), bits), widen(value, bits), bits);
                    return offset(widen(value, bits), d2, bits);
                }
            }
        }
        return null;
    }

    private static long modelStrlen(Mem mem, long at) {
        for (long n = 0; n < 4000; n++) if (mem.readByte(at + n) == 0) return n;
        return -1;
    }

    // ------------------------------------------------------------------ building

    private static Expr var(PassContext ctx, String name) {
        CFunction.Var decl = ctx.fn.vars.get(name);
        Id id = new Id(name, decl != null && decl.param ? Id.Kind.PARAM : Id.Kind.VAR);
        id.type = decl == null ? CType.UNKNOWN : decl.type;
        return id;
    }

    /** View an expression as a plain integer of {@code bits}, casting only when it is not one already. */
    private static Expr widen(Expr e, int bits) {
        if (e.type.isScalarInt() && e.type.bits == bits && !(e.type.isPointer() && e.type.elemSize > 1)) return e;
        CType t = CType.integer(bits, false);
        return new Cast(t, t.name, e);
    }

    private static Expr bin(String o, Expr l, Expr r, int bits) {
        Bin b = new Bin(o, l, r);
        b.type = l.type.isPointer() ? l.type : CType.integer(bits, l.type.signed && r.type.signed);
        b.sgn = b.type.signed;
        return b;
    }

    private static Expr offset(Expr e, BigInteger d, int bits) {
        BigInteger s = CEval.signed(d, bits);
        if (s.signum() == 0) return e;
        Expr base = e.type.isPointer() && e.type.elemSize > 1 ? widen(e, bits) : e;
        CType lit = CType.integer(bits, true);
        return bin(s.signum() > 0 ? "+" : "-", base, new Lit(CEval.mask(s.abs(), bits), lit), bits);
    }

    private static Expr pointer(PassContext ctx, Expr e, String to) {
        if (e.type.isPointer()) return e;
        CType target = CType.pointerTo(to.equals("void") ? CType.VOID : CType.integer(8, true, "char"), ctx.fn.pointerBits);
        return new Cast(target, to + " *", e);
    }

    private static Call call(String name, Expr... args) { return new Call(new Id(name, Id.Kind.FUNC), List.of(args)); }

    private static Stmt assign(PassContext ctx, String v, Expr value) {
        Expr target = var(ctx, v);
        ctx.typer.retype(value);
        // An assignment converts by itself; only a change of width needs to be spelled out.
        Assign a = new Assign("=", target, value.type.isScalarInt() && value.type.bits == target.type.bits ? value : ctx.fit(value, target.type));
        a.type = target.type;
        return new Stmt.ExprStmt(a);
    }
}
