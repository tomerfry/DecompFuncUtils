package decompfuncutils.refine.pass;

import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Undoes if-conversion. A compiler turns {@code x = c ? a : b} into a conditional move, and the
 * decompiler shows that as {@code x = b; if (c) x = a;}. Where the disassembly confirms there is
 * no real branch, the two statements are one select again -- and a select that is a minimum,
 * maximum or absolute value is named as such.
 */
public final class SelectPass implements RefinePass {
    @Override public String id() { return "select"; }
    @Override public String title() { return "Recover selects (cmov) and min / max / abs"; }
    @Override public String description() {
        return "Turns 'x = b; if (c) x = a;' and 'if (c) x = a; else x = b;' back into 'x = c ? a : b' when the "
            + "instructions show a conditional move rather than a jump, then asks the prover whether the select is "
            + "MIN, MAX or abs of its operands.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.choice("evidence", "Convert an 'if' when", "branchless", List.of("branchless", "always"),
                "branchless: only where the disassembly has no conditional jump for it (cmov, setcc, csel). always: any matching 'if'."),
            Param.integer("maxSize", "Largest operand (nodes)", 12, 1, 200, "Selects with bigger operands stay as 'if'."),
            Param.bool("idioms", "Name MIN / MAX / abs", true, "Replace a select that the prover shows is a minimum, maximum or absolute value."),
            Param.bool("plainTernary", "Keep selects that are no idiom as 'c ? a : b'", true,
                "Off: only selects that turn out to be MIN / MAX / abs are rewritten."));
    }

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        int max = ctx.integer("maxSize");
        boolean always = ctx.choice("evidence").equals("always");
        boolean idioms = ctx.flag("idioms"), plain = ctx.flag("plainTernary");
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                if (ctx.cancelled()) return changed;
                if (!(block.body.get(i) instanceof Stmt.If iff)) continue;
                Assign then = soleAssign(iff.then);
                if (then == null || !(then.l instanceof Id x) || !x.type.isScalarInt()) continue;
                if (!AstUtil.isPure(iff.cond) || !AstUtil.isPure(then.r) || AstUtil.size(then.r) > max) continue;
                if (!always && !branchless(ctx, iff)) continue;

                List<Stmt> before = new ArrayList<>();
                Expr otherwise;
                int first = i;
                if (iff.otherwise != null) {
                    // if (c) x = a; else x = b;
                    Assign other = soleAssign(iff.otherwise);
                    if (other == null || !AstUtil.same(other.l, x) || !AstUtil.isPure(other.r) || AstUtil.size(other.r) > max) continue;
                    otherwise = other.r;
                    before.add(iff);
                } else if (i > 0 && block.body.get(i - 1) instanceof Stmt.ExprStmt prev && prev.e instanceof Assign init
                        && init.o.equals("=") && AstUtil.same(init.l, x) && AstUtil.isPure(init.r) && AstUtil.size(init.r) <= max
                        && !AstUtil.mentions(iff.cond, x.name) && !AstUtil.mentions(then.r, x.name) && !AstUtil.mentions(init.r, x.name)) {
                    // x = b; if (c) x = a;
                    otherwise = init.r;
                    before.add(prev);
                    before.add(iff);
                    first = i - 1;
                } else {
                    // if (c) x = a;   (x keeps its value otherwise)
                    otherwise = x.copy();
                    before.add(iff);
                }
                Cond select = new Cond(iff.cond.copy(), then.r.copy(), otherwise.copy());
                select.type = x.type;
                select.addr = iff.cond.addr;
                ctx.typer.retype(select);
                Named named = idioms ? idiom(ctx, select) : null;
                boolean keepsOld = otherwise instanceof Id o && o.name.equals(x.name);
                // A select that merely keeps the old value reads better as the 'if' it was.
                if (named == null && (!plain || keepsOld)) continue;
                Assign assign = new Assign("=", x.copy(), select);
                assign.type = x.type;
                Stmt.ExprStmt after = new Stmt.ExprStmt(assign);
                if (!ctx.accept("select", before, List.of(after), Set.of())) continue;
                if (named != null) {
                    Expr marked = ctx.acceptChecked("min-max-abs", select, named.call, named.result);
                    if (marked != null) assign.r = marked;
                }
                if (after.note instanceof Rewrite rw) rw.evidence = ctx.disassembly(iff.addr, iff.maxAddr, 10);
                block.body.set(first, after);
                if (first != i) block.body.remove(i);
                changed = true;
                i = first;
            }
        }
        return changed;
    }

    private static Assign soleAssign(Stmt.Block b) {
        if (b.body.size() != 1 || !(b.body.get(0) instanceof Stmt.ExprStmt es)) return null;
        return es.e instanceof Assign a && a.o.equals("=") ? a : null;
    }

    /** True when no instruction the 'if' was decompiled from is a conditional jump. */
    private static boolean branchless(PassContext ctx, Stmt.If iff) {
        Address lo = iff.addr, hi = iff.maxAddr;
        if (ctx.program == null || lo == null) return false;
        if (hi == null) hi = lo;
        InstructionIterator it = ctx.program.getListing().getInstructions(lo, true);
        int n = 0;
        while (it.hasNext() && n++ < 64) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(hi) > 0) break;
            if (ins.getFlowType().isConditional() && ins.getFlowType().isJump()) return false;
        }
        return n > 0;
    }

    /**
     * If {@code select} is the minimum, maximum or absolute value of its operands, return that
     * call. The candidates are simply proposed; the verifier decides which, if any, is right.
     */
    private static Named idiom(PassContext ctx, Cond select) {
        if (!(select.c instanceof Bin cmp) || !Typer.ORDER.contains(cmp.o)) return null;
        List<Expr> candidates = new ArrayList<>();
        Expr a = select.a, b = select.b;
        // abs first: a select between x and -x is also MAX(x, -x), which nobody would write.
        boolean negated = (a instanceof Un ua && ua.o.equals("-") && AstUtil.same(ua.e, b))
            || (b instanceof Un ub && ub.o.equals("-") && AstUtil.same(ub.e, a));
        if (negated) {
            candidates.add(call("abs", (a instanceof Un ? b : a).copy()));
            candidates.add(call("abs", (a instanceof Un ? a : b).copy()));
        }
        for (String f : new String[] {"MIN", "MAX"}) {
            // MIN / MAX compare the way their operand types say. Where the machine comparison
            // is of the other signedness, cast the operands so the printed call means the same.
            Expr x = signedAs(a.copy(), cmp.sgn), y = signedAs(b.copy(), cmp.sgn);
            // MIN(x, 255), not MIN(255, x).
            candidates.add(x instanceof Lit && !(y instanceof Lit) ? call(f, y, x) : call(f, x, y));
        }
        for (Expr c : candidates) {
            ctx.typer.retype(c);
            if (!c.type.isScalarInt()) continue;
            Expr fitted = ctx.fit(c, select.type);
            decompfuncutils.refine.sem.Verifier.Result r = ctx.verifier.check(select, fitted);
            if (r.status == Rewrite.Status.PROVEN || r.status == Rewrite.Status.TESTED) return new Named(fitted, r);
        }
        return null;
    }

    private record Named(Expr call, decompfuncutils.refine.sem.Verifier.Result result) {}

    private static Expr signedAs(Expr e, boolean signed) {
        if (e instanceof Lit || e.type.kind != CType.Kind.INT || e.type.signed == signed) return e;
        CType t = CType.integer(e.type.bits, signed);
        return new Cast(t, t.name, e);
    }

    private static Call call(String name, Expr... args) {
        return new Call(new Id(name, Id.Kind.FUNC), List.of(args));
    }
}
