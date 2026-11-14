package decompfuncutils.refine.pass;

import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.sem.CEval;
import decompfuncutils.refine.sem.CInterp;
import decompfuncutils.refine.sem.CSym;
import decompfuncutils.refine.sem.Mem;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Removes branches that cannot be taken. Some conditions look data dependent and are not --
 * {@code x * (x + 1)} is always even -- whether an obfuscator put them there or an optimizer
 * left them behind. The solver decides each condition; a decided one is replaced by the branch
 * that always runs.
 */
public final class OpaquePass implements RefinePass {
    @Override public String id() { return "opaque"; }
    @Override public String title() { return "Remove branches that cannot be taken"; }
    @Override public String description() {
        return "Asks the solver whether each 'if' condition has the same value for every input (an opaque predicate). "
            + "If it does, the dead branch is dropped. Only proved conditions are touched.";
    }
    @Override public List<Param> params() {
        return List.of(Param.bool("loops", "Also decide loop conditions", false,
            "Drop 'while' loops whose condition is always false. Off by default: an always-true loop condition is common and intended."));
    }

    @Override public boolean run(PassContext ctx) {
        if (ctx.verifier.sym() == null) return false;
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        boolean loops = ctx.flag("loops");
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                if (ctx.cancelled()) return changed;
                Stmt s = block.body.get(i);
                if (s instanceof Stmt.If iff) {
                    Boolean truth = decide(ctx, iff.cond);
                    if (truth == null) continue;
                    Stmt.Block taken = truth ? iff.then : iff.otherwise;
                    List<Stmt> replacement = taken == null ? List.of() : taken.body;
                    Rewrite rw = ctx.record(truth ? "always-true" : "always-false",
                        "if (" + CPrinter.text(iff.cond) + ") ...", truth ? "(then branch only)" : taken == null ? "(removed)" : "(else branch only)",
                        Rewrite.Status.PROVEN, "the condition is " + truth + " for every input", iff.addr);
                    rw.evidence = ctx.disassembly(iff.addr, iff.maxAddr, 10);
                    for (Stmt r : replacement) if (r.note == null) r.note = rw;
                    block.body.remove(i);
                    block.body.addAll(i, replacement);
                    changed = true;
                    i--;
                } else if (loops && s instanceof Stmt.While w) {
                    Boolean truth = decide(ctx, w.cond);
                    if (truth == null || truth) continue;
                    ctx.record("never-entered", "while (" + CPrinter.text(w.cond) + ") ...", "(removed)", Rewrite.Status.PROVEN,
                        "the condition is false for every input", w.addr);
                    block.body.remove(i--);
                    changed = true;
                }
            }
        }
        return changed;
    }

    /** TRUE / FALSE when the condition is constant, null when it is not or cannot be decided. */
    private static Boolean decide(PassContext ctx, Expr cond) {
        if (cond instanceof Lit || !AstUtil.isPure(cond)) return null;
        // A few concrete evaluations first: most conditions are seen both ways immediately.
        Boolean seen = null;
        for (int t = 0; t < 12; t++) {
            long seed = CEval.mix(0xabcd + t);
            try {
                CInterp run = new CInterp(ctx.fn, new Mem(ctx.program, seed, 0), seed, 2000, CInterp.Calls.STUB, null);
                boolean v = run.eval(cond).signum() != 0;
                if (seen != null && seen != v) return null;
                seen = v;
            } catch (CInterp.Unsupported | CInterp.Budget | CEval.Fault | ArithmeticException e) {
                break;
            }
        }
        CSym sym = ctx.verifier.sym();
        return sym.constantTruth(cond, sym.newState());
    }
}
