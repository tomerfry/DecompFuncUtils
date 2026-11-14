package decompfuncutils.refine.pass;

import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Removes assignments nothing reads. Other passes leave these behind: the condition temporary of
 * a loop whose condition was rewritten, the value computed for a branch that turned out to be
 * dead.
 */
public final class DeadStorePass implements RefinePass {
    @Override public String id() { return "dead-stores"; }
    @Override public String title() { return "Remove assignments nothing reads"; }
    @Override public String description() {
        return "Deletes 'x = expr;' when x is a register variable whose value cannot reach a later read and expr has no side "
            + "effects. Liveness is judged conservatively: any later mention of x keeps the assignment, and stack variables are "
            + "only touched in functions where no stack address is ever taken.";
    }

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                if (!(block.body.get(i) instanceof Stmt.ExprStmt es) || !(es.e instanceof Assign a) || !a.o.equals("=")
                        || !(a.l instanceof Id x) || (x.kind != Id.Kind.VAR && x.kind != Id.Kind.PARAM)) continue;
                if (!ctx.fn.removable(x.name) || !AstUtil.isPure(a.r)) continue;
                if (AstUtil.liveAfter(ctx.fn, es, x.name)) continue;
                ctx.record("dead-store", CPrinter.text(es), "(removed)", Rewrite.Status.STRUCTURAL,
                    x.name + " is not read again before it is reassigned or goes out of use", es.addr);
                block.body.remove(i--);
                changed = true;
            }
        }
        return changed;
    }
}
