package decompfuncutils.refine.pass;

import decompfuncutils.refine.Rewrite.Status;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.sem.CSym;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Undoes loop rotation. Compilers turn {@code while (c) body} into
 * {@code if (c) do body while (c')}, often with c' computed from values the body has already
 * overwritten. Symbolic execution of the loop body shows when the exit test and the entry guard
 * are the same condition, which is what allows the guard to be folded back into the loop; a loop
 * with an initializer and a trailing step then reads as {@code for}.
 */
public final class LoopsPass implements RefinePass {
    @Override public String id() { return "loops"; }
    @Override public String title() { return "Restore while / for loops (undo loop rotation)"; }
    @Override public String description() {
        return "Turns 'if (c) { do { ... } while (c2); }' back into 'while (c) { ... }' when the solver proves the exit test "
            + "equals the entry guard after the body has run, rewrites 'do { if (c) break; ... } while (true)' as a while loop, "
            + "and writes loops with an initializer and a trailing step as 'for'.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.bool("derotate", "Fold the entry guard back into the loop", true, "if (c) do ... while (c)  becomes  while (c) ..."),
            Param.bool("breakLoops", "Rewrite 'while (true)' loops that begin or end with a break", true,
                "do { if (c) break; ... } while (true)  becomes  while (!c) { ... }"),
            Param.bool("forLoops", "Write counted loops as 'for'", true, "init; while (c) { ...; step; }  becomes  for (init; c; step) { ... }"),
            Param.integer("maxBody", "Largest loop body to analyse (statements)", 40, 1, 2000, "Bigger loops are left alone."));
    }

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                if (ctx.cancelled()) return changed;
                Stmt s = block.body.get(i);
                if (s instanceof Stmt.If g && ctx.flag("derotate") && derotate(ctx, block, i, g)) { changed = true; i = Math.max(-1, i - 1); continue; }
                if (ctx.flag("breakLoops") && breakLoop(ctx, block, i, s)) { changed = true; i = Math.max(-1, i - 1); continue; }
                if (s instanceof Stmt.While w && ctx.flag("forLoops") && toFor(ctx, block, i, w)) { changed = true; i = Math.max(-1, i - 2); }
            }
        }
        return changed;
    }

    private static int size(Stmt s) {
        int[] n = new int[1];
        AstUtil.walk(s, x -> n[0]++);
        return n[0];
    }

    private static boolean hasContinue(Stmt s) {
        boolean[] hit = new boolean[1];
        AstUtil.walk(s, x -> {
            if (x instanceof Stmt.Continue || x instanceof Stmt.Goto || x instanceof Stmt.Label || x instanceof Stmt.Raw) hit[0] = true;
        });
        return hit[0];
    }

    // ------------------------------------------------------------------ if (G) { init; do B while (C); }

    private boolean derotate(PassContext ctx, Stmt.Block block, int at, Stmt.If g) {
        CSym sym = ctx.verifier.sym();
        if (sym == null || g.otherwise != null || g.then.body.isEmpty()) return false;
        List<Stmt> inner = g.then.body;
        if (!(inner.get(inner.size() - 1) instanceof Stmt.DoWhile d)) return false;
        if (size(d) > ctx.integer("maxBody") || !AstUtil.isPure(g.cond) || !AstUtil.isPure(d.cond)) return false;
        List<Stmt> init = new ArrayList<>(inner.subList(0, inner.size() - 1));
        Set<String> initVars = new HashSet<>();
        for (Stmt s : init) {
            if (!(s instanceof Stmt.ExprStmt es) || !(es.e instanceof Assign a) || !a.o.equals("=") || !(a.l instanceof Id x)
                    || x.kind == Id.Kind.GLOBAL || !AstUtil.isPure(a.r)) return false;
            initVars.add(x.name);
        }
        if (init.size() > 6) return false;
        // Hoisting the initializers out of the guard changes those variables when the guard is
        // false; that is only invisible if nothing reads them afterwards.
        for (String v : initVars) if (AstUtil.liveAfter(ctx.fn, g, v)) return false;

        CSym.State entry = sym.newState(), afterInit = sym.newState();
        for (Stmt s : init) if (!sym.exec(s, afterInit)) return false;
        Expr cond = d.cond;
        String why;
        if (sym.sameTruth(g.cond, entry, d.cond, afterInit) == CSym.Verdict.PROVEN) {
            why = "the guard is the loop condition on entry (proved)";
        } else {
            // The exit test may be the guard in disguise: evaluated on values the body has since
            // overwritten. Run the body symbolically from an arbitrary state and compare the two
            // at the bottom of the loop.
            if (hasContinue(d.body)) return false;
            if (sym.sameTruth(g.cond, entry, g.cond, afterInit) != CSym.Verdict.PROVEN) return false;
            CSym.State bottom = sym.newState();
            try {
                for (Stmt s : d.body.body) {
                    if (sym.exec(s, bottom)) continue;
                    sym.havoc(bottom, AstUtil.assigned(s), ctx.fn::typeOf, AstUtil.writesMemory(s));
                }
            } catch (UnsupportedOperationException e) {
                return false;
            }
            if (sym.sameTruth(d.cond, bottom, g.cond, bottom) != CSym.Verdict.PROVEN) return false;
            cond = g.cond.copy();
            why = "after the body runs, the exit test '" + CPrinter.text(d.cond) + "' equals the guard (proved)";
        }
        Stmt.While loop = new Stmt.While(cond, d.body);
        loop.span(g.addr, g.maxAddr);
        List<Stmt> after = new ArrayList<>(init);
        after.add(loop);
        Set<String> dead = new HashSet<>(initVars);
        // Temporaries that only fed the old exit test are now unread.
        for (String v : AstUtil.assigned(d.body)) if (!AstUtil.liveAfter(ctx.fn, g, v)) dead.add(v);
        if (!ctx.accept("derotate", List.of(g), after, dead, Status.PROVEN, why)) return false;
        block.body.remove(at);
        block.body.addAll(at, after);
        return true;
    }

    // ------------------------------------------------------------------ while (true) with a break at an end

    private boolean breakLoop(PassContext ctx, Stmt.Block block, int at, Stmt s) {
        Stmt.Block body;
        if (s instanceof Stmt.DoWhile d && isTrue(d.cond)) body = d.body;
        else if (s instanceof Stmt.While w && isTrue(w.cond)) body = w.body;
        else return false;
        if (body.body.size() < 2 || size(s) > ctx.integer("maxBody")) return false;
        Stmt first = body.body.get(0), last = body.body.get(body.body.size() - 1);
        Stmt replacement;
        Stmt.If exit;
        if (isBreakIf(first)) {
            exit = (Stmt.If) first;
            // Other breaks and continues in the rest still leave, or re-test, the same loop.
            List<Stmt> rest = new ArrayList<>(body.body.subList(1, body.body.size()));
            replacement = new Stmt.While(not(exit.cond.copy(), ctx), new Stmt.Block(rest));
        } else if (isBreakIf(last)) {
            exit = (Stmt.If) last;
            List<Stmt> rest = new ArrayList<>(body.body.subList(0, body.body.size() - 1));
            // In do-while, 'continue' jumps to the test; in the original it jumped to the top.
            for (Stmt r : rest) if (hasContinue(r)) return false;
            replacement = new Stmt.DoWhile(new Stmt.Block(rest), not(exit.cond.copy(), ctx));
        } else return false;
        if (!AstUtil.isPure(exit.cond)) return false;
        replacement.span(s.addr, s.maxAddr);
        if (!ctx.accept("break-loop", List.of(s), List.of(replacement), Set.of(), Status.STRUCTURAL,
                "the loop's only way out at that end is the break")) return false;
        block.body.set(at, replacement);
        return true;
    }

    private static boolean isTrue(Expr e) { return e instanceof Lit l && l.isInt() && l.value.signum() != 0; }

    private static boolean isBreakIf(Stmt s) {
        return s instanceof Stmt.If i && i.otherwise == null && i.then.body.size() == 1 && i.then.body.get(0) instanceof Stmt.Break;
    }

    private static Expr not(Expr cond, PassContext ctx) {
        if (cond instanceof Bin b && Typer.COMPARE.contains(b.o)) {
            Bin n = new Bin(SimplifyPass.negate(b.o), b.l, b.r);
            n.type = b.type;
            n.sgn = b.sgn;
            n.addr = b.addr;
            return n;
        }
        if (cond instanceof Un u && u.o.equals("!")) return u.e;
        Un n = new Un("!", cond);
        n.type = CType.BOOL;
        return n;
    }

    // ------------------------------------------------------------------ init; while (C) { ...; step; }

    private boolean toFor(PassContext ctx, Stmt.Block block, int at, Stmt.While w) {
        if (at == 0 || w.body.body.isEmpty() || size(w) > ctx.integer("maxBody")) return false;
        if (!(block.body.get(at - 1) instanceof Stmt.ExprStmt initStmt) || !(initStmt.e instanceof Assign init) || !init.o.equals("=")
                || !(init.l instanceof Id v) || !AstUtil.isPure(init.r)) return false;
        Stmt last = w.body.body.get(w.body.body.size() - 1);
        if (!(last instanceof Stmt.ExprStmt stepStmt) || !steps(stepStmt.e, v.name)) return false;
        if (!AstUtil.mentions(w.cond, v.name) || !AstUtil.isPure(w.cond)) return false;
        List<Stmt> rest = new ArrayList<>(w.body.body.subList(0, w.body.body.size() - 1));
        // 'continue' would skip the step in the while form but not in the for form.
        for (Stmt r : rest) if (hasContinue(r)) return false;
        // The induction variable must not also be written in the middle of the body.
        for (Stmt r : rest) if (AstUtil.assigned(r).contains(v.name)) return false;
        Expr cond = w.cond;
        if (cond instanceof Bin b && (b.o.equals("!=") || b.o.equals("==")) && b.r instanceof Id rid && rid.name.equals(v.name)
                && !AstUtil.mentions(b.l, v.name)) {
            Bin swapped = new Bin(b.o, b.r, b.l);
            swapped.type = b.type;
            swapped.sgn = b.sgn;
            swapped.addr = b.addr;
            cond = swapped;
        }
        Stmt.For loop = new Stmt.For(init, cond, stepStmt.e, new Stmt.Block(rest));
        loop.span(initStmt.addr, w.maxAddr);
        loop.span(w.addr, w.maxAddr);
        if (!ctx.accept("for-loop", List.of(initStmt, w), List.of(loop), Set.of(), Status.STRUCTURAL,
                "an initializer, a test and a trailing step are a for loop")) return false;
        block.body.set(at, loop);
        block.body.remove(at - 1);
        return true;
    }

    /** Whether {@code e} is a step of {@code name}: name = name op k, name op= k, name++ / name--. */
    private static boolean steps(Expr e, String name) {
        if (e instanceof Un u && (u.o.equals("++") || u.o.equals("--"))) return u.e instanceof Id id && id.name.equals(name);
        if (!(e instanceof Assign a) || !(a.l instanceof Id id) || !id.name.equals(name)) return false;
        if (!a.o.equals("=")) return AstUtil.isPure(a.r);
        return AstUtil.mentions(a.r, name) && AstUtil.isPure(a.r);
    }
}
