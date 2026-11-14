package decompfuncutils.refine.pass;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Folds a temporary into its single use in the statement that follows:
 * {@code t = a / 10; r = t * 3;} becomes {@code r = a / 10 * 3;}. Optimized code is full of such
 * splits, and an idiom spread over two statements cannot be recognized until it is one expression
 * again.
 */
public final class FoldTempsPass implements RefinePass {
    @Override public String id() { return "fold-temps"; }
    @Override public String title() { return "Fold single-use temporaries"; }
    @Override public String description() {
        return "Substitutes a variable assigned once and read once, in the very next statement, into that read -- "
            + "provided nothing in between can change what the expression means. Tested by running both versions.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.integer("maxSize", "Largest expression to fold (nodes)", 24, 1, 400,
                "Expressions bigger than this stay in their own statement."),
            Param.bool("namedVariables", "Also fold user-named variables", false,
                "By default only decompiler-generated temporaries (iVar1, uVar2, ...) are folded; names you gave are kept."));
    }

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        int max = ctx.integer("maxSize");
        boolean named = ctx.flag("namedVariables");
        for (Stmt.Block block : blocks) {
            for (int i = 0; i + 1 < block.body.size(); i++) {
                if (ctx.cancelled()) return changed;
                if (!(block.body.get(i) instanceof Stmt.ExprStmt def) || !(def.e instanceof Assign a) || !a.o.equals("=")
                        || !(a.l instanceof Id t) || (t.kind != Id.Kind.VAR && t.kind != Id.Kind.PARAM)) continue;
                if (!named && !isGenerated(t.name)) continue;
                CFunction.Var decl = ctx.fn.vars.get(t.name);
                if (decl == null || !decl.type.isScalarInt() || !t.type.isScalarInt()) continue;
                // Folding deletes the assignment; a stack slot something may still read must keep it.
                if (!ctx.fn.removable(t.name)) continue;
                Expr value = a.r;
                if (!AstUtil.isPure(value) || AstUtil.size(value) > max) continue;
                Stmt use = block.body.get(i + 1);
                if (!foldable(use, t.name, value)) continue;
                if (AstUtil.liveAfter(ctx.fn, use, t.name)) continue;
                Stmt replaced = use.copy();
                Expr inlined = value;
                boolean[] done = new boolean[1];
                substitute(replaced, t, inlined, done);
                if (!done[0]) continue;
                if (!ctx.accept("fold-temp", List.of(def, use), List.of(replaced), Set.of(t.name))) continue;
                block.body.set(i + 1, replaced);
                block.body.remove(i);
                changed = true;
                i = Math.max(-1, i - 2);
            }
        }
        return changed;
    }

    static boolean isGenerated(String name) {
        return name.matches("[a-z]{1,3}Var\\d+|param_\\d+|local_[0-9a-f]+|[a-z]+Stack_[0-9a-f]+|in_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|unaff_[A-Za-z0-9_]+");
    }

    /**
     * Whether {@code use} reads {@code name} exactly once, in a position reached before anything
     * in {@code use} could disturb {@code value}.
     */
    private static boolean foldable(Stmt use, String name, Expr value) {
        List<Expr> direct = use.exprs();
        if (direct.isEmpty() || use instanceof Stmt.While || use instanceof Stmt.DoWhile || use instanceof Stmt.For
                || use instanceof Stmt.CaseLabel) return false;
        int count = 0;
        for (Expr e : direct) count += occurrences(e, name);
        if (count != 1) return false;
        for (Stmt.Block b : use.blocks()) if (AstUtil.mentions(b, name)) return false;
        Expr e = direct.get(0);
        // Writes inside the using expression, other than the assignment it is, would be reordered.
        Expr body = e instanceof Assign top && top.o.equals("=") ? top.r : e;
        if (e instanceof Assign top) {
            if (!top.o.equals("=")) return false;
            if (top.l instanceof Id target && target.name.equals(name)) return false;
            // "x[t] = ..." is fine (the subscript is read before the store), a target with
            // side effects of its own is not.
            if (!(top.l instanceof Id) && !AstUtil.isPure(top.l)) return false;
            // "*(c ? p : p - 1) = 0" is no easier to read than the two statements it came from.
            if (AstUtil.mentions(top.l, name) && AstUtil.size(value) > 3) return false;
        }
        boolean memory = AstUtil.readsMemory(value);
        boolean[] bad = new boolean[1];
        AstUtil.walk(body, x -> {
            if (x instanceof Assign || (x instanceof Un u && (u.o.equals("++") || u.o.equals("--")))) bad[0] = true;
            // A call may write the memory the folded expression reads, and would now run first.
            if (memory && x instanceof Call c && !AstUtil.isPure(c)) bad[0] = true;
            // Short-circuit and ternary operands may not run at all; the temp always did.
        });
        if (bad[0]) return false;
        return !underConditional(body, name);
    }

    /** Whether the single use sits in an operand that is only conditionally evaluated. */
    private static boolean underConditional(Expr e, String name) {
        if (e instanceof Bin b && (b.o.equals("&&") || b.o.equals("||"))) {
            return AstUtil.mentions(b.r, name) || underConditional(b.l, name);
        }
        if (e instanceof Cond c) return AstUtil.mentions(c.a, name) || AstUtil.mentions(c.b, name) || underConditional(c.c, name);
        for (int i = 0; i < e.kids(); i++) if (underConditional(e.kid(i), name)) return true;
        return false;
    }

    private static int occurrences(Expr e, String name) {
        int[] n = new int[1];
        AstUtil.walk(e, x -> { if (x instanceof Id id && id.name.equals(name) && id.kind != Id.Kind.FUNC) n[0]++; });
        return n[0];
    }

    private static void substitute(Stmt s, Id target, Expr value, boolean[] done) {
        List<Expr> es = s.exprs();
        for (int i = 0; i < es.size(); i++) {
            Expr before = es.get(i);
            Expr after = AstUtil.rewrite(before, x -> {
                if (done[0] || !(x instanceof Id id) || !id.name.equals(target.name) || id.kind == Id.Kind.FUNC) return x;
                done[0] = true;
                Expr v = value.copy();
                // The temporary's type is part of the meaning: keep it when it differs.
                if (id.type.isScalarInt() && v.type.isScalarInt() && (v.type.bits != id.type.bits || v.type.signed != id.type.signed)) {
                    return new Cast(id.type, id.type.name, v);
                }
                return v;
            });
            if (after != before) s.expr(i, after);
        }
    }
}
