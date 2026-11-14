package decompfuncutils.refine.pass;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.rules.Rule;
import decompfuncutils.refine.rules.RuleMatcher;
import decompfuncutils.refine.rules.RuleSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Applies rewrite rules: the built-in groups that are switched on, then the user's own. This is
 * the engine's open end -- a new idiom is one line of rule text, and the verifier keeps a wrong
 * rule from doing damage.
 */
public final class RulesPass implements RefinePass {
    @Override public String id() { return "rules"; }
    @Override public String title() { return "Rewrite rules (idioms)"; }
    @Override public String description() {
        return "Pattern => replacement rules for what optimizers leave behind: rotates built from shifts, sign and "
            + "absolute-value tricks, division by a power of two, range checks folded into one comparison. Rule groups are "
            + "switched individually and your own rules are appended. Every match is tested and, where possible, proved.";
    }

    @Override public boolean run(PassContext ctx) {
        List<Rule> rules = active(ctx);
        if (rules.isEmpty()) return false;
        boolean[] changed = new boolean[1];
        AstUtil.walk(ctx.fn.body, s -> {
            List<Expr> es = s.exprs();
            for (int i = 0; i < es.size(); i++) {
                Expr before = es.get(i);
                Expr after = apply(before, null, s, rules, ctx, changed);
                if (after != before) s.expr(i, after);
            }
        });
        return changed[0];
    }

    /** Rules in effect for a configuration: enabled built-in groups in file order, then user rules. */
    public static List<Rule> active(PassContext ctx) {
        List<Rule> rules = new ArrayList<>();
        for (RuleSet.Group g : RuleSet.builtin().groups.values()) {
            if (ctx.config.groupEnabled(g.name, g.enabledByDefault)) rules.addAll(g.rules);
        }
        if (!ctx.config.userRules.isBlank()) {
            RuleSet user = ctx.engine.userRules(ctx.config.userRules);
            for (RuleSet.Group g : user.groups.values()) rules.addAll(g.rules);
        }
        return rules;
    }

    private Expr apply(Expr e, Expr parent, Stmt holder, List<Rule> rules, PassContext ctx, boolean[] changed) {
        for (int i = 0; i < e.kids(); i++) {
            Expr k = e.kid(i);
            Expr r = apply(k, e, holder, rules, ctx, changed);
            if (r != k) e.kid(i, r);
        }
        if (ctx.cancelled()) return e;
        for (Rule rule : rules) {
            Map<String, Expr> b = RuleMatcher.match(rule, e);
            if (b == null || !effectsPreserved(rule, b)) continue;
            Expr out;
            try {
                out = RuleMatcher.instantiate(rule, b, e, ctx.typer);
            } catch (RuntimeException ex) {
                continue;
            }
            Expr ok = ctx.accept(rule.name, e, out);
            if (ok == null) continue;
            changed[0] = true;
            return dropNeutralCast(ok, parent, holder, ctx.fn);
        }
        return e;
    }

    /** An operand with side effects must be evaluated exactly once before and after. */
    private static boolean effectsPreserved(Rule rule, Map<String, Expr> b) {
        for (Map.Entry<String, Expr> e : b.entrySet()) {
            if (AstUtil.isPure(e.getValue())) continue;
            if (count(rule.pattern, e.getKey()) != 1 || count(rule.replacement, e.getKey()) != 1) return false;
        }
        return true;
    }

    private static int count(Expr e, String meta) {
        int[] n = new int[1];
        AstUtil.walk(e, x -> { if (x instanceof Id id && id.kind == Id.Kind.META && id.name.equals(meta)) n[0]++; });
        return n[0];
    }

    private static final Set<String> SIGN_BLIND = Set.of("+", "-", "*", "&", "|", "^", "==", "!=");

    /**
     * A replacement whose signedness differs from the original's is wrapped in a cast so that
     * whatever consumes it still extends and compares it the same way. Where the consumer cannot
     * tell the difference, the cast is only noise; remove it.
     */
    static Expr dropNeutralCast(Expr e, Expr parent, Stmt holder, CFunction fn) {
        if (!(e instanceof Cast c) || c.note == null || !c.type.isScalarInt() || !c.e.type.isScalarInt()
                || c.type.bits != c.e.type.bits || c.type.isPointer() != c.e.type.isPointer()) return e;
        boolean neutral;
        if (parent == null) {
            neutral = !(holder instanceof Stmt.Return) || (fn.returnType.isScalarInt() && fn.returnType.bits == c.type.bits);
            if (holder instanceof Stmt.Switch) neutral = false;
        } else if (parent instanceof Assign a) {
            neutral = a.r == e && a.o.equals("=") && a.l.type.isScalarInt() && a.l.type.bits == c.type.bits;
        } else if (parent instanceof Bin b) {
            Expr other = b.l == e ? b.r : b.l;
            neutral = SIGN_BLIND.contains(b.o) && other.type.isScalarInt() && other.type.bits == c.type.bits
                && (Typer.COMPARE.contains(b.o) || b.type.bits == c.type.bits) && b.scale == 0;
        } else if (parent instanceof Cast outer) {
            neutral = outer.type.isScalarInt() && outer.type.bits <= c.type.bits;
        } else if (parent instanceof Un u) {
            neutral = u.o.equals("-") || u.o.equals("~") || u.o.equals("!");
        } else if (parent instanceof Cond cond) {
            neutral = cond.c == e || (cond.type.isScalarInt() && cond.type.bits == c.type.bits);
        } else neutral = false;
        if (!neutral) return e;
        c.e.note = c.note;
        if (c.e.addr == null) c.e.addr = c.addr;
        return c.e;
    }
}
