package decompfuncutils.refine.pass;

import decompfuncutils.refine.RefineEngine;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.rules.Rule;
import decompfuncutils.refine.rules.RuleMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Finds helper functions the compiler inlined, and puts the call back.
 *
 * <p>Every small function of the program is refined the same way as the function being viewed and
 * reduced, where possible, to a single returned expression over its parameters. That expression is
 * then a pattern: wherever it occurs in this function with other operands in the parameters'
 * places, the code is that helper's body, inlined. Because both sides went through the same
 * rewrites, a helper matches even though the optimizer mangled each copy differently -- as long as
 * it mangled them into the same idiom. The interpreter then runs the original expression against
 * a real call of the helper before the call is written.
 */
public final class InlinePass implements RefinePass {
    @Override public String id() { return "inline"; }
    @Override public String title() { return "Recover inlined helper functions"; }
    @Override public String description() {
        return "Matches expressions against the bodies of the program's small functions and replaces a match with a call to the "
            + "function. The match is confirmed by evaluating the expression and the call on the same inputs.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.integer("minSize", "Smallest body worth matching (nodes)", 6, 3, 200,
                "Bodies smaller than this, such as 'a + b', would match all over the place."),
            Param.integer("maxCalleeBytes", "Largest candidate function (bytes of code)", 160, 8, 4096,
                "Functions bigger than this are unlikely to have been inlined whole."),
            Param.integer("maxCandidates", "Most candidate functions to consider", 300, 1, 5000,
                "Candidates are decompiled once per program and configuration; a large number makes the first run slow."));
    }

    @Override public boolean run(PassContext ctx) {
        List<RefineEngine.Helper> helpers = ctx.engine.helpers(ctx.fn.function, ctx.config,
            ctx.integer("maxCalleeBytes"), ctx.integer("maxCandidates"), ctx.integer("minSize"), ctx.monitor);
        if (helpers.isEmpty()) return false;
        boolean[] changed = new boolean[1];
        AstUtil.walk(ctx.fn.body, s -> {
            List<Expr> es = s.exprs();
            for (int i = 0; i < es.size(); i++) {
                Expr before = es.get(i);
                Expr after = apply(before, null, s, helpers, ctx, changed);
                if (after != before) s.expr(i, after);
            }
        });
        return changed[0];
    }

    private Expr apply(Expr e, Expr parent, Stmt holder, List<RefineEngine.Helper> helpers, PassContext ctx, boolean[] changed) {
        for (int i = 0; i < e.kids(); i++) {
            Expr k = e.kid(i);
            Expr r = apply(k, e, holder, helpers, ctx, changed);
            if (r != k) e.kid(i, r);
        }
        if (ctx.cancelled() || e instanceof Id || e instanceof Lit) return e;
        for (RefineEngine.Helper h : helpers) {
            if (AstUtil.size(e) < h.size) continue;
            Rule rule = h.rule;
            Map<String, Expr> b = RuleMatcher.match(rule, e);
            if (b == null) continue;
            List<Expr> args = new ArrayList<>();
            boolean pure = true;
            for (String p : h.params) {
                Expr bound = b.get(p);
                if (bound == null) { args = null; break; }
                pure &= AstUtil.isPure(bound);
                args.add(bound.copy());
            }
            // An argument with side effects is evaluated once by a call, but possibly several
            // times, or in another order, by the inlined body.
            if (args == null || !pure) continue;
            Id callee = new Id(h.function.getName(), Id.Kind.FUNC);
            callee.function = h.function;
            callee.type = h.returnType;
            Call call = new Call(callee, args);
            call.type = h.returnType;
            call.pure = true;
            Expr ok = ctx.accept("inlined " + h.function.getName(), e, call);
            if (ok == null) continue;
            changed[0] = true;
            return RulesPass.dropNeutralCast(ok, parent, holder, ctx.fn);
        }
        return e;
    }
}
