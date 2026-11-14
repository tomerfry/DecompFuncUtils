package decompfuncutils.refine.rules;

import decompfuncutils.refine.ast.Expr;

/** One rewrite rule: where {@code pattern} matches and {@code guard} holds, write {@code replacement}. */
public final class Rule {
    public final String name;
    public final String group;
    public final Expr pattern;
    public final Expr replacement;
    /** Null when the rule has no "where" clause. */
    public final Expr guard;
    /** The rule as written, for messages. */
    public final String source;
    public final int line;

    public Rule(String name, String group, Expr pattern, Expr replacement, Expr guard, String source, int line) {
        this.name = name;
        this.group = group;
        this.pattern = pattern;
        this.replacement = replacement;
        this.guard = guard;
        this.source = source;
        this.line = line;
    }
}
