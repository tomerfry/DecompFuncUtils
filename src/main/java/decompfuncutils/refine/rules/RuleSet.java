package decompfuncutils.refine.rules;

import decompfuncutils.refine.ast.AstUtil;
import decompfuncutils.refine.ast.CLexer;
import decompfuncutils.refine.ast.CParser;
import decompfuncutils.refine.ast.CType;
import decompfuncutils.refine.ast.Expr;
import decompfuncutils.refine.ast.Tok;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rewrite rules parsed from text.
 *
 * <pre>
 * # comment
 * [group-name off] One-line description of the group ("off" = disabled unless switched on)
 * rule-name: pattern =&gt; replacement where guard
 * </pre>
 *
 * Patterns and replacements are C expressions. {@code $x} matches any expression,
 * {@code $c:const} only a constant, {@code $v:var} only a variable; a name used twice must match
 * the same thing both times. {@code (_)e} matches a cast to any type. The guard is an expression
 * over the constants bound by the pattern and the predicates listed in {@link RuleMatcher}. In a
 * replacement, {@code eval(expr)} is replaced by the constant it evaluates to.
 *
 * <p>A rule only proposes; the engine checks every instance before applying it, so an unsound
 * rule costs time rather than correctness.
 */
public final class RuleSet {
    /** A rule group as declared by its header. */
    public static final class Group {
        public final String name;
        public final boolean enabledByDefault;
        public final String description;
        public final List<Rule> rules = new ArrayList<>();

        Group(String name, boolean enabledByDefault, String description) {
            this.name = name;
            this.enabledByDefault = enabledByDefault;
            this.description = description;
        }
    }

    /** A line that did not parse. */
    public static final class Problem {
        public final int line;
        public final String message;

        Problem(int line, String message) { this.line = line; this.message = message; }
        @Override public String toString() { return "line " + line + ": " + message; }
    }

    public final Map<String, Group> groups = new LinkedHashMap<>();
    public final List<Problem> problems = new ArrayList<>();

    private static final Pattern HEADER = Pattern.compile("\\[\\s*([A-Za-z0-9_-]+)(\\s+(on|off))?\\s*\\]\\s*(.*)");
    private static final Pattern NAMED = Pattern.compile("([A-Za-z_][A-Za-z0-9_-]*)\\s*:(?!:)\\s*(.*)", Pattern.DOTALL);
    private static RuleSet builtin;

    /** The rules shipped with the extension. */
    public static synchronized RuleSet builtin() {
        if (builtin == null) {
            try (InputStream in = RuleSet.class.getResourceAsStream("/decompfuncutils/refine/builtin.rules")) {
                if (in == null) throw new IllegalStateException("builtin.rules is missing from the extension");
                builtin = parse(new String(in.readAllBytes(), StandardCharsets.UTF_8), "builtin");
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return builtin;
    }

    public static RuleSet parse(String text, String defaultGroup) {
        RuleSet set = new RuleSet();
        Group group = null;
        String[] lines = text.split("\\r?\\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = stripComment(lines[i]);
            if (line.isBlank()) continue;
            int at = i + 1;
            Matcher header = HEADER.matcher(line.strip());
            if (header.matches()) {
                group = set.groups.computeIfAbsent(header.group(1),
                    n -> new Group(n, !"off".equals(header.group(3)), header.group(4).strip()));
                continue;
            }
            // A rule runs on over following lines that are indented.
            StringBuilder body = new StringBuilder(line.strip());
            while (i + 1 < lines.length && !lines[i + 1].isEmpty() && Character.isWhitespace(lines[i + 1].charAt(0))
                    && !stripComment(lines[i + 1]).isBlank()) {
                body.append(' ').append(stripComment(lines[++i]).strip());
            }
            if (group == null) group = set.groups.computeIfAbsent(defaultGroup, n -> new Group(n, true, ""));
            try {
                group.rules.add(parseRule(body.toString(), group.name, at, group.rules.size()));
            } catch (RuntimeException e) {
                set.problems.add(new Problem(at, e.getMessage() == null ? e.toString() : e.getMessage()));
            }
        }
        return set;
    }

    private static String stripComment(String line) {
        int hash = line.indexOf('#');
        return hash < 0 ? line : line.substring(0, hash);
    }

    private static Rule parseRule(String text, String group, int line, int index) {
        String name = group + "-" + (index + 1);
        String body = text;
        Matcher named = NAMED.matcher(text);
        // "name: ..." -- but not a pattern that merely starts with an identifier and a ternary colon.
        if (named.matches() && named.group(2).contains("=>") && !text.substring(0, text.indexOf(':')).contains("?")) {
            name = named.group(1);
            body = named.group(2);
        }
        List<Tok> toks = CLexer.lex(body);
        int arrow = -1, where = -1, depth = 0;
        for (int i = 0; i < toks.size(); i++) {
            Tok t = toks.get(i);
            if (t.is("(") || t.is("[")) depth++;
            else if (t.is(")") || t.is("]")) depth--;
            else if (depth == 0 && arrow < 0 && t.is("=>")) arrow = i;
            else if (depth == 0 && arrow >= 0 && t.kind == Tok.Kind.ID && t.text.equals("where")) where = i;
        }
        if (arrow < 0) throw new IllegalArgumentException("Expected 'pattern => replacement'");
        int end = where < 0 ? toks.size() : where;
        Expr pattern = foldNegatives(whole(toks.subList(0, arrow), "pattern"));
        Expr replacement = foldNegatives(whole(toks.subList(arrow + 1, end), "replacement"));
        Expr guard = where < 0 ? null : foldNegatives(whole(toks.subList(where + 1, toks.size()), "guard"));
        java.util.Set<String> bound = metas(pattern);
        for (String m : metas(replacement)) {
            if (!bound.contains(m)) throw new IllegalArgumentException("$" + m + " is used in the replacement but not bound by the pattern");
        }
        if (guard != null) {
            for (String m : metas(guard)) {
                if (!bound.contains(m)) throw new IllegalArgumentException("$" + m + " is used in the guard but not bound by the pattern");
            }
        }
        if (pattern instanceof Expr.Id) throw new IllegalArgumentException("A pattern that is a lone metavariable would match everything");
        return new Rule(name, group, pattern, replacement, guard, text, line);
    }

    private static Expr whole(List<Tok> toks, String what) {
        if (toks.isEmpty()) throw new IllegalArgumentException("Empty " + what);
        CParser p = new CParser(new ArrayList<>(toks), null, 64, null);
        Expr e;
        try {
            e = p.parseExpr();
        } catch (CParser.ParseError err) {
            throw new IllegalArgumentException("In the " + what + ": " + err.getMessage());
        }
        if (!p.atEnd()) throw new IllegalArgumentException("In the " + what + ": unexpected '" + p.peek().text + "'");
        return e;
    }

    /** "-5" parses as negation of 5; make it the literal -5 so it matches a decompiler constant. */
    private static Expr foldNegatives(Expr e) {
        return AstUtil.rewrite(e, x -> {
            if (x instanceof Expr.Un u && u.o.equals("-") && u.e instanceof Expr.Lit l && l.flexible && l.isInt()) {
                Expr.Lit n = new Expr.Lit(Expr.Lit.Kind.INT, l.value.negate(), null, CType.UNKNOWN);
                n.flexible = true;
                return n;
            }
            return x;
        });
    }

    private static java.util.Set<String> metas(Expr e) {
        java.util.Set<String> out = new java.util.HashSet<>();
        AstUtil.walk(e, x -> { if (x instanceof Expr.Id id && id.kind == Expr.Id.Kind.META) out.add(id.name); });
        return out;
    }

    public int size() {
        int n = 0;
        for (Group g : groups.values()) n += g.rules.size();
        return n;
    }
}
