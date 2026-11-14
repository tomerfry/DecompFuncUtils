package decompfuncutils.refine.ast;

import decompfuncutils.refine.ast.Expr.*;
import ghidra.program.model.address.Address;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Prints the refinement AST back to C in the decompiler's layout. Besides the text it records
 * where each syntactic class and each rewritten subtree landed, and which machine address each
 * line belongs to, so a view can colour the text, mark what changed and follow the listing.
 */
public final class CPrinter {
    public static final class Options {
        /** Parenthesize shifts and arithmetic inside bitwise operators even where C does not need it. */
        public boolean clarifyParens = true;
        /** How literals a pass computed are written: "auto", "hex" or "dec". */
        public String literals = "auto";
        public int indent = 2;
        /** Leave out declarations of locals the body no longer mentions. */
        public boolean dropUnusedLocals = true;
    }

    /** A stretch of the printed text. {@code kind} is a syntax class or "rewrite". */
    public static final class Span {
        public final int start, end;
        public final String kind;
        public final Object note;

        Span(int start, int end, String kind, Object note) { this.start = start; this.end = end; this.kind = kind; this.note = note; }
    }

    public static final class Printed {
        public String text;
        public final List<Span> spans = new ArrayList<>();
        /** Machine address of each line (index = line number from 0), null where there is none. */
        public final List<Address> lineAddress = new ArrayList<>();
    }

    private static final Map<String, Integer> PREC = Map.ofEntries(
        Map.entry(",", 0), Map.entry("||", 3), Map.entry("&&", 4), Map.entry("|", 5), Map.entry("^", 6),
        Map.entry("&", 7), Map.entry("==", 8), Map.entry("!=", 8), Map.entry("<", 9), Map.entry(">", 9),
        Map.entry("<=", 9), Map.entry(">=", 9), Map.entry("<<", 10), Map.entry(">>", 10), Map.entry("+", 11),
        Map.entry("-", 11), Map.entry("*", 12), Map.entry("/", 12), Map.entry("%", 12));
    private static final int P_ASSIGN = 1, P_COND = 2, P_UNARY = 13, P_POSTFIX = 14;
    private static final Set<String> BITWISE = Set.of("|", "^", "&");
    private static final Set<String> SHIFT = Set.of("<<", ">>");
    private static final Set<String> ARITH = Set.of("+", "-", "*", "/", "%");

    private final Options options;
    private final StringBuilder out = new StringBuilder();
    private final Printed printed = new Printed();
    private int depth;
    private Address lineAddr;

    public CPrinter(Options options) { this.options = options == null ? new Options() : options; }

    /** Print one expression with default options; used for log messages, keys and tests. */
    public static String text(Expr e) {
        CPrinter p = new CPrinter(null);
        p.expr(e, 0);
        return p.out.toString();
    }

    /** Print one statement (and what it contains) with default options. */
    public static String text(Stmt s) {
        CPrinter p = new CPrinter(null);
        p.stmt(s);
        return p.out.toString().strip();
    }

    public Printed print(CFunction f) {
        for (String c : f.header) { out.append(c); newline(null); }
        if (!f.header.isEmpty()) newline(null);
        if (f.prototype != null) {
            span("prototype", null, () -> out.append(f.prototype));
            newline(f.function == null ? null : f.function.getEntryPoint());
            newline(null);
        }
        out.append('{');
        newline(null);
        depth++;
        Set<String> used = new HashSet<>();
        collectNames(f.body, used);
        boolean any = false;
        for (CFunction.Var v : f.locals) {
            if (v.dropped || (options.dropUnusedLocals && !used.contains(v.name))) continue;
            indent();
            span("declaration", null, () -> out.append(v.text).append(';'));
            newline(null);
            any = true;
        }
        if (any) { indent(); newline(null); }
        for (Stmt s : f.body.body) stmt(s);
        depth--;
        out.append('}');
        newline(null);
        printed.text = out.toString();
        return printed;
    }

    private static void collectNames(Stmt s, Set<String> used) {
        for (Expr e : s.exprs()) collectNames(e, used);
        if (s instanceof Stmt.Block b) for (Stmt c : b.body) collectNames(c, used);
        for (Stmt.Block b : s.blocks()) collectNames(b, used);
        if (s instanceof Stmt.Raw raw) {
            // Raw text is opaque: any identifier-looking word in it may be a variable.
            for (String line : raw.lines) for (String w : line.split("[^A-Za-z0-9_]+")) used.add(w);
        }
    }

    private static void collectNames(Expr e, Set<String> used) {
        if (e instanceof Id id) used.add(id.name);
        if (e instanceof Expr.Raw raw) for (String w : raw.text.split("[^A-Za-z0-9_]+")) used.add(w);
        for (int i = 0; i < e.kids(); i++) collectNames(e.kid(i), used);
    }

    // ------------------------------------------------------------------ layout

    private void indent() { out.append(" ".repeat(depth * options.indent)); }

    private void newline(Address addr) {
        printed.lineAddress.add(addr != null ? addr : lineAddr);
        lineAddr = null;
        out.append('\n');
    }

    private void span(String kind, Object note, Runnable body) {
        int start = out.length();
        body.run();
        if (out.length() > start) printed.spans.add(new Span(start, out.length(), kind, note));
    }

    private void word(String kind, String text) { span(kind, null, () -> out.append(text)); }

    // ------------------------------------------------------------------ statements

    private void stmt(Stmt s) {
        if (s.note != null) {
            int start = out.length();
            stmtBody(s);
            int end = out.length();
            while (end > start && Character.isWhitespace(out.charAt(end - 1))) end--;
            int from = start;
            while (from < end && out.charAt(from) == ' ') from++;
            printed.spans.add(new Span(from, end, "rewrite", s.note));
        } else stmtBody(s);
    }

    private void block(Stmt.Block b) {
        out.append('{');
        newline(null);
        depth++;
        for (Stmt s : b.body) stmt(s);
        depth--;
        indent();
        out.append('}');
    }

    private void stmtBody(Stmt s) {
        if (s.addr != null) lineAddr = s.addr;
        switch (s) {
            case Stmt.Block b -> {
                indent();
                block(b);
                newline(null);
            }
            case Stmt.ExprStmt e -> {
                indent();
                if (lineAddr == null) lineAddr = e.e.addr;
                expr(e.e, 0);
                out.append(';');
                newline(null);
            }
            case Stmt.If i -> {
                indent();
                ifChain(i);
                newline(null);
            }
            case Stmt.While w -> {
                indent();
                word("keyword", "while");
                out.append(" (");
                expr(w.cond, 0);
                out.append(") ");
                block(w.body);
                newline(null);
            }
            case Stmt.DoWhile d -> {
                indent();
                word("keyword", "do");
                out.append(' ');
                block(d.body);
                out.append(' ');
                word("keyword", "while");
                out.append(" (");
                expr(d.cond, 0);
                out.append(");");
                newline(null);
            }
            case Stmt.For f -> {
                indent();
                word("keyword", "for");
                out.append(" (");
                if (f.init != null) expr(f.init, 0);
                out.append("; ");
                if (f.cond != null) expr(f.cond, 0);
                out.append("; ");
                if (f.step != null) expr(f.step, 0);
                out.append(") ");
                block(f.body);
                newline(null);
            }
            case Stmt.Switch sw -> {
                indent();
                word("keyword", "switch");
                out.append(" (");
                expr(sw.e, 0);
                out.append(") ");
                block(sw.body);
                newline(null);
            }
            case Stmt.CaseLabel c -> {
                depth--;
                indent();
                depth++;
                if (c.value == null) word("keyword", "default");
                else {
                    word("keyword", "case");
                    out.append(' ');
                    expr(c.value, 0);
                }
                out.append(':');
                newline(null);
            }
            case Stmt.Return r -> {
                indent();
                word("keyword", "return");
                if (r.e != null) {
                    out.append(' ');
                    expr(r.e, 0);
                }
                out.append(';');
                newline(null);
            }
            case Stmt.Break b -> { indent(); word("keyword", "break"); out.append(';'); newline(null); }
            case Stmt.Continue c -> { indent(); word("keyword", "continue"); out.append(';'); newline(null); }
            case Stmt.Goto g -> {
                indent();
                word("keyword", "goto");
                out.append(' ').append(g.label).append(';');
                newline(null);
            }
            case Stmt.Label l -> { out.append(l.name).append(':'); newline(null); }
            case Stmt.Comment c -> { indent(); word("comment", c.text); newline(null); }
            case Stmt.Raw raw -> {
                for (String line : raw.lines) { indent(); out.append(line); newline(null); }
            }
            default -> throw new IllegalStateException("Unknown statement " + s.getClass());
        }
    }

    private void ifChain(Stmt.If i) {
        word("keyword", "if");
        out.append(" (");
        expr(i.cond, 0);
        out.append(") ");
        if (i.otherwise == null && i.then.body.size() == 1 && i.then.body.get(0).note == null
                && (i.then.body.get(0) instanceof Stmt.Break || i.then.body.get(0) instanceof Stmt.Continue
                    || i.then.body.get(0) instanceof Stmt.Goto)) {
            // "if (c) break;" stays on one line, as the decompiler prints it.
            Stmt only = i.then.body.get(0);
            if (only instanceof Stmt.Goto g) {
                word("keyword", "goto");
                out.append(' ').append(g.label).append(';');
            } else {
                word("keyword", only instanceof Stmt.Break ? "break" : "continue");
                out.append(';');
            }
            return;
        }
        block(i.then);
        if (i.otherwise == null) return;
        newline(null);
        indent();
        word("keyword", "else");
        out.append(' ');
        if (i.otherwise.body.size() == 1 && i.otherwise.body.get(0) instanceof Stmt.If nested && nested.note == null) {
            ifChain(nested);
        } else block(i.otherwise);
    }

    // ------------------------------------------------------------------ expressions

    private static int prec(Expr e) {
        return switch (e) {
            case Bin b -> PREC.getOrDefault(b.o, 11);
            case Assign a -> P_ASSIGN;
            case Cond c -> P_COND;
            case Un u -> u.postfix ? P_POSTFIX : P_UNARY;
            case Cast c -> P_UNARY;
            default -> 15;
        };
    }

    private void expr(Expr e, int min) {
        if (e.note != null) {
            int start = out.length();
            exprBody(e, min);
            printed.spans.add(new Span(start, out.length(), "rewrite", e.note));
        } else exprBody(e, min);
    }

    private void exprBody(Expr e, int min) {
        boolean paren = prec(e) < min;
        if (paren) out.append('(');
        switch (e) {
            case Id id -> word(switch (id.kind) {
                case FUNC -> "function";
                case PARAM -> "parameter";
                case GLOBAL -> "global";
                case META -> "meta";
                default -> "variable";
            }, id.kind == Id.Kind.META ? "$" + id.name : id.name);
            case Lit l -> word("constant", literal(l));
            case Un u -> {
                if (u.postfix) {
                    expr(u.e, P_POSTFIX);
                    out.append(u.o);
                } else {
                    out.append(u.o);
                    int at = out.length();
                    expr(u.e, P_UNARY);
                    // "- -x" and "& &x" must not fuse into another operator.
                    if (out.length() > at && out.charAt(at) == u.o.charAt(0) && (u.o.equals("-") || u.o.equals("&") || u.o.equals("+"))) {
                        out.insert(at, ' ');
                        shiftSpans(at);
                    }
                }
            }
            case Bin b -> {
                int p = prec(b);
                operand(b, b.l, p);
                out.append(b.o.equals(",") ? ", " : " " + b.o + " ");
                operand(b, b.r, p + 1);
            }
            case Assign a -> {
                expr(a.l, P_COND);
                out.append(' ').append(a.o).append(' ');
                expr(a.r, P_ASSIGN);
            }
            case Cond c -> {
                expr(c.c, P_COND + 1);
                out.append(" ? ");
                expr(c.a, P_ASSIGN);
                out.append(" : ");
                expr(c.b, P_COND);
            }
            case Call c -> {
                if (c.fn instanceof Id) expr(c.fn, 0);
                else {
                    out.append('(');
                    expr(c.fn, 0);
                    out.append(')');
                }
                out.append('(');
                for (int i = 0; i < c.args.size(); i++) {
                    if (i > 0) out.append(", ");
                    expr(c.args.get(i), P_ASSIGN);
                }
                out.append(')');
            }
            case Cast c -> {
                out.append('(');
                word("type", c.text);
                out.append(')');
                expr(c.e, P_UNARY);
            }
            case Index ix -> {
                expr(ix.base, P_POSTFIX);
                out.append('[');
                expr(ix.index, 0);
                out.append(']');
            }
            case Member m -> {
                expr(m.base, P_POSTFIX);
                out.append(m.arrow ? "->" : ".").append(m.field);
            }
            case Expr.Raw raw -> out.append(raw.text);
            default -> throw new IllegalStateException("Unknown expression " + e.getClass());
        }
        if (paren) out.append(')');
    }

    private void shiftSpans(int at) {
        for (int i = printed.spans.size() - 1; i >= 0; i--) {
            Span s = printed.spans.get(i);
            if (s.end <= at) break;
            printed.spans.set(i, new Span(s.start >= at ? s.start + 1 : s.start, s.end + 1, s.kind, s.note));
        }
    }

    private void operand(Bin parent, Expr child, int min) {
        boolean clarify = false;
        // The decompiler always brackets the operands of && and ||; keep its look.
        if (Typer.LOGICAL.contains(parent.o) && child instanceof Bin lc && !lc.o.equals(parent.o)) clarify = true;
        if (options.clarifyParens && child instanceof Bin c && !c.o.equals(parent.o)) {
            if (BITWISE.contains(parent.o)) clarify = SHIFT.contains(c.o) || ARITH.contains(c.o) || BITWISE.contains(c.o);
            else if (SHIFT.contains(parent.o)) clarify = ARITH.contains(c.o) || SHIFT.contains(c.o);
            else if (parent.o.equals("||")) clarify = c.o.equals("&&");
            else if (Typer.COMPARE.contains(parent.o)) clarify = SHIFT.contains(c.o);
        }
        if (clarify && prec(child) >= min) {
            out.append('(');
            expr(child, 0);
            out.append(')');
        } else expr(child, min);
    }

    private String literal(Lit l) {
        if (l.text != null) return l.text;
        if (l.value == null) return "?";
        BigInteger v = l.type.isKnown() && !l.flexible ? l.signedValue() : l.value;
        if (l.kind == Lit.Kind.CHAR && v.signum() >= 0 && v.bitLength() <= 7) {
            int c = v.intValue();
            if (c == 0) return "'\\0'";
            if (c == '\n') return "'\\n'";
            if (c == '\t') return "'\\t'";
            if (c == '\'' || c == '\\') return "'\\" + (char) c + "'";
            if (c >= 0x20 && c < 0x7f) return "'" + (char) c + "'";
            return String.format("'\\x%02x'", c);
        }
        boolean negative = v.signum() < 0;
        BigInteger abs = v.abs();
        boolean decimal = switch (options.literals) {
            case "dec" -> true;
            case "hex" -> false;
            default -> abs.compareTo(BigInteger.valueOf(16)) < 0
                || (abs.bitLength() < 40 && abs.mod(BigInteger.valueOf(100)).signum() == 0)
                || (abs.bitLength() <= 10 && abs.mod(BigInteger.TEN).signum() == 0);
        };
        return (negative ? "-" : "") + (decimal ? abs.toString() : "0x" + abs.toString(16));
    }
}
