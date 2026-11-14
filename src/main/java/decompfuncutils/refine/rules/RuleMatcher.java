package decompfuncutils.refine.rules;

import decompfuncutils.refine.ast.AstUtil;
import decompfuncutils.refine.ast.CType;
import decompfuncutils.refine.ast.Expr;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.ast.Typer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Matches rule patterns against expressions and builds replacements.
 *
 * <p>Matching is structural, with the leeway a reader would expect: the operands of commutative
 * operators may appear in either order, and {@code a < b} also matches {@code b > a}.
 *
 * <p>Guard vocabulary (also available inside {@code eval(...)}): integer arithmetic and
 * comparisons on bound constants, plus
 * <ul>
 * <li>{@code bits($x)} -- width of what $x matched;</li>
 * <li>{@code signed($x)}, {@code unsigned($x)}, {@code is_ptr($x)}, {@code is_const($x)}, {@code pure($x)};</li>
 * <li>{@code sval($c)} -- a bound constant read as signed;</li>
 * <li>{@code is_pow2(n)}, {@code log2(n)}, {@code mask(n)} = 2^n - 1;</li>
 * <li>{@code signed_op()}, {@code unsigned_op()} -- whether the matched root is the signed machine
 *     operation (for / % &gt;&gt; and ordering comparisons).</li>
 * </ul>
 */
public final class RuleMatcher {
    private RuleMatcher() {}

    /** Bindings for {@code rule} at {@code subject}, or null when it does not apply there. */
    public static Map<String, Expr> match(Rule rule, Expr subject) {
        Map<String, Expr> b = new HashMap<>();
        if (!match(rule.pattern, subject, b)) return null;
        if (rule.guard != null) {
            try {
                if (guard(rule.guard, b, subject).signum() == 0) return null;
            } catch (RuntimeException e) {
                return null;
            }
        }
        return b;
    }

    private static boolean match(Expr p, Expr s, Map<String, Expr> b) {
        if (p instanceof Id id && id.kind == Id.Kind.META) {
            Expr bound = b.get(id.name);
            if (bound != null) return AstUtil.same(bound, s);
            if ("const".equals(id.metaKind) && !(s instanceof Lit l && l.isInt())) return false;
            if ("var".equals(id.metaKind) && !(s instanceof Id v && v.kind != Id.Kind.FUNC)) return false;
            b.put(id.name, s);
            return true;
        }
        switch (p) {
            case Lit pl -> {
                if (!(s instanceof Lit sl) || !pl.isInt() || !sl.isInt()) {
                    return s instanceof Lit sl2 && !pl.isInt() && !sl2.isInt() && String.valueOf(pl.text).equals(sl2.text);
                }
                int bits = sl.type.bits == 0 ? 64 : sl.type.bits;
                return pl.value.mod(BigInteger.ONE.shiftLeft(bits)).equals(sl.value.mod(BigInteger.ONE.shiftLeft(bits)));
            }
            case Id pid -> { return s instanceof Id sid && pid.name.equals(sid.name); }
            case Un pu -> {
                return s instanceof Un su && pu.o.equals(su.o) && pu.postfix == su.postfix && match(pu.e, su.e, b);
            }
            case Bin pb -> {
                if (!(s instanceof Bin sb)) return false;
                if (pb.o.equals(sb.o)) {
                    Map<String, Expr> saved = new HashMap<>(b);
                    if (match(pb.l, sb.l, b) && match(pb.r, sb.r, b)) return true;
                    restore(b, saved);
                    if (Typer.COMMUTATIVE.contains(pb.o) && sb.scale == 0) {
                        if (match(pb.l, sb.r, b) && match(pb.r, sb.l, b)) return true;
                        restore(b, saved);
                    }
                    return false;
                }
                String flipped = flip(sb.o);
                if (flipped != null && pb.o.equals(flipped)) {
                    Map<String, Expr> saved = new HashMap<>(b);
                    if (match(pb.l, sb.r, b) && match(pb.r, sb.l, b)) return true;
                    restore(b, saved);
                }
                return false;
            }
            case Cond pc -> {
                return s instanceof Cond sc && match(pc.c, sc.c, b) && match(pc.a, sc.a, b) && match(pc.b, sc.b, b);
            }
            case Cast pc -> {
                if (!(s instanceof Cast sc)) return false;
                boolean any = !pc.type.isKnown() && pc.type.kind != CType.Kind.VOID;
                if (!any && (pc.type.bits != sc.type.bits || pc.type.signed != sc.type.signed || pc.type.isPointer() != sc.type.isPointer())) return false;
                return match(pc.e, sc.e, b);
            }
            case Call pc -> {
                if (!(s instanceof Call sc) || pc.args.size() != sc.args.size() || !match(pc.fn, sc.fn, b)) return false;
                for (int i = 0; i < pc.args.size(); i++) if (!match(pc.args.get(i), sc.args.get(i), b)) return false;
                return true;
            }
            case Index pi -> { return s instanceof Index si && match(pi.base, si.base, b) && match(pi.index, si.index, b); }
            case Member pm -> {
                return s instanceof Member sm && pm.field.equals(sm.field) && pm.arrow == sm.arrow && match(pm.base, sm.base, b);
            }
            case Assign pa -> { return s instanceof Assign sa && pa.o.equals(sa.o) && match(pa.l, sa.l, b) && match(pa.r, sa.r, b); }
            default -> { return false; }
        }
    }

    private static void restore(Map<String, Expr> b, Map<String, Expr> saved) {
        b.clear();
        b.putAll(saved);
    }

    public static String flip(String o) {
        return switch (o) {
            case "<" -> ">";
            case ">" -> "<";
            case "<=" -> ">=";
            case ">=" -> "<=";
            default -> null;
        };
    }

    // ------------------------------------------------------------------ guards

    private static BigInteger truth(boolean b) { return b ? BigInteger.ONE : BigInteger.ZERO; }

    /** Evaluate a guard (or an eval(...) body) over unbounded integers. */
    static BigInteger guard(Expr g, Map<String, Expr> b, Expr root) {
        switch (g) {
            case Lit l -> {
                if (!l.isInt()) throw new IllegalArgumentException("non-integer literal in guard");
                return l.value;
            }
            case Id id -> {
                Expr bound = id.kind == Id.Kind.META ? b.get(id.name) : null;
                if (bound instanceof Lit l && l.isInt()) return l.value;
                throw new IllegalArgumentException("$" + id.name + " is not a constant");
            }
            case Un u -> {
                BigInteger v = guard(u.e, b, root);
                return switch (u.o) {
                    case "-" -> v.negate();
                    case "~" -> v.not();
                    case "!" -> truth(v.signum() == 0);
                    default -> throw new IllegalArgumentException("operator " + u.o + " in guard");
                };
            }
            case Bin bin -> {
                if (bin.o.equals("&&")) return truth(guard(bin.l, b, root).signum() != 0 && guard(bin.r, b, root).signum() != 0);
                if (bin.o.equals("||")) return truth(guard(bin.l, b, root).signum() != 0 || guard(bin.r, b, root).signum() != 0);
                BigInteger x = guard(bin.l, b, root), y = guard(bin.r, b, root);
                return switch (bin.o) {
                    case "+" -> x.add(y);
                    case "-" -> x.subtract(y);
                    case "*" -> x.multiply(y);
                    case "/" -> x.divide(y);
                    case "%" -> x.mod(y);
                    case "&" -> x.and(y);
                    case "|" -> x.or(y);
                    case "^" -> x.xor(y);
                    case "<<" -> x.shiftLeft(y.intValueExact());
                    case ">>" -> x.shiftRight(y.intValueExact());
                    case "==" -> truth(x.equals(y));
                    case "!=" -> truth(!x.equals(y));
                    case "<" -> truth(x.compareTo(y) < 0);
                    case "<=" -> truth(x.compareTo(y) <= 0);
                    case ">" -> truth(x.compareTo(y) > 0);
                    case ">=" -> truth(x.compareTo(y) >= 0);
                    default -> throw new IllegalArgumentException("operator " + bin.o + " in guard");
                };
            }
            case Cond c -> { return guard(c.c, b, root).signum() != 0 ? guard(c.a, b, root) : guard(c.b, b, root); }
            case Call c -> {
                String name = c.name();
                if (name == null) throw new IllegalArgumentException("call in guard");
                Expr arg = c.args.isEmpty() ? null : operand(c.args.get(0), b);
                switch (name) {
                    case "bits": return BigInteger.valueOf(arg.type.bits);
                    case "signed": return truth(arg.type.kind == CType.Kind.INT && arg.type.signed);
                    case "unsigned": return truth(arg.type.isScalarInt() && !(arg.type.kind == CType.Kind.INT && arg.type.signed));
                    case "is_ptr": return truth(arg.type.isPointer());
                    case "is_const": return truth(arg instanceof Lit l && l.isInt());
                    case "pure": return truth(AstUtil.isPure(arg));
                    case "sval": {
                        if (!(arg instanceof Lit l) || !l.isInt()) throw new IllegalArgumentException("sval of a non-constant");
                        return l.type.isKnown() ? decompfuncutils.refine.sem.CEval.signed(l.value, l.type.bits) : l.value;
                    }
                    case "is_pow2": {
                        BigInteger v = guard(c.args.get(0), b, root);
                        return truth(v.signum() > 0 && v.bitCount() == 1);
                    }
                    case "log2": {
                        BigInteger v = guard(c.args.get(0), b, root);
                        if (v.signum() <= 0) throw new IllegalArgumentException("log2 of a non-positive value");
                        return BigInteger.valueOf(v.bitLength() - 1);
                    }
                    case "mask": return BigInteger.ONE.shiftLeft(guard(c.args.get(0), b, root).intValueExact()).subtract(BigInteger.ONE);
                    case "signed_op": return truth(root instanceof Bin rb && rb.sgn);
                    case "unsigned_op": return truth(root instanceof Bin rb && !rb.sgn);
                    case "eval": return guard(c.args.get(0), b, root);
                    default: throw new IllegalArgumentException("unknown guard function " + name);
                }
            }
            default -> throw new IllegalArgumentException("unsupported guard expression");
        }
    }

    /** What a predicate argument refers to: the expression a metavariable matched, else itself. */
    private static Expr operand(Expr e, Map<String, Expr> b) {
        if (e instanceof Id id && id.kind == Id.Kind.META) {
            Expr bound = b.get(id.name);
            if (bound == null) throw new IllegalArgumentException("$" + id.name + " is not bound");
            return bound;
        }
        return e;
    }

    // ------------------------------------------------------------------ replacement

    /**
     * Build the replacement for a match. The result is freshly typed from the matched operands,
     * so the same rule yields 32-bit arithmetic on 32-bit operands and 64-bit on 64-bit ones.
     */
    public static Expr instantiate(Rule rule, Map<String, Expr> b, Expr subject, Typer typer) {
        Expr out = build(rule.replacement, b, subject, typer);
        return typer.retype(out);
    }

    private static Expr build(Expr t, Map<String, Expr> b, Expr root, Typer typer) {
        switch (t) {
            case Id id -> {
                if (id.kind != Id.Kind.META) return id.copy();
                Expr bound = b.get(id.name).copy();
                return bound;
            }
            case Lit l -> {
                Lit c = (Lit) l.copy();
                if (c.flexible) c.type = CType.UNKNOWN;
                return c;
            }
            case Call c -> {
                String name = c.name();
                if ("eval".equals(name) && c.args.size() == 1) {
                    Lit lit = new Lit(Lit.Kind.INT, guard(c.args.get(0), b, root), null, CType.UNKNOWN);
                    lit.flexible = true;
                    return lit;
                }
                if (("as_unsigned".equals(name) || "as_signed".equals(name)) && c.args.size() == 1) {
                    Expr inner = typer.retype(build(c.args.get(0), b, root, typer));
                    boolean want = name.equals("as_signed");
                    if (inner.type.kind != CType.Kind.INT || inner.type.signed == want) return inner;
                    CType to = CType.integer(inner.type.bits, want);
                    return new Cast(to, to.name, inner);
                }
                List<Expr> args = new ArrayList<>();
                for (Expr a : c.args) args.add(build(a, b, root, typer));
                return new Call(build(c.fn, b, root, typer), args);
            }
            case Un u -> { return new Un(u.o, build(u.e, b, root, typer), u.postfix); }
            case Bin bin -> { return new Bin(bin.o, build(bin.l, b, root, typer), build(bin.r, b, root, typer)); }
            case Cond c -> { return new Cond(build(c.c, b, root, typer), build(c.a, b, root, typer), build(c.b, b, root, typer)); }
            case Cast c -> { return new Cast(c.type, c.text, build(c.e, b, root, typer)); }
            case Index ix -> { return new Index(build(ix.base, b, root, typer), build(ix.index, b, root, typer)); }
            case Member m -> {
                Member n = new Member(build(m.base, b, root, typer), m.field, m.arrow);
                n.offset = m.offset;
                n.type = m.type;
                return n;
            }
            case Assign a -> { return new Assign(a.o, build(a.l, b, root, typer), build(a.r, b, root, typer)); }
            default -> { return t.copy(); }
        }
    }
}
