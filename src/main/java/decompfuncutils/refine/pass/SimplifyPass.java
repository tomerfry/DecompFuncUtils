package decompfuncutils.refine.pass;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.rules.RuleMatcher;
import decompfuncutils.refine.sem.CEval;
import java.math.BigInteger;
import java.util.List;

/**
 * Housekeeping that makes the other passes' patterns line up and their results readable:
 * constants folded and moved to the right of comparisons, negations pushed into the comparison
 * they negate, {@code x + -1} written as {@code x - 1}.
 */
public final class SimplifyPass implements RefinePass {
    @Override public String id() { return "simplify"; }
    @Override public String title() { return "Normalize expressions"; }
    @Override public String description() {
        return "Folds constant arithmetic, writes 'x + -1' as 'x - 1', puts constants on the right of comparisons "
            + "('-1 < x' becomes 'x >= 0') and absorbs negations into comparisons. Each change is verified like any other rewrite.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.bool("constantsRight", "Constants on the right of comparisons", true,
                "Rewrite 'K < x' as 'x > K', and 'x > -1' as 'x >= 0'."),
            Param.bool("foldConstants", "Fold constant arithmetic", true, "Compute operations whose operands are all constants."));
    }

    @Override public boolean run(PassContext ctx) {
        boolean right = ctx.flag("constantsRight"), fold = ctx.flag("foldConstants");
        return AstUtil.rewriteAll(ctx.fn.body, e -> {
            Expr r = step(e, right, fold);
            if (r == null || r == e) return e;
            Expr ok = ctx.accept("normalize", e, r);
            return ok == null ? e : ok;
        });
    }

    private static Lit lit(BigInteger v, CType t) {
        CType type = t.isBool() || t.isPointer() ? CType.integer(t.bits, false) : t;
        return new Lit(Lit.Kind.INT, CEval.mask(v, type.bits), null, type);
    }

    private static boolean isInt(Expr e) { return e instanceof Lit l && l.isInt() && l.type.isScalarInt(); }

    /** One simplification step at {@code e}, or null when none applies. */
    private static Expr step(Expr e, boolean right, boolean fold) {
        switch (e) {
            case Bin b -> {
                if (fold && isInt(b.l) && isInt(b.r) && b.type.isScalarInt() && b.scale == 0) {
                    try {
                        Lit l = (Lit) b.l, r = (Lit) b.r;
                        if (Typer.COMPARE.contains(b.o)) {
                            int w = Math.max(l.type.bits, r.type.bits);
                            boolean v = CEval.compare(b.o, CEval.convert(l.value, l.type, w), CEval.convert(r.value, r.type, w), w, b.sgn);
                            return lit(v ? BigInteger.ONE : BigInteger.ZERO, CType.integer(8, false));
                        }
                        if (!Typer.LOGICAL.contains(b.o) && !b.o.equals(",")) {
                            int w = b.type.bits;
                            boolean shift = b.o.equals("<<") || b.o.equals(">>");
                            BigInteger y = shift ? r.value : CEval.convert(r.value, r.type, w);
                            return lit(CEval.binary(b.o, CEval.convert(l.value, l.type, w), y, w, b.sgn), b.type);
                        }
                    } catch (CEval.Fault | IllegalArgumentException ex) {
                        return null;
                    }
                }
                // x + -c  ->  x - c
                if ((b.o.equals("+") || b.o.equals("-")) && b.r instanceof Lit r && r.isInt() && r.type.isScalarInt()
                        && r.type.bits == b.type.bits && r.value.testBit(r.type.bits - 1) && r.kind == Lit.Kind.INT
                        && (r.type.signed || (r.text != null && r.text.startsWith("-")))) {
                    BigInteger positive = CEval.mask(r.value.negate(), r.type.bits);
                    if (positive.bitLength() < r.type.bits) {
                        Bin n = new Bin(b.o.equals("+") ? "-" : "+", b.l, lit(positive, r.type));
                        n.type = b.type;
                        n.sgn = b.sgn;
                        n.scale = b.scale;
                        return n;
                    }
                }
                if (right && Typer.COMPARE.contains(b.o) && isInt(b.l) && !isInt(b.r)) {
                    String flipped = RuleMatcher.flip(b.o);
                    Bin n = new Bin(flipped == null ? b.o : flipped, b.r, b.l);
                    n.type = b.type;
                    n.sgn = b.sgn;
                    return n;
                }
                // x > -1 (signed)  ->  x >= 0 ;  x < 1 (signed)  ->  x <= 0
                if (right && b.sgn && isInt(b.r) && b.r.type.bits > 0) {
                    Lit r = (Lit) b.r;
                    BigInteger v = CEval.signed(r.value, r.type.bits);
                    if (b.o.equals(">") && v.equals(BigInteger.ONE.negate())) return compare(">=", b, BigInteger.ZERO);
                    if (b.o.equals("<") && v.equals(BigInteger.ONE)) return compare("<=", b, BigInteger.ZERO);
                }
                return null;
            }
            case Un u -> {
                if (fold && isInt(u.e) && u.type.isScalarInt() && (u.o.equals("-") || u.o.equals("~"))) {
                    Lit l = (Lit) u.e;
                    return lit(CEval.unary(u.o, CEval.convert(l.value, l.type, u.type.bits), u.type.bits), u.type);
                }
                if (u.o.equals("!") && u.e instanceof Bin b && Typer.COMPARE.contains(b.o)) {
                    Bin n = new Bin(negate(b.o), b.l, b.r);
                    n.type = b.type;
                    n.sgn = b.sgn;
                    return n;
                }
                if (u.o.equals("!") && u.e instanceof Un inner && inner.o.equals("!") && inner.e.type.isBool()) return inner.e;
                return null;
            }
            case Cond c -> {
                // Prefer a positive, strict condition; swap the branches to pay for it.
                if (c.c instanceof Un u && u.o.equals("!")) return new Cond(u.e, c.b, c.a).typed(c.type);
                if (c.c instanceof Bin b && (b.o.equals(">=") || b.o.equals("<="))) {
                    Bin n = new Bin(negate(b.o), b.l, b.r);
                    n.type = b.type;
                    n.sgn = b.sgn;
                    return new Cond(n, c.b, c.a).typed(c.type);
                }
                return null;
            }
            case Cast c -> {
                if (fold && isInt(c.e) && c.type.isScalarInt() && !c.type.isPointer() && !c.type.isBool()) {
                    Lit l = (Lit) c.e;
                    return lit(CEval.convert(l.value, l.type, c.type.bits), c.type);
                }
                return null;
            }
            default -> { return null; }
        }
    }

    private static Expr compare(String o, Bin from, BigInteger k) {
        Bin n = new Bin(o, from.l, lit(k, from.r.type));
        n.type = from.type;
        n.sgn = from.sgn;
        return n;
    }

    static String negate(String o) {
        return switch (o) {
            case "==" -> "!=";
            case "!=" -> "==";
            case "<" -> ">=";
            case ">=" -> "<";
            case ">" -> "<=";
            case "<=" -> ">";
            default -> throw new IllegalArgumentException(o);
        };
    }
}
