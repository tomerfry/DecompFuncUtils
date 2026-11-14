package decompfuncutils.refine.ast;

import decompfuncutils.refine.ast.Expr.*;
import java.util.Set;

/**
 * Types for nodes that have no p-code behind them: expressions a pass built or a rule
 * instantiated. The rules are C's usual arithmetic conversions without integer promotion, because
 * the decompiler's own output is p-code sized (an 8-bit add stays 8 bits wide).
 */
public final class Typer {
    public static final Set<String> COMPARE = Set.of("==", "!=", "<", ">", "<=", ">=");
    public static final Set<String> ORDER = Set.of("<", ">", "<=", ">=");
    public static final Set<String> LOGICAL = Set.of("&&", "||");
    public static final Set<String> COMMUTATIVE = Set.of("+", "*", "&", "|", "^", "==", "!=", "&&", "||");

    private final int pointerBits;

    public Typer(int pointerBits) { this.pointerBits = pointerBits; }

    public int pointerBits() { return pointerBits; }

    /** Common type two operands are brought to before an arithmetic or comparison operator. */
    public static CType common(CType a, CType b) {
        if (!a.isScalarInt()) return b;
        if (!b.isScalarInt()) return a;
        if (a.isPointer()) return a;
        if (b.isPointer()) return b;
        if (a.bits != b.bits) {
            CType wide = a.bits > b.bits ? a : b;
            return wide.isBool() ? CType.integer(wide.bits, false) : wide;
        }
        boolean signed = a.signed && b.signed;
        CType pick = a.isBool() ? b : a;
        if (pick.isBool()) return CType.integer(pick.bits, false);
        return pick.signed == signed ? pick : pick.withSign(signed);
    }

    /**
     * Give {@code e} and every untyped node below it a type. Nodes that already have a known type
     * (anything parsed from decompiler output) are left alone. Literals written in a rule take the
     * width of the operand they meet.
     */
    public Expr retype(Expr e) {
        for (int i = 0; i < e.kids(); i++) retype(e.kid(i));
        switch (e) {
            case Bin b -> {
                adopt(b.l, b.r);
                adopt(b.r, b.l);
                if (b.type.isKnown() && !(b.type.isBool() && !isBoolOp(b.o))) break;
                if (COMPARE.contains(b.o) || LOGICAL.contains(b.o)) {
                    b.type = CType.BOOL;
                    b.sgn = ORDER.contains(b.o) && common(b.l.type, b.r.type).signed;
                } else if (b.o.equals("<<") || b.o.equals(">>")) {
                    b.type = b.l.type.isBool() ? CType.integer(b.l.type.bits, false) : b.l.type;
                    b.sgn = b.l.type.signed;
                } else if (b.o.equals(",")) {
                    b.type = b.r.type;
                } else {
                    // Two truth values combined arithmetically: C computes that in int.
                    b.type = b.l.type.isBool() && b.r.type.isBool() ? CType.integer(32, true) : common(b.l.type, b.r.type);
                    b.sgn = b.type.signed;
                    b.scale = 0;
                    if (b.o.equals("+") || b.o.equals("-")) {
                        if (b.l.type.isPointer() && !b.r.type.isPointer()) b.scale = b.l.type.elemSize;
                        else if (b.r.type.isPointer() && !b.l.type.isPointer() && b.o.equals("+")) b.scale = b.r.type.elemSize;
                        if (b.scale == 1) b.scale = 0;
                    }
                }
            }
            case Un u -> {
                if (u.type.isKnown()) break;
                switch (u.o) {
                    case "!" -> u.type = CType.BOOL;
                    case "*" -> u.type = u.e.type.pointee != null ? u.e.type.pointee : CType.UNKNOWN;
                    case "&" -> u.type = CType.pointerTo(u.e.type, pointerBits);
                    default -> u.type = u.e.type.isBool() ? CType.integer(u.e.type.bits, false) : u.e.type;
                }
            }
            case Cond c -> {
                adopt(c.a, c.b);
                adopt(c.b, c.a);
                if (!c.type.isKnown()) c.type = common(c.a.type, c.b.type);
            }
            case Assign a -> {
                adopt(a.r, a.l);
                if (!a.type.isKnown()) a.type = a.l.type;
            }
            case Index ix -> {
                if (!ix.type.isKnown() && ix.base.type.pointee != null) ix.type = ix.base.type.pointee;
            }
            case Call c -> {
                String name = c.name();
                if (!c.type.isKnown() && name != null && c.fn instanceof Id id && id.function == null
                        && decompfuncutils.refine.sem.Builtins.isKnown(name)) {
                    c.type = decompfuncutils.refine.sem.Builtins.resultType(name, c.args, pointerBits);
                }
            }
            case Lit l -> {
                // A rule literal no operand has claimed yet: int, or long when it does not fit.
                if (!l.type.isKnown() && l.isInt()) {
                    l.type = CType.integer(l.value.bitLength() > 31 ? 64 : 32, true);
                    l.flexible = true;
                }
            }
            default -> { }
        }
        return e;
    }

    private static boolean isBoolOp(String o) { return COMPARE.contains(o) || LOGICAL.contains(o); }

    /** Let a width-less rule literal take the type of its sibling operand. */
    private static void adopt(Expr lit, Expr other) {
        if (lit instanceof Lit l && l.flexible && l.isInt() && other.type.isScalarInt()
                && !(other instanceof Lit o && o.flexible)) {
            CType t = other.type.isPointer() || other.type.isBool() ? CType.integer(other.type.bits, false) : other.type;
            l.value = l.value.mod(java.math.BigInteger.ONE.shiftLeft(t.bits));
            l.type = t;
            l.flexible = false;
        }
    }
}
