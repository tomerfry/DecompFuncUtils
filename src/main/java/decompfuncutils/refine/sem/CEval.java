package decompfuncutils.refine.sem;

import decompfuncutils.refine.ast.CType;
import java.math.BigInteger;

/**
 * Fixed-width integer arithmetic as the machine does it. Values are non-negative
 * {@link BigInteger}s already reduced to their width; signedness is a property of the operation.
 */
public final class CEval {
    /** The original code would trap here (division by zero, mostly). */
    public static final class Fault extends RuntimeException {
        public Fault(String message) { super(message, null, false, false); }
    }

    private CEval() {}

    public static BigInteger mask(BigInteger v, int bits) {
        return v.signum() >= 0 && v.bitLength() <= bits ? v : v.mod(BigInteger.ONE.shiftLeft(bits));
    }

    public static BigInteger signed(BigInteger v, int bits) {
        return bits > 0 && v.testBit(bits - 1) ? v.subtract(BigInteger.ONE.shiftLeft(bits)) : v;
    }

    /** Bring a value of type {@code from} to {@code toBits}: truncate, or extend by its own signedness. */
    public static BigInteger convert(BigInteger v, CType from, int toBits) {
        if (from.bits == toBits || from.bits == 0) return mask(v, toBits);
        if (from.bits > toBits) return mask(v, toBits);
        return from.signed && from.kind == CType.Kind.INT ? mask(signed(v, from.bits), toBits) : v;
    }

    public static boolean compare(String o, BigInteger a, BigInteger b, int bits, boolean sgn) {
        if (sgn) { a = signed(a, bits); b = signed(b, bits); }
        int c = a.compareTo(b);
        return switch (o) {
            case "==" -> c == 0;
            case "!=" -> c != 0;
            case "<" -> c < 0;
            case "<=" -> c <= 0;
            case ">" -> c > 0;
            case ">=" -> c >= 0;
            default -> throw new IllegalArgumentException(o);
        };
    }

    /**
     * Arithmetic on operands already converted to {@code bits}. For shifts, {@code b} is the raw
     * unsigned shift amount; an amount of the width or more gives zero (or all sign bits), which
     * is what p-code defines and what the decompiler's output assumes.
     */
    public static BigInteger binary(String o, BigInteger a, BigInteger b, int bits, boolean sgn) {
        switch (o) {
            case "+": return mask(a.add(b), bits);
            case "-": return mask(a.subtract(b), bits);
            case "*": return mask(a.multiply(b), bits);
            case "&": return a.and(b);
            case "|": return a.or(b);
            case "^": return a.xor(b);
            case "/": case "%": {
                if (b.signum() == 0) throw new Fault("division by zero");
                if (!sgn) return o.equals("/") ? a.divide(b) : a.mod(b);
                BigInteger x = signed(a, bits), y = signed(b, bits);
                // BigInteger truncates toward zero, as the machine does.
                return mask(o.equals("/") ? x.divide(y) : x.remainder(y), bits);
            }
            case "<<": return b.bitLength() > 31 || b.intValue() >= bits ? BigInteger.ZERO : mask(a.shiftLeft(b.intValue()), bits);
            case ">>": {
                boolean big = b.bitLength() > 31 || b.intValue() >= bits;
                if (!sgn) return big ? BigInteger.ZERO : a.shiftRight(b.intValue());
                BigInteger x = signed(a, bits);
                return mask(big ? (x.signum() < 0 ? BigInteger.ONE.negate() : BigInteger.ZERO) : x.shiftRight(b.intValue()), bits);
            }
            default: throw new IllegalArgumentException("Unknown operator " + o);
        }
    }

    public static BigInteger unary(String o, BigInteger a, int bits) {
        return switch (o) {
            case "-" -> mask(a.negate(), bits);
            case "~" -> mask(a.not(), bits);
            case "!" -> a.signum() == 0 ? BigInteger.ONE : BigInteger.ZERO;
            default -> throw new IllegalArgumentException("Unknown operator " + o);
        };
    }

    /** SplitMix64: the deterministic source behind unwritten memory and stubbed calls. */
    public static long mix(long z) {
        z += 0x9e3779b97f4a7c15L;
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }
}
