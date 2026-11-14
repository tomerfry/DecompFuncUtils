package decompfuncutils.refine.sem;

import decompfuncutils.refine.ast.CType;
import decompfuncutils.refine.ast.Expr;
import decompfuncutils.refine.ast.Typer;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Functions the engine knows the meaning of: the idiom names its rewrites introduce (abs, MIN,
 * rotl, memset, ...) and the decompiler's own pseudo-functions (CONCAT44, SUB41, ZEXT48, CARRY4,
 * ...). Knowing the meaning is what lets a rewrite that introduces one of them be proved or tested
 * rather than taken on trust.
 */
public final class Builtins {
    /** Pure functions of their arguments. */
    public static final Set<String> PURE = Set.of("abs", "MIN", "MAX", "rotl", "rotr", "bswap", "POPCOUNT", "LZCOUNT");
    /** Functions that read or write memory; the interpreter runs them, the prover does not. */
    public static final Set<String> MEMORY = Set.of("strlen", "memset", "memcpy", "memmove", "strcpy", "strncpy");
    private static final Pattern PSEUDO = Pattern.compile("(CONCAT|SUB|ZEXT|SEXT|CARRY|SCARRY|SBORROW)\\d+");

    private Builtins() {}

    public static boolean isPseudo(String name) { return name != null && PSEUDO.matcher(name).matches(); }
    public static boolean isPure(String name) { return name != null && (PURE.contains(name) || isPseudo(name)); }
    /** No side effects, though the result may depend on memory: the pure functions and strlen. */
    public static boolean isSideEffectFree(String name) { return isPure(name) || "strlen".equals(name); }
    public static boolean isKnown(String name) { return isPure(name) || (name != null && MEMORY.contains(name)); }

    private static String family(String name) {
        int i = 0;
        while (i < name.length() && !Character.isDigit(name.charAt(i))) i++;
        return name.substring(0, i);
    }

    /** Type of a call to a builtin a pass synthesized, from its argument types. */
    public static CType resultType(String name, List<Expr> args, int pointerBits) {
        switch (name) {
            case "abs", "rotl", "rotr", "bswap":
                return args.isEmpty() ? CType.UNKNOWN : plain(args.get(0).type);
            case "MIN", "MAX":
                return args.size() < 2 ? CType.UNKNOWN : plain(Typer.common(args.get(0).type, args.get(1).type));
            case "strlen":
                return CType.integer(pointerBits, false, pointerBits == 64 ? "size_t" : "uint");
            case "memset", "memcpy", "memmove", "strcpy", "strncpy":
                return CType.pointerTo(CType.VOID, pointerBits);
            case "POPCOUNT", "LZCOUNT":
                return CType.integer(32, true);
            default:
                return CType.UNKNOWN;
        }
    }

    private static CType plain(CType t) { return t.isBool() ? CType.integer(t.bits, false) : t; }

    /**
     * Evaluate a pure builtin. {@code args} are the argument values at the widths of
     * {@code types}; the result is reduced to {@code bits}.
     */
    public static BigInteger eval(String name, List<BigInteger> args, List<CType> types, int bits) {
        BigInteger a = args.isEmpty() ? BigInteger.ZERO : args.get(0);
        CType ta = types.isEmpty() ? CType.UNKNOWN : types.get(0);
        switch (name) {
            case "abs": {
                BigInteger s = CEval.signed(a, ta.bits);
                return CEval.mask(CEval.convert(CEval.mask(s.abs(), ta.bits), ta, bits), bits);
            }
            case "MIN", "MAX": {
                CType common = Typer.common(ta, types.get(1));
                BigInteger x = CEval.convert(a, ta, common.bits), y = CEval.convert(args.get(1), types.get(1), common.bits);
                boolean less = CEval.compare("<", x, y, common.bits, common.signed);
                BigInteger pick = name.equals("MIN") == less ? x : y;
                return CEval.convert(pick, common, bits);
            }
            case "rotl", "rotr": {
                int w = ta.bits;
                int n = args.get(1).mod(BigInteger.valueOf(w)).intValue();
                if (name.equals("rotr")) n = (w - n) % w;
                BigInteger r = n == 0 ? a : CEval.mask(a.shiftLeft(n), w).or(a.shiftRight(w - n));
                return CEval.mask(r, bits);
            }
            case "bswap": {
                BigInteger r = BigInteger.ZERO;
                for (int i = 0; i < ta.bits / 8; i++) r = r.shiftLeft(8).or(a.shiftRight(8 * i).and(BigInteger.valueOf(0xff)));
                return CEval.mask(r, bits);
            }
            case "POPCOUNT": return BigInteger.valueOf(a.bitCount());
            case "LZCOUNT": return BigInteger.valueOf(ta.bits - a.bitLength());
            default: break;
        }
        switch (family(name)) {
            case "CONCAT": return CEval.mask(a.shiftLeft(types.get(1).bits).or(args.get(1)), bits);
            case "SUB": return CEval.mask(a.shiftRight(8 * args.get(1).intValueExact()), bits);
            case "ZEXT": return CEval.mask(a, bits);
            case "SEXT": return CEval.mask(CEval.signed(a, ta.bits), bits);
            case "CARRY": return a.add(args.get(1)).bitLength() > ta.bits ? BigInteger.ONE : BigInteger.ZERO;
            case "SCARRY": {
                BigInteger s = CEval.signed(a, ta.bits).add(CEval.signed(args.get(1), ta.bits));
                return fits(s, ta.bits) ? BigInteger.ZERO : BigInteger.ONE;
            }
            case "SBORROW": {
                BigInteger s = CEval.signed(a, ta.bits).subtract(CEval.signed(args.get(1), ta.bits));
                return fits(s, ta.bits) ? BigInteger.ZERO : BigInteger.ONE;
            }
            default: throw new UnsupportedOperationException("No model for " + name);
        }
    }

    private static boolean fits(BigInteger signedValue, int bits) {
        BigInteger half = BigInteger.ONE.shiftLeft(bits - 1);
        return signedValue.compareTo(half) < 0 && signedValue.compareTo(half.negate()) >= 0;
    }
}
