package decompfuncutils.symbolic;

import com.microsoft.z3.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

/** Fixed-width low-p-code integer semantics. No expression is silently concretized. */
public final class SymbolicArithmetic {
    private final Context ctx;

    public SymbolicArithmetic(Context ctx) { this.ctx = ctx; }

    public BitVecExpr constant(BigInteger value, int bits) {
        return ctx.mkBV(value.mod(BigInteger.ONE.shiftLeft(bits)).toString(), bits);
    }

    public BitVecExpr resize(BitVecExpr value, int bits, boolean signed) {
        int old = value.getSortSize();
        if (old == bits) return value;
        if (old > bits) return ctx.mkExtract(bits - 1, 0, value);
        return signed ? ctx.mkSignExt(bits - old, value) : ctx.mkZeroExt(bits - old, value);
    }

    public BoolExpr truth(BitVecExpr value) {
        return ctx.mkNot(ctx.mkEq(value, ctx.mkBV(0, value.getSortSize())));
    }

    private BitVecExpr bool(BoolExpr predicate, int bits) {
        return (BitVecExpr) ctx.mkITE(predicate, ctx.mkBV(1, bits), ctx.mkBV(0, bits));
    }

    public BitVecExpr apply(int opcode, int bits, BitVecExpr... in) {
        BitVecExpr a = in[0];
        BitVecExpr b = in.length > 1 ? in[1] : null;
        BitVecExpr result = switch (opcode) {
            case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT -> resize(a, bits, false);
            case PcodeOp.INT_SEXT -> resize(a, bits, true);
            case PcodeOp.INT_ADD -> ctx.mkBVAdd(a, b);
            case PcodeOp.INT_SUB -> ctx.mkBVSub(a, b);
            case PcodeOp.INT_MULT -> ctx.mkBVMul(a, b);
            case PcodeOp.INT_AND -> ctx.mkBVAND(a, b);
            case PcodeOp.INT_OR -> ctx.mkBVOR(a, b);
            case PcodeOp.INT_XOR -> ctx.mkBVXOR(a, b);
            case PcodeOp.INT_NEGATE -> ctx.mkBVNot(a);
            case PcodeOp.INT_2COMP -> ctx.mkBVNeg(a);
            case PcodeOp.INT_EQUAL -> bool(ctx.mkEq(a, b), bits);
            case PcodeOp.INT_NOTEQUAL -> bool(ctx.mkNot(ctx.mkEq(a, b)), bits);
            case PcodeOp.INT_LESS -> bool(ctx.mkBVULT(a, b), bits);
            case PcodeOp.INT_LESSEQUAL -> bool(ctx.mkBVULE(a, b), bits);
            case PcodeOp.INT_SLESS -> bool(ctx.mkBVSLT(a, b), bits);
            case PcodeOp.INT_SLESSEQUAL -> bool(ctx.mkBVSLE(a, b), bits);
            case PcodeOp.BOOL_NEGATE -> bool(ctx.mkNot(truth(a)), bits);
            case PcodeOp.BOOL_AND -> bool(ctx.mkAnd(truth(a), truth(b)), bits);
            case PcodeOp.BOOL_OR -> bool(ctx.mkOr(truth(a), truth(b)), bits);
            case PcodeOp.BOOL_XOR -> bool(ctx.mkXor(truth(a), truth(b)), bits);
            case PcodeOp.INT_CARRY -> bool(ctx.mkBVULT(ctx.mkBVAdd(a, b), a), bits);
            case PcodeOp.INT_SCARRY -> bool(ctx.mkAnd(ctx.mkEq(sign(a), sign(b)),
                ctx.mkNot(ctx.mkEq(sign(a), sign(ctx.mkBVAdd(a, b))))), bits);
            case PcodeOp.INT_SBORROW -> bool(ctx.mkAnd(ctx.mkNot(ctx.mkEq(sign(a), sign(b))),
                ctx.mkNot(ctx.mkEq(sign(a), sign(ctx.mkBVSub(a, b))))), bits);
            case PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT -> shift(opcode, a, b);
            case PcodeOp.PIECE -> ctx.mkConcat(a, b);
            case PcodeOp.SUBPIECE -> {
                if (!(b.simplify() instanceof BitVecNum n)) throw unsupported("symbolic SUBPIECE offset");
                int low = n.getBigInteger().intValueExact() * 8;
                if (low < 0 || low + bits > a.getSortSize()) throw unsupported("invalid SUBPIECE");
                yield ctx.mkExtract(low + bits - 1, low, a);
            }
            case PcodeOp.POPCOUNT -> {
                BitVecExpr sum = ctx.mkBV(0, bits);
                for (int i = 0; i < a.getSortSize(); i++) {
                    sum = ctx.mkBVAdd(sum, resize(ctx.mkExtract(i, i, a), bits, false));
                }
                yield sum;
            }
            case PcodeOp.LZCOUNT -> {
                BitVecExpr count = ctx.mkBV(a.getSortSize(), bits);
                for (int i = 0; i < a.getSortSize(); i++) {
                    count = (BitVecExpr) ctx.mkITE(ctx.mkEq(ctx.mkExtract(i, i, a), ctx.mkBV(1, 1)),
                        ctx.mkBV(a.getSortSize() - 1 - i, bits), count);
                }
                yield count;
            }
            // Division is deliberately unsupported until exceptional inputs are modeled.
            default -> throw unsupported("p-code " + PcodeOp.getMnemonic(opcode));
        };
        if (result.getSortSize() != bits) throw unsupported("unexpected operand width for " + PcodeOp.getMnemonic(opcode));
        return (BitVecExpr) result.simplify();
    }

    private BitVecExpr sign(BitVecExpr value) {
        return ctx.mkExtract(value.getSortSize() - 1, value.getSortSize() - 1, value);
    }

    private BitVecExpr shift(int op, BitVecExpr value, BitVecExpr amount) {
        // Compare before narrowing the shift count: e.g. an 8-bit value << 256 is zero.
        int wide = Math.max(value.getSortSize() + 1, amount.getSortSize());
        BoolExpr excessive = ctx.mkBVUGE(resize(amount, wide, false), ctx.mkBV(value.getSortSize(), wide));
        BitVecExpr small = resize(amount, value.getSortSize(), false);
        BitVecExpr shifted = switch (op) {
            case PcodeOp.INT_LEFT -> ctx.mkBVSHL(value, small);
            case PcodeOp.INT_RIGHT -> ctx.mkBVLSHR(value, small);
            default -> ctx.mkBVASHR(value, small);
        };
        BitVecExpr fill = op == PcodeOp.INT_SRIGHT
            ? resize(sign(value), value.getSortSize(), true) : ctx.mkBV(0, value.getSortSize());
        return (BitVecExpr) ctx.mkITE(excessive, fill, shifted);
    }

    static UnsupportedOperationException unsupported(String reason) {
        return new UnsupportedOperationException(reason);
    }
}
