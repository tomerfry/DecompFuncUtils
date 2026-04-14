package decompfuncutils.mcp.tools;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;

import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Renders a pcode Varnode as a human-readable expression using HighVariable
 * names where available, recursing through the def-use graph to a bounded depth.
 *
 * Shared by PathConstraintsTool and the symbolic-branch annotation in the emulator.
 */
public final class PcodeExpressionRenderer {

    private final Program program;
    private final int maxDepth;

    public PcodeExpressionRenderer(Program program, int maxDepth) {
        this.program = program;
        this.maxDepth = Math.max(1, maxDepth);
    }

    public String render(Varnode vn) {
        return render(vn, 0, new IdentityHashMap<>());
    }

    private String render(Varnode vn, int depth, Map<Varnode, Boolean> visiting) {
        if (vn == null) return "<null>";
        if (vn.isConstant()) return hex(vn.getOffset(), vn.getSize());

        // Prefer a named HighVariable/HighSymbol if one exists.
        String named = tryName(vn);
        if (named != null) return named;

        if (depth >= maxDepth) return fallbackName(vn);
        if (visiting.putIfAbsent(vn, Boolean.TRUE) != null) {
            // Cycle (PHI or similar) — return a placeholder.
            return fallbackName(vn);
        }
        try {
            PcodeOp def = vn.getDef();
            if (def == null) return fallbackName(vn);
            return renderOp(def, depth, visiting);
        } finally {
            visiting.remove(vn);
        }
    }

    private String renderOp(PcodeOp op, int depth, Map<Varnode, Boolean> visiting) {
        int d = depth + 1;
        switch (op.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
                return render(op.getInput(0), d, visiting);
            case PcodeOp.INT_ADD:
            case PcodeOp.PTRADD:
                return bin(op, " + ", d, visiting);
            case PcodeOp.INT_SUB:
                return bin(op, " - ", d, visiting);
            case PcodeOp.INT_MULT:
                return bin(op, " * ", d, visiting);
            case PcodeOp.INT_DIV: case PcodeOp.INT_SDIV:
                return bin(op, " / ", d, visiting);
            case PcodeOp.INT_REM: case PcodeOp.INT_SREM:
                return bin(op, " % ", d, visiting);
            case PcodeOp.INT_AND:   return bin(op, " & ", d, visiting);
            case PcodeOp.INT_OR:    return bin(op, " | ", d, visiting);
            case PcodeOp.INT_XOR:   return bin(op, " ^ ", d, visiting);
            case PcodeOp.INT_LEFT:  return bin(op, " << ", d, visiting);
            case PcodeOp.INT_RIGHT: return bin(op, " >> ", d, visiting);
            case PcodeOp.INT_SRIGHT: return bin(op, " s>> ", d, visiting);
            case PcodeOp.INT_EQUAL:    return bin(op, " == ", d, visiting);
            case PcodeOp.INT_NOTEQUAL: return bin(op, " != ", d, visiting);
            case PcodeOp.INT_LESS:        return bin(op, " u< ", d, visiting);
            case PcodeOp.INT_LESSEQUAL:   return bin(op, " u<= ", d, visiting);
            case PcodeOp.INT_SLESS:       return bin(op, " < ", d, visiting);
            case PcodeOp.INT_SLESSEQUAL:  return bin(op, " <= ", d, visiting);
            case PcodeOp.BOOL_AND: return bin(op, " && ", d, visiting);
            case PcodeOp.BOOL_OR:  return bin(op, " || ", d, visiting);
            case PcodeOp.BOOL_XOR: return bin(op, " ^^ ", d, visiting);
            case PcodeOp.BOOL_NEGATE:
                return "!(" + render(op.getInput(0), d, visiting) + ")";
            case PcodeOp.INT_NEGATE:
                return "~" + render(op.getInput(0), d, visiting);
            case PcodeOp.INT_2COMP:
                return "-" + render(op.getInput(0), d, visiting);
            case PcodeOp.INT_ZEXT:
                return "zext(" + render(op.getInput(0), d, visiting) + ")";
            case PcodeOp.INT_SEXT:
                return "sext(" + render(op.getInput(0), d, visiting) + ")";
            case PcodeOp.SUBPIECE: {
                Varnode piece = op.getInput(1);
                long shift = piece.isConstant() ? piece.getOffset() : -1;
                return "subpiece(" + render(op.getInput(0), d, visiting)
                    + ", " + shift + ", size=" + op.getOutput().getSize() + ")";
            }
            case PcodeOp.LOAD:
                // inputs[0] = space id, inputs[1] = pointer
                return "*(" + render(op.getInput(1), d, visiting) + ")";
            case PcodeOp.PTRSUB:
                return "(" + render(op.getInput(0), d, visiting) + " + "
                    + render(op.getInput(1), d, visiting) + ")";
            case PcodeOp.MULTIEQUAL: {
                StringBuilder sb = new StringBuilder("phi(");
                for (int i = 0; i < op.getNumInputs(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(render(op.getInput(i), d, visiting));
                }
                return sb.append(")").toString();
            }
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
            case PcodeOp.CALLOTHER: {
                StringBuilder sb = new StringBuilder(
                    op.getOpcode() == PcodeOp.CALL ? "call(" :
                    op.getOpcode() == PcodeOp.CALLIND ? "callind(" : "callother(");
                for (int i = 0; i < op.getNumInputs(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(render(op.getInput(i), d, visiting));
                }
                return sb.append(")").toString();
            }
            case PcodeOp.INT_CARRY:  return "carry(" + bin(op, ", ", d, visiting) + ")";
            case PcodeOp.INT_SCARRY: return "scarry(" + bin(op, ", ", d, visiting) + ")";
            case PcodeOp.INT_SBORROW: return "sborrow(" + bin(op, ", ", d, visiting) + ")";
            case PcodeOp.POPCOUNT:    return "popcount(" + render(op.getInput(0), d, visiting) + ")";
            case PcodeOp.LZCOUNT:     return "lzcount(" + render(op.getInput(0), d, visiting) + ")";
            case PcodeOp.PIECE:
                return "concat(" + render(op.getInput(0), d, visiting)
                    + ", " + render(op.getInput(1), d, visiting) + ")";
            default:
                return PcodeOp.getMnemonic(op.getOpcode()) + "(...)";
        }
    }

    private String bin(PcodeOp op, String mid, int d, Map<Varnode, Boolean> visiting) {
        return "(" + render(op.getInput(0), d, visiting) + mid
            + render(op.getInput(1), d, visiting) + ")";
    }

    private String tryName(Varnode vn) {
        HighVariable hv = vn.getHigh();
        if (hv != null) {
            HighSymbol sym = hv.getSymbol();
            if (sym != null) {
                String n = sym.getName();
                if (isUsefulName(n)) return n;
            }
            String n = hv.getName();
            if (isUsefulName(n)) return n;
        }
        return null;
    }

    private static boolean isUsefulName(String n) {
        return n != null && !n.isEmpty()
            && !n.equals("UNNAMED") && !n.equals("<null>");
    }

    private String fallbackName(Varnode vn) {
        if (vn.isConstant()) return hex(vn.getOffset(), vn.getSize());
        if (vn.isRegister() && program != null) {
            try {
                Register r = program.getRegister(vn.getAddress(), vn.getSize());
                if (r != null) return r.getName();
            } catch (Exception ignored) {}
        }
        if (vn.getAddress() != null && vn.getAddress().getAddressSpace() != null) {
            String sp = vn.getAddress().getAddressSpace().getName();
            if ("stack".equalsIgnoreCase(sp)) {
                return "stack[" + Long.toHexString(vn.getOffset()) + "]";
            }
            if ("unique".equalsIgnoreCase(sp)) {
                return "tmp_" + Long.toHexString(vn.getOffset());
            }
            return sp + "[" + Long.toHexString(vn.getOffset()) + "]";
        }
        return "<vn@" + vn.getOffset() + ">";
    }

    private static String hex(long value, int size) {
        if (size > 0 && size < 8) {
            long mask = (1L << (size * 8)) - 1L;
            value &= mask;
        }
        return "0x" + Long.toHexString(value);
    }
}
