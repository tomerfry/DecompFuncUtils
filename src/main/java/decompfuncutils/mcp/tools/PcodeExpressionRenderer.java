package decompfuncutils.mcp.tools;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
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
                Varnode src = op.getInput(0);
                int outSize = op.getOutput() != null ? op.getOutput().getSize() : -1;
                // Low-bytes narrowing cast: render as `(uintN_t)expr` instead of `subpiece(expr, 0, size=N)`.
                if (piece != null && piece.isConstant() && piece.getOffset() == 0
                        && (outSize == 1 || outSize == 2 || outSize == 4)) {
                    String typeName = outSize == 1 ? "uint8_t"
                                    : outSize == 2 ? "uint16_t" : "uint32_t";
                    return "(" + typeName + ")" + render(src, d, visiting);
                }
                long shift = piece != null && piece.isConstant() ? piece.getOffset() : -1;
                return "subpiece(" + render(src, d, visiting)
                    + ", " + shift + ", size=" + outSize + ")";
            }
            case PcodeOp.LOAD: {
                // inputs[0] = space id, inputs[1] = pointer.
                // If the pointer is (named struct pointer + constant field offset),
                // render as base->field rather than *((base + 0xN)).
                Varnode ptr = op.getInput(1);
                String fieldAccess = tryRenderStructFieldLoad(ptr);
                if (fieldAccess != null) return fieldAccess;
                return "*(" + render(ptr, d, visiting) + ")";
            }
            case PcodeOp.PTRSUB: {
                // PTRSUB is used for struct-field pointer math: base + constOffset.
                // Prefer base->field rendering when types permit.
                String fieldAccess = tryRenderStructFieldPointer(op.getInput(0), op.getInput(1));
                if (fieldAccess != null) return "&" + fieldAccess;
                return "(" + render(op.getInput(0), d, visiting) + " + "
                    + render(op.getInput(1), d, visiting) + ")";
            }
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

    /**
     * If `ptr` is `(namedStructPointer + constOffset)`, render the corresponding
     * load as `base->field`. Returns null when the pattern doesn't apply.
     */
    private String tryRenderStructFieldLoad(Varnode ptr) {
        if (ptr == null) return null;
        BaseOffset bo = baseOffsetOf(ptr);
        if (bo == null) return null;
        String baseName = tryName(bo.base);
        if (baseName == null) return null;
        Structure s = pointedStructure(bo.base);
        if (s == null) return null;
        int offset = (int) bo.offset;
        if (offset < 0 || offset >= s.getLength()) return null;
        DataTypeComponent comp = s.getComponentContaining(offset);
        if (comp == null) return null;
        String field = comp.getFieldName();
        if (field == null || field.isEmpty()) {
            field = "field_" + Integer.toHexString(comp.getOffset());
        }
        // If the load aligns to the start of the component, use -> directly;
        // otherwise annotate the sub-offset so the reader knows we're inside a field.
        if (offset == comp.getOffset()) {
            return baseName + "->" + field;
        }
        return baseName + "->" + field + "+" + (offset - comp.getOffset());
    }

    /**
     * PTRSUB(base, const) → render as `base->field` (address-of used separately).
     */
    private String tryRenderStructFieldPointer(Varnode base, Varnode off) {
        if (base == null || off == null || !off.isConstant()) return null;
        String baseName = tryName(base);
        if (baseName == null) return null;
        Structure s = pointedStructure(base);
        if (s == null) return null;
        int offset = (int) off.getOffset();
        if (offset < 0 || offset >= s.getLength()) return null;
        DataTypeComponent comp = s.getComponentContaining(offset);
        if (comp == null || comp.getOffset() != offset) return null;
        String field = comp.getFieldName();
        if (field == null || field.isEmpty()) {
            field = "field_" + Integer.toHexString(comp.getOffset());
        }
        return baseName + "->" + field;
    }

    /**
     * Resolve a varnode of the form `base + constant` (via PTRADD/PTRSUB/INT_ADD)
     * into a (base, offset) pair. Returns (vn, 0) for a plain base pointer.
     */
    private BaseOffset baseOffsetOf(Varnode vn) {
        if (vn == null) return null;
        PcodeOp def = vn.getDef();
        if (def == null) return new BaseOffset(vn, 0);
        int op = def.getOpcode();
        if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
            return baseOffsetOf(def.getInput(0));
        }
        if (op == PcodeOp.PTRSUB || op == PcodeOp.PTRADD || op == PcodeOp.INT_ADD) {
            Varnode a = def.getInput(0);
            Varnode b = def.getInput(1);
            if (a != null && b != null && b.isConstant()) {
                long mult = (op == PcodeOp.PTRADD && def.getNumInputs() >= 3
                    && def.getInput(2) != null && def.getInput(2).isConstant())
                    ? def.getInput(2).getOffset() : 1L;
                return new BaseOffset(a, b.getOffset() * mult);
            }
            if (a != null && b != null && a.isConstant()) {
                return new BaseOffset(b, a.getOffset());
            }
        }
        return new BaseOffset(vn, 0);
    }

    private Structure pointedStructure(Varnode base) {
        if (base == null) return null;
        HighVariable hv = base.getHigh();
        if (hv == null) return null;
        DataType dt = hv.getDataType();
        if (dt instanceof Pointer p) {
            DataType pointed = p.getDataType();
            if (pointed instanceof Structure s) return s;
        }
        if (dt instanceof Structure s) return s;
        return null;
    }

    private static final class BaseOffset {
        final Varnode base;
        final long offset;
        BaseOffset(Varnode base, long offset) { this.base = base; this.offset = offset; }
    }

    private static String hex(long value, int size) {
        if (size > 0 && size < 8) {
            long mask = (1L << (size * 8)) - 1L;
            value &= mask;
        }
        return "0x" + Long.toHexString(value);
    }
}
