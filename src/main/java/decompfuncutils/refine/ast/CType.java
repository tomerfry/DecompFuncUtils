package decompfuncutils.refine.ast;

import ghidra.program.model.data.*;

/**
 * The part of a C type the refinement engine reasons with: how wide a value is, whether its
 * arithmetic is signed, and how far pointer arithmetic steps. Anything else about a type stays in
 * the text the decompiler printed.
 */
public final class CType {
    public enum Kind { INT, BOOL, PTR, FLOAT, AGGREGATE, VOID, UNKNOWN }

    public static final CType UNKNOWN = new CType(Kind.UNKNOWN, 0, false, null, 0, "?");
    public static final CType VOID = new CType(Kind.VOID, 0, false, null, 0, "void");
    public static final CType BOOL = new CType(Kind.BOOL, 8, false, null, 0, "bool");

    public final Kind kind;
    /** Width in bits; 0 when unknown or void. */
    public final int bits;
    public final boolean signed;
    /** What a pointer points at; null unless {@link Kind#PTR}. */
    public final CType pointee;
    /** Element size in bytes used by pointer arithmetic and indexing. */
    public final int elemSize;
    /** C spelling, used when a pass has to print a cast it synthesized. */
    public final String name;

    private CType(Kind kind, int bits, boolean signed, CType pointee, int elemSize, String name) {
        this.kind = kind;
        this.bits = bits;
        this.signed = signed;
        this.pointee = pointee;
        this.elemSize = elemSize;
        this.name = name;
    }

    public static CType integer(int bits, boolean signed) {
        return new CType(Kind.INT, bits, signed, null, 0, defaultName(bits, signed));
    }

    public static CType integer(int bits, boolean signed, String name) {
        return new CType(Kind.INT, bits, signed, null, 0, name);
    }

    public static CType pointerTo(CType pointee, int pointerBits) {
        int elem = pointee == null || pointee.kind == Kind.VOID || pointee.kind == Kind.UNKNOWN
            ? 1 : Math.max(1, pointee.byteSize());
        String n = (pointee == null ? "void" : pointee.name) + " *";
        return new CType(Kind.PTR, pointerBits, false, pointee == null ? VOID : pointee, elem, n);
    }

    public static CType aggregate(int bytes, int elemSize, CType elem, String name) {
        return new CType(Kind.AGGREGATE, bytes * 8, false, elem, elemSize, name);
    }

    public static CType floating(int bits, String name) {
        return new CType(Kind.FLOAT, bits, true, null, 0, name);
    }

    /** Map a Ghidra data type; {@code pointerBits} is the program's pointer width. */
    public static CType of(DataType dt, int pointerBits) {
        if (dt == null) return UNKNOWN;
        String name = dt.getDisplayName();
        while (dt instanceof TypeDef td) dt = td.getBaseDataType();
        if (dt instanceof VoidDataType) return VOID;
        if (dt instanceof BooleanDataType) return new CType(Kind.BOOL, Math.max(1, dt.getLength()) * 8, false, null, 0, name);
        if (dt instanceof Pointer p) {
            int width = p.getLength() > 0 ? p.getLength() * 8 : pointerBits;
            DataType target = p.getDataType();
            CType pointee = target == null ? VOID : of(target, pointerBits);
            int elem = target == null || target.getLength() <= 0 ? 1 : target.getLength();
            if (target instanceof FunctionDefinition) elem = 1;
            return new CType(Kind.PTR, width, false, pointee, elem, name);
        }
        if (dt instanceof AbstractIntegerDataType i) {
            return new CType(Kind.INT, dt.getLength() * 8, i.isSigned(), null, 0, name);
        }
        if (dt instanceof AbstractFloatDataType) return new CType(Kind.FLOAT, dt.getLength() * 8, true, null, 0, name);
        if (dt instanceof ghidra.program.model.data.Enum) return new CType(Kind.INT, dt.getLength() * 8, false, null, 0, name);
        if (dt instanceof Undefined || dt instanceof DefaultDataType) {
            return new CType(Kind.INT, Math.max(1, dt.getLength()) * 8, false, null, 0, name);
        }
        if (dt instanceof Array a) {
            CType elem = of(a.getDataType(), pointerBits);
            return new CType(Kind.AGGREGATE, a.getLength() * 8, false, elem, Math.max(1, a.getElementLength()), name);
        }
        if (dt instanceof Composite) return new CType(Kind.AGGREGATE, Math.max(0, dt.getLength()) * 8, false, null, 0, name);
        if (dt instanceof FunctionDefinition) return new CType(Kind.UNKNOWN, 0, false, null, 1, name);
        return dt.getLength() > 0 ? new CType(Kind.INT, dt.getLength() * 8, false, null, 0, name) : UNKNOWN;
    }

    public boolean isKnown() { return kind != Kind.UNKNOWN && kind != Kind.VOID && bits > 0; }
    public boolean isPointer() { return kind == Kind.PTR; }
    public boolean isBool() { return kind == Kind.BOOL; }
    public boolean isFloat() { return kind == Kind.FLOAT; }
    public boolean isAggregate() { return kind == Kind.AGGREGATE; }
    /** A value integer arithmetic applies to: integers, booleans and pointers. */
    public boolean isScalarInt() { return bits > 0 && (kind == Kind.INT || kind == Kind.BOOL || kind == Kind.PTR); }
    public int byteSize() { return (bits + 7) / 8; }

    public CType withSign(boolean s) {
        return kind == Kind.INT && s != signed ? integer(bits, s) : this;
    }

    private static String defaultName(int bits, boolean signed) {
        return switch (bits) {
            case 8 -> signed ? "char" : "uchar";
            case 16 -> signed ? "short" : "ushort";
            case 32 -> signed ? "int" : "uint";
            case 64 -> signed ? "long" : "ulong";
            default -> (signed ? "int" : "uint") + bits + "_t";
        };
    }

    public boolean sameShape(CType o) {
        return o != null && kind == o.kind && bits == o.bits && signed == o.signed && elemSize == o.elemSize;
    }

    @Override public String toString() { return name; }
}
