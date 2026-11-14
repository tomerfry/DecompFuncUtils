package decompfuncutils.refine.ast;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Expression nodes of the refinement AST. Every node carries the width and signedness its value is
 * computed with (taken from the p-code behind the decompiler token where there is one), so the
 * evaluator and the prover agree with the machine rather than with C's promotion rules.
 */
public abstract class Expr {
    /** Value type of this expression; never null. */
    public CType type = CType.UNKNOWN;
    /** P-code operation the decompiler printed this node for, if any. */
    public PcodeOp op;
    /** Lowest machine address this expression was printed for, if known. */
    public Address addr;
    /** Set on the root of a subtree a pass produced; drives highlighting and the rewrite log. */
    public Object note;

    public abstract int kids();
    public abstract Expr kid(int i);
    public abstract void kid(int i, Expr e);
    /** Deep copy, keeping types and provenance. */
    public abstract Expr copy();

    protected <T extends Expr> T from(T src) {
        type = src.type;
        op = src.op;
        addr = src.addr;
        note = src.note;
        @SuppressWarnings("unchecked") T self = (T) this;
        return self;
    }

    public Expr typed(CType t) { this.type = t == null ? CType.UNKNOWN : t; return this; }
    public Expr at(Address a) { if (addr == null) addr = a; return this; }

    /** A named thing: variable, parameter, global, function, or a rule metavariable. */
    public static final class Id extends Expr {
        public enum Kind { VAR, PARAM, GLOBAL, FUNC, META }
        public String name;
        public Kind kind;
        public HighVariable high;
        /** Callee when this names a function. */
        public Function function;
        /** Global address when this names program data. */
        public Address storage;
        /** For metavariables: the constraint after the colon ("const", "var", or null). */
        public String metaKind;

        public Id(String name, Kind kind) { this.name = name; this.kind = kind; }
        @Override public int kids() { return 0; }
        @Override public Expr kid(int i) { throw new IndexOutOfBoundsException(); }
        @Override public void kid(int i, Expr e) { throw new IndexOutOfBoundsException(); }
        @Override public Expr copy() {
            Id c = new Id(name, kind).from(this);
            c.high = high; c.function = function; c.storage = storage; c.metaKind = metaKind;
            return c;
        }
    }

    /** A literal. Integers and characters carry a value; strings and floats only their text. */
    public static final class Lit extends Expr {
        public enum Kind { INT, CHAR, STRING, FLOAT }
        public Kind kind;
        /**
         * Unsigned value masked to the literal's width; null for floats. For a string literal the
         * decompiler printed, the address of the string in the program; null for one a pass made.
         */
        public BigInteger value;
        /** Text as the decompiler printed it; null for a literal a pass computed. */
        public String text;
        /** A literal from a rule that takes its width from the operand it meets. */
        public boolean flexible;

        public Lit(BigInteger value, CType type) { this.kind = Kind.INT; this.value = value; this.type = type; }
        public Lit(Kind kind, BigInteger value, String text, CType type) {
            this.kind = kind; this.value = value; this.text = text; this.type = type;
        }
        /** An integer or character constant. A string literal is not one, even where its address is known. */
        public boolean isInt() { return value != null && kind != Kind.STRING && kind != Kind.FLOAT; }
        /** Value read as signed when the literal's type is signed. */
        public BigInteger signedValue() {
            if (value == null || !type.signed || type.bits == 0) return value;
            return value.testBit(type.bits - 1) ? value.subtract(BigInteger.ONE.shiftLeft(type.bits)) : value;
        }
        @Override public int kids() { return 0; }
        @Override public Expr kid(int i) { throw new IndexOutOfBoundsException(); }
        @Override public void kid(int i, Expr e) { throw new IndexOutOfBoundsException(); }
        @Override public Expr copy() {
            Lit c = new Lit(kind, value, text, type).from(this);
            c.flexible = flexible;
            return c;
        }
    }

    /** Prefix and postfix unary operators: - ~ ! * &amp; ++x --x x++ x--. */
    public static final class Un extends Expr {
        public String o;
        public Expr e;
        public boolean postfix;

        public Un(String o, Expr e) { this.o = o; this.e = e; }
        public Un(String o, Expr e, boolean postfix) { this.o = o; this.e = e; this.postfix = postfix; }
        @Override public int kids() { return 1; }
        @Override public Expr kid(int i) { return e; }
        @Override public void kid(int i, Expr x) { e = x; }
        @Override public Expr copy() { return new Un(o, e.copy(), postfix).from(this); }
    }

    /** Binary operators, including comparisons, logical operators and the comma. */
    public static final class Bin extends Expr {
        public String o;
        public Expr l, r;
        /** Whether / % &gt;&gt; and the ordering comparisons are the signed machine operation. */
        public boolean sgn;
        /**
         * Pointer arithmetic: the byte size the integer operand of + or - is multiplied by. Zero
         * when this is plain integer arithmetic.
         */
        public int scale;

        public Bin(String o, Expr l, Expr r) { this.o = o; this.l = l; this.r = r; }
        @Override public int kids() { return 2; }
        @Override public Expr kid(int i) { return i == 0 ? l : r; }
        @Override public void kid(int i, Expr x) { if (i == 0) l = x; else r = x; }
        @Override public Expr copy() {
            Bin c = new Bin(o, l.copy(), r.copy()).from(this);
            c.sgn = sgn;
            c.scale = scale;
            return c;
        }
    }

    /** Assignment, plain or compound. */
    public static final class Assign extends Expr {
        public String o;
        public Expr l, r;

        public Assign(String o, Expr l, Expr r) { this.o = o; this.l = l; this.r = r; }
        @Override public int kids() { return 2; }
        @Override public Expr kid(int i) { return i == 0 ? l : r; }
        @Override public void kid(int i, Expr x) { if (i == 0) l = x; else r = x; }
        @Override public Expr copy() { return new Assign(o, l.copy(), r.copy()).from(this); }
    }

    /** c ? a : b */
    public static final class Cond extends Expr {
        public Expr c, a, b;

        public Cond(Expr c, Expr a, Expr b) { this.c = c; this.a = a; this.b = b; }
        @Override public int kids() { return 3; }
        @Override public Expr kid(int i) { return i == 0 ? c : i == 1 ? a : b; }
        @Override public void kid(int i, Expr x) { if (i == 0) c = x; else if (i == 1) a = x; else b = x; }
        @Override public Expr copy() { return new Cond(c.copy(), a.copy(), b.copy()).from(this); }
    }

    /** A call. {@code fn} is an {@link Id} for direct calls and any expression for indirect ones. */
    public static final class Call extends Expr {
        public Expr fn;
        public final List<Expr> args = new ArrayList<>();
        /**
         * Known to have no side effects although the callee is a program function: set on calls
         * the engine put back for an inlined helper whose whole body is one expression.
         */
        public boolean pure;

        public Call(Expr fn, List<Expr> args) { this.fn = fn; this.args.addAll(args); }
        public String name() { return fn instanceof Id id ? id.name : null; }
        @Override public int kids() { return args.size() + 1; }
        @Override public Expr kid(int i) { return i == 0 ? fn : args.get(i - 1); }
        @Override public void kid(int i, Expr x) { if (i == 0) fn = x; else args.set(i - 1, x); }
        @Override public Expr copy() {
            List<Expr> a = new ArrayList<>();
            for (Expr x : args) a.add(x.copy());
            Call c = new Call(fn.copy(), a).from(this);
            c.pure = pure;
            return c;
        }
    }

    /** (type)e. The target type is the node's own {@link #type}; {@code text} is how to print it. */
    public static final class Cast extends Expr {
        public String text;
        public Expr e;

        public Cast(CType to, String text, Expr e) { this.type = to; this.text = text; this.e = e; }
        @Override public int kids() { return 1; }
        @Override public Expr kid(int i) { return e; }
        @Override public void kid(int i, Expr x) { e = x; }
        @Override public Expr copy() { return new Cast(type, text, e.copy()).from(this); }
    }

    /** base[index] */
    public static final class Index extends Expr {
        public Expr base, index;

        public Index(Expr base, Expr index) { this.base = base; this.index = index; }
        @Override public int kids() { return 2; }
        @Override public Expr kid(int i) { return i == 0 ? base : index; }
        @Override public void kid(int i, Expr x) { if (i == 0) base = x; else index = x; }
        @Override public Expr copy() { return new Index(base.copy(), index.copy()).from(this); }
    }

    /** base.field or base-&gt;field */
    public static final class Member extends Expr {
        public Expr base;
        public String field;
        public boolean arrow;
        /** Byte offset of the field inside its composite, or -1 when unknown. */
        public int offset = -1;

        public Member(Expr base, String field, boolean arrow) { this.base = base; this.field = field; this.arrow = arrow; }
        @Override public int kids() { return 1; }
        @Override public Expr kid(int i) { return base; }
        @Override public void kid(int i, Expr x) { base = x; }
        @Override public Expr copy() {
            Member c = new Member(base.copy(), field, arrow).from(this);
            c.offset = offset;
            return c;
        }
    }

    /** Text the parser could not make sense of; printed back verbatim and never reasoned about. */
    public static final class Raw extends Expr {
        public String text;

        public Raw(String text) { this.text = text; }
        @Override public int kids() { return 0; }
        @Override public Expr kid(int i) { throw new IndexOutOfBoundsException(); }
        @Override public void kid(int i, Expr e) { throw new IndexOutOfBoundsException(); }
        @Override public Expr copy() { return new Raw(text).from(this); }
    }
}
