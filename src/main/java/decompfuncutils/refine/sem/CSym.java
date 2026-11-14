package decompfuncutils.refine.sem;

import com.microsoft.z3.*;
import decompfuncutils.refine.ast.CPrinter;
import decompfuncutils.refine.ast.CType;
import decompfuncutils.refine.ast.Stmt;
import decompfuncutils.refine.ast.Typer;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.symbolic.SymbolicArithmetic;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Symbolic semantics of the refinement AST over Z3 bit-vectors. Variables are free symbols of
 * their declared width, memory is one array from addresses to bytes, and every operator means
 * exactly what {@link CInterp} computes for it. Used to prove that a rewritten expression equals
 * the one it replaces for all inputs, to decide branch conditions that can only go one way, and to
 * execute straight-line assignments symbolically (loop tails, callee bodies).
 */
public final class CSym implements AutoCloseable {
    public enum Verdict { PROVEN, REFUTED, UNKNOWN }

    /** A symbolic store: variable values (absent = the variable's own symbol) and memory. */
    public final class State {
        public final Map<String, BitVecExpr> env = new HashMap<>();
        public Expr<ArraySort<BitVecSort, BitVecSort>> mem = baseMemory;

        public State copy() {
            State s = new State();
            s.env.putAll(env);
            s.mem = mem;
            return s;
        }
    }

    private final Context ctx;
    private final Solver solver;
    private final SymbolicArithmetic ar;
    private final int pointerBits;
    private final boolean bigEndian;
    private final Expr<ArraySort<BitVecSort, BitVecSort>> baseMemory;
    private final List<BoolExpr> assume = new ArrayList<>();
    private final Map<String, FuncDecl<?>> functions = new HashMap<>();
    private int timeoutMs = 800;
    /** Set while building terms when a call was modelled as an unknown function. */
    private boolean opaqueCalls;
    /** Why the last query came back UNKNOWN, or the counterexample for REFUTED. */
    public String detail = "";
    public int queries;

    public CSym(int pointerBits, boolean bigEndian) {
        this.ctx = new Context();
        this.solver = ctx.mkSolver();
        this.ar = new SymbolicArithmetic(ctx);
        this.pointerBits = pointerBits;
        this.bigEndian = bigEndian;
        this.baseMemory = ctx.mkConst("mem", ctx.mkArraySort(ctx.mkBitVecSort(pointerBits), ctx.mkBitVecSort(8)));
    }

    public void setTimeoutMs(int ms) { timeoutMs = Math.max(10, ms); }
    public State newState() { return new State(); }
    @Override public void close() { ctx.close(); }

    private static UnsupportedOperationException unsupported(String why) { return new UnsupportedOperationException(why); }

    private static int bits(decompfuncutils.refine.ast.Expr e) {
        if (!e.type.isScalarInt()) throw unsupported("no integer width for " + CPrinter.text(e));
        return e.type.bits;
    }

    private BitVecExpr num(BigInteger v, int bits) { return ar.constant(v, bits); }
    private BitVecExpr flag(BoolExpr b) { return (BitVecExpr) ctx.mkITE(b, ctx.mkBV(1, 8), ctx.mkBV(0, 8)); }
    private BoolExpr truth(BitVecExpr v) { return ctx.mkNot(ctx.mkEq(v, ctx.mkBV(0, v.getSortSize()))); }

    /** Resize as a cast from {@code from} would: truncate, or extend by the source's signedness. */
    private BitVecExpr convert(BitVecExpr v, CType from, int toBits) {
        return ar.resize(v, toBits, from.signed && from.kind == CType.Kind.INT);
    }

    // ------------------------------------------------------------------ terms

    public BitVecExpr term(decompfuncutils.refine.ast.Expr e, State st) {
        switch (e) {
            case Lit l -> {
                if (!l.isInt()) throw unsupported("non-integer literal");
                return num(l.value, bits(l));
            }
            case Id id -> {
                if (id.kind == Id.Kind.META) throw unsupported("unbound metavariable");
                if (id.kind == Id.Kind.FUNC) {
                    if (id.function == null) throw unsupported("unknown function address");
                    return num(BigInteger.valueOf(id.function.getEntryPoint().getOffset()), pointerBits);
                }
                if (id.type.isAggregate()) return ctx.mkBVConst("&" + id.name, pointerBits);
                if (id.kind == Id.Kind.GLOBAL && id.storage != null) {
                    return load(st, num(BigInteger.valueOf(id.storage.getOffset()), pointerBits), bits(id) / 8);
                }
                BitVecExpr bound = st.env.get(id.name);
                if (bound != null) return ar.resize(bound, bits(id), false);
                return ctx.mkBVConst(id.name + "#" + bits(id), bits(id));
            }
            case Un u -> {
                switch (u.o) {
                    case "*": return load(st, address(term(u.e, st)), Math.max(1, bits(u) / 8));
                    case "&": return addressOf(u.e, st);
                    case "!": return flag(ctx.mkNot(truth(term(u.e, st))));
                    case "-": return ar.apply(PcodeOp.INT_2COMP, bits(u), convert(term(u.e, st), u.e.type, bits(u)));
                    case "~": return ar.apply(PcodeOp.INT_NEGATE, bits(u), convert(term(u.e, st), u.e.type, bits(u)));
                    default: throw unsupported("operator " + u.o);
                }
            }
            case Bin b -> { return binary(b, st); }
            case Cond c -> {
                int w = bits(c);
                return (BitVecExpr) ctx.mkITE(truth(term(c.c, st)), convert(term(c.a, st), c.a.type, w), convert(term(c.b, st), c.b.type, w));
            }
            case Cast c -> {
                if (c.type.isFloat() || c.e.type.isFloat()) throw unsupported("floating point");
                BitVecExpr v = term(c.e, st);
                return c.e.type.isAggregate() ? ar.resize(v, bits(c), false) : convert(v, c.e.type, bits(c));
            }
            case Index ix -> { return load(st, addressOf(ix, st), Math.max(1, bits(ix) / 8)); }
            case Member m -> {
                if (m.offset < 0) throw unsupported("field without offset");
                if (!m.arrow && !(m.base instanceof Un bu && bu.o.equals("*")) && !(m.base instanceof Index) && !m.base.type.isAggregate()) {
                    BitVecExpr whole = term(m.base, st);
                    int lo = 8 * m.offset;
                    if (lo + bits(m) > whole.getSortSize()) throw unsupported("piece outside value");
                    return ctx.mkExtract(lo + bits(m) - 1, lo, whole);
                }
                return load(st, addressOf(m, st), Math.max(1, bits(m) / 8));
            }
            case Call c -> { return call(c, st); }
            default -> throw unsupported(e.getClass().getSimpleName());
        }
    }

    private BitVecExpr address(BitVecExpr v) { return ar.resize(v, pointerBits, false); }

    private BitVecExpr addressOf(decompfuncutils.refine.ast.Expr e, State st) {
        switch (e) {
            case Id id -> {
                if (id.kind == Id.Kind.GLOBAL && id.storage != null) return num(BigInteger.valueOf(id.storage.getOffset()), pointerBits);
                return ctx.mkBVConst("&" + id.name, pointerBits);
            }
            case Un u when u.o.equals("*") -> { return address(term(u.e, st)); }
            case Index ix -> {
                BitVecExpr base = ix.base.type.isAggregate() || !ix.base.type.isScalarInt() ? addressOf(ix.base, st) : address(term(ix.base, st));
                int elem = ix.base.type.elemSize > 0 ? ix.base.type.elemSize : Math.max(1, ix.type.byteSize());
                BitVecExpr index = ar.resize(term(ix.index, st), pointerBits, ix.index.type.signed);
                return ctx.mkBVAdd(base, ctx.mkBVMul(index, ctx.mkBV(elem, pointerBits)));
            }
            case Member m -> {
                if (m.offset < 0) throw unsupported("field without offset");
                BitVecExpr base = m.arrow ? address(term(m.base, st)) : addressOf(m.base, st);
                return ctx.mkBVAdd(base, ctx.mkBV(m.offset, pointerBits));
            }
            case Cast c -> { return addressOf(c.e, st); }
            default -> throw unsupported("address of " + CPrinter.text(e));
        }
    }

    private BitVecExpr load(State st, BitVecExpr addr, int bytes) {
        if (bytes < 1 || bytes > 16) throw unsupported("load width");
        BitVecExpr value = null;
        for (int i = bytes - 1; i >= 0; i--) {
            int at = bigEndian ? bytes - 1 - i : i;
            BitVecExpr b = (BitVecExpr) ctx.mkSelect(st.mem, ctx.mkBVAdd(addr, ctx.mkBV(at, pointerBits)));
            value = value == null ? b : ctx.mkConcat(value, b);
        }
        return value;
    }

    private void store(State st, BitVecExpr addr, int bytes, BitVecExpr value) {
        for (int i = 0; i < bytes; i++) {
            int at = bigEndian ? bytes - 1 - i : i;
            st.mem = ctx.mkStore(st.mem, ctx.mkBVAdd(addr, ctx.mkBV(at, pointerBits)), ctx.mkExtract(i * 8 + 7, i * 8, value));
        }
    }

    private BitVecExpr binary(Bin b, State st) {
        switch (b.o) {
            case "&&": return flag(ctx.mkAnd(truth(term(b.l, st)), truth(term(b.r, st))));
            case "||": return flag(ctx.mkOr(truth(term(b.l, st)), truth(term(b.r, st))));
            case ",": throw unsupported("comma");
            default: break;
        }
        if (b.l.type.isFloat() || b.r.type.isFloat() || b.type.isFloat()) throw unsupported("floating point");
        BitVecExpr l = term(b.l, st), r = term(b.r, st);
        if (Typer.COMPARE.contains(b.o)) {
            int w = Math.max(bits(b.l), bits(b.r));
            BitVecExpr x = convert(l, b.l.type, w), y = convert(r, b.r.type, w);
            BoolExpr c = switch (b.o) {
                case "==" -> ctx.mkEq(x, y);
                case "!=" -> ctx.mkNot(ctx.mkEq(x, y));
                case "<" -> b.sgn ? ctx.mkBVSLT(x, y) : ctx.mkBVULT(x, y);
                case "<=" -> b.sgn ? ctx.mkBVSLE(x, y) : ctx.mkBVULE(x, y);
                case ">" -> b.sgn ? ctx.mkBVSGT(x, y) : ctx.mkBVUGT(x, y);
                default -> b.sgn ? ctx.mkBVSGE(x, y) : ctx.mkBVUGE(x, y);
            };
            return flag(c);
        }
        int w = bits(b);
        if (b.o.equals("<<") || b.o.equals(">>")) {
            int lw = bits(b.l);
            int opcode = b.o.equals("<<") ? PcodeOp.INT_LEFT : b.sgn ? PcodeOp.INT_SRIGHT : PcodeOp.INT_RIGHT;
            if (b.o.equals(">>") && lw != w) return convert(ar.apply(opcode, lw, l, r), b.l.type, w);
            return ar.apply(opcode, w, convert(l, b.l.type, w), r);
        }
        BitVecExpr x = convert(l, b.l.type, w), y = convert(r, b.r.type, w);
        if (b.scale > 1) {
            BitVecExpr k = ctx.mkBV(b.scale, w);
            if (b.o.equals("+") && b.r.type.isPointer() && !b.l.type.isPointer()) x = ctx.mkBVMul(x, k);
            else y = ctx.mkBVMul(y, k);
        }
        int opcode = switch (b.o) {
            case "+" -> PcodeOp.INT_ADD;
            case "-" -> PcodeOp.INT_SUB;
            case "*" -> PcodeOp.INT_MULT;
            case "&" -> PcodeOp.INT_AND;
            case "|" -> PcodeOp.INT_OR;
            case "^" -> PcodeOp.INT_XOR;
            case "/" -> b.sgn ? PcodeOp.INT_SDIV : PcodeOp.INT_DIV;
            case "%" -> b.sgn ? PcodeOp.INT_SREM : PcodeOp.INT_REM;
            default -> throw unsupported("operator " + b.o);
        };
        if (b.o.equals("/") || b.o.equals("%")) {
            // Where the original traps there is nothing to preserve, so those inputs are excluded.
            assume.add(ctx.mkNot(ctx.mkEq(y, ctx.mkBV(0, w))));
            if (b.sgn) {
                assume.add(ctx.mkNot(ctx.mkAnd(ctx.mkEq(x, num(BigInteger.ONE.shiftLeft(w - 1), w)),
                    ctx.mkEq(y, num(BigInteger.ONE.negate(), w)))));
            }
        }
        return ar.apply(opcode, w, x, y);
    }

    private BitVecExpr call(Call c, State st) {
        String name = c.name();
        if (name == null) throw unsupported("indirect call");
        int w = bits(c);
        List<BitVecExpr> args = new ArrayList<>();
        for (decompfuncutils.refine.ast.Expr a : c.args) args.add(term(a, st));
        CType ta = c.args.isEmpty() ? CType.UNKNOWN : c.args.get(0).type;
        switch (name) {
            case "abs": {
                BitVecExpr x = args.get(0);
                BitVecExpr r = (BitVecExpr) ctx.mkITE(ctx.mkBVSLT(x, ctx.mkBV(0, x.getSortSize())), ctx.mkBVNeg(x), x);
                return convert(r, ta, w);
            }
            case "MIN", "MAX": {
                CType common = Typer.common(ta, c.args.get(1).type);
                BitVecExpr x = convert(args.get(0), ta, common.bits), y = convert(args.get(1), c.args.get(1).type, common.bits);
                BoolExpr less = common.signed ? ctx.mkBVSLT(x, y) : ctx.mkBVULT(x, y);
                BitVecExpr r = (BitVecExpr) (name.equals("MIN") ? ctx.mkITE(less, x, y) : ctx.mkITE(less, y, x));
                return convert(r, common, w);
            }
            case "rotl", "rotr": {
                BitVecExpr x = args.get(0);
                BitVecExpr n = ar.resize(args.get(1), x.getSortSize(), false);
                BitVecExpr r = name.equals("rotl") ? ctx.mkBVRotateLeft(x, n) : ctx.mkBVRotateRight(x, n);
                return ar.resize(r, w, false);
            }
            case "bswap": {
                BitVecExpr x = args.get(0), r = null;
                for (int i = 0; i < x.getSortSize() / 8; i++) {
                    BitVecExpr b = ctx.mkExtract(i * 8 + 7, i * 8, x);
                    r = r == null ? b : ctx.mkConcat(r, b);
                }
                return ar.resize(r, w, false);
            }
            case "POPCOUNT": return ar.apply(PcodeOp.POPCOUNT, w, args.get(0));
            case "LZCOUNT": return ar.apply(PcodeOp.LZCOUNT, w, args.get(0));
            default: break;
        }
        if (Builtins.isPseudo(name)) {
            String family = name.replaceAll("\\d+$", "");
            switch (family) {
                case "CONCAT": return ar.resize(ctx.mkConcat(args.get(0), args.get(1)), w, false);
                case "SUB": return ar.apply(PcodeOp.SUBPIECE, w, args.get(0), args.get(1));
                case "ZEXT": return ar.resize(args.get(0), w, false);
                case "SEXT": return ar.resize(args.get(0), w, true);
                case "CARRY": return ar.resize(ar.apply(PcodeOp.INT_CARRY, 8, args.get(0), args.get(1)), w, false);
                case "SCARRY": return ar.resize(ar.apply(PcodeOp.INT_SCARRY, 8, args.get(0), args.get(1)), w, false);
                case "SBORROW": return ar.resize(ar.apply(PcodeOp.INT_SBORROW, 8, args.get(0), args.get(1)), w, false);
                default: break;
            }
        }
        if (Builtins.MEMORY.contains(name)) throw unsupported("memory builtin " + name);
        // Any other call: an unknown but fixed function of its arguments. Sound for comparing two
        // expressions that each make the call once in the same state, which is all it is used for.
        Sort[] domain = new Sort[args.size()];
        StringBuilder key = new StringBuilder(name).append('/').append(w);
        for (int i = 0; i < domain.length; i++) {
            domain[i] = args.get(i).getSort();
            key.append('/').append(args.get(i).getSortSize());
        }
        opaqueCalls = true;
        FuncDecl<?> f = functions.computeIfAbsent(key.toString(), k -> ctx.mkFuncDecl(k, domain, ctx.mkBitVecSort(w)));
        return (BitVecExpr) ctx.mkApp(f, args.toArray(new com.microsoft.z3.Expr<?>[0]));
    }

    // ------------------------------------------------------------------ straight-line execution

    /**
     * Execute one statement symbolically. Only assignments to variables and stores through
     * pointers are understood; anything else returns false and leaves the state untouched.
     */
    public boolean exec(Stmt s, State st) {
        if (!(s instanceof Stmt.ExprStmt es) || !(es.e instanceof Assign a) || !a.o.equals("=")) return false;
        try {
            if (a.l instanceof Id id && id.kind != Id.Kind.GLOBAL && id.kind != Id.Kind.FUNC && id.type.isScalarInt()) {
                st.env.put(id.name, convert(term(a.r, st), a.r.type, bits(id)));
                return true;
            }
            if (a.l instanceof Un u && u.o.equals("*") || a.l instanceof Index || a.l instanceof Member m && m.offset >= 0 && m.arrow) {
                BitVecExpr value = convert(term(a.r, st), a.r.type, bits(a.l));
                BitVecExpr addr = a.l instanceof Un u2 ? address(term(u2.e, st)) : addressOf(a.l, st);
                store(st, addr, Math.max(1, bits(a.l) / 8), value);
                return true;
            }
        } catch (UnsupportedOperationException | Z3Exception e) {
            detail = String.valueOf(e.getMessage());
        }
        return false;
    }

    private int fresh;

    /**
     * Forget what is known about {@code vars} (and, optionally, all of memory): each gets a fresh
     * unconstrained value. Used to step over a statement that cannot be executed symbolically
     * without claiming anything about what it does.
     */
    public void havoc(State st, java.util.Collection<String> vars, java.util.function.Function<String, CType> types, boolean memory) {
        for (String v : vars) {
            CType t = types.apply(v);
            if (t == null || !t.isScalarInt()) throw unsupported("no width for " + v);
            st.env.put(v, ctx.mkBVConst(v + "!" + (fresh++), t.bits));
        }
        if (memory) st.mem = ctx.mkConst("mem!" + (fresh++), ctx.mkArraySort(ctx.mkBitVecSort(pointerBits), ctx.mkBitVecSort(8)));
    }

    /** Is {@code a} (in {@code sa}) nonzero exactly when {@code b} (in {@code sb}) is, for every input? */
    public Verdict sameTruth(decompfuncutils.refine.ast.Expr a, State sa, decompfuncutils.refine.ast.Expr b, State sb) {
        assume.clear();
        detail = "";
        opaqueCalls = false;
        try {
            Status s = check(ctx.mkNot(ctx.mkEq(truth(term(a, sa)), truth(term(b, sb)))));
            if (s == Status.UNSATISFIABLE) return Verdict.PROVEN;
            if (s == Status.SATISFIABLE && opaqueCalls) {
                detail = "depends on a function the solver has no model of";
                return Verdict.UNKNOWN;
            }
            if (s == Status.SATISFIABLE) {
                detail = "counterexample: " + brief(solver.getModel());
                return Verdict.REFUTED;
            }
            detail = "solver gave up: " + solver.getReasonUnknown();
            return Verdict.UNKNOWN;
        } catch (UnsupportedOperationException | Z3Exception e) {
            detail = "not modelled: " + e.getMessage();
            return Verdict.UNKNOWN;
        }
    }

    // ------------------------------------------------------------------ queries

    private Status check(BoolExpr goal) {
        queries++;
        solver.reset();
        Params p = ctx.mkParams();
        p.add("timeout", timeoutMs);
        solver.setParameters(p);
        for (BoolExpr a : assume) solver.add(a);
        solver.add(goal);
        return solver.check();
    }

    /** Are {@code a} and {@code b} equal for every input, in fresh states? */
    public Verdict equivalent(decompfuncutils.refine.ast.Expr a, decompfuncutils.refine.ast.Expr b) {
        return equivalent(a, newState(), b, newState());
    }

    /** Is {@code a} in state {@code sa} equal to {@code b} in state {@code sb} for every input? */
    public Verdict equivalent(decompfuncutils.refine.ast.Expr a, State sa, decompfuncutils.refine.ast.Expr b, State sb) {
        assume.clear();
        detail = "";
        opaqueCalls = false;
        try {
            BitVecExpr x = term(a, sa), y = term(b, sb);
            if (x.getSortSize() != y.getSortSize()) y = convert(y, b.type, x.getSortSize());
            Status s = check(ctx.mkNot(ctx.mkEq(x, y)));
            if (s == Status.UNSATISFIABLE) return Verdict.PROVEN;
            if (s == Status.SATISFIABLE && opaqueCalls) {
                // The solver was free to choose what the unknown function returns; that is not
                // an input for which the real code differs.
                detail = "depends on a function the solver has no model of";
                return Verdict.UNKNOWN;
            }
            if (s == Status.SATISFIABLE) {
                detail = "counterexample: " + brief(solver.getModel());
                return Verdict.REFUTED;
            }
            detail = "solver gave up: " + solver.getReasonUnknown();
            return Verdict.UNKNOWN;
        } catch (UnsupportedOperationException | Z3Exception e) {
            detail = "not modelled: " + e.getMessage();
            return Verdict.UNKNOWN;
        }
    }

    /**
     * Decide a condition that can only go one way. Returns TRUE or FALSE when the condition has
     * that value for every input, and null otherwise.
     */
    public Boolean constantTruth(decompfuncutils.refine.ast.Expr cond, State st) {
        assume.clear();
        detail = "";
        try {
            BoolExpr t = truth(term(cond, st));
            if (check(ctx.mkNot(t)) == Status.UNSATISFIABLE) return Boolean.TRUE;
            if (check(t) == Status.UNSATISFIABLE) return Boolean.FALSE;
        } catch (UnsupportedOperationException | Z3Exception e) {
            detail = "not modelled: " + e.getMessage();
        }
        return null;
    }

    private static String brief(Model m) {
        StringBuilder sb = new StringBuilder();
        for (FuncDecl<?> d : m.getConstDecls()) {
            if (sb.length() > 160) { sb.append(" ..."); break; }
            String name = d.getName().toString();
            if (name.equals("mem")) continue;
            int hash = name.indexOf('#');
            com.microsoft.z3.Expr<?> v = m.getConstInterp(d);
            String value = v instanceof BitVecNum n ? "0x" + n.getBigInteger().toString(16) : String.valueOf(v);
            sb.append(sb.length() > 0 ? ", " : "").append(hash < 0 ? name : name.substring(0, hash)).append(" = ").append(value);
        }
        return sb.toString();
    }
}
