package decompfuncutils.refine.sem;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import ghidra.program.model.listing.Function;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Concrete interpreter for the refinement AST. It exists to compare things: a fragment before and
 * after a rewrite, or a whole refined function against the machine code under the emulator.
 * Whatever it cannot model raises {@link Unsupported}, which callers report as "not checked" --
 * never as agreement.
 */
public final class CInterp {
    /** The code uses something the interpreter has no model for. */
    public static final class Unsupported extends RuntimeException {
        public Unsupported(String message) { super(message, null, false, false); }
    }

    /** The run exceeded its step budget (a long or endless loop for these inputs). */
    public static final class Budget extends RuntimeException {
        public Budget() { super("step budget exceeded", null, false, false); }
    }

    /** Supplies the body of a program function the interpreted code calls; null when unavailable. */
    public interface Resolver { CFunction resolve(Function callee); }

    public enum Calls { FAIL, STUB }
    public enum Flow { NORMAL, BREAK, CONTINUE, RETURN }

    public final Map<String, BigInteger> env = new HashMap<>();
    /** Values the run invented for variables it read before anything assigned them. */
    public final Map<String, BigInteger> inputs = new HashMap<>();
    public final Mem mem;
    /** Calls made to functions that were stubbed, in order, with their arguments. */
    public final List<String> callLog;
    public BigInteger returnValue;

    private final CFunction fn;
    private final long seed;
    private final Resolver resolver;
    private final Calls calls;
    private final int depth;
    private final int[] steps;
    private final int maxSteps;
    private final Map<String, Long> frame = new HashMap<>();
    private long frameTop;

    public CInterp(CFunction fn, Mem mem, long seed, int maxSteps, Calls calls, Resolver resolver) {
        this(fn, mem, seed, new int[1], maxSteps, calls, resolver, 0, new ArrayList<>());
    }

    private CInterp(CFunction fn, Mem mem, long seed, int[] steps, int maxSteps, Calls calls, Resolver resolver,
            int depth, List<String> callLog) {
        this.fn = fn;
        this.mem = mem;
        this.seed = seed;
        this.steps = steps;
        this.maxSteps = maxSteps;
        this.calls = calls;
        this.resolver = resolver;
        this.depth = depth;
        this.callLog = callLog;
        boolean wide = fn == null || fn.pointerBits == 64;
        this.frameTop = (wide ? 0x7ffd_4000_0000L : 0x7fd0_0000L) - depth * 0x10_0000L;
        if (fn != null) layoutFrame();
    }

    /** Locals that live in memory: aggregates, and scalars whose address is taken. */
    private void layoutFrame() {
        Set<String> addressed = new HashSet<>();
        collectAddressed(fn.body, addressed);
        for (CFunction.Var v : fn.vars.values()) {
            if (v.type.isAggregate() || addressed.contains(v.name)) {
                int size = Math.max(1, v.type.byteSize());
                frameTop -= (size + 15) & ~15L;
                frame.put(v.name, frameTop);
            }
        }
    }

    private static void collectAddressed(Stmt s, Set<String> out) {
        for (Expr e : s.exprs()) collectAddressed(e, out);
        if (s instanceof Stmt.Block b) for (Stmt c : b.body) collectAddressed(c, out);
        for (Stmt.Block b : s.blocks()) collectAddressed(b, out);
    }

    private static void collectAddressed(Expr e, Set<String> out) {
        if (e instanceof Un u && u.o.equals("&")) {
            Expr root = u.e;
            while (root instanceof Member m && !m.arrow || root instanceof Index) root = root.kid(0);
            if (root instanceof Id id) out.add(id.name);
        }
        for (int i = 0; i < e.kids(); i++) collectAddressed(e.kid(i), out);
    }

    // ------------------------------------------------------------------ inputs

    /**
     * The value an unset variable has in a trial. Derived from the seed and the name only, so two
     * runs of different code agree on it. Biased toward the values that expose arithmetic
     * mistakes: zero, small numbers, and the extremes of the type.
     */
    public static BigInteger initial(long seed, String name, CType type) {
        int bits = type.bits;
        long h = CEval.mix(seed * 31 + name.hashCode());
        long r = CEval.mix(h);
        BigInteger random = new BigInteger(Long.toUnsignedString(r)).shiftLeft(64).or(new BigInteger(Long.toUnsignedString(CEval.mix(r))));
        if (type.isPointer()) {
            // A plausible, well separated address.
            return CEval.mask(BigInteger.valueOf(0x10_0000_0000L + ((h >>> 8 & 0xffff) << 16)), bits);
        }
        if (type.isBool()) return BigInteger.valueOf(h & 1);
        switch ((int) (h & 15)) {
            case 0: return BigInteger.ZERO;
            case 1: return BigInteger.ONE;
            case 2: return CEval.mask(BigInteger.ONE.negate(), bits);
            case 3: return BigInteger.ONE.shiftLeft(bits - 1);
            case 4: return BigInteger.ONE.shiftLeft(bits - 1).subtract(BigInteger.ONE);
            // Small values dominate: they are what loop bounds and indices look like, and a
            // trial whose loop runs 2^60 times tells nothing.
            case 5, 6, 7, 8, 9, 10: return BigInteger.valueOf(r & 31);
            case 11: return CEval.mask(BigInteger.valueOf(-(r & 31)), bits);
            case 12: return CEval.mask(BigInteger.valueOf(r & 0xffff), bits);
            default: return CEval.mask(random, bits);
        }
    }

    private BigInteger read(String name, CType type) {
        BigInteger v = env.get(name);
        if (v == null) {
            v = initial(seed, name, type);
            env.put(name, v);
            inputs.put(name, v);
        }
        return CEval.mask(v, type.bits);
    }

    // ------------------------------------------------------------------ expressions

    private static int bits(Expr e) {
        if (!e.type.isScalarInt()) throw new Unsupported("no integer width for " + CPrinter.text(e));
        return e.type.bits;
    }

    private void tick() { if (++steps[0] > maxSteps) throw new Budget(); }

    public BigInteger eval(Expr e) {
        switch (e) {
            case Lit l -> {
                if (l.kind == Lit.Kind.STRING && l.value != null) return CEval.mask(l.value, bits(l));
                if (l.kind == Lit.Kind.STRING && l.text != null && l.text.startsWith("\"")) {
                    return BigInteger.valueOf(mem.literal(decode(l.text), fn == null || fn.pointerBits == 64));
                }
                if (!l.isInt()) throw new Unsupported("non-integer literal " + l.text);
                return CEval.mask(l.value, bits(l));
            }
            case Id id -> {
                if (id.kind == Id.Kind.FUNC) {
                    if (id.function == null) throw new Unsupported("address of unknown function " + id.name);
                    return BigInteger.valueOf(id.function.getEntryPoint().getOffset());
                }
                Long slot = frame.get(id.name);
                if (slot != null) return id.type.isAggregate() ? BigInteger.valueOf(slot) : mem.read(slot, id.type.byteSize());
                if (id.kind == Id.Kind.GLOBAL) {
                    if (id.storage == null) throw new Unsupported("global without storage " + id.name);
                    if (id.type.isAggregate()) return BigInteger.valueOf(id.storage.getOffset());
                    return mem.read(id.storage.getOffset(), Math.max(1, bits(id) / 8));
                }
                if (id.kind == Id.Kind.META) throw new Unsupported("unbound metavariable $" + id.name);
                return read(id.name, typeOf(id));
            }
            case Un u -> {
                switch (u.o) {
                    case "*": return mem.read(eval(u.e).longValue(), Math.max(1, bits(u) / 8));
                    case "&": return BigInteger.valueOf(addressOf(u.e));
                    case "++", "--": {
                        BigInteger old = eval(u.e);
                        long step = u.e.type.isPointer() ? Math.max(1, u.e.type.elemSize) : 1;
                        BigInteger now = CEval.mask(u.o.equals("++") ? old.add(BigInteger.valueOf(step)) : old.subtract(BigInteger.valueOf(step)), bits(u.e));
                        store(u.e, now);
                        return u.postfix ? old : now;
                    }
                    case "!": return eval(u.e).signum() == 0 ? BigInteger.ONE : BigInteger.ZERO;
                    default: return CEval.unary(u.o, CEval.convert(eval(u.e), u.e.type, bits(u)), bits(u));
                }
            }
            case Bin b -> { return binary(b); }
            case Assign a -> {
                BigInteger v;
                if (a.o.equals("=")) v = CEval.convert(eval(a.r), a.r.type, bits(a.l));
                else {
                    String o = a.o.substring(0, a.o.length() - 1);
                    int w = bits(a.l);
                    BigInteger x = eval(a.l), y = eval(a.r);
                    boolean shift = o.equals("<<") || o.equals(">>");
                    if (!shift) {
                        y = CEval.convert(y, a.r.type, w);
                        if (a.l.type.isPointer() && a.l.type.elemSize > 1 && (o.equals("+") || o.equals("-"))) {
                            y = CEval.mask(y.multiply(BigInteger.valueOf(a.l.type.elemSize)), w);
                        }
                    }
                    v = CEval.binary(o, x, y, w, a.l.type.signed);
                }
                store(a.l, v);
                return v;
            }
            case Cond c -> {
                Expr pick = eval(c.c).signum() != 0 ? c.a : c.b;
                return CEval.convert(eval(pick), pick.type, bits(c));
            }
            case Cast c -> {
                if (c.type.isFloat() || c.e.type.isFloat()) throw new Unsupported("floating point");
                if (c.e.type.isAggregate()) return CEval.mask(eval(c.e), bits(c));
                return CEval.convert(eval(c.e), c.e.type, bits(c));
            }
            case Index ix -> { return mem.read(addressOf(ix), Math.max(1, bits(ix) / 8)); }
            case Member m -> {
                if (m.offset < 0) throw new Unsupported("field without offset ." + m.field);
                if (!m.arrow && !hasAddress(m.base)) {
                    // A piece of a value held in a register-like variable: x._4_2_
                    return CEval.mask(eval(m.base).shiftRight(8 * m.offset), bits(m));
                }
                return mem.read(addressOf(m), Math.max(1, bits(m) / 8));
            }
            case Call c -> { return call(c); }
            default -> throw new Unsupported("expression " + CPrinter.text(e));
        }
    }

    private CType typeOf(Id id) {
        if (id.type.isScalarInt()) return id.type;
        CType declared = fn == null ? null : fn.typeOf(id.name);
        if (declared != null && declared.isScalarInt()) return declared;
        throw new Unsupported("no integer width for " + id.name);
    }

    private BigInteger binary(Bin b) {
        switch (b.o) {
            case "&&": return eval(b.l).signum() != 0 && eval(b.r).signum() != 0 ? BigInteger.ONE : BigInteger.ZERO;
            case "||": return eval(b.l).signum() != 0 || eval(b.r).signum() != 0 ? BigInteger.ONE : BigInteger.ZERO;
            case ",": eval(b.l); return eval(b.r);
            default: break;
        }
        BigInteger l = eval(b.l), r = eval(b.r);
        if (b.l.type.isFloat() || b.r.type.isFloat() || b.type.isFloat()) throw new Unsupported("floating point");
        if (Typer.COMPARE.contains(b.o)) {
            int w = Math.max(bits(b.l), bits(b.r));
            return CEval.compare(b.o, CEval.convert(l, b.l.type, w), CEval.convert(r, b.r.type, w), w, b.sgn)
                ? BigInteger.ONE : BigInteger.ZERO;
        }
        int w = bits(b);
        if (b.o.equals("<<") || b.o.equals(">>")) {
            // A right shift works on the left operand's own width, then the result is resized.
            int lw = bits(b.l);
            if (b.o.equals(">>") && lw != w) return CEval.convert(CEval.binary(">>", l, r, lw, b.sgn), b.l.type, w);
            return CEval.binary(b.o, CEval.convert(l, b.l.type, w), r, w, b.sgn);
        }
        BigInteger x = CEval.convert(l, b.l.type, w), y = CEval.convert(r, b.r.type, w);
        if (b.scale > 1) {
            BigInteger k = BigInteger.valueOf(b.scale);
            if (b.o.equals("+") && b.r.type.isPointer() && !b.l.type.isPointer()) x = CEval.mask(x.multiply(k), w);
            else y = CEval.mask(y.multiply(k), w);
        }
        return CEval.binary(b.o, x, y, w, b.sgn);
    }

    private boolean hasAddress(Expr e) {
        return switch (e) {
            case Id id -> frame.containsKey(id.name) || id.kind == Id.Kind.GLOBAL;
            case Un u -> u.o.equals("*");
            case Index ix -> true;
            case Member m -> m.arrow || hasAddress(m.base);
            default -> false;
        };
    }

    private long addressOf(Expr e) {
        switch (e) {
            case Id id -> {
                Long slot = frame.get(id.name);
                if (slot != null) return slot;
                if (id.kind == Id.Kind.GLOBAL && id.storage != null) return id.storage.getOffset();
                if (id.kind == Id.Kind.FUNC && id.function != null) return id.function.getEntryPoint().getOffset();
                throw new Unsupported("address of " + id.name);
            }
            case Un u -> {
                if (u.o.equals("*")) return eval(u.e).longValue();
                throw new Unsupported("address of " + CPrinter.text(e));
            }
            case Index ix -> {
                long base = ix.base.type.isAggregate() || !ix.base.type.isScalarInt() ? addressOf(ix.base) : eval(ix.base).longValue();
                int elem = ix.base.type.elemSize > 0 ? ix.base.type.elemSize : Math.max(1, ix.type.byteSize());
                BigInteger i = eval(ix.index);
                long index = CEval.signed(i, bits(ix.index)).longValue();
                return base + index * elem;
            }
            case Member m -> {
                if (m.offset < 0) throw new Unsupported("field without offset ." + m.field);
                return (m.arrow ? eval(m.base).longValue() : addressOf(m.base)) + m.offset;
            }
            case Cast c -> { return addressOf(c.e); }
            default -> throw new Unsupported("address of " + CPrinter.text(e));
        }
    }

    private void store(Expr target, BigInteger value) {
        switch (target) {
            case Id id -> {
                Long slot = frame.get(id.name);
                if (slot != null) mem.write(slot, Math.max(1, id.type.byteSize()), value);
                else if (id.kind == Id.Kind.GLOBAL) {
                    if (id.storage == null) throw new Unsupported("global without storage " + id.name);
                    mem.write(id.storage.getOffset(), Math.max(1, bits(id) / 8), value);
                } else env.put(id.name, CEval.mask(value, typeOf(id).bits));
            }
            case Member m when !m.arrow && !hasAddress(m.base) -> {
                if (m.offset < 0) throw new Unsupported("field without offset ." + m.field);
                int w = bits(m.base), shift = 8 * m.offset;
                BigInteger hole = BigInteger.ONE.shiftLeft(bits(m)).subtract(BigInteger.ONE).shiftLeft(shift);
                BigInteger merged = eval(m.base).andNot(hole).or(CEval.mask(value, bits(m)).shiftLeft(shift));
                store(m.base, CEval.mask(merged, w));
            }
            case Un u when u.o.equals("*") -> mem.write(eval(u.e).longValue(), Math.max(1, bits(u) / 8), value);
            case Index ix -> mem.write(addressOf(ix), Math.max(1, bits(ix) / 8), value);
            case Member m -> mem.write(addressOf(m), Math.max(1, bits(m) / 8), value);
            default -> throw new Unsupported("assignment to " + CPrinter.text(target));
        }
    }

    // ------------------------------------------------------------------ calls

    private BigInteger call(Call c) {
        tick();
        String name = c.name();
        List<BigInteger> args = new ArrayList<>();
        List<CType> types = new ArrayList<>();
        for (Expr a : c.args) {
            args.add(eval(a));
            types.add(a.type);
        }
        int w = c.type.isScalarInt() ? c.type.bits : 0;
        if (name != null && Builtins.isPure(name)) {
            if (w == 0) throw new Unsupported("no width for " + name);
            return Builtins.eval(name, args, types, w);
        }
        if (name != null && Builtins.MEMORY.contains(name) && (c.fn instanceof Id id && id.function == null)) {
            return memoryBuiltin(name, args, w);
        }
        Function target = c.fn instanceof Id id ? id.function : null;
        if (target != null && resolver != null && !target.isExternal() && !target.isThunk() && depth < 8) {
            CFunction body = resolver.resolve(target);
            if (body != null) {
                CInterp inner = new CInterp(body, mem, seed, steps, maxSteps, calls, resolver, depth + 1, callLog);
                for (int i = 0; i < body.params.size() && i < args.size(); i++) {
                    CFunction.Var p = body.params.get(i);
                    if (!p.type.isScalarInt()) throw new Unsupported("non-scalar parameter " + p.name);
                    inner.env.put(p.name, CEval.convert(args.get(i), types.get(i), p.type.bits));
                }
                Flow flow = inner.exec(body.body);
                if (w == 0) return BigInteger.ZERO;
                if (flow != Flow.RETURN || inner.returnValue == null) throw new Unsupported(target.getName() + " returned no value");
                return CEval.convert(inner.returnValue, body.returnType.isScalarInt() ? body.returnType : c.type, w);
            }
        }
        if (calls == Calls.STUB && name != null) {
            long h = name.hashCode();
            StringBuilder log = new StringBuilder(name).append('(');
            for (int i = 0; i < args.size(); i++) {
                h = CEval.mix(h ^ args.get(i).longValue());
                log.append(i > 0 ? "," : "").append(args.get(i).toString(16));
            }
            callLog.add(log.append(')').toString());
            return w == 0 ? BigInteger.ZERO : CEval.mask(new BigInteger(Long.toUnsignedString(CEval.mix(h))), w);
        }
        throw new Unsupported("call to " + (name == null ? "computed target" : name));
    }

    private BigInteger memoryBuiltin(String name, List<BigInteger> args, int w) {
        long a0 = args.get(0).longValue();
        switch (name) {
            case "strlen": {
                long n = 0;
                while (mem.readByte(a0 + n) != 0) { n++; tick(); }
                return CEval.mask(BigInteger.valueOf(n), w == 0 ? 64 : w);
            }
            case "memset": {
                BigInteger n = args.get(2);
                if (n.bitLength() > 24) throw new Budget();
                int v = args.get(1).intValue() & 0xff;
                for (long i = 0; i < n.longValue(); i++) { mem.writeByte(a0 + i, v); tick(); }
                return w == 0 ? BigInteger.ZERO : CEval.mask(args.get(0), w);
            }
            case "memcpy", "memmove": {
                BigInteger n = args.get(2);
                if (n.bitLength() > 24) throw new Budget();
                long src = args.get(1).longValue(), len = n.longValue();
                if (name.equals("memmove") && Long.compareUnsigned(a0, src) > 0) {
                    for (long i = len - 1; i >= 0; i--) { mem.writeByte(a0 + i, mem.readByte(src + i)); tick(); }
                } else {
                    for (long i = 0; i < len; i++) { mem.writeByte(a0 + i, mem.readByte(src + i)); tick(); }
                }
                return w == 0 ? BigInteger.ZERO : CEval.mask(args.get(0), w);
            }
            case "strcpy": {
                long src = args.get(1).longValue();
                for (long i = 0; ; i++) {
                    int b = mem.readByte(src + i);
                    mem.writeByte(a0 + i, b);
                    tick();
                    if (b == 0) break;
                }
                return w == 0 ? BigInteger.ZERO : CEval.mask(args.get(0), w);
            }
            case "strncpy": {
                BigInteger n = args.get(2);
                if (n.bitLength() > 24) throw new Budget();
                long src = args.get(1).longValue();
                boolean ended = false;
                for (long i = 0; i < n.longValue(); i++) {
                    int b = ended ? 0 : mem.readByte(src + i);
                    if (b == 0) ended = true;
                    mem.writeByte(a0 + i, b);
                    tick();
                }
                return w == 0 ? BigInteger.ZERO : CEval.mask(args.get(0), w);
            }
            default: throw new Unsupported("call to " + name);
        }
    }

    /** Bytes of a C string literal as printed (quotes included), escapes resolved. */
    public static byte[] decode(String literal) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        String s = literal.substring(1, literal.length() - 1);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != 92 || i + 1 >= s.length()) { out.writeBytes(String.valueOf(c).getBytes(java.nio.charset.StandardCharsets.UTF_8)); continue; }
            char e = s.charAt(++i);
            switch (e) {
                case 'n' -> out.write(10);
                case 't' -> out.write(9);
                case 'r' -> out.write(13);
                case 'a' -> out.write(7);
                case 'b' -> out.write(8);
                case 'f' -> out.write(12);
                case 'v' -> out.write(11);
                case 'x' -> {
                    int j = i + 1, v = 0;
                    while (j < s.length() && j < i + 3 && Character.digit(s.charAt(j), 16) >= 0) v = v * 16 + Character.digit(s.charAt(j++), 16);
                    out.write(v);
                    i = j - 1;
                }
                default -> {
                    if (e >= '0' && e <= '7') {
                        int j = i, v = 0;
                        while (j < s.length() && j < i + 3 && s.charAt(j) >= '0' && s.charAt(j) <= '7') v = v * 8 + (s.charAt(j++) - '0');
                        out.write(v);
                        i = j - 1;
                    } else out.write(e);
                }
            }
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ statements

    public Flow exec(Stmt s) {
        tick();
        switch (s) {
            case Stmt.Block b -> { return execAll(b.body, 0); }
            case Stmt.ExprStmt e -> { eval(e.e); return Flow.NORMAL; }
            case Stmt.If i -> {
                if (eval(i.cond).signum() != 0) return exec(i.then);
                return i.otherwise == null ? Flow.NORMAL : exec(i.otherwise);
            }
            case Stmt.While w -> {
                while (eval(w.cond).signum() != 0) {
                    Flow f = exec(w.body);
                    if (f == Flow.BREAK) break;
                    if (f == Flow.RETURN) return f;
                }
                return Flow.NORMAL;
            }
            case Stmt.DoWhile d -> {
                do {
                    Flow f = exec(d.body);
                    if (f == Flow.BREAK) break;
                    if (f == Flow.RETURN) return f;
                } while (eval(d.cond).signum() != 0);
                return Flow.NORMAL;
            }
            case Stmt.For f -> {
                if (f.init != null) eval(f.init);
                while (f.cond == null || eval(f.cond).signum() != 0) {
                    Flow flow = exec(f.body);
                    if (flow == Flow.BREAK) break;
                    if (flow == Flow.RETURN) return flow;
                    if (f.step != null) eval(f.step);
                    tick();
                }
                return Flow.NORMAL;
            }
            case Stmt.Switch sw -> {
                BigInteger v = eval(sw.e);
                int w = bits(sw.e), start = -1, fallback = -1;
                List<Stmt> body = sw.body.body;
                for (int i = 0; i < body.size() && start < 0; i++) {
                    if (!(body.get(i) instanceof Stmt.CaseLabel c)) continue;
                    if (c.value == null) fallback = i;
                    else if (CEval.convert(eval(c.value), c.value.type, w).equals(v)) start = i;
                }
                if (start < 0) start = fallback;
                if (start < 0) return Flow.NORMAL;
                Flow flow = execAll(body, start);
                return flow == Flow.BREAK ? Flow.NORMAL : flow;
            }
            case Stmt.Return r -> {
                returnValue = null;
                if (r.e != null) {
                    BigInteger v = eval(r.e);
                    returnValue = fn != null && fn.returnType.isScalarInt() && r.e.type.isScalarInt()
                        ? CEval.convert(v, r.e.type, fn.returnType.bits) : v;
                }
                return Flow.RETURN;
            }
            case Stmt.Break b -> { return Flow.BREAK; }
            case Stmt.Continue c -> { return Flow.CONTINUE; }
            case Stmt.CaseLabel c -> { return Flow.NORMAL; }
            case Stmt.Label l -> { return Flow.NORMAL; }
            case Stmt.Comment c -> { return Flow.NORMAL; }
            default -> throw new Unsupported("statement " + s.getClass().getSimpleName());
        }
    }

    private Flow execAll(List<Stmt> body, int from) {
        for (int i = from; i < body.size(); i++) {
            Flow f = exec(body.get(i));
            if (f != Flow.NORMAL) return f;
        }
        return Flow.NORMAL;
    }
}
