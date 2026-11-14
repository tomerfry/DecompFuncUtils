package decompfuncutils.refine.pass;

import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

/**
 * Reassembles buffer initialization the compiler merged into wide constant stores.
 * {@code strcpy(buf, "DFU1")} or a run of byte assignments reaches the decompiler as
 * {@code *(undefined8 *)buf = 0x31554644}: correct, and unreadable. Consecutive constant stores
 * to one base are laid out as bytes; a run that spells a string, or is all zero, is written as
 * the call it most plausibly was.
 */
public final class StoresPass implements RefinePass {
    @Override public String id() { return "stores"; }
    @Override public String title() { return "Reassemble merged constant stores"; }
    @Override public String description() {
        return "Lays consecutive constant stores to the same base out as bytes. A run that is a string followed by zeros becomes "
            + "strcpy / strncpy with the string spelled out, an all-zero run becomes memset. Tested by running both versions.";
    }
    @Override public List<Param> params() {
        return List.of(
            Param.integer("minBytes", "Smallest run to rewrite (bytes)", 4, 2, 4096, "Shorter runs are left as plain stores."),
            Param.integer("minString", "Shortest string worth naming (characters)", 3, 1, 256, "Fewer printable characters are more likely a number."),
            Param.bool("zeroFill", "Write all-zero runs as memset", true, "Only for runs made of at least two stores."));
    }

    /** One constant store, as a byte range relative to a base pointer. */
    private record Store(Expr base, long offset, int size, BigInteger value, Stmt stmt) {}

    @Override public boolean run(PassContext ctx) {
        boolean changed = false;
        List<Stmt.Block> blocks = new ArrayList<>();
        AstUtil.walk(ctx.fn.body, s -> { if (s instanceof Stmt.Block b) blocks.add(b); });
        for (Stmt.Block block : blocks) {
            for (int i = 0; i < block.body.size(); i++) {
                List<Store> run = new ArrayList<>();
                int j = i;
                for (; j < block.body.size(); j++) {
                    Store st = decompose(block.body.get(j));
                    if (st == null || (!run.isEmpty() && !AstUtil.same(run.get(0).base, st.base))) break;
                    run.add(st);
                }
                if (run.isEmpty()) continue;
                Stmt replacement = rebuild(ctx, run);
                if (replacement != null) {
                    List<Stmt> before = new ArrayList<>();
                    for (Store s : run) before.add(s.stmt);
                    if (ctx.accept(replacement instanceof Stmt.ExprStmt es && es.e instanceof Call c ? c.name() : "stores",
                            before, List.of(replacement), Set.of())) {
                        for (int k = 0; k < run.size(); k++) block.body.remove(i);
                        block.body.add(i, replacement);
                        changed = true;
                        continue;
                    }
                }
                i = j - 1 < i ? i : j - 1;
            }
        }
        return changed;
    }

    private static Expr stripCasts(Expr e) {
        while (e instanceof Cast c && c.type.isPointer()) e = c.e;
        return e;
    }

    private static Store decompose(Stmt s) {
        if (!(s instanceof Stmt.ExprStmt es) || !(es.e instanceof Assign a) || !a.o.equals("=")) return null;
        if (!(a.r instanceof Lit value) || !value.isInt() || !a.l.type.isScalarInt() || a.l.type.bits % 8 != 0) return null;
        int size = a.l.type.bits / 8;
        Expr base;
        long offset;
        if (a.l instanceof Un u && u.o.equals("*")) {
            Expr p = stripCasts(u.e);
            if (p instanceof Bin b && b.o.equals("+") && b.r instanceof Lit k && k.isInt()) {
                base = stripCasts(b.l);
                offset = k.signedValue().longValue() * Math.max(1, b.scale);
            } else {
                base = p;
                offset = 0;
            }
        } else if (a.l instanceof Index ix && ix.index instanceof Lit k && k.isInt() && !ix.base.type.isAggregate()) {
            base = stripCasts(ix.base);
            int elem = ix.base.type.elemSize > 0 ? ix.base.type.elemSize : size;
            offset = k.value.longValue() * elem;
        } else return null;
        if (!AstUtil.isPure(base) || AstUtil.readsMemory(base) || offset < 0 || offset > 0x10000) return null;
        BigInteger v = value.value.mod(BigInteger.ONE.shiftLeft(size * 8));
        return new Store(base, offset, size, v, s);
    }

    private static Stmt rebuild(PassContext ctx, List<Store> run) {
        TreeMap<Long, Integer> bytes = new TreeMap<>();
        for (Store s : run) {
            for (int i = 0; i < s.size; i++) {
                int shift = 8 * (ctx.fn.bigEndian ? s.size - 1 - i : i);
                // A later store over an earlier one wins, as it does in memory.
                bytes.put(s.offset + i, s.value.shiftRight(shift).intValue() & 0xff);
            }
        }
        long lo = bytes.firstKey(), n = bytes.lastKey() - lo + 1;
        if (n != bytes.size() || n < ctx.integer("minBytes")) return null;
        int text = 0;
        while (text < n && printable(bytes.get(lo + text))) text++;
        boolean zerosAfter = true;
        for (long i = text; i < n; i++) zerosAfter &= bytes.get(lo + i) == 0;
        Expr dest = destination(ctx, run.get(0).base, lo);
        Call call;
        if (text == 0 && zerosAfter) {
            if (!ctx.flag("zeroFill") || run.size() < 2) return null;
            call = call("memset", dest, new Lit(BigInteger.ZERO, CType.integer(32, true)), size(ctx, n));
        } else if (zerosAfter && text >= ctx.integer("minString") && text < n) {
            StringBuilder sb = new StringBuilder("\"");
            for (int i = 0; i < text; i++) sb.append(escape(bytes.get(lo + i)));
            Lit literal = new Lit(Lit.Kind.STRING, null, sb.append('"').toString(),
                CType.pointerTo(CType.integer(8, true, "char"), ctx.fn.pointerBits));
            call = n == text + 1 ? call("strcpy", dest, literal) : call("strncpy", dest, literal, size(ctx, n));
        } else return null;
        ctx.typer.retype(call);
        return new Stmt.ExprStmt(call);
    }

    private static boolean printable(int b) { return (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\t'; }

    private static String escape(int b) {
        return switch (b) {
            case '\n' -> "\\n";
            case '\t' -> "\\t";
            case '"' -> "\\\"";
            case '\\' -> "\\\\";
            default -> String.valueOf((char) b);
        };
    }

    private static Expr size(PassContext ctx, long n) {
        return new Lit(BigInteger.valueOf(n), CType.integer(ctx.fn.pointerBits, false));
    }

    private static Expr destination(PassContext ctx, Expr base, long lo) {
        Expr p = base.copy();
        CType chars = CType.pointerTo(CType.integer(8, true, "char"), ctx.fn.pointerBits);
        if (!(p.type.isPointer() && p.type.elemSize <= 1)) p = new Cast(chars, "char *", p);
        if (lo == 0) return p;
        Bin sum = new Bin("+", p, new Lit(BigInteger.valueOf(lo), CType.integer(ctx.fn.pointerBits, true)));
        sum.type = chars;
        return sum;
    }

    private static Call call(String name, Expr... args) { return new Call(new Id(name, Id.Kind.FUNC), List.of(args)); }
}
