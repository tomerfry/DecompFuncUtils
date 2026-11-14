package decompfuncutils.refine.pass;

import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.ast.Expr.*;
import decompfuncutils.refine.sem.CEval;
import decompfuncutils.refine.sem.MachineEmu;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Computes calls whose arguments are all constants by running the callee. Constant-key decoders,
 * table lookups and hash-of-literal helpers are written as calls precisely so the value does not
 * appear in the binary; the emulator can simply produce it.
 *
 * <p>Only a callee that is demonstrably a function of its arguments is evaluated: a leaf, with no
 * references to writable data, that writes nothing outside its own stack frame and returns the
 * same value when memory it should not depend on is filled differently.
 */
public final class ConstCallPass implements RefinePass {
    @Override public String id() { return "const-calls"; }
    @Override public String title() { return "Evaluate calls with constant arguments (emulation)"; }
    @Override public String description() {
        return "Runs a callee's machine code under the emulator when every argument is a constant and the callee is a pure leaf "
            + "function, and replaces the call with the value it returned. The original call stays visible in the rewrite's note.";
    }
    @Override public List<Param> params() {
        return List.of(Param.integer("maxInstructions", "Instruction budget per call", 50000, 100, 5_000_000,
            "A callee that runs longer than this is left as a call."));
    }

    /** Results by program state, callee and arguments. Null values record "could not be evaluated". */
    private final Map<String, BigInteger> cache = java.util.Collections.synchronizedMap(new HashMap<>());

    @Override public boolean run(PassContext ctx) {
        return AstUtil.rewriteAll(ctx.fn.body, e -> {
            if (!(e instanceof Call c) || !(c.fn instanceof Id id) || id.function == null || !c.type.isScalarInt()) return e;
            if (ctx.cancelled()) return e;
            List<BigInteger> args = new ArrayList<>();
            for (Expr a : c.args) {
                if (!(a instanceof Lit l) || !l.isInt() || !l.type.isScalarInt()) return e;
                args.add(l.value);
            }
            Function callee = id.function;
            if (callee.isExternal() || callee.isThunk() || callee.equals(ctx.fn.function)) return e;
            String key = ctx.program.getUniqueProgramID() + ":" + ctx.program.getModificationNumber() + ":" + callee.getEntryPoint() + args;
            BigInteger value = cache.get(key);
            String how = "computed earlier in this session";
            if (value == null && !cache.containsKey(key)) {
                StringBuilder why = new StringBuilder();
                value = evaluate(ctx, callee, c, args, why);
                if (cache.size() > 4096) cache.clear();
                cache.put(key, value);
                how = why.toString();
            }
            if (value == null) return e;
            Lit lit = new Lit(Lit.Kind.INT, CEval.mask(value, c.type.bits), null, c.type.isPointer() || c.type.isBool() ? CType.integer(c.type.bits, false) : c.type);
            lit.addr = c.addr;
            Rewrite rw = ctx.record("evaluated " + callee.getName(), CPrinter.text(c), CPrinter.text(lit), Rewrite.Status.TESTED, how, c.addr);
            lit.note = rw;
            return lit;
        });
    }

    private static BigInteger evaluate(PassContext ctx, Function callee, Call call, List<BigInteger> args, StringBuilder how) {
        CFunction body = ctx.engine.body(callee, ctx.monitor);
        String where = "call to " + callee.getName() + " at " + call.addr;
        if (body == null || body.high == null || body.params.size() != args.size() || !body.returnType.isScalarInt()) {
            ctx.trace(where + ": the callee's parameters or return type do not line up with the call");
            return null;
        }
        if (referencesWritableData(ctx, callee)) {
            ctx.trace(where + ": the callee refers to writable data, so its result is not determined by its arguments");
            return null;
        }
        List<VariableStorage> storage = new ArrayList<>();
        List<BigInteger> values = new ArrayList<>();
        for (int i = 0; i < args.size(); i++) {
            CFunction.Var p = body.params.get(i);
            if (p.symbol == null || p.symbol.getStorage() == null || !p.type.isScalarInt()) return null;
            storage.add(p.symbol.getStorage());
            values.add(CEval.convert(args.get(i), call.args.get(i).type, p.type.bits));
        }
        VariableStorage ret = body.high.getFunctionPrototype() == null ? null : body.high.getFunctionPrototype().getReturnStorage();
        if (ret == null || !ret.isRegisterStorage()) return null;
        int budget = ctx.integer("maxInstructions");
        // Twice, with different contents in every byte the image does not define: a function of
        // its arguments alone cannot tell the difference.
        MachineEmu.Run first = MachineEmu.call(ctx.program, callee, storage, values, ret, 0x1111, 0, budget, true, ctx.monitor);
        if (first.problem != null || !first.written.isEmpty()) {
            ctx.trace(where + ": " + (first.problem != null ? first.problem : "the callee writes memory outside its stack frame"));
            return null;
        }
        MachineEmu.Run second = MachineEmu.call(ctx.program, callee, storage, values, ret, 0x7777_2222L, 3, budget, true, ctx.monitor);
        if (second.problem != null || !second.written.isEmpty() || !second.returnValue.equals(first.returnValue)) {
            ctx.trace(where + ": the result changes with memory the program image does not define");
            return null;
        }
        how.append("emulated ").append(first.instructions).append(" instructions of ").append(callee.getName())
            .append("; a leaf that writes nothing and does not depend on undefined memory");
        return CEval.mask(first.returnValue, body.returnType.bits);
    }

    /** A function that reads a variable global is not a function of its arguments alone. */
    private static boolean referencesWritableData(PassContext ctx, Function callee) {
        int n = 0;
        for (Instruction ins : ctx.program.getListing().getInstructions(callee.getBody(), true)) {
            if (n++ > 4000) return true;
            for (Reference ref : ins.getReferencesFrom()) {
                if (!ref.getReferenceType().isData()) continue;
                Address to = ref.getToAddress();
                if (to == null || !to.isMemoryAddress()) continue;
                MemoryBlock block = ctx.program.getMemory().getBlock(to);
                if (block == null || block.isWrite()) return true;
            }
        }
        return false;
    }
}
