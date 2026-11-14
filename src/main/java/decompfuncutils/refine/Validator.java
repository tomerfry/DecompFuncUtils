package decompfuncutils.refine;

import decompfuncutils.refine.RefineResult.Validation;
import decompfuncutils.refine.ast.CFunction;
import decompfuncutils.refine.sem.CEval;
import decompfuncutils.refine.sem.CInterp;
import decompfuncutils.refine.sem.MachineEmu;
import decompfuncutils.refine.sem.Mem;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * The end-to-end check: the function's machine code under the emulator against the refined C
 * under the interpreter, on the same arguments and the same memory. Per-rewrite verification
 * shows each step was sound; this shows the steps add up to the binary's behaviour -- and it does
 * not share the decompiler's own assumptions, because one side is the instructions themselves.
 *
 * <p>What is compared: the returned value, and the final contents of every byte either side wrote
 * outside its stack frame. A function that calls something the emulator cannot run (an import),
 * or that the interpreter cannot model, is reported as not checked rather than as agreeing.
 */
final class Validator {
    private Validator() {}

    static Validation run(CFunction fn, RefineEngine engine, RefineConfig cfg, TaskMonitor monitor) {
        Validation v = new Validation();
        if (fn.function == null || fn.high == null) return skip(v, "no function to emulate");
        FunctionPrototype proto = fn.high.getFunctionPrototype();
        List<VariableStorage> storage = new ArrayList<>();
        for (CFunction.Var p : fn.params) {
            if (!p.type.isScalarInt()) return skip(v, "parameter " + p.name + " is not an integer or pointer");
            if (p.symbol == null || p.symbol.getStorage() == null) return skip(v, "parameter " + p.name + " has no storage");
            storage.add(p.symbol.getStorage());
        }
        VariableStorage returnStorage = null;
        boolean returns = fn.returnType.isScalarInt();
        if (returns) {
            returnStorage = proto == null ? null : proto.getReturnStorage();
            if (returnStorage == null || !returnStorage.isRegisterStorage()) return skip(v, "the return value is not in a register");
        }
        int[] zero = {0, 3, 9, 40};
        CInterp.Resolver resolver = callee -> engine.body(callee, monitor);
        for (int t = 0; t < cfg.validateTrials; t++) {
            if (monitor != null && monitor.isCancelled()) break;
            long seed = CEval.mix(0x7a11da7eL + t * 0x9e3779b97f4a7c15L);
            int zeroEvery = zero[t % zero.length];
            List<BigInteger> args = new ArrayList<>();
            for (CFunction.Var p : fn.params) args.add(CInterp.initial(seed, p.name, p.type));

            Mem mem = new Mem(fn.program, seed, zeroEvery);
            CInterp interp = new CInterp(fn, mem, seed, cfg.maxSteps, CInterp.Calls.FAIL, resolver);
            BigInteger refined = null;
            try {
                // Parameters are read through the interpreter's own initial(), i.e. the same values.
                interp.exec(fn.body);
                refined = interp.returnValue;
            } catch (CInterp.Unsupported e) {
                return skip(v, "the interpreter cannot model this function: " + e.getMessage());
            } catch (CInterp.Budget | CEval.Fault | ArithmeticException e) {
                continue;   // too long, or traps, for these inputs
            }
            MachineEmu.Run machine = MachineEmu.call(fn.program, fn.function, storage, args, returnStorage, seed, zeroEvery,
                cfg.validateMaxInstructions, false, monitor);
            if (machine.problem != null) {
                if (machine.inconclusive) continue;
                return skip(v, machine.problem);
            }
            v.trials++;
            String diff = null;
            if (returns) {
                int bits = fn.returnType.bits;
                BigInteger want = CEval.mask(machine.returnValue, bits);
                if (refined == null) diff = "the refined code returns nothing where the machine code returns 0x" + want.toString(16);
                else if (!CEval.mask(refined, bits).equals(want)) {
                    diff = "returns 0x" + CEval.mask(refined, bits).toString(16) + " where the machine code returns 0x" + want.toString(16);
                }
            }
            if (diff == null) {
                TreeSet<Long> touched = new TreeSet<>(machine.written.keySet());
                for (Long a : mem.written.keySet()) if (!isInterpFrame(fn, a)) touched.add(a);
                Mem pristine = new Mem(fn.program, seed, zeroEvery);
                for (Long a : touched) {
                    Byte m = machine.written.get(a);
                    int machineByte = m != null ? m & 0xff : pristine.readByte(a);
                    int refinedByte = mem.readByte(a);
                    if (machineByte != refinedByte) {
                        diff = String.format("byte at 0x%x ends as 0x%02x where the machine code leaves 0x%02x", a, refinedByte, machineByte);
                        break;
                    }
                }
            }
            if (diff != null) {
                v.outcome = Validation.Outcome.DIFFERS;
                v.detail = diff + " for " + describe(fn, args);
                return v;
            }
            v.agreed++;
        }
        if (v.agreed > 0) v.outcome = Validation.Outcome.AGREES;
        else skip(v, "no trial ran to completion on both sides");
        return v;
    }

    /** Addresses the interpreter gave to address-taken locals; the machine keeps those on its own stack. */
    private static boolean isInterpFrame(CFunction fn, long addr) {
        long top = fn.pointerBits == 64 ? 0x7ffd_4000_0000L : 0x7fd0_0000L;
        return Long.compareUnsigned(addr, top - 0x1000_0000L) >= 0 && Long.compareUnsigned(addr, top) < 0;
    }

    private static Validation skip(Validation v, String why) {
        v.outcome = Validation.Outcome.NOT_CHECKED;
        v.detail = why;
        return v;
    }

    private static String describe(CFunction fn, List<BigInteger> args) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < args.size(); i++) {
            sb.append(i > 0 ? ", " : "").append(fn.params.get(i).name).append("=0x").append(args.get(i).toString(16));
        }
        return sb.length() == 0 ? "no arguments" : sb.toString();
    }
}
