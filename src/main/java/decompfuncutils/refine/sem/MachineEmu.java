package decompfuncutils.refine.sem;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Runs one function of the program as machine code under Ghidra's p-code emulator: arguments
 * placed where the calling convention says, a sentinel return address, and memory the image does
 * not define supplied by the same seed-derived source {@link Mem} uses -- so a run here and a run
 * of {@link CInterp} over the refined code start from the same world and can be compared.
 */
@SuppressWarnings("removal")
public final class MachineEmu {
    /** Outcome of one emulated call. */
    public static final class Run {
        /** Null when the function returned normally; otherwise why the run does not count. */
        public String problem;
        /** True when {@link #problem} is about this input only (too long, trapped), not the function. */
        public boolean inconclusive;
        public BigInteger returnValue;
        /** Final value of every byte the function wrote outside its own stack. */
        public final Map<Long, Byte> written = new TreeMap<>();
        public int instructions;
    }

    private static final long STACK_64 = 0x7ffe_f000_0000L, STACK_32 = 0x7fe0_0000L;
    private static final long STACK_SPAN = 0x10_0000L;
    private static final long SENTINEL_64 = 0x5e17_1e10_0000L, SENTINEL_32 = 0x5e17_1000L;

    private MachineEmu() {}

    public static boolean inStack(Program program, long addr) {
        long top = program.getDefaultPointerSize() >= 8 ? STACK_64 : STACK_32;
        return Long.compareUnsigned(addr, top - STACK_SPAN) >= 0 && Long.compareUnsigned(addr, top + STACK_SPAN) < 0;
    }

    /**
     * Call {@code function} with {@code args} stored at {@code storage}.
     *
     * @param returnStorage where the result comes back, or null when nothing is returned
     * @param stopAtCalls refuse to enter any callee (used to establish that a function is a leaf)
     */
    public static Run call(Program program, Function function, List<VariableStorage> storage, List<BigInteger> args,
            VariableStorage returnStorage, long seed, int zeroEvery, int maxInstructions, boolean stopAtCalls, TaskMonitor monitor) {
        Run run = new Run();
        boolean wide = program.getDefaultPointerSize() >= 8;
        int pointer = program.getDefaultPointerSize();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        long sp = wide ? STACK_64 : STACK_32;
        long sentinel = wide ? SENTINEL_64 : SENTINEL_32;
        EmulatorHelper emu = new EmulatorHelper(program);
        try {
            emu.setMemoryFaultHandler(new MemoryFaultHandler() {
                @Override public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
                    if (!address.getAddressSpace().isMemorySpace()) {
                        // Registers and temporaries nobody set read as zero.
                        for (int i = 0; i < size; i++) buf[bufOffset + i] = 0;
                        return true;
                    }
                    for (int i = 0; i < size; i++) buf[bufOffset + i] = (byte) Mem.lazyByte(seed, zeroEvery, address.getOffset() + i);
                    return true;
                }
                @Override public boolean unknownAddress(Address address, boolean write) { return false; }
            });
            Register spReg = emu.getStackPointerRegister(), pcReg = emu.getPCRegister();
            if (spReg == null || pcReg == null) return fail(run, "the processor has no stack pointer or program counter register");
            emu.writeRegister(spReg, BigInteger.valueOf(sp));

            // The return address goes wherever this calling convention keeps it.
            PrototypeModel model = function.getCallingConvention();
            if (model == null) model = program.getCompilerSpec().getDefaultCallingConvention();
            Varnode[] ret = model == null ? null : model.getReturnAddress();
            if (ret == null || ret.length == 0) return fail(run, "the calling convention does not say where the return address is");
            for (Varnode v : ret) {
                if (v.getAddress().isStackAddress()) {
                    emu.writeMemoryValue(space.getAddress(sp + v.getOffset()), v.getSize(), sentinel);
                } else if (v.isRegister()) {
                    Register r = program.getRegister(v.getAddress(), v.getSize());
                    if (r == null) return fail(run, "unknown return-address register");
                    emu.writeRegister(r, BigInteger.valueOf(sentinel));
                } else return fail(run, "unsupported return-address location");
            }
            for (int i = 0; i < storage.size(); i++) {
                VariableStorage s = storage.get(i);
                BigInteger value = args.get(i);
                if (s == null || s.isBadStorage() || s.isUnassignedStorage()) return fail(run, "parameter " + (i + 1) + " has no storage");
                if (s.isRegisterStorage()) emu.writeRegister(s.getRegister(), value);
                else if (s.isStackStorage()) {
                    byte[] bytes = bytes(value, s.size(), program.getLanguage().isBigEndian());
                    emu.writeMemory(space.getAddress(sp + s.getStackOffset()), bytes);
                } else return fail(run, "parameter " + (i + 1) + " is neither in a register nor on the stack");
            }
            emu.enableMemoryWriteTracking(true);
            emu.writeRegister(pcReg, function.getEntryPoint().getOffset());
            TaskMonitor mon = monitor == null ? TaskMonitor.DUMMY : monitor;
            while (true) {
                Address pc = emu.getExecutionAddress();
                if (pc.getOffset() == sentinel) break;
                if (run.instructions >= maxInstructions) return unsure(run, "ran longer than " + maxInstructions + " instructions");
                if (mon.isCancelled()) return unsure(run, "cancelled");
                MemoryBlock block = program.getMemory().getBlock(pc);
                Function at = program.getFunctionManager().getFunctionContaining(pc);
                if (stopAtCalls && at != null && !at.equals(function) && run.instructions > 0) return fail(run, "it calls " + at.getName());
                if (at != null && at.isThunk()) {
                    // A PLT stub: go where the dynamic linker would have pointed it, when that is here.
                    Function real = at.getThunkedFunction(true);
                    if (real != null && !real.isExternal() && !real.isThunk()) {
                        emu.writeRegister(pcReg, real.getEntryPoint().getOffset());
                        continue;
                    }
                }
                if (block == null || !block.isInitialized() || block.isExternalBlock() || (at != null && (at.isThunk() || at.isExternal()))) {
                    return fail(run, "it calls " + (at != null ? at.getName() : "code outside the program at " + pc)
                        + ", which the emulator cannot run");
                }
                if (!emu.step(mon)) return unsure(run, "the machine code faulted at " + pc + ": " + emu.getLastError());
                run.instructions++;
            }
            if (returnStorage != null) {
                if (returnStorage.isRegisterStorage()) {
                    run.returnValue = emu.readRegister(returnStorage.getRegister());
                    if (run.returnValue.signum() < 0) run.returnValue = run.returnValue.mod(BigInteger.ONE.shiftLeft(returnStorage.size() * 8));
                } else return fail(run, "the result is not returned in a register");
            }
            for (AddressRange range : emu.getTrackedMemoryWriteSet()) {
                if (!range.getAddressSpace().isMemorySpace() || range.getAddressSpace().isUniqueSpace()
                        || !range.getAddressSpace().equals(space)) continue;
                long len = range.getLength();
                if (len > 0x10000) return unsure(run, "wrote more than 64 KiB");
                long start = range.getMinAddress().getOffset();
                if (inStack(program, start)) continue;
                byte[] data = emu.readMemory(range.getMinAddress(), (int) len);
                for (int i = 0; i < data.length; i++) if (!inStack(program, start + i)) run.written.put(start + i, data[i]);
            }
            return run;
        } catch (Exception e) {
            return unsure(run, "emulation failed: " + e);
        } finally {
            emu.dispose();
        }
    }

    private static Run fail(Run run, String why) { run.problem = why; return run; }
    private static Run unsure(Run run, String why) { run.problem = why; run.inconclusive = true; return run; }

    private static byte[] bytes(BigInteger value, int size, boolean bigEndian) {
        byte[] out = new byte[size];
        for (int i = 0; i < size; i++) out[bigEndian ? size - 1 - i : i] = value.shiftRight(8 * i).byteValue();
        return out;
    }
}
