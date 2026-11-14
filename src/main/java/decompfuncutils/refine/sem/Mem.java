package decompfuncutils.refine.sem;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 * Memory for concrete runs. Bytes come from, in order: what the run wrote, the program image, and
 * otherwise a value derived from the address and the trial's seed. That last source is what lets
 * two independent runs (two versions of the code, or the code and the machine emulator) see the
 * same "unknown" memory without sharing any state.
 */
public final class Mem {
    public final Map<Long, Byte> written = new TreeMap<>();
    /** String literals the interpreted code mentions, placed at addresses of their own. */
    private final Map<Long, Byte> literals = new TreeMap<>();
    private final Program program;
    private final long seed;
    /** One byte in this many is zero, so string loops terminate; 0 turns the bias off. */
    private final int zeroEvery;
    private final boolean bigEndian;

    public Mem(Program program, long seed, int zeroEvery) {
        this.program = program;
        this.seed = seed;
        this.zeroEvery = zeroEvery;
        this.bigEndian = program != null && program.getLanguage().isBigEndian();
    }

    public boolean bigEndian() { return bigEndian; }

    /** The byte unwritten, non-image memory holds at {@code addr} for a given seed. */
    public static int lazyByte(long seed, int zeroEvery, long addr) {
        long h = CEval.mix(seed ^ (addr * 0x100000001b3L));
        if (zeroEvery > 0 && Long.remainderUnsigned(h >>> 40, zeroEvery) == 0) return 0;
        return (int) (h & 0xff);
    }

    public int readByte(long addr) {
        Byte w = written.get(addr);
        if (w != null) return w & 0xff;
        Byte lit = literals.get(addr);
        if (lit != null) return lit & 0xff;
        Integer image = imageByte(addr);
        return image != null ? image : lazyByte(seed, zeroEvery, addr);
    }

    /** Byte of the program image at {@code addr}, or null when the image does not define it. */
    public Integer imageByte(long addr) {
        if (program == null) return null;
        try {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address a = space.getAddress(addr);
            MemoryBlock block = program.getMemory().getBlock(a);
            if (block == null || !block.isInitialized()) return null;
            return program.getMemory().getByte(a) & 0xff;
        } catch (Exception e) {
            return null;
        }
    }

    public void writeByte(long addr, int value) { written.put(addr, (byte) value); }

    /**
     * Address of a string literal's bytes (a terminating zero is appended). The same text always
     * gets the same address, so two runs agree on it.
     */
    public long literal(byte[] bytes, boolean wide) {
        long h = CEval.mix(java.util.Arrays.hashCode(bytes) * 0x9e3779b97f4a7c15L + bytes.length);
        long base = wide ? 0x6f00_0000_0000L + ((h >>> 16 & 0xff_ffffL) << 12) : 0x6f00_0000L + ((h >>> 16 & 0xfffL) << 12);
        for (int i = 0; i < bytes.length; i++) literals.put(base + i, bytes[i]);
        literals.put(base + bytes.length, (byte) 0);
        return base;
    }

    public BigInteger read(long addr, int bytes) {
        BigInteger v = BigInteger.ZERO;
        for (int i = 0; i < bytes; i++) {
            int b = readByte(addr + (bigEndian ? i : bytes - 1 - i));
            v = v.shiftLeft(8).or(BigInteger.valueOf(b));
        }
        return v;
    }

    public void write(long addr, int bytes, BigInteger value) {
        for (int i = 0; i < bytes; i++) {
            int b = value.shiftRight(8 * (bigEndian ? bytes - 1 - i : i)).intValue() & 0xff;
            writeByte(addr + i, b);
        }
    }
}
