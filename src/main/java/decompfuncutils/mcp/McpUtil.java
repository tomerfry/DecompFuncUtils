package decompfuncutils.mcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Shared utilities for MCP tools.
 */
public class McpUtil {

    /**
     * Per-request cancellable monitor injected by the MCP protocol handler so
     * tools can run cooperatively-cancellable work (e.g. long-running taint
     * analysis over many functions). Tools should prefer this over
     * {@link TaskMonitor#DUMMY} when they have a polling loop.
     */
    private static final ThreadLocal<TaskMonitor> ACTIVE_MONITOR = new ThreadLocal<>();

    public static void setActiveMonitor(TaskMonitor monitor) {
        if (monitor == null) {
            ACTIVE_MONITOR.remove();
        } else {
            ACTIVE_MONITOR.set(monitor);
        }
    }

    /**
     * Returns the active per-request monitor, or {@link TaskMonitor#DUMMY} when
     * none has been installed (e.g. when a tool is invoked outside the MCP
     * dispatcher).
     */
    public static TaskMonitor activeMonitor() {
        TaskMonitor m = ACTIVE_MONITOR.get();
        return m == null ? TaskMonitor.DUMMY : m;
    }

    /**
     * Resolve the decompile timeout in seconds, treating -1, 0, or any
     * non-positive number from the caller as "no timeout" (mapped to
     * Integer.MAX_VALUE so the decompiler call doesn't truncate work).
     * Defaults to {@code defaultSeconds} when no override is supplied.
     */
    public static int resolveDecompileTimeout(Object override, int defaultSeconds) {
        if (override == null) return defaultSeconds;
        if (!(override instanceof Number)) return defaultSeconds;
        int v = ((Number) override).intValue();
        if (v <= 0) return Integer.MAX_VALUE;
        return v;
    }

    /**
     * Parse a hex address string (with or without "0x" prefix) into a Ghidra Address.
     */
    public static Address parseAddress(String addrStr, Program program) {
        if (addrStr == null || addrStr.isEmpty()) {
            throw new IllegalArgumentException("Address string is null or empty");
        }
        // Strip 0x prefix if present
        String cleaned = addrStr.strip().replaceFirst("^0[xX]", "");
        Address addr = program.getAddressFactory().getAddress(cleaned);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + addrStr);
        }
        return addr;
    }

    /**
     * Convert a raw pointer value read from memory into a code address, normalizing
     * the ARM Thumb low-bit marker. ARM/THUMB function pointers store the entry
     * with bit 0 set so BX/BLX switches to Thumb; the actual function symbol lives
     * at the even address.
     */
    public static Address normalizeCodePointer(long value, AddressSpace space) {
        return space.getAddress(value & ~1L);
    }

    /**
     * Resolve the function targeted by a raw pointer value, transparently clearing
     * the Thumb bit when the raw address has no function but the cleared one does.
     * Returns null if no function is found at either address.
     */
    public static Function resolveFunctionFromPointer(long value, AddressSpace space,
                                                       FunctionManager fm) {
        Address raw = space.getAddress(value);
        Function func = fm.getFunctionAt(raw);
        if (func != null) return func;
        if ((value & 1L) != 0) {
            Address aligned = space.getAddress(value & ~1L);
            return fm.getFunctionAt(aligned);
        }
        return null;
    }
}
