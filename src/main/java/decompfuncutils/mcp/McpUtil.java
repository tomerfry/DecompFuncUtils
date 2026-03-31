package decompfuncutils.mcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Shared utilities for MCP tools.
 */
public class McpUtil {

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
}
