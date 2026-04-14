package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.*;

/**
 * One-shot concrete emulation of a function / code range using Ghidra's
 * {@link EmulatorHelper}. Optionally records conditional-branch outcomes
 * from the single concrete run (tier-1 "constraint" observations).
 */
public class EmulateFunctionTool implements McpTool {

    private static final int DEFAULT_MAX_STEPS = 100_000;
    private static final int HARD_MAX_STEPS = 2_000_000;
    private static final int MAX_MEM_WRITE_RANGES = 200;
    private static final int MAX_MEM_WRITE_INLINE_HEX = 256;
    private static final int MAX_FINAL_REGS = 128;
    private static final int MAX_BRANCH_TRACE = 5000;

    @Override
    public String name() { return "ghidra_emulate_function"; }

    @Override
    public String description() {
        return "Run Ghidra's built-in p-code emulator on a code range. Seeds registers/memory, " +
               "runs until a breakpoint / return-sentinel / max-steps / error, and returns final " +
               "register state, tracked memory writes, and (optionally) a conditional-branch trace " +
               "of the single concrete run. Note: branchTrace reflects ONE execution — it is not a " +
               "generalized path condition. The stack pointer is not auto-initialized; callers " +
               "should seed 'stackPointer' for functions that use the stack.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("entry", Map.of("type", "string",
            "description", "Entry address (hex) where emulation begins"));
        props.put("registers", Map.of("type", "object",
            "description", "Optional map of register-name -> value (decimal or 0x-hex string) to seed"));
        props.put("memory", Map.of("type", "array",
            "description", "Optional list of {address, hexBytes} entries to write into memory before running",
            "items", Map.of("type", "object")));
        props.put("stopAddresses", Map.of("type", "array",
            "description", "Addresses (hex) at which to stop (breakpoints)",
            "items", Map.of("type", "string")));
        props.put("returnAddressSentinel", Map.of("type", "string",
            "description", "Optional sentinel return address (hex). If provided, a breakpoint is set here " +
                           "AND the value is written to [SP] so a normal RET lands on it. Stop reason becomes 'return_sentinel'."));
        props.put("stackPointer", Map.of("type", "string",
            "description", "Optional initial stack pointer value (decimal or 0x-hex). Written to the " +
                           "language's default SP register unless 'stackPointerRegister' overrides it."));
        props.put("stackPointerRegister", Map.of("type", "string",
            "description", "Optional SP register name override (default: language default)"));
        props.put("maxSteps", Map.of("type", "integer",
            "description", "Max instructions to step (default 100000, hard cap 2000000)"));
        props.put("recordBranches", Map.of("type", "boolean",
            "description", "If true, emit a branchTrace of conditional branches encountered and whether each was taken (default false)"));
        props.put("trackMemoryWrites", Map.of("type", "boolean",
            "description", "If true, return the set of memory ranges written during emulation (default true)"));
        schema.put("properties", props);
        schema.put("required", List.of("entry"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @SuppressWarnings("unchecked")
    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalStateException("No program is open");

        Address entry = McpUtil.parseAddress((String) arguments.get("entry"), program);

        int maxSteps = Math.min(
            ((Number) arguments.getOrDefault("maxSteps", DEFAULT_MAX_STEPS)).intValue(),
            HARD_MAX_STEPS);
        boolean recordBranches = Boolean.TRUE.equals(arguments.get("recordBranches"));
        boolean trackMemoryWrites = !Boolean.FALSE.equals(arguments.get("trackMemoryWrites"));

        Map<String, Object> regSeeds = (Map<String, Object>)
            arguments.getOrDefault("registers", Collections.emptyMap());
        List<Object> memSeeds = (List<Object>)
            arguments.getOrDefault("memory", Collections.emptyList());
        List<Object> stopList = (List<Object>)
            arguments.getOrDefault("stopAddresses", Collections.emptyList());

        String sentinelStr = (String) arguments.get("returnAddressSentinel");
        Address sentinel = (sentinelStr != null && !sentinelStr.isEmpty())
            ? McpUtil.parseAddress(sentinelStr, program) : null;

        String spRegOverride = (String) arguments.get("stackPointerRegister");
        String spValStr = (String) arguments.get("stackPointer");

        EmulatorHelper emu = new EmulatorHelper(program);
        try {
            // --- Seed stack pointer first so subsequent sentinel-on-stack works ---
            Register spReg = (spRegOverride != null)
                ? program.getLanguage().getRegister(spRegOverride)
                : emu.getStackPointerRegister();
            if (spValStr != null && !spValStr.isEmpty() && spReg != null) {
                emu.writeRegister(spReg, parseBigInt(spValStr));
            }

            // --- Seed general registers ---
            for (Map.Entry<String, Object> e : regSeeds.entrySet()) {
                BigInteger val = parseBigInt(String.valueOf(e.getValue()));
                emu.writeRegister(e.getKey(), val);
            }

            // --- Seed memory ---
            for (Object m : memSeeds) {
                if (!(m instanceof Map)) continue;
                Map<String, Object> mm = (Map<String, Object>) m;
                Address a = McpUtil.parseAddress((String) mm.get("address"), program);
                byte[] bytes = hexToBytes((String) mm.get("hexBytes"));
                emu.writeMemory(a, bytes);
            }

            if (trackMemoryWrites) emu.enableMemoryWriteTracking(true);

            // --- Breakpoints ---
            Set<Address> stops = new HashSet<>();
            for (Object s : stopList) {
                Address a = McpUtil.parseAddress((String) s, program);
                emu.setBreakpoint(a);
                stops.add(a);
            }
            if (sentinel != null) {
                emu.setBreakpoint(sentinel);
                stops.add(sentinel);
                // Write sentinel onto [SP] so a normal return lands on it.
                try {
                    if (spReg != null) {
                        BigInteger sp = emu.readRegister(spReg);
                        if (sp != null && sp.signum() != 0) {
                            int ptrSize = program.getDefaultPointerSize();
                            Address spAddr = program.getAddressFactory()
                                .getDefaultAddressSpace().getAddress(sp.longValue());
                            emu.writeMemoryValue(spAddr, ptrSize, sentinel.getOffset());
                        }
                    }
                } catch (Exception ignored) {
                    // Non-fatal: sentinel still works as a breakpoint.
                }
            }

            // --- Set PC to entry ---
            Register pcReg = emu.getPCRegister();
            emu.writeRegister(pcReg, entry.getOffset());

            // --- Step loop ---
            List<Map<String, Object>> branches = new ArrayList<>();
            String stopReason = "max_steps";
            String lastError = null;
            int steps = 0;
            Address lastPc = entry;
            TaskMonitor monitor = TaskMonitor.DUMMY;

            for (int i = 0; i < maxSteps; i++) {
                Address pc = emu.getExecutionAddress();
                lastPc = pc;

                if (stops.contains(pc)) {
                    stopReason = (sentinel != null && pc.equals(sentinel))
                        ? "return_sentinel" : "breakpoint";
                    break;
                }

                Instruction instr = recordBranches
                    ? program.getListing().getInstructionAt(pc) : null;

                boolean ok;
                try {
                    ok = emu.step(monitor);
                } catch (Exception e) {
                    stopReason = "error";
                    lastError = e.getMessage();
                    break;
                }
                if (!ok) {
                    stopReason = "error";
                    lastError = emu.getLastError();
                    break;
                }
                steps++;

                if (instr != null
                        && instr.getFlowType() != null
                        && instr.getFlowType().isConditional()
                        && branches.size() < MAX_BRANCH_TRACE) {
                    recordBranch(branches, emu, pc, instr);
                }
            }

            // --- Build result ---
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("stopReason", stopReason);
            result.put("pcAtStop", lastPc.toString());
            result.put("steps", steps);
            if (lastError != null) result.put("lastError", lastError);
            result.put("registers", collectFinalRegisters(emu, program));

            if (trackMemoryWrites) {
                result.put("memoryWrites", collectMemoryWrites(emu));
            }

            if (recordBranches) {
                result.put("branchTrace", branches);
                result.put("branchTraceNote",
                    "Observations from ONE concrete run. Not a generalized path condition — " +
                    "different inputs can take different branches.");
                if (branches.size() >= MAX_BRANCH_TRACE) {
                    result.put("branchTraceTruncated", true);
                }
            }
            return result;
        } finally {
            emu.dispose();
        }
    }

    private static void recordBranch(List<Map<String, Object>> out,
                                     EmulatorHelper emu, Address pc, Instruction instr) {
        Address newPc = emu.getExecutionAddress();
        Address fallThrough = instr.getFallThrough();
        boolean taken = (fallThrough == null) || !newPc.equals(fallThrough);

        Map<String, Object> b = new LinkedHashMap<>();
        b.put("pc", pc.toString());
        b.put("instruction", instr.toString());
        b.put("taken", taken);
        b.put("nextPc", newPc.toString());
        if (fallThrough != null) b.put("fallThroughPc", fallThrough.toString());

        Map<String, String> inputs = new LinkedHashMap<>();
        try {
            for (Object obj : instr.getInputObjects()) {
                if (obj instanceof Register) {
                    Register r = (Register) obj;
                    try {
                        BigInteger v = emu.readRegister(r);
                        if (v != null) inputs.put(r.getName(), "0x" + v.toString(16));
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
        if (!inputs.isEmpty()) b.put("inputs", inputs);

        out.add(b);
    }

    private static Map<String, String> collectFinalRegisters(EmulatorHelper emu, Program program) {
        Map<String, String> finalRegs = new LinkedHashMap<>();
        // Always include PC and SP first.
        Register pc = emu.getPCRegister();
        Register sp = emu.getStackPointerRegister();
        if (pc != null) tryPutReg(finalRegs, emu, pc);
        if (sp != null) tryPutReg(finalRegs, emu, sp);

        for (Register r : program.getLanguage().getRegisters()) {
            if (!r.isBaseRegister()) continue;
            if (finalRegs.size() >= MAX_FINAL_REGS) break;
            if (finalRegs.containsKey(r.getName())) continue;
            tryPutReg(finalRegs, emu, r);
        }
        return finalRegs;
    }

    private static void tryPutReg(Map<String, String> out, EmulatorHelper emu, Register r) {
        try {
            BigInteger v = emu.readRegister(r);
            if (v != null) out.put(r.getName(), "0x" + v.toString(16));
        } catch (Exception ignored) {}
    }

    private static List<Map<String, Object>> collectMemoryWrites(EmulatorHelper emu) {
        List<Map<String, Object>> out = new ArrayList<>();
        AddressSetView written = emu.getTrackedMemoryWriteSet();
        if (written == null) return out;
        for (AddressRange range : written) {
            if (out.size() >= MAX_MEM_WRITE_RANGES) break;
            Map<String, Object> mw = new LinkedHashMap<>();
            mw.put("address", range.getMinAddress().toString());
            long len = range.getLength();
            mw.put("length", len);
            if (len > 0 && len <= MAX_MEM_WRITE_INLINE_HEX) {
                try {
                    byte[] bytes = emu.readMemory(range.getMinAddress(), (int) len);
                    StringBuilder hex = new StringBuilder();
                    for (byte b : bytes) hex.append(String.format("%02x", b & 0xFF));
                    mw.put("hex", hex.toString());
                } catch (Exception ignored) {}
            }
            out.add(mw);
        }
        return out;
    }

    private static BigInteger parseBigInt(String s) {
        if (s == null) throw new IllegalArgumentException("null numeric value");
        String c = s.strip();
        if (c.isEmpty()) throw new IllegalArgumentException("empty numeric value");
        boolean neg = false;
        if (c.startsWith("-")) { neg = true; c = c.substring(1); }
        BigInteger v;
        if (c.startsWith("0x") || c.startsWith("0X")) {
            v = new BigInteger(c.substring(2), 16);
        } else {
            v = new BigInteger(c);
        }
        return neg ? v.negate() : v;
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null) throw new IllegalArgumentException("hexBytes is null");
        String cleaned = hex.replaceAll("\\s+", "").replaceFirst("^0[xX]", "");
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("hexBytes must have even length");
        }
        byte[] out = new byte[cleaned.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
