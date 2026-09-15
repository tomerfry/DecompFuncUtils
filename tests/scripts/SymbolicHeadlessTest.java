import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import decompfuncutils.mcp.tools.ExplorePathsTool;
import decompfuncutils.mcp.tools.EmulateFunctionTool;
import decompfuncutils.symbolic.SymbolicArithmetic;
import com.microsoft.z3.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.util.*;

/** Deterministic x64 machine-code fixtures exercise the solver and concrete replay together. */
public class SymbolicHeadlessTest extends GhidraScript {
    private int passed, failed, fixture;

    @Override public void run() throws Exception {
        arithmetic();
        // cmp edi,5; jl failure; cmp edi,10; jge failure; success: mov eax,1; ret; failure: xor eax,eax; ret
        Address range = code("83ff057c0b83ff0a7d06b801000000c331c0c3");
        Map<String,Object> args = args(range, 10);
        Map<String,Object> result = explore(args);
        check("range_found", "found".equals(result.get("status")), result);
        if ("found".equals(result.get("status"))) {
            Map<String,Object> solution = solution(result);
            Map<?,?> inputs = (Map<?,?>) solution.get("inputs");
            int x = new BigInteger(inputs.get("x").toString().substring(2), 16).intValue();
            check("preceding_constraints", x >= 5 && x < 10, inputs);
            Map<?,?> replay = (Map<?,?>) solution.get("replay");
            check("concrete_replay", Boolean.TRUE.equals(replay.get("verified")), replay);
            @SuppressWarnings("unchecked") Map<String,Object> replayArgs = (Map<String,Object>) solution.get("emulateArguments");
            Map<?,?> emulated = (Map<?,?>) new EmulateFunctionTool().execute(replayArgs, currentProgram, null);
            check("exported_replay", range.add(10).toString().equals(emulated.get("pcAtStop")), emulated.get("pcAtStop"));
        }
        // The second comparison contradicts the first path constraint: x >= 5 AND x < 3.
        Address impossible = code("83ff057c0b83ff037d06b801000000c331c0c3");
        result = explore(args(impossible, 10));
        check("contradiction_exhausted", "exhausted".equals(result.get("status")) && Boolean.TRUE.equals(result.get("complete")), result);
        args.put("avoidAddresses", List.of(range.add(5).toString()));
        result = explore(args);
        check("avoid_exhausted", "exhausted".equals(result.get("status")), result);
        args.remove("avoidAddresses");
        for (String limit : List.of("maxStates", "maxStepsPerPath", "maxPcodeOps")) {
            args.put(limit, 1);
            result = explore(args);
            check(limit, "incomplete".equals(result.get("status")) && Boolean.FALSE.equals(result.get("complete")), result);
            args.remove(limit);
        }
        // mov al,[rsi]; cmp al,0x42; jne failure; success: mov eax,1; ret; failure: xor eax,eax; ret
        Address mem = code("8a063c427506b801000000c331c0c3");
        args = args(mem, 6);
        args.put("registers", Map.of("RSI", "0x700000"));
        args.put("symbolicInputs", List.of(Map.of("name", "byte", "address", "00700000", "size", 1)));
        result = explore(args);
        check("symbolic_memory", "found".equals(result.get("status")) && "0x42".equals(((Map<?,?>) solution(result).get("inputs")).get("byte")), result);
        args = args(mem, 6);
        args.put("symbolicInputs", List.of(Map.of("name", "ptr", "register", "RSI")));
        check("symbolic_pointer_incomplete", "incomplete".equals(explore(args).get("status")), "symbolic address");
        Address loop = code("ebfe90c3");
        args = args(loop, 2);
        args.put("maxVisitsPerAddress", 2);
        result = explore(args);
        check("loop_bound", ((Map<?,?>) result.get("stops")).containsKey("visit_limit"), result);
        Address call = code("e8fbffff0f90c3");
        result = explore(args(call, 5));
        check("call_incomplete", "incomplete".equals(result.get("status")), result);
        args = args(range, 10);
        args.put("maxStates", 1.5);
        invalid("fractional_limit", args);
        args = args(range, 10);
        args.put("symbolicInputs", List.of(Map.of("name", "sp", "register", "RSP")));
        invalid("symbolic_sp", args);
        args = args(range, 10);
        args.put("symbolicInputs", List.of(Map.of("name", "x", "register", "RDI"), Map.of("name", "y", "register", "EDI")));
        invalid("overlapping_symbols", args);
        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    private void arithmetic() {
        try (Context ctx = new Context()) {
            SymbolicArithmetic a = new SymbolicArithmetic(ctx);
            check("wide_shift", ((BitVecNum) a.apply(PcodeOp.INT_LEFT, 8, ctx.mkBV(1,8), ctx.mkBV(256,16))).getInt() == 0, "1 << 256");
            check("signed_shift", ((BitVecNum) a.apply(PcodeOp.INT_SRIGHT, 8, ctx.mkBV(128,8), ctx.mkBV(256,16))).getInt() == 255, "negative >> 256");
            check("signed_overflow", ((BitVecNum) a.apply(PcodeOp.INT_SCARRY, 8, ctx.mkBV(127,8), ctx.mkBV(1,8))).getInt() == 1, "127 + 1");
            check("leading_zeros", ((BitVecNum) a.apply(PcodeOp.LZCOUNT, 8, ctx.mkBV(16,8))).getInt() == 3, "clz(16)");
        }
    }
    private Address code(String hex) throws Exception {
        Address at = toAddr(0x500000L + fixture++ * 0x100);
        byte[] bytes = HexFormat.of().parseHex(hex);
        MemoryBlock block = currentProgram.getMemory().createInitializedBlock("symbolic_test_" + fixture, at, bytes.length, (byte) 0, monitor, false);
        block.setExecute(true);
        currentProgram.getMemory().setBytes(at, bytes);
        // Disassemble every reachable fragment, including deliberately unreachable targets.
        for (int i = 0; i < bytes.length; i++) {
            if (currentProgram.getListing().getInstructionContaining(at.add(i)) == null) disassemble(at.add(i));
        }
        createFunction(at, "symbolic_test_" + fixture).setBody(new ghidra.program.model.address.AddressSet(at, at.add(bytes.length - 1)));
        return at;
    }
    private Map<String,Object> args(Address entry, int target) {
        return new LinkedHashMap<>(Map.of("entry", entry.toString(), "targetAddresses", List.of(entry.add(target).toString()),
            "stackPointer", "0x800000", "memory", List.of(Map.of("address", "00800000", "hexBytes", "0000000000000000")),
            "symbolicInputs", List.of(Map.of("name", "x", "register", "EDI"))));
    }
    @SuppressWarnings("unchecked") private Map<String,Object> explore(Map<String,Object> args) throws Exception {
        return (Map<String,Object>) new ExplorePathsTool().execute(args, currentProgram, null);
    }
    @SuppressWarnings("unchecked") private Map<String,Object> solution(Map<String,Object> result) {
        return ((List<Map<String,Object>>) result.get("solutions")).get(0);
    }
    private void invalid(String name, Map<String,Object> args) throws Exception {
        try { explore(args); check(name, false, "accepted invalid input"); }
        catch (IllegalArgumentException expected) { check(name, true, expected.getMessage()); }
    }
    private void check(String name, boolean ok, Object detail) {
        if (ok) passed++; else failed++;
        println("CHECK " + name + ": " + (ok ? "PASS" : "FAIL") + " " + detail);
    }
}
