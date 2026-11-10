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
        extended(range, mem, loop);
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

    /** Division, skipped calls, undefined memory, several solutions, and the emulator's reporting. */
    @SuppressWarnings("unchecked")
    private void extended(Address range, Address mem, Address loop) throws Exception {
        Map<?,?> replay = (Map<?,?>) solution(explore(args(range, 10))).get("replay");
        check("replay_path_matched", Boolean.TRUE.equals(replay.get("pathMatched")), replay);

        // mov eax,edi; xor edx,edx; mov ecx,7; div ecx; cmp edx,3; jne failure; success...; failure...
        Address rem = code("89f831d2b907000000f7f183fa037506b801000000c331c0c3");
        Map<String,Object> result = explore(args(rem, 16));
        boolean found = "found".equals(result.get("status"));
        check("division_found", found, result);
        if (found) {
            long x = Long.parseLong(((Map<?,?>) solution(result).get("inputs")).get("x").toString().substring(2), 16);
            check("remainder_constraint", x % 7 == 3, x);
            check("constant_divisor_cannot_fault", Integer.valueOf(0).equals(result.get("divisionFaultPaths")), result.get("divisionFaultPaths"));
        }
        // mov eax,100; xor edx,edx; div edi; cmp eax,10; jne failure; success...; failure...
        Address quotient = code("b86400000031d2f7f783f80a7506b801000000c331c0c3");
        result = explore(args(quotient, 14));
        found = "found".equals(result.get("status"));
        check("symbolic_divisor_found", found, result);
        if (found) {
            check("symbolic_divisor_value", "0xa".equals(((Map<?,?>) solution(result).get("inputs")).get("x")), solution(result).get("inputs"));
            check("zero_divisor_counted", ((Number) result.get("divisionFaultPaths")).intValue() >= 1, result.get("divisionFaultPaths"));
        }

        // call <unmapped>; cmp eax,0x2a; jne failure; success...; failure...
        Address called = code("e8fbffff0f83f82a7506b801000000c331c0c3");
        check("call_stops_by_default", "incomplete".equals(explore(args(called, 10)).get("status")), "callPolicy=stop");
        Map<String,Object> args = args(called, 10);
        args.put("callPolicy", "skip");
        result = explore(args);
        found = "found".equals(result.get("status"));
        check("call_skipped_found", found, result);
        if (found) {
            Map<String,Object> solution = solution(result);
            List<Map<String,Object>> calls = (List<Map<String,Object>>) solution.get("skippedCalls");
            check("call_return_assumed", calls != null && calls.size() == 1 && "0x2a".equals(calls.get(0).get("assumedReturn")), calls);
            replay = (Map<?,?>) solution.get("replay");
            check("call_skip_replay", Boolean.TRUE.equals(replay.get("verified")) && Boolean.TRUE.equals(replay.get("pathMatched")), replay);
            Map<String,Object> replayArgs = (Map<String,Object>) solution.get("emulateArguments");
            Map<?,?> emulated = (Map<?,?>) new EmulateFunctionTool().execute(replayArgs, currentProgram, null);
            check("call_skip_exported_replay", called.add(10).toString().equals(emulated.get("pcAtStop"))
                && Integer.valueOf(1).equals(emulated.get("skippedCallCount")), emulated);
        }

        // The byte at [rsi] has no seed and no program bytes behind it.
        args = args(mem, 6);
        args.put("registers", Map.of("RSI", "0x700000"));
        check("undefined_memory_stops_by_default", "incomplete".equals(explore(args).get("status")), "uninitializedMemory=stop");
        args.put("uninitializedMemory", "symbolic");
        result = explore(args);
        found = "found".equals(result.get("status"));
        check("undefined_memory_symbolic", found, result);
        if (found) {
            List<Map<String,Object>> assumed = (List<Map<String,Object>>) solution(result).get("assumedMemory");
            check("undefined_memory_reported", assumed != null && assumed.stream().anyMatch(
                m -> "00700000".equals(m.get("address")) && "42".equals(m.get("hexBytes"))), assumed);
            check("undefined_memory_replay", Boolean.TRUE.equals(((Map<?,?>) solution(result).get("replay")).get("verified")), solution(result).get("replay"));
        }
        args.put("uninitializedMemory", "zero");
        result = explore(args);
        check("undefined_memory_zero", "exhausted".equals(result.get("status")) && Boolean.TRUE.equals(result.get("complete")), result);
        args.put("uninitializedMemory", "random");
        invalid("unknown_memory_policy", args);

        // cmp edi,5; je ok; cmp edi,9; je ok; xor eax,eax; ret; ok: mov eax,1; ret
        Address two = code("83ff05740883ff09740331c0c3b801000000c3");
        args = args(two, 13);
        result = explore(args);
        check("one_solution_by_default", ((List<?>) result.get("solutions")).size() == 1 && Boolean.FALSE.equals(result.get("complete")), result);
        args.put("maxSolutions", 4);
        result = explore(args);
        Set<Object> values = new HashSet<>();
        for (Map<String,Object> s : (List<Map<String,Object>>) result.get("solutions")) values.add(((Map<?,?>) s.get("inputs")).get("x"));
        check("all_solutions", values.equals(Set.of("0x5", "0x9")) && Boolean.TRUE.equals(result.get("complete")), result);

        // Concrete emulator: time limit, undefined reads, memory dump.
        EmulateFunctionTool emulator = new EmulateFunctionTool();
        Map<String,Object> run = new LinkedHashMap<>(Map.of("entry", loop.toString(), "maxSteps", 2000000, "timeoutMs", 50));
        Map<?,?> emulated = (Map<?,?>) emulator.execute(run, currentProgram, null);
        check("emulator_timeout", "timeout".equals(emulated.get("stopReason")), emulated.get("stopReason") + " after " + emulated.get("steps"));
        run = new LinkedHashMap<>(Map.of("entry", mem.toString(), "stackPointer", "0x800000",
            "registers", Map.of("RSI", "0x700000"), "stopAddresses", List.of(mem.add(2).toString())));
        emulated = (Map<?,?>) emulator.execute(run, currentProgram, null);
        List<Map<String,Object>> reads = (List<Map<String,Object>>) emulated.get("uninitializedReads");
        check("emulator_reports_undefined_read", reads != null && reads.stream().anyMatch(m -> "00700000".equals(m.get("address"))), emulated);
        run.put("memory", List.of(Map.of("address", "00700000", "hexBytes", "42")));
        run.put("readMemory", List.of(Map.of("address", "00700000", "length", 1)));
        emulated = (Map<?,?>) emulator.execute(run, currentProgram, null);
        List<Map<String,Object>> dump = (List<Map<String,Object>>) emulated.get("memoryAtStop");
        check("emulator_seeded_read_is_quiet", emulated.get("uninitializedReads") == null, emulated.get("uninitializedReads"));
        check("emulator_memory_dump", dump != null && "42".equals(dump.get(0).get("hex")), dump);
        run.put("timeoutMs", 0);
        try { emulator.execute(run, currentProgram, null); check("emulator_bad_timeout", false, "accepted 0"); }
        catch (IllegalArgumentException expected) { check("emulator_bad_timeout", true, expected.getMessage()); }
    }

    private void arithmetic() {
        try (Context ctx = new Context()) {
            SymbolicArithmetic a = new SymbolicArithmetic(ctx);
            check("unsigned_division", ((BitVecNum) a.apply(PcodeOp.INT_DIV, 8, ctx.mkBV(100,8), ctx.mkBV(7,8))).getInt() == 14, "100 / 7");
            check("signed_remainder", ((BitVecNum) a.apply(PcodeOp.INT_SREM, 8, ctx.mkBV(249,8), ctx.mkBV(3,8))).getInt() == 255, "-7 % 3");
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
