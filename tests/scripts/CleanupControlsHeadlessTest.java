import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import decompfuncutils.mcp.*;
import decompfuncutils.mcp.tools.*;
import com.google.gson.*;
import java.util.*;
import java.nio.file.*;
import java.util.concurrent.*;

/** Exercises the cleanup controls through JSON-RPC on a disposable real program. */
public class CleanupControlsHeadlessTest extends GhidraScript {
    private int passed, failed;
    private ProgramDB program;
    private McpProtocolHandler handler;
    private final Gson gson = new Gson();
    private final DecompInterfacePool pool = new DecompInterfacePool();
    private static final String MUTABILITY = "ghidra_set_data_mutability";
    private static final String USES = "ghidra_get_variable_uses";
    private static final String SPLIT = "ghidra_split_variable_lifetime";
    private static final String UNION = "ghidra_set_union_field";
    private static final String SCRIPT = "ghidra_run_script";

    public void run() throws Exception {
        program = new ProgramDB("cleanup_fixture", currentProgram.getLanguage(), currentProgram.getLanguage()
            .getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        try {
            fixture();
            McpToolRegistry registry = new McpToolRegistry();
            registry.register(new SetDataMutabilityTool());
            registry.register(new GetVariableUsesTool());
            registry.register(new SplitVariableLifetimeTool());
            registry.register(new SetUnionFieldTool());
            registry.register(new RunScriptTool());
            registry.register(new DecompileFunctionTool(pool));
            handler = new McpProtocolHandler(registry, () -> program, () -> null);
            mutabilityTests();
            useTests();
            scriptTests();
        } finally {
            pool.disposeAll();
            program.release(this);
        }
        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    private void fixture() throws Exception {
        int tx = program.startTransaction("fixture");
        try {
            var block = program.getMemory().createInitializedBlock("code", address(0x500000), 0x2000, (byte) 0, monitor, false);
            block.setExecute(true);
            block.setWrite(true);
            // Read a defined literal from a writable block and fold arithmetic on it.
            function("literal", 0x500000, "8b05fa0f000083c001c3");
            program.getMemory().setInt(address(0x501000), 42);
            program.getListing().createData(address(0x501000), IntegerDataType.dataType);
            program.getListing().createData(address(0x501004), IntegerDataType.dataType);
            // mov eax,[rdi]; mov edx,[rsi]; add eax,edx; ret
            Function read = function("read_union", 0x500100, "8b078b1601d0c3");
            UnionDataType union = new UnionDataType("Choice");
            union.add(IntegerDataType.dataType, "word", null);
            union.add(IntegerDataType.dataType, "alternate", null);
            DataType choice = program.getDataTypeManager().addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
            read.addParameter(new ParameterImpl("first", new PointerDataType(choice), program), SourceType.USER_DEFINED);
            read.addParameter(new ParameterImpl("second", new PointerDataType(choice), program), SourceType.USER_DEFINED);
            // Two disjoint results in EAX separated by calls: decompiler speculatively merges their locals.
            function("reuse", 0x500200, "e8fb00000089c7e874010000e8ef00000089c7e868010000c3");
            Function source = function("source", 0x500300, "b807000000c3");
            source.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
            Function sink = function("consume", 0x500380, "c3");
            sink.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            sink.addParameter(new ParameterImpl("value", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
        } finally { program.endTransaction(tx, true); }
    }

    private void mutabilityTests() {
        String before = decompile("500000");
        check("literal_initially_loaded", !before.contains("return 43;"), before);
        call(MUTABILITY, Map.of("addresses", List.of("501000", "501004"), "mutability", "constant"));
        check("per_data_constant", data().isConstant(), data());
        check("block_permissions_preserved", program.getMemory().getBlock(address(0x501000)).isWrite(), "write flag");
        String after = decompile("500000");
        check("literal_folded", after.contains("return 43;") || after.contains("return 0x2b;"), after);
        call(MUTABILITY, Map.of("addresses", List.of("501000"), "mutability", "volatile"));
        check("volatile_supported", data().isVolatile(), data());
        call(MUTABILITY, Map.of("addresses", List.of("501000"), "mutability", "writable"));
        check("writable_supported", MutabilitySettingsDefinition.DEF.getValueString(data()).equals("writable"), data());
        call(MUTABILITY, Map.of("addresses", List.of("501000"), "mutability", "normal"));
        check("reset_normal", !data().isConstant() && !data().isVolatile(), data());
        invalid("invalid_batch", MUTABILITY, Map.of("addresses", List.of("501000", "500000"), "mutability", "constant"), "No defined data");
        check("invalid_batch_unchanged", !data().isConstant(), data());
        invalid("reject_interior", MUTABILITY, Map.of("addresses", List.of("501001"), "mutability", "constant"), "No defined data");
        invalid("reject_bad_mode", MUTABILITY, Map.of("addresses", List.of("501000"), "mutability", "readonly"), "mutability");
    }

    private void useTests() {
        JsonObject all = call(USES, Map.of("functionAddress", "500200", "limit", 500));
        JsonObject page = call(USES, Map.of("functionAddress", "500200", "limit", 1));
        check("uses_pagination", page.getAsJsonArray("uses").size() == 1 && page.get("hasMore").getAsBoolean(), page);
        JsonObject selected = null;
        for (JsonElement item : all.getAsJsonArray("uses")) {
            if (item.getAsJsonObject().get("canSplit").getAsBoolean()) { selected = item.getAsJsonObject(); break; }
        }
        check("find_separable_lifetime", selected != null, all);
        if (selected != null) {
            Map<String, Object> args = selector("500200", selected);
            args.put("newName", "first_lifetime");
            args.put("newType", "int");
            Map<String, Object> stale = new HashMap<>(args);
            stale.put("expectedVariable", "not_the_variable");
            invalid("stale_selector", SPLIT, stale, "Variable changed");
            Map<String, Object> wrongSize = new HashMap<>(args);
            wrongSize.put("newType", "char");
            invalid("split_rejects_resize", SPLIT, wrongSize, "must match");
            call(SPLIT, args);
            String code = decompile("500200");
            check("lifetime_name_persisted", code.contains("first_lifetime"), code);
            JsonObject fresh = call(USES, Map.of("functionAddress", "500200", "variableName", "first_lifetime"));
            check("split_instances_visible", fresh.get("total").getAsInt() > 0, fresh);
            for (JsonElement use : fresh.getAsJsonArray("uses")) {
                check("split_group_isolated", !use.getAsJsonObject().get("canSplit").getAsBoolean(), use);
                break;
            }
        }
        JsonObject unionUses = call(USES, Map.of("functionAddress", "500100", "limit", 500));
        JsonObject unionUse = null;
        for (JsonElement item : unionUses.getAsJsonArray("uses")) {
            JsonObject use = item.getAsJsonObject();
            if (use.has("unionFields") && use.get("variable").getAsString().equals("first")) { unionUse = use; break; }
        }
        check("find_union_use", unionUse != null, unionUses);
        if (unionUse != null) {
            Map<String, Object> args = selector("500100", unionUse);
            args.put("fieldOrdinal", 50);
            invalid("invalid_union_member", UNION, args, "fieldOrdinal");
            args.put("fieldOrdinal", 1);
            call(UNION, args);
            String code = decompile("500100");
            check("union_override_rendered", code.contains("first->alternate") && code.contains("second->word"), code);
            check("union_facet_persisted", Arrays.stream(program.getFunctionManager().getFunctionAt(address(0x500100)).getLocalVariables())
                .anyMatch(v -> v.getName().startsWith("unionfacet")), code);
            JsonObject fresh = call(USES, Map.of("functionAddress", "500100", "variableName", "first"));
            Map<String, Object> restore = selector("500100", fresh.getAsJsonArray("uses").get(0).getAsJsonObject());
            restore.put("fieldOrdinal", 0);
            call(UNION, restore);
            code = decompile("500100");
            check("union_override_replaced", code.contains("first->word") && !code.contains("alternate"), code);
            restore.put("newName", "parameter_cannot_split");
            invalid("parameter_split_rejected", SPLIT, restore, "no separable merge group");
        }
        invalid("fractional_operation_time", UNION, Map.of("functionAddress", "500100", "operationAddress", "500100",
            "operationTime", 0.5, "slot", 0, "fieldOrdinal", 0), "operationTime");
        invalid("missing_function", USES, Map.of("functionAddress", "501000"), "No internal function");
    }

    private void scriptTests() throws Exception {
        Path dir = Files.createTempDirectory("dfu_cleanup_scripts_");
        Path file = dir.resolve("McpCleanupFixture.java");
        Files.writeString(file, """
            import ghidra.app.script.GhidraScript;
            import javax.swing.SwingUtilities;
            public class McpCleanupFixture extends GhidraScript {
                public void run() throws Exception {
                    if (SwingUtilities.isEventDispatchThread()) throw new Exception("running on EDT");
                    println("program=" + currentProgram.getName());
                    println("arg=" + getScriptArgs()[0]);
                    currentProgram.getMemory().setInt(currentAddress, 99);
                    if (getScriptArgs()[0].equals("fail")) throw new Exception("intentional failure");
                    if (getScriptArgs()[0].equals("wait")) {
                        while (true) { monitor.checkCancelled(); Thread.sleep(10); }
                    }
                    println("done");
                }
            }
            """);
        Map<String, Object> args = new HashMap<>(Map.of("script", file.toString(), "args", List.of("ok"), "address", "501000"));
        JsonObject result = call(SCRIPT, args);
        check("script_output_and_context", result.get("output").getAsString().contains("program=cleanup_fixture") &&
            result.get("output").getAsString().contains("arg=ok"), result);
        check("script_edit_committed", program.getMemory().getInt(address(0x501000)) == 99, result);
        int tx = program.startTransaction("reset literal");
        program.getMemory().setInt(address(0x501000), 42);
        program.endTransaction(tx, true);
        args.put("args", List.of("fail"));
        invalid("script_failure_reported", SCRIPT, args, "intentional failure");
        check("script_failure_rolled_back", program.getMemory().getInt(address(0x501000)) == 42, "value");
        args.put("args", List.of("wait"));
        args.put("timeoutSeconds", 1);
        invalid("script_timeout", SCRIPT, args, "cancelled");
        check("script_timeout_rolled_back", program.getMemory().getInt(address(0x501000)) == 42, "value");
        args.put("args", List.of("ok"));
        args.put("timeoutSeconds", 60);
        args.put("maxOutputChars", 10);
        result = call(SCRIPT, args);
        check("script_bounded_output", result.get("outputTruncated").getAsBoolean() && result.get("output").getAsString().length() == 10, result);
        args.put("script", "McpCleanupFixture.java");
        check("script_lookup_by_name", call(SCRIPT, args).get("status").getAsString().equals("script_completed"), "name lookup");
        tx = program.startTransaction("reset for cancellation");
        program.getMemory().setInt(address(0x501000), 42);
        program.endTransaction(tx, true);
        args.put("args", List.of("wait"));
        Map<String, Object> cancelledArgs = Map.copyOf(args);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<JsonObject> running = worker.submit(() -> rpc(SCRIPT, cancelledArgs));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (program.getMemory().getInt(address(0x501000)) != 99 && System.nanoTime() < deadline) Thread.sleep(10);
            check("cancel_script_started", program.getMemory().getInt(address(0x501000)) == 99, "script start");
            handler.handleRequest(gson.toJson(Map.of("jsonrpc", "2.0", "method", "notifications/cancelled",
                "params", Map.of("requestId", 1))), null);
            JsonObject cancelled = running.get(10, TimeUnit.SECONDS);
            check("mcp_cancellation_reported", cancelled.has("error"), cancelled);
            check("mcp_cancellation_rolled_back", program.getMemory().getInt(address(0x501000)) == 42, "value");
        } finally { worker.shutdownNow(); }
        invalid("script_not_found", SCRIPT, Map.of("script", "ThisScriptDoesNotExist.java"), "Script not found");
        invalid("script_invalid_args", SCRIPT, Map.of("script", file.toString(), "args", List.of(1)), "array of strings");
    }

    private Data data() { return program.getListing().getDefinedDataAt(address(0x501000)); }
    private Address address(long value) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(value); }
    private Function function(String name, long at, String bytes) throws Exception {
        byte[] code = HexFormat.of().parseHex(bytes);
        program.getMemory().setBytes(address(at), code);
        new DisassembleCommand(address(at), new AddressSet(address(at), address(at + code.length - 1)), true).applyTo(program, monitor);
        Function function = program.getFunctionManager().createFunction(name, address(at),
            new AddressSet(address(at), address(at + code.length - 1)), SourceType.USER_DEFINED);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        return function;
    }
    private Map<String, Object> selector(String function, JsonObject use) {
        Map<String, Object> result = new HashMap<>();
        result.put("functionAddress", function);
        result.put("operationAddress", use.get("operationAddress").getAsString());
        result.put("operationTime", use.get("operationTime").getAsInt());
        result.put("slot", use.get("slot").getAsInt());
        result.put("expectedVariable", use.get("variable").getAsString());
        return result;
    }
    private String decompile(String address) { return call("ghidra_decompile_function", Map.of("address", address)).get("decompilation").getAsString(); }
    private JsonObject rpc(String name, Map<String, Object> args) {
        return JsonParser.parseString(handler.handleRequest(gson.toJson(Map.of("jsonrpc", "2.0", "id", 1,
            "method", "tools/call", "params", Map.of("name", name, "arguments", args))), null)).getAsJsonObject();
    }
    private JsonObject call(String name, Map<String, Object> args) {
        JsonObject response = rpc(name, args);
        if (response.has("error")) throw new AssertionError(response);
        return JsonParser.parseString(response.getAsJsonObject("result").getAsJsonArray("content").get(0)
            .getAsJsonObject().get("text").getAsString()).getAsJsonObject();
    }
    private void invalid(String test, String tool, Map<String, Object> args, String message) {
        JsonObject response = rpc(tool, args);
        check(test, response.has("error") && response.getAsJsonObject("error").get("message").getAsString().contains(message), response);
    }
    private void check(String test, boolean ok, Object detail) {
        if (ok) { passed++; println("CHECK " + test + ": PASS"); }
        else { failed++; println("CHECK " + test + ": FAIL (" + detail + ")"); }
    }
}
