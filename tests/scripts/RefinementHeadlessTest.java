import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.framework.plugintool.PluginTool;
import decompfuncutils.mcp.*;
import decompfuncutils.mcp.tools.*;
import com.google.gson.*;
import java.util.*;

/** Real database + decompiler + JSON-RPC regression tests, isolated from the imported program. */
public class RefinementHeadlessTest extends GhidraScript {
    private int passed, failed;
    private ProgramDB program;
    private McpProtocolHandler handler;
    private final Gson gson = new Gson();
    private final DecompInterfacePool pool = new DecompInterfacePool();
    private Function caller, callee, locals, thunk, external;
    private static final String REPLACE = "ghidra_replace_stack_variables";
    private static final String NO_RETURN = "ghidra_set_function_no_return";

    @Override public void run() throws Exception {
        // Separate ProgramDB means the dispatcher can commit/abort its own transactions,
        // independently of the headless script's surrounding import transaction.
        program = new ProgramDB("refinement_fixture", currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        try {
            fixture();
            McpToolRegistry registry = new McpToolRegistry();
            registry.register(new SetFunctionNoReturnTool());
            registry.register(new ReplaceStackVariablesTool());
            registry.register(new GetFunctionTool());
            registry.register(new DecompileFunctionTool(pool));
            // Force an error AFTER the real replacement has removed and added variables.
            registry.register(new McpTool() {
                public String name() { return "test_rollback"; }
                public String description() { return "Test-only failure injection"; }
                public Map<String, Object> inputSchema() { return new ReplaceStackVariablesTool().inputSchema(); }
                public boolean isMutating() { return true; }
                public Object execute(Map<String, Object> args, Program p, PluginTool t) throws Exception {
                    new ReplaceStackVariablesTool().execute(args, p, t);
                    throw new IllegalStateException("injected failure after replacement");
                }
            });
            handler = new McpProtocolHandler(registry, () -> program, () -> null);
            noReturnTests();
            stackTests();
        } finally {
            pool.disposeAll();
            program.release(this);
        }
        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    private void fixture() throws Exception {
        int tx = program.startTransaction("fixtures");
        try {
            Address base = address(0x500000);
            var block = program.getMemory().createInitializedBlock("code", base, 0x1000, (byte) 0, monitor, false);
            block.setExecute(true);
            // call callee; mov eax,7; ret
            program.getMemory().setBytes(base, HexFormat.of().parseHex("e8fb000000b807000000c3"));
            for (long at : new long[] {0x500100, 0x500200, 0x500300, 0x500400, 0x500500}) {
                program.getMemory().setByte(address(at), (byte) 0xc3);
            }
            new DisassembleCommand(base, null, true).applyTo(program, monitor);
            caller = function("caller", 0x500000, 11);
            caller.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
            callee = function("callee", 0x500100, 1);
            callee.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            locals = function("locals", 0x500200, 1);
            local("fragment_a", -64, IntegerDataType.dataType);
            local("fragment_b", -60, IntegerDataType.dataType);
            local("keep_neighbor", -48, IntegerDataType.dataType);
            local("partial", -36, new ArrayDataType(CharDataType.dataType, 8, 1));
            locals.addLocalVariable(new LocalVariableImpl("keep_register", 0, IntegerDataType.dataType,
                program.getRegister("EAX"), program), SourceType.USER_DEFINED);
            locals.setCustomVariableStorage(true);
            locals.addParameter(new ParameterImpl("stack_arg", IntegerDataType.dataType, 8, program), SourceType.USER_DEFINED);
            // Model mixed register/stack storage to ensure it is never silently removed.
            VariableStorage mixed = new VariableStorage(program,
                new Varnode(program.getAddressFactory().getStackSpace().getAddress(-100), 4),
                new Varnode(program.getRegister("ECX").getAddress(), 4));
            locals.addLocalVariable(new LocalVariableImpl("mixed", 0, LongLongDataType.dataType,
                mixed, true, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            StructureDataType record = new StructureDataType(new CategoryPath("/refinement"), "Recovered", 0);
            record.add(IntegerDataType.dataType, "tag", null);
            record.add(IntegerDataType.dataType, "length", null);
            program.getDataTypeManager().addDataType(record, DataTypeConflictHandler.DEFAULT_HANDLER);
            external = program.getExternalManager().addExtFunction("testlib", "external_exit", null, SourceType.USER_DEFINED).getFunction();
            thunk = function("exit_thunk", 0x500300, 1);
            thunk.setThunkedFunction(external);
            Namespace first = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "First", SourceType.USER_DEFINED);
            Namespace second = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "Second", SourceType.USER_DEFINED);
            Function a = function("duplicate", 0x500400, 1);
            a.setParentNamespace(first);
            Function b = function("duplicate", 0x500500, 1);
            b.setParentNamespace(second);
        } finally {
            program.endTransaction(tx, true);
        }
    }

    private void noReturnTests() {
        String before = decompile(caller);
        check("caller_baseline_returns", before.contains("return 7;"), before);
        String signature = callee.getPrototypeString(true, true);
        JsonObject result = call(NO_RETURN, Map.of("name", "callee", "noReturn", true));
        check("set_no_return", result.get("noReturn").getAsBoolean() && callee.hasNoReturn(), result);
        check("signature_preserved", signature.equals(callee.getPrototypeString(true, true)), callee.getSignature());
        String after = decompile(caller);
        check("caller_fallthrough_removed", !after.contains("return 7;") && after.contains("callee("), after);
        check("no_return_inspect", call("ghidra_get_function", Map.of("name", "callee")).get("noReturn").getAsBoolean(), "inspection");
        check("no_return_idempotent", "unchanged".equals(call(NO_RETURN, Map.of("name", "callee", "noReturn", true)).get("status").getAsString()), "status");
        call(NO_RETURN, Map.of("address", callee.getEntryPoint().toString(), "noReturn", false));
        check("clear_no_return_restores_caller", !callee.hasNoReturn() && decompile(caller).contains("return 7;"), decompile(caller));
        invalid("strict_boolean", NO_RETURN, Map.of("name", "callee", "noReturn", "false"), "must be a boolean");
        invalid("missing_boolean", NO_RETURN, Map.of("name", "callee"), "must be a boolean");
        invalid("missing_target", NO_RETURN, Map.of("noReturn", true), "non-empty string");
        invalid("missing_function", NO_RETURN, Map.of("name", "absent", "noReturn", true), "not found");
        invalid("ambiguous_name", NO_RETURN, Map.of("name", "duplicate", "noReturn", true), "Ambiguous");
        call(NO_RETURN, Map.of("name", "First::duplicate", "noReturn", true));
        check("qualified_target", program.getFunctionManager().getFunctionAt(address(0x500400)).hasNoReturn()
            && !program.getFunctionManager().getFunctionAt(address(0x500500)).hasNoReturn(), "namespace targeting");
        call(NO_RETURN, Map.of("name", "external_exit", "noReturn", true));
        check("external_target", external.hasNoReturn(), "external name");
        result = call(NO_RETURN, Map.of("address", thunk.getEntryPoint().toString(), "noReturn", false));
        check("thunk_updates_reported_target", !external.hasNoReturn()
            && result.get("targetAddress").getAsString().equals(external.getEntryPoint().toString()), result);
    }

    private void stackTests() throws Exception {
        Map<String, Object> args = stackArgs(List.of(
            variable("buffer", "char[16]", "-0x40"), variable("record", "Recovered", -32)));
        Map<String, Object> preview = new HashMap<>(args);
        preview.put("dryRun", true);
        String before = snapshot();
        JsonObject result = call(REPLACE, preview);
        check("preview_overlap_report", result.getAsJsonArray("removedVariables").size() == 3
            && result.getAsJsonArray("createdVariables").size() == 2, result);
        check("preview_unchanged", before.equals(snapshot()), snapshot());
        invalid("rollback_error", "test_rollback", args, "injected failure");
        check("rollback_restores_all_variables", before.equals(snapshot()), snapshot());

        invalidStack("unknown_type", List.of(variable("buffer", "char[16]", -64), variable("bad", "MissingType", -32)), "Unknown data type");
        invalidStack("void_type", List.of(variable("bad", "void", -64)), "positive size");
        invalidStack("overlapping_replacements", List.of(variable("a", "char[16]", -64), variable("b", "int", -60)), "ranges overlap");
        invalidStack("duplicate_names", List.of(variable("a", "int", -64), variable("a", "int", -32)), "Duplicate replacement name");
        invalidStack("unaffected_name_collision", List.of(variable("keep_neighbor", "int", -64)), "unaffected variable");
        invalidStack("register_name_collision", List.of(variable("keep_register", "int", -64)), "unaffected variable");
        invalidStack("parameter_name_collision", List.of(variable("stack_arg", "int", -64)), "unaffected variable");
        invalidStack("parameter_storage_protected", List.of(variable("bad", "int", 8)), "parameter area");
        invalidStack("compound_storage_protected", List.of(variable("bad", "int", -100)), "compound storage");
        invalidStack("fractional_offset", List.of(variable("bad", "int", -64.5)), "32-bit integer");
        invalidStack("overflow_offset", List.of(variable("bad", "int", 4294967232L)), "32-bit integer");
        invalidStack("cross_zero", List.of(variable("bad", "char[16]", -8)), "crosses zero");
        invalidStack("empty_batch", List.of(), "1 to 1000");
        invalidStack("invalid_name", List.of(variable("bad name", "int", -64)), "invalid characters");
        invalid("thunk_locals_rejected", REPLACE, Map.of("functionName", "exit_thunk", "variables", args.get("variables")), "non-thunk");
        check("invalid_batches_unchanged", before.equals(snapshot()), snapshot());

        result = call(REPLACE, args);
        check("bulk_replacement", result.get("status").getAsString().equals("replaced")
            && localNamed("fragment_a") == null && localNamed("fragment_b") == null
            && localNamed("partial") == null && localNamed("buffer").getLength() == 16
            && localNamed("record").getLength() == 8, result);
        check("unrelated_storage_preserved", localNamed("keep_neighbor").getStackOffset() == -48
            && localNamed("keep_register").isRegisterVariable() && localNamed("mixed") != null
            && locals.getParameterCount() == 1, snapshot());
        check("types_and_source", localNamed("buffer").getDataType() instanceof Array
            && localNamed("record").getDataType() instanceof Structure
            && localNamed("record").getSource() == SourceType.USER_DEFINED, snapshot());
        JsonArray vars = call("ghidra_get_function", Map.of("name", "locals")).getAsJsonArray("localVariables");
        boolean offsets = false;
        for (JsonElement element : vars) {
            JsonObject v = element.getAsJsonObject();
            if (v.get("name").getAsString().equals("buffer")) {
                offsets = v.get("stackOffset").getAsInt() == -64 && v.get("firstUseOffset").getAsInt() == 0;
            }
        }
        check("inspect_numeric_offsets", offsets, vars);
        String applied = snapshot();
        call(REPLACE, args);
        check("repeat_same_layout", applied.equals(snapshot()), snapshot());
        call(REPLACE, stackArgs(List.of(variable("pointer", "Recovered *", "-80"))));
        check("create_without_existing_local", localNamed("pointer").getLength() == program.getDefaultPointerSize(), snapshot());
    }

    private Address address(long at) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(at); }
    private Function function(String name, long at, int size) throws Exception {
        return program.getFunctionManager().createFunction(name, address(at),
            new AddressSet(address(at), address(at + size - 1)), SourceType.USER_DEFINED);
    }
    private void local(String name, int offset, DataType type) throws Exception {
        locals.addLocalVariable(new LocalVariableImpl(name, type, offset, program), SourceType.USER_DEFINED);
    }
    private Variable localNamed(String name) {
        for (Variable variable : locals.getLocalVariables()) if (variable.getName().equals(name)) return variable;
        return null;
    }
    private Map<String, Object> variable(String name, String type, Object offset) {
        return Map.of("name", name, "dataType", type, "stackOffset", offset);
    }
    private Map<String, Object> stackArgs(List<?> variables) {
        return Map.of("functionAddress", locals.getEntryPoint().toString(), "variables", variables);
    }
    private String snapshot() {
        List<String> state = new ArrayList<>();
        for (Variable v : locals.getAllVariables()) {
            state.add(v.getName() + "|" + v.getDataType().getPathName() + "|" + v.getVariableStorage()
                + "|" + v.getFirstUseOffset() + "|" + v.getSource() + "|" + v.getComment());
        }
        Collections.sort(state);
        return state.toString();
    }
    private JsonObject rpc(String name, Map<String, Object> args) {
        return JsonParser.parseString(handler.handleRequest(gson.toJson(Map.of("jsonrpc", "2.0", "id", 1,
            "method", "tools/call", "params", Map.of("name", name, "arguments", args))), null)).getAsJsonObject();
    }
    private JsonObject call(String name, Map<String, Object> args) {
        JsonObject response = rpc(name, args);
        if (response.has("error")) throw new AssertionError(response.toString());
        return JsonParser.parseString(response.getAsJsonObject("result").getAsJsonArray("content")
            .get(0).getAsJsonObject().get("text").getAsString()).getAsJsonObject();
    }
    private String decompile(Function f) {
        return call("ghidra_decompile_function", Map.of("address", f.getEntryPoint().toString())).get("decompilation").getAsString();
    }
    private void invalidStack(String name, List<?> variables, String message) {
        invalid(name, REPLACE, stackArgs(variables), message);
    }
    private void invalid(String name, String tool, Map<String, Object> args, String message) {
        JsonObject response = rpc(tool, args);
        check(name, response.has("error") && response.getAsJsonObject("error").get("message").getAsString().contains(message), response);
    }
    private void check(String name, boolean ok, Object detail) {
        if (ok) { passed++; println("CHECK " + name + ": PASS"); }
        else { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }
}
