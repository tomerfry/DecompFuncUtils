// Headless regression test for AngrEmulateTool (ghidra_angr_emulate).
//
// Driven by tests/run_angr_test.ps1, which imports and analyzes tests/angr/libangrdemo.so. Each
// check calls a function of the fixture by name with plain arguments, the way an agent would,
// and compares against what the C source says it must do. Needs a Python with angr
// (tools/setup-angr.ps1); the runner refuses to start without one.
//@category Test
import decompfuncutils.mcp.tools.AngrEmulateTool;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class AngrEmulateHeadlessTest extends GhidraScript {

    private final AngrEmulateTool tool = new AngrEmulateTool();
    private int failures = 0;

    private void check(String label, boolean ok, Object detail) {
        println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (detail == null ? "" : "  (" + clip(String.valueOf(detail)) + ")"));
        if (!ok) {
            failures++;
        }
    }

    private static String clip(String s) {
        s = s.replace("\n", "\\n");
        return s.length() > 700 ? s.substring(0, 700) + "..." : s;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> call(String function, List<?> args, Object... more) throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("function", function);
        request.put("args", args);
        for (int i = 0; i + 1 < more.length; i += 2) {
            request.put(String.valueOf(more[i]), more[i + 1]);
        }
        return (Map<String, Object>) tool.execute(request, currentProgram, null);
    }

    private String failure(String function, List<?> args, Object... more) {
        try {
            return "NO ERROR: " + call(function, args, more);
        }
        catch (Exception e) {
            return String.valueOf(e.getMessage());
        }
    }

    /**
     * A position-independent executable with a dynamic section and DT_NEEDED entries - the shape
     * of nearly every real Linux binary, and unlike the shared-object fixture one whose memory
     * image used to be mistaken for an ELF file by the loader.
     */
    @SuppressWarnings("unchecked")
    private void executable() throws Exception {
        java.nio.file.Path image = decompfuncutils.angr.AngrImage.of(currentProgram, monitor)
            .directory.resolve("image.bin");
        byte[] head = new byte[14];
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(image)) {
            in.read(head);
        }
        check("exe: the exported image does not start like an executable",
            "DFU-ANGR-IMAGE".equals(new String(head, java.nio.charset.StandardCharsets.US_ASCII)),
            new String(head, java.nio.charset.StandardCharsets.ISO_8859_1));

        String entry = currentProgram.getListing().getGlobalFunctions("_start").isEmpty() ? "entry" : "_start";
        Map<String, Object> result;
        try {
            result = call(entry, List.of());
        }
        catch (Exception e) {
            check("exe: a PIE executable loads and runs", false, e.getMessage());
            return;
        }
        println("EXE " + result);
        check("exe: a PIE executable loads and runs", "returned".equals(result.get("outcome")), result);
        String calls = String.valueOf(result.get("calls"));
        check("exe: its import from a library that is not there is stubbed, with the argument",
            calls.contains("dep_exported_func") && calls.contains("0x7")
                && String.valueOf(result.get("unmodelledExternals")).contains("dep_exported_func"), result);
        check("exe: addresses in the result are Ghidra's", String.valueOf(result.get("function")).contains(
            currentProgram.getListing().getGlobalFunctions(entry).get(0).getEntryPoint().toString()),
            result.get("function"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        if (!"libangrdemo.so".equals(currentProgram.getName())) {
            executable();
            // The runner fails on any FAIL line; the shared-object pass prints the summary.
            if (failures > 0) {
                println("HEADLESS_TEST_RESULT FAIL (" + currentProgram.getName() + ")");
            }
            return;
        }
        check("tool name", "ghidra_angr_emulate".equals(tool.name()), tool.name());
        check("read-only, off the Swing thread", !tool.isMutating() && !tool.requiresEdt(), null);
        Map<String, Object> props = (Map<String, Object>) tool.inputSchema().get("properties");
        check("schema declares its options", props.keySet().containsAll(List.of("function", "args",
            "stubs", "wantReturn", "find", "avoid", "memory", "registers", "readMemory", "stdin",
            "strictMemory", "symbolic", "maxSteps", "timeoutMs", "maxPaths", "trace", "arch")),
            props.keySet());

        // --- plain calls: integers in, integer out ---
        long start = System.currentTimeMillis();
        Map<String, Object> add = call("add3", List.of(1.0, 2.0, -10.0));
        long firstCallMs = System.currentTimeMillis() - start;
        println("FIRST " + add);
        check("add3 returns", "returned".equals(add.get("outcome")), add);
        check("add3(1,2,-10) is -7 as a 32-bit value", num(ret(add).get("signed32")) == -7, ret(add));
        check("says how the call was set up", String.valueOf(add.get("called")).contains("RDI")
            && String.valueOf(add.get("called")).contains("no signature"), add.get("called"));
        check("reports the engine", String.valueOf(add.get("engine")).startsWith("angr "), add.get("engine"));

        Map<String, Object> many = call("many_args", List.of(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0));
        check("stack arguments placed (many_args = 204)", num(ret(many).get("signed")) == 204,
            many.get("called") + " -> " + ret(many));

        start = System.currentTimeMillis();
        Map<String, Object> hexArg = call("add3", List.of("0x10", 1.0, 1.0));
        long warmCallMs = System.currentTimeMillis() - start;
        check("a hex string is an integer", num(ret(hexArg).get("signed")) == 18, ret(hexArg));
        check("the worker is reused (warm call is quick)", warmCallMs < 3000,
            "first=" + firstCallMs + "ms warm=" + warmCallMs + "ms");
        check("function accepted by address",
            num(ret(call(currentProgram.getListing().getGlobalFunctions("add3").get(0).getEntryPoint()
                .toString(), List.of(1.0, 1.0, 1.0))).get("signed")) == 3, null);

        // --- strings, and library calls in the trace ---
        Map<String, Object> good = call("check_password", List.of("hunter2"));
        Map<String, Object> bad = call("check_password", List.of("nope"));
        check("check_password(\"hunter2\") is 1", num(ret(good).get("signed")) == 1, ret(good));
        check("check_password(\"nope\") is 0", num(ret(bad).get("signed")) == 0, ret(bad));
        String badCalls = String.valueOf(bad.get("calls"));
        check("the strcmp call shows both strings",
            badCalls.contains("strcmp") && badCalls.contains("\"nope\"") && badCalls.contains("\"hunter2\""),
            badCalls);
        check("call sites carry Ghidra's names", badCalls.contains("check_password+0x"), badCalls);

        // --- out-parameters ---
        Map<String, Object> greet = call("fill_greeting",
            List.of(Map.of("buffer", 32.0), 32.0, "world"));
        Map<String, Object> out = buffers(greet).isEmpty() ? Map.of() : buffers(greet).get(0);
        check("fill_greeting returns the length", num(ret(greet).get("signed")) == 13, ret(greet));
        check("the out-buffer is reported", "hello, world!".equals(out.get("string"))
            && Boolean.TRUE.equals(out.get("changed")), buffers(greet));

        // --- structs with pointer fields ---
        Map<String, Object> score = call("point_score",
            List.of(Map.of("struct", List.of(3.0, 4.0, "abc"))));
        check("struct argument (3*10 + 4 + strlen(\"abc\"))", num(ret(score).get("signed")) == 37,
            score);

        // --- a missing pointer is a fault, not a zero ---
        Map<String, Object> nullDeref = call("deref", List.of(0.0));
        Map<String, Object> fault = (Map<String, Object>) nullDeref.getOrDefault("fault", Map.of());
        check("deref(NULL) faults", "fault".equals(nullDeref.get("outcome")), nullDeref);
        check("the fault names the address and where", "0x0".equals(fault.get("address"))
            && String.valueOf(fault.get("inBlockAt")).contains("(deref"), fault);
        check("the fault says what to do", String.valueOf(fault.get("hint")).contains("NULL"),
            fault.get("hint"));
        Map<String, Object> lenient = call("deref", List.of(0.0), "strictMemory", false);
        check("strictMemory=false reads zero instead", num(ret(lenient).get("signed")) == 1, lenient);
        Map<String, Object> seeded = call("deref", List.of(Map.of("int", 41.0, "size", 4.0)));
        check("an int is not a pointer either", "fault".equals(seeded.get("outcome")), seeded);
        Map<String, Object> viaStruct = call("deref", List.of(Map.of("struct", List.of(41.0))));
        check("deref(&41) is 42", num(ret(viaStruct).get("signed")) == 42, viaStruct);

        // --- globals: written, seeded, read back, and not carried between calls ---
        Map<String, Object> bump = call("bump_counter", List.of(5.0),
            "readMemory", List.of(Map.of("address", "g_counter", "length", 4.0)));
        check("bump_counter(5) is 12", num(ret(bump).get("signed")) == 12, ret(bump));
        check("the global write is reported with its symbol",
            String.valueOf(bump.get("globalWrites")).contains("g_counter")
                && String.valueOf(bump.get("globalWrites")).contains("0xc"), bump.get("globalWrites"));
        check("readMemory by symbol name", String.valueOf(bump.get("memory")).contains("0c000000"),
            bump.get("memory"));
        check("each call starts from the program's own memory",
            num(ret(call("bump_counter", List.of(5.0))).get("signed")) == 12, null);
        Map<String, Object> seededGlobal = call("bump_counter", List.of(5.0),
            "memory", List.of(Map.of("address", "g_counter", "int", 100.0, "size", 4.0)));
        check("memory seeds a global by name", num(ret(seededGlobal).get("signed")) == 105,
            ret(seededGlobal));

        // --- imports nothing can model, and stubs ---
        Map<String, Object> device = call("needs_device", List.of());
        check("an unmodelled import returns 0 and is named",
            num(ret(device).get("signed")) == 0
                && String.valueOf(device.get("unmodelledExternals")).contains("mystery_device_read"),
            device);
        Map<String, Object> stubbed = call("needs_device", List.of(),
            "stubs", Map.of("mystery_device_read", "0x1234"));
        check("stubs gives an import a return value", num(ret(stubbed).get("signed")) == 1, stubbed);
        Map<String, Object> twice = call("twice_add", List.of(4.0));
        check("twice_add(4) is 18", num(ret(twice).get("signed")) == 18, ret(twice));
        check("internal calls are in the trace by name",
            String.valueOf(twice.get("calls")).contains("add3"), twice.get("calls"));
        Map<String, Object> twiceStubbed = call("twice_add", List.of(4.0), "stubs", Map.of("add3", 10.0));
        check("stubs replaces an internal function", num(ret(twiceStubbed).get("signed")) == 20,
            twiceStubbed);

        // --- output and heap results ---
        Map<String, Object> hello = call("say_hello", List.of("bob"));
        check("stdout is captured", "hello bob\ndone\n".equals(hello.get("stdout")), hello.get("stdout"));
        Map<String, Object> report = call("report", List.of("disk"));
        check("fprintf(stderr, ...) and fputs(..., stdout) work through the imported stream variables",
            "returned".equals(report.get("outcome")) && "warning: disk\n".equals(report.get("stderr"))
                && "reported\n".equals(report.get("stdout")), report);
        Map<String, Object> upper = call("dup_upper", List.of("mixed Case"));
        check("a returned heap string is shown", "MIXED CASE".equals(ret(upper).get("string")),
            ret(upper));

        // --- solving for inputs ---
        Map<String, Object> magic = call("magic_check",
            List.of(Map.of("symbolicBytes", 4.0, "name", "buf")), "wantReturn", "1");
        Map<String, Object> buf = input(magic, "buf");
        String hex = String.valueOf(buf.get("hex"));
        boolean solves = hex.length() == 8 && hex.startsWith("4446")
            && (Integer.parseInt(hex.substring(4, 6), 16) ^ Integer.parseInt(hex.substring(6, 8), 16)) == 0x5a
            && ((Integer.parseInt(hex.substring(4, 6), 16) + Integer.parseInt(hex.substring(6, 8), 16)) & 0xff) == 0x9c;
        check("wantReturn solves magic_check", solves, magic);
        check("it ran as a symbolic exploration", "symbolic".equals(magic.get("mode")), magic.get("mode"));

        Map<String, Object> password = call("check_password",
            List.of(Map.of("symbolicBytes", 8.0, "name", "pw")), "wantReturn", 1.0);
        check("the password is recovered and unique", "hunter2".equals(input(password, "pw").get("string"))
            && Boolean.TRUE.equals(input(password, "pw").get("unique")), password.get("inputs"));

        Map<String, Object> classes = call("classify", List.of(Map.of("symbolicInt", 32.0, "name", "v")));
        Set<Long> returns = new TreeSet<>();
        boolean consistent = true;
        for (Map<String, Object> path : (List<Map<String, Object>>) classes.getOrDefault("paths", List.of())) {
            long r = num(ret(path).get("signed"));
            if (r > Integer.MAX_VALUE) {
                r -= 1L << 32;
            }
            long v = (int) num(input(path, "v").get("signed"));
            returns.add(r);
            consistent &= (v < 0 && r == -1) || (v > 100 && r == 2) || (v >= 0 && v <= 100 && r == 1);
        }
        check("every path of classify is found", returns.equals(new TreeSet<>(List.of(-1L, 1L, 2L))), classes);
        check("each path's example input produces its return value", consistent, classes.get("paths"));

        Map<String, Object> assumed = call("needs_device", List.of(), "symbolic", true, "wantReturn", "1");
        check("a symbolic run reports what an import must return",
            String.valueOf(assumed.get("assumedReturns")).contains("0x1234"), assumed);

        Map<String, Object> found = call("twice_add", List.of(Map.of("symbolicInt", 32.0)),
            "find", List.of("add3"));
        check("find stops at a function", "found".equals(found.get("outcome"))
            && String.valueOf(found.get("stoppedAt")).contains("(add3)"), found);
        Map<String, Object> noPath = call("classify", List.of(1.0), "wantReturn", "7");
        check("an impossible outcome says so", "no_path".equals(noPath.get("outcome")), noPath);

        // --- limits ---
        Map<String, Object> spin = call("spin", List.of(1.0), "maxSteps", 300.0);
        check("maxSteps stops a loop", "max_steps".equals(spin.get("stopReason"))
            && "unfinished".equals(spin.get("outcome"))
            && String.valueOf(spin.get("stoppedAt")).contains("(spin+"), spin);
        Map<String, Object> slow = call("spin", List.of(1.0), "timeoutMs", 400.0, "maxSteps", 5000000.0);
        check("timeoutMs stops a loop", "timeout".equals(slow.get("stopReason")), slow.get("stopReason"));

        // --- errors an agent can act on ---
        check("unknown function is explained",
            failure("no_such_function", List.of()).contains("no function, label or address"),
            failure("no_such_function", List.of()));
        check("an import cannot be called",
            failure("strcmp", List.of("a", "b")).contains("import"), failure("strcmp", List.of("a", "b")));
        check("unknown argument form is explained",
            failure("add3", List.of(Map.of("bogus", 1.0))).contains("unknown argument form"),
            failure("add3", List.of(Map.of("bogus", 1.0))));
        check("floating-point arguments are refused",
            failure("add3", List.of(1.5)).contains("not an integer"), failure("add3", List.of(1.5)));
        check("unknown register is explained",
            failure("add3", List.of(), "registers", Map.of("NOPE", 1.0)).contains("Unknown register"),
            failure("add3", List.of(), "registers", Map.of("NOPE", 1.0)));
        check("unknown stub target is explained",
            failure("add3", List.of(), "stubs", Map.of("nothing_here", 1.0)).contains("stubs"),
            failure("add3", List.of(), "stubs", Map.of("nothing_here", 1.0)));
        Map<String, Object> viaRegister = call("add3", List.of(1.0, 2.0), "registers", Map.of("RDX", "0x10"));
        check("registers sets what args did not", num(ret(viaRegister).get("signed")) == 19, viaRegister);

        // --- a Ghidra signature changes placement and typing, and the image is re-exported ---
        Function add3 = currentProgram.getListing().getGlobalFunctions("add3").get(0);
        add3.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        add3.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
            SourceType.USER_DEFINED,
            new ParameterImpl("a", IntegerDataType.dataType, currentProgram),
            new ParameterImpl("b", IntegerDataType.dataType, currentProgram),
            new ParameterImpl("c", IntegerDataType.dataType, currentProgram));
        Map<String, Object> typed = call("add3", List.of(1.0, 2.0, -10.0));
        println("TYPED " + typed);
        check("with a signature the result is typed", num(ret(typed).get("signed")) == -7
            && "int".equals(ret(typed).get("type")), ret(typed));
        check("the signature is shown", String.valueOf(typed.get("called")).contains("int add3(int a, int b, int c)"),
            typed.get("called"));
        Map<String, Object> wrongCount = call("add3", List.of(1.0, 2.0));
        check("an argument-count mismatch is flagged",
            String.valueOf(wrongCount.get("warnings")).contains("3 parameter(s) but 2"),
            wrongCount.get("warnings"));

        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ret(Map<String, Object> result) {
        Object value = result.get("returnValue");
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> buffers(Map<String, Object> result) {
        Object value = result.get("buffers");
        return value instanceof List ? (List<Map<String, Object>>) value : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> input(Map<String, Object> result, String name) {
        Object inputs = result.get("inputs");
        if (inputs instanceof Map<?, ?> map) {
            Object entry = map.get(name);
            if (entry == null && map.size() == 1) {
                entry = map.values().iterator().next();
            }
            if (entry instanceof Map) {
                return (Map<String, Object>) entry;
            }
        }
        return Map.of();
    }

    private static long num(Object value) {
        return value instanceof Number n ? n.longValue() : Long.MIN_VALUE;
    }
}
