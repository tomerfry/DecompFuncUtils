// Headless regression test for the angr debugger's MCP face: AngrDebugTool (ghidra_angr_debug)
// and AngrHookTool (ghidra_angr_hook), and through them the session layer the debugger panel
// shares (AngrDebugger / AngrDebugSession) and the hook store (AngrHooks).
//
// Driven by tests/run_angr_test.ps1 -Script AngrDebugHeadlessTest.java over tests/angr/libangrdemo.so,
// and over tests/angr/libangrxmain.so with libangrxdep.so beside it in the project for the part
// where the destination is in another program.
// The runner points DFU_ANGR_HOOKS at a scratch folder, so no real hooks are touched.
//@category Test
import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.angr.AngrHooks;
import decompfuncutils.angr.AngrImports;
import decompfuncutils.mcp.tools.AngrDebugTool;
import decompfuncutils.mcp.tools.AngrEmulateTool;
import decompfuncutils.mcp.tools.AngrHookTool;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class AngrDebugHeadlessTest extends GhidraScript {

    private final AngrDebugTool debug = new AngrDebugTool();
    private final AngrHookTool hooks = new AngrHookTool();
    private final AngrEmulateTool emulate = new AngrEmulateTool();
    private int failures = 0;

    private void check(String label, boolean ok, Object detail) {
        String text = detail == null ? "" : String.valueOf(detail).replace("\n", "\\n");
        println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (text.isEmpty() ? "" : "  (" + (text.length() > 600 ? text.substring(0, 600) + "..." : text) + ")"));
        if (!ok) {
            failures++;
        }
    }

    private static Map<String, Object> args(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            map.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> dbg(String action, Object... pairs) throws Exception {
        Map<String, Object> request = args(pairs);
        request.put("action", action);
        return (Map<String, Object>) debug.execute(request, currentProgram, null);
    }

    private String dbgError(String action, Object... pairs) {
        try {
            return "NO ERROR: " + dbg(action, pairs);
        }
        catch (Exception e) {
            return String.valueOf(e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> hook(String action, Object... pairs) throws Exception {
        Map<String, Object> request = args(pairs);
        request.put("action", action);
        return (Map<String, Object>) hooks.execute(request, currentProgram, null);
    }

    private String hookError(String action, Object... pairs) {
        try {
            return "NO ERROR: " + hook(action, pairs);
        }
        catch (Exception e) {
            return String.valueOf(e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> run(String function, List<?> arguments) throws Exception {
        return (Map<String, Object>) emulate.execute(args("function", function, "args", arguments),
            currentProgram, null);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        if ("libangrxmain.so".equals(currentProgram.getName())) {
            try {
                crossModule();
            }
            finally {
                AngrDebugger.forget(currentProgram);
            }
            println("HEADLESS_TEST_SUMMARY failures=" + failures);
            println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
            return;
        }
        if (!"libangrdemo.so".equals(currentProgram.getName())) {
            println(getClass().getSimpleName() + ": skipping " + currentProgram.getName());
            return;
        }
        AtomicInteger notifications = new AtomicInteger();
        AngrDebugger.Listener listener = program -> notifications.incrementAndGet();
        AngrDebugger.addListener(listener);
        try {
            body(notifications);
        }
        finally {
            AngrDebugger.removeListener(listener);
            AngrDebugger.forget(currentProgram);
        }
        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    @SuppressWarnings("unchecked")
    private void body(AtomicInteger notifications) throws Exception {
        check("tool names", "ghidra_angr_debug".equals(debug.name()) && "ghidra_angr_hook".equals(hooks.name()), null);
        check("hooks go to the scratch folder", System.getenv("DFU_ANGR_HOOKS") != null
            && AngrHooks.root().toString().equals(System.getenv("DFU_ANGR_HOOKS")), AngrHooks.root());
        check("no session yet is explained", dbgError("state").contains("No debug session"), dbgError("state"));

        // --- start, step into, breakpoint, step out, edit, finish ---
        Map<String, Object> s = dbg("start", "function", "twice_add", "args", List.of(4.0));
        println("START " + s);
        check("start stops at the first instruction", "paused".equals(s.get("status"))
            && "twice_add".equals(s.get("location")) && num(s.get("instructions")) == 0, s);
        check("start shows the argument register", "0x4".equals(((Map<String, Object>) s.get("registers")).get("rdi")),
            s.get("registers"));
        check("the session is shared and listeners are told",
            AngrDebugger.session(currentProgram) != null && notifications.get() > 0,
            "notifications=" + notifications.get());

        s = dbg("step_into", "count", 3.0);
        check("step_into executes exactly that many instructions", num(s.get("instructions")) == 3
            && "step".equals(s.get("stop")), s);
        check("changed registers are reported", !((Map<String, Object>) s.get("changedRegisters")).isEmpty(),
            s.get("changedRegisters"));

        Map<String, Object> bp = dbg("add_breakpoint", "address", "add3");
        check("breakpoint by function name", String.valueOf(bp.get("breakpoints")).contains("(add3)"), bp);
        s = dbg("continue");
        check("continue stops at the breakpoint", "breakpoint".equals(s.get("stop"))
            && "add3".equals(s.get("location")) && num(s.get("depth")) == 1, s);
        check("the call into add3 is in the trace", String.valueOf(s.get("newCalls")).contains("add3"),
            s.get("newCalls"));
        s = dbg("step_out");
        check("step_out returns to the caller", String.valueOf(s.get("location")).startsWith("twice_add+")
            && num(s.get("depth")) == 0, s);
        check("add3(4,4,1) left 9 in rax", "0x9".equals(((Map<String, Object>) s.get("changedRegisters")).get("rax")),
            s.get("changedRegisters"));
        s = dbg("set", "register", "rax", "value", 100.0);
        s = dbg("continue");
        check("an edited register changes the result (100 * 2)", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == 200, s);
        check("stepping a finished path is explained", dbgError("step_into").contains("finished"),
            dbgError("step_into"));
        dbg("clear_breakpoints");

        // --- full detail ---
        s = dbg("start", "function", "add3", "args", List.of(1.0, 2.0, 3.0), "detail", "full");
        check("detail=full has every register and the stack",
            s.get("registers") instanceof List && ((Map<String, Object>) s.get("stack")).get("sp") != null, s.keySet());

        // --- step over a library call ---
        dbg("start", "function", "check_password", "args", List.of("nope"));
        s = dbg("step_over", "count", 7.0);
        boolean sawStrcmp = String.valueOf(s.get("newCalls")).contains("strcmp");
        for (int i = 0; i < 12 && !sawStrcmp && "paused".equals(s.get("status")); i++) {
            s = dbg("step_over");
            sawStrcmp = String.valueOf(s.get("newCalls")).contains("strcmp");
        }
        check("step_over runs a library call as one step", sawStrcmp
            && String.valueOf(s.get("location")).startsWith("check_password"), s);
        check("the call shows both strings", String.valueOf(s.get("newCalls")).contains("\"hunter2\""),
            s.get("newCalls"));

        // --- a missing import returns an unknown: fork, paths, concretize ---
        s = dbg("start", "function", "needs_device", "args", List.of());
        s = dbg("continue");
        println("FORK " + s);
        List<Map<String, Object>> paths = (List<Map<String, Object>>) s.getOrDefault("paths", List.of());
        List<Map<String, Object>> symbols = (List<Map<String, Object>>) s.getOrDefault("symbols", List.of());
        check("an unknown import value forks execution", "fork".equals(s.get("stop")) && paths.size() == 2, s);
        check("the unknown is a named symbol", symbols.size() == 1
            && String.valueOf(symbols.get(0).get("name")).startsWith("mystery_device_read_ret"), symbols);
        check("each path says which side it took",
            String.valueOf(paths.get(0).get("guard")).contains("0x1234")
                && String.valueOf(paths.get(1).get("guard")).contains("0x1234"), paths);
        check("the fork is explained", String.valueOf(s.get("hint")).contains("select_path"), s.get("hint"));
        String symbol = symbols.isEmpty() ? "?" : String.valueOf(symbols.get(0).get("name"));
        int equalSide = String.valueOf(paths.get(0).get("guard")).contains("==") ? 0 : 1;

        s = dbg("select_path", "path", (double) (1 - equalSide));
        check("select_path switches paths", num(s.get("path")) == 1 - equalSide, s);
        String contradiction = dbgError("concretize", "symbol", symbol, "value", "0x1234");
        check("a contradicting value is refused", contradiction.contains("contradicts"), contradiction);
        s = dbg("concretize", "symbol", symbol);
        Map<String, Object> pinned = ((List<Map<String, Object>>) s.get("symbols")).get(0);
        check("concretize without a value picks one that fits", pinned.get("value") != null
            && !"0x1234".equals(pinned.get("value")), pinned);
        s = dbg("continue");
        check("the 'not equal' path returns 0", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == 0, s);
        s = dbg("select_path", "path", (double) equalSide);
        s = dbg("continue");
        check("the 'equal' path returns 1", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == 1, s);

        s = dbg("start", "function", "needs_device", "args", List.of(), "unmodelledImports", "zero");
        s = dbg("continue");
        check("unmodelledImports=zero runs straight through", "returned".equals(s.get("status"))
            && s.get("paths") == null && num(ret(s).get("signed")) == 0, s);

        // --- symbolize a register, fork on it, concretize everything ---
        dbg("start", "function", "classify", "args", List.of(5.0));
        s = dbg("symbolize", "register", "rdi", "name", "v");
        check("symbolize makes a register unknown under the given name",
            String.valueOf(s.get("symbols")).contains("name=v"), s.get("symbols"));
        s = dbg("continue");
        check("execution forks on the new unknown", "fork".equals(s.get("stop")), s);
        s = dbg("concretize", "all", true);
        s = dbg("continue");
        check("concretize all lets the path run to its end", "returned".equals(s.get("status")), s);

        // --- faults keep the state inspectable ---
        dbg("start", "function", "deref", "args", List.of(0.0));
        s = dbg("continue");
        Map<String, Object> fault = (Map<String, Object>) s.getOrDefault("fault", Map.of());
        check("a NULL dereference stops as a fault at the instruction", "fault".equals(s.get("status"))
            && String.valueOf(s.get("location")).startsWith("deref+") && "0x0".equals(fault.get("address")), s);

        // --- watches and memory writes ---
        s = dbg("start", "function", "bump_counter", "args", List.of(5.0), "watch", List.of("g_counter:4"));
        check("a watch shows a global before the run", String.valueOf(s.get("memory")).contains("07000000"),
            s.get("memory"));
        s = dbg("continue");
        check("and after it", String.valueOf(s.get("memory")).contains("0c000000"), s.get("memory"));
        check("the write is reported with its symbol", String.valueOf(s.get("writes")).contains("g_counter"),
            s.get("writes"));

        // --- a run that does not end is bounded and stays usable ---
        dbg("start", "function", "spin", "args", List.of(1.0));
        s = dbg("continue", "timeoutMs", 700.0);
        check("continue honours timeoutMs", "timeout".equals(s.get("stop")) && "paused".equals(s.get("status"))
            && num(s.get("instructions")) > 10, s);
        long before = num(s.get("instructions"));
        s = dbg("step_into");
        check("the session is still steppable afterwards", num(s.get("instructions")) == before + 1, s);

        destinations();

        // --- hooks: the import list, templates, saving, effect, reload, removal ---
        Map<String, Object> imports = hook("imports");
        String importText = String.valueOf(imports.get("imports"));
        check("imports says how each one is handled",
            importText.contains("name=mystery_device_read") && importText.contains("handledBy=stub")
                && importText.contains("handledBy=angr model"), imports);
        check("stubs are counted (mystery_device_read, cfg_mode, cfg_level)", num(imports.get("stubbed")) == 3,
            imports.get("stubbed"));

        Map<String, Object> template = hook("template", "target", "mystery_device_read");
        check("a template is offered", String.valueOf(template.get("code")).contains("def hook(ctx"),
            template.get("code"));
        String broken = hookError("set", "name", "device", "target", "mystery_device_read",
            "code", "def hook(ctx)\n    return 1\n");
        check("a syntax error is caught before saving", broken.contains("does not compile")
            && AngrHooks.get(currentProgram, "device") == null, broken);
        check("code without an entry point is refused",
            hookError("set", "name", "device", "code", "x = 1\n").contains("def hook"),
            hookError("set", "name", "device", "code", "x = 1\n"));
        check("a bad name is refused", hookError("set", "name", "../evil", "code", "def hook(ctx):\n    return 1\n")
            .contains("hook name"), hookError("set", "name", "../evil", "code", "def hook(ctx):\n    return 1\n"));

        String code = "def hook(ctx, reg):\n    ctx.log('device read', reg)\n    return 0x1234 if reg == 3 else 0\n";
        Map<String, Object> saved = hook("set", "name", "device", "target", "mystery_device_read", "code", code);
        check("a hook is saved as a file", String.valueOf(saved.get("file")).endsWith("device.py")
            && new java.io.File(String.valueOf(saved.get("file"))).isFile(), saved);
        check("list shows it", String.valueOf(hook("list").get("hooks")).contains("name=device"), hook("list"));
        check("get returns the code", code.equals(hook("get", "name", "device").get("code")),
            hook("get", "name", "device"));
        check("imports now says python hook",
            String.valueOf(hook("imports").get("imports")).contains("handledBy=python hook"), null);

        Map<String, Object> emulated = run("needs_device", List.of());
        check("the emulator uses the hook", num(ret(emulated).get("signed")) == 1
            && String.valueOf(emulated.get("pythonHooks")).contains("device")
            && String.valueOf(emulated.get("calls")).contains("device read 3"), emulated);
        dbg("start", "function", "needs_device", "args", List.of());
        s = dbg("continue");
        check("the debugger uses the hook, so nothing is unknown", "returned".equals(s.get("status"))
            && s.get("paths") == null && num(ret(s).get("signed")) == 1, s);

        hook("disable", "name", "device");
        check("a disabled hook is not applied", num(ret(run("needs_device", List.of())).get("signed")) == 0, null);
        dbg("start", "function", "needs_device", "args", List.of(), "unmodelledImports", "zero");
        Map<String, Object> enabled = hook("enable", "name", "device");
        check("a change reaches the running session", Boolean.TRUE.equals(enabled.get("appliedToRunningSession")),
            enabled);
        s = dbg("continue");
        check("and takes effect there", "returned".equals(s.get("status")) && num(ret(s).get("signed")) == 1, s);

        hook("set", "name", "boom", "target", "mystery_device_read", "code", "def hook(ctx):\n    return 1 / 0\n");
        hook("disable", "name", "device");
        dbg("start", "function", "needs_device", "args", List.of());
        s = dbg("continue");
        check("a hook that raises is a fault naming the line", "fault".equals(s.get("status"))
            && String.valueOf(s.get("fault")).contains("ZeroDivisionError at line 2"), s.get("fault"));
        hook("delete", "name", "boom");
        check("delete removes it", Boolean.TRUE.equals(hook("delete", "name", "device").get("deleted"))
            && ((List<?>) hook("list").get("hooks")).isEmpty(), hook("list"));

        // --- an inline hook observes and edits without replacing the function ---
        hook("set", "name", "peek", "target", "add3", "kind", "inline", "skip", 0.0,
            "code", "def hook(ctx):\n    ctx.log('entering add3 with', ctx.reg('rdi'))\n    ctx.set_reg('rdi', 10)\n");
        Map<String, Object> inline = run("add3", List.of(1.0, 2.0, 3.0));
        check("an inline hook runs at the address and the function still executes",
            num(ret(inline).get("signed")) == 15 && String.valueOf(inline.get("calls")).contains("entering add3 with 1"),
            inline);
        hook("delete", "name", "peek");

        // --- stop ---
        check("stop ends the session", "stopped".equals(dbg("stop").get("status"))
            && AngrDebugger.session(currentProgram) == null, null);
        check("stopping twice is harmless", "no_session".equals(dbg("stop").get("status")), null);
        AngrDebugSession gone = AngrDebugger.session(currentProgram);
        check("no session is left behind", gone == null, gone);
    }

    /**
     * A destination in another program: libangrxmain.so imports from libangrxdep.so, which sits
     * in the same project. Both are shared objects loaded at the same base, so the library has to
     * be moved to run next to the importer.
     */
    @SuppressWarnings("unchecked")
    private void crossModule() throws Exception {
        final String lib = "libangrxdep.so";

        // Without the library in the session, its functions are what they always were: unknown.
        dbg("start", "function", "xlocal", "args", List.of(5.0));
        Map<String, Object> s = dbg("continue");
        check("without the library an import of it is an unknown", "returned".equals(s.get("status"))
            && s.get("modules") == null && String.valueOf(s.get("unmodelledExternals")).contains("xdep_apply"), s);

        // Asked for by name, the library runs next to the program and the call runs its code:
        // add_one() through a function-pointer table that had to move with the library.
        s = dbg("start", "function", "xlocal", "args", List.of(5.0), "modules", List.of(lib));
        check("a library named at start is loaded", String.valueOf(s.get("modules")).contains(lib)
            && String.valueOf(s.get("hint")).contains("Loaded with it: " + lib), s);
        s = dbg("continue", "detail", "full");
        check("a call into it runs its real code", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == 6, s);
        check("the call is shown as running in the library", String.valueOf(s.get("calls")).contains("into=" + lib), s.get("calls"));
        List<Map<String, Object>> imports = AngrImports.describe(currentProgram, null, monitor);
        String handled = "";
        for (Map<String, Object> row : imports) {
            if ("xdep_apply".equals(row.get("name"))) {
                handled = String.valueOf(row.get("handledBy"));
            }
        }
        check("the import list says where such a call runs", handled.equals("code in " + lib), handled);

        // A stub still wins over the library's code.
        dbg("start", "function", "xlocal", "args", List.of(5.0), "modules", List.of(lib),
            "stubs", Map.of("xdep_apply", 77.0));
        s = dbg("continue");
        check("a stub wins over the library's code", num(ret(s).get("signed")) == 77, s);

        // A breakpoint in the library stops a session of the importer.
        Program library = AngrDebugger.pair(currentProgram, lib, null, monitor);
        Address apply = library.getListing().getGlobalFunctions("xdep_apply").get(0).getEntryPoint();
        Address secret = library.getListing().getGlobalFunctions("xdep_secret").get(0).getEntryPoint();
        Address checkEntry = library.getListing().getGlobalFunctions("xdep_check").get(0).getEntryPoint();
        check("both programs sit at the same base in Ghidra, so one has to move",
            library.getImageBase().equals(currentProgram.getImageBase()), library.getImageBase());
        AngrDebugger.setBreakpoint(library, apply, true);
        dbg("start", "function", "xlocal", "args", List.of(5.0));
        s = dbg("continue");
        check("a breakpoint in the library stops there", "breakpoint".equals(s.get("stop"))
            && (lib + "!xdep_apply").equals(s.get("location")) && lib.equals(s.get("module"))
            && apply.toString().equals(s.get("moduleAddress")), s);
        check("the address it runs at is not the one Ghidra shows for it",
            !String.valueOf(s.get("pc")).equals("0x" + Long.toHexString(apply.getOffset())), s.get("pc"));
        AngrDebugger.clearBreakpoints(library);
        // Lets go of the library as well: from here on only a destination brings it back.
        AngrDebugger.forget(currentProgram);

        // ---- the destination in the library ----
        Map<String, Object> set = dbg("set_destination", "address", "xdep_check");
        check("naming an import means its code in the library", (lib + "!xdep_check @ " + checkEntry)
                .equals(set.get("destination")) && String.valueOf(set.get("next")).contains("loads " + lib), set);
        set = dbg("set_destination", "address", "xdep_secret", "program", lib);
        check("a place in the library can be named with 'program'",
            (lib + "!xdep_secret @ " + secret).equals(set.get("destination")), set);
        set = dbg("set_destination", "address", lib + "!xdep_secret");
        check("or as library!name", (lib + "!xdep_secret @ " + secret).equals(set.get("destination")), set);
        check("a library that is not in the project is explained",
            dbgError("set_destination", "address", "libnowhere.so!f").contains("no program named"),
            dbgError("set_destination", "address", "libnowhere.so!f"));

        // xroute() gets to xdep_secret() only if cfg_mode() == 2 (unknown import of the program),
        // xdep_level == 3 (a variable of the library), cfg_tier() == 4 (unknown import of the
        // library), triple(key) == 21 (the library calling back) and key + 2 == 9.
        s = dbg("start", "function", "xroute", "args", List.of(Map.of("symbolicInt", 32.0, "name", "key")));
        check("a session started with a destination in a library loads the library",
            String.valueOf(s.get("modules")).contains(lib)
                && String.valueOf(s.get("destination")).contains(lib + "!xdep_secret"), s);
        s = dbg("seek");
        println("XSEEK " + s);
        Map<String, Object> seek = (Map<String, Object>) s.getOrDefault("seek", Map.of());
        check("seek arrives in the other program", "destination".equals(s.get("stop"))
            && "reached".equals(seek.get("result")) && (lib + "!xdep_secret").equals(s.get("location")), s);
        check("it says where that is in the library's own terms", lib.equals(s.get("module"))
            && secret.toString().equals(s.get("moduleAddress")), s.get("module") + " " + s.get("moduleAddress"));
        check("the search was guided across both programs", Boolean.TRUE.equals(seek.get("guided"))
            && String.valueOf(s.get("seekGuide")).contains("in 2 modules"), s.get("seekGuide"));

        Map<String, Object> ledger = (Map<String, Object>) s.getOrDefault("ledger", Map.of());
        List<Map<String, Object>> entries = (List<Map<String, Object>>) ledger.getOrDefault("entries", List.of());
        List<String> unknowns = new ArrayList<>();
        List<String> where = new ArrayList<>();
        for (Map<String, Object> entry : entries) {
            where.add(String.valueOf(entry.get("where")));
            if ("unknown".equals(entry.get("kind"))) {
                unknowns.add(String.valueOf(entry.get("symbol")).replaceAll("_ret_\\d+$", ""));
            }
        }
        check("the only unknowns on the way are the two imports nothing defines",
            unknowns.equals(List.of("cfg_mode", "cfg_tier")), unknowns + " " + entries);
        check("the ledger names places in both programs", !where.isEmpty() && where.get(0).startsWith("xroute+")
            && where.get(where.size() - 1).startsWith(lib + "!xdep_check+"), where);
        check("the ledger says which destination and which library", String.valueOf(ledger.get("destination"))
            .contains(lib + "!xdep_secret") && Boolean.TRUE.equals(ledger.get("atDestination"))
            && String.valueOf(ledger.get("modules")).contains(lib), ledger.get("destination"));
        Map<String, Long> values = new HashMap<>();
        for (Map<String, Object> unknown : (List<Map<String, Object>>) ledger.getOrDefault("unknowns", List.of())) {
            String name = String.valueOf(unknown.get("name")).replaceAll("_ret_\\d+$", "");
            values.put(name, Long.decode(String.valueOf(unknown.get("value"))));
        }
        check("its values take the path through both programs",
            values.size() == 3 && values.get("key") == 7 && (int) (long) values.get("cfg_mode") == 2
                && (int) (long) values.get("cfg_tier") == 4, values);
        String calls = String.valueOf(dbg("state", "detail", "full").get("calls"));
        check("the calls show the crossing and the callback", calls.contains("call=xdep_check")
            && calls.contains("into=" + lib) && calls.contains("call=triple"), calls);

        s = dbg("continue");
        check("execution carries on from there and returns through both", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == (7 ^ 0x5a), s);

        // Nothing in xnever() leads to the library.
        dbg("start", "function", "xnever", "args", List.of(1.0));
        s = dbg("seek");
        check("a function that never enters the library cannot get there", "seek_exhausted".equals(s.get("stop")), s);

        // A destination set after the session started: started again while it has not moved...
        AngrDebugger.forget(currentProgram);
        s = dbg("start", "function", "xroute", "args", List.of(Map.of("symbolicInt", 32.0, "name", "key")));
        check("with no destination the library is not loaded", s.get("modules") == null, s.get("modules"));
        dbg("set_destination", "address", lib + "!xdep_secret");
        s = dbg("seek");
        check("a session that has not moved is started again to load it", "destination".equals(s.get("stop"))
            && String.valueOf(s.get("reloaded")).contains(lib), s.get("stop") + " " + s.get("reloaded"));

        // ...and refused, with the way out, once it has.
        AngrDebugger.forget(currentProgram);
        dbg("start", "function", "xroute", "args", List.of(Map.of("symbolicInt", 32.0, "name", "key")));
        dbg("step_into");
        dbg("set_destination", "address", lib + "!xdep_secret");
        check("one that has moved says to start again", dbgError("seek").contains("did not load")
            && dbgError("seek").contains("Start the session again"), dbgError("seek"));

        check("clearing the destination clears it in the library too",
            "none".equals(dbg("clear_destination").get("destination"))
                && AngrDebugger.destinations(currentProgram).isEmpty(), AngrDebugger.destinations(currentProgram));
    }

    /** A destination to get to, the search for a way there, and the ledger of what it took. */
    @SuppressWarnings("unchecked")
    private void destinations() throws Exception {
        check("seek without a destination is explained",
            dbgError("seek").contains("No destination is set") || dbgError("seek").contains("No debug session"),
            dbgError("seek"));
        Map<String, Object> set = dbg("set_destination", "address", "unlock");
        check("a destination is set by function name", String.valueOf(set.get("destination")).contains("(unlock)"), set);

        // gate() reaches unlock() only if cfg_mode() == 2, cfg_level() >= 10 and key*3 + level == 100,
        // where both functions are imports nothing models.
        dbg("start", "function", "gate", "args", List.of(Map.of("symbolicInt", 32.0, "name", "key")));
        Map<String, Object> s = dbg("seek");
        println("SEEK " + s);
        Map<String, Object> seek = (Map<String, Object>) s.getOrDefault("seek", Map.of());
        check("seek arrives at the destination", "destination".equals(s.get("stop"))
            && "unlock".equals(s.get("location")) && "reached".equals(seek.get("result")), s);
        check("the search was guided by Ghidra's control-flow graph", Boolean.TRUE.equals(seek.get("guided"))
            && String.valueOf(s.get("seekGuide")).contains("control-flow graph"), s.get("seekGuide"));
        check("arriving is explained", String.valueOf(s.get("hint")).contains("Reached the destination"), s.get("hint"));
        check("the path it took became the current one, the start is kept",
            num(s.get("path")) != 0 && ((List<?>) s.getOrDefault("paths", List.of())).size() == 2, s.get("paths"));

        Map<String, Object> ledger = (Map<String, Object>) s.getOrDefault("ledger", Map.of());
        List<Map<String, Object>> entries = (List<Map<String, Object>>) ledger.getOrDefault("entries", List.of());
        List<String> kinds = new ArrayList<>();
        for (Map<String, Object> entry : entries) {
            kinds.add(String.valueOf(entry.get("kind")));
        }
        check("the ledger records the way in order: unknown, branch, unknown, branch, branch",
            kinds.equals(List.of("unknown", "branch", "unknown", "branch", "branch")), kinds);
        check("a call into code that is not there is kept symbolic and noted",
            entries.size() == 5 && String.valueOf(entries.get(0).get("text")).contains("cfg_mode() is not modelled")
                && String.valueOf(entries.get(0).get("symbol")).startsWith("cfg_mode_ret"), entries);
        check("each branch carries the condition this path took",
            entries.size() == 5 && String.valueOf(entries.get(1).get("condition")).contains("== 0x2")
                && String.valueOf(entries.get(4).get("condition")).contains("key"), entries);
        check("ledger addresses carry Ghidra's names", entries.size() == 5
            && String.valueOf(entries.get(1).get("where")).startsWith("gate+"), entries);
        check("it counts the decisions and the constraints", num(ledger.get("decisions")) == 3
            && num(ledger.get("constraintCount")) == 3, ledger.get("decisions") + " / " + ledger.get("constraintCount"));

        Map<String, Long> values = new HashMap<>();
        Map<String, String> requires = new HashMap<>();
        for (Map<String, Object> unknown : (List<Map<String, Object>>) ledger.getOrDefault("unknowns", List.of())) {
            String name = String.valueOf(unknown.get("name"));
            String key = name.startsWith("cfg_mode") ? "mode" : name.startsWith("cfg_level") ? "level" : name;
            values.put(key, Long.decode(String.valueOf(unknown.get("value"))));
            requires.put(key, String.valueOf(unknown.get("requires")));
        }
        check("the ledger states what the path requires of the unknown return value",
            String.valueOf(requires.get("mode")).contains("== 0x2")
                && String.valueOf(requires.get("level")).contains(">=s 0xa"), requires);
        boolean satisfies = values.size() == 3 && (int) (long) values.get("mode") == 2
            && (int) (long) values.get("level") >= 10
            && (int) (values.get("key") * 3 + values.get("level")) == 100;
        check("the values it gives satisfy the whole path together", satisfies, values);

        Object markdown = debug.execute(args("action", "ledger", "format", "markdown"), currentProgram, null);
        check("the ledger can be had as a Markdown document", markdown instanceof String text
            && text.contains("## On the way") && text.contains("cfg_mode_ret")
            && text.contains("What the path requires of each unknown") && text.contains("reached"), markdown);

        s = dbg("continue");
        check("stepping on from the destination works", "returned".equals(s.get("status"))
            && num(ret(s).get("signed")) == 1, s);

        // With the argument fixed, the unknown has to make up for it: 5*3 + level == 100.
        dbg("start", "function", "gate", "args", List.of(5.0));
        s = dbg("seek");
        String fixed = String.valueOf(((Map<String, Object>) s.getOrDefault("ledger", Map.of())).get("unknowns"));
        check("with a concrete argument the unknown is solved for", "destination".equals(s.get("stop"))
            && fixed.contains("value=0x55"), fixed);

        // A call through a pointer nobody set: the target itself is unknown.
        dbg("start", "function", "via_callback", "args", List.of(3.0));
        s = dbg("seek");
        String callbackLedger = String.valueOf(s.get("ledger"));
        check("a call to an unknown target is skipped, not a dead end", "destination".equals(s.get("stop")), s);
        check("and its return value is constrained in the ledger",
            callbackLedger.contains("a call through") && callbackLedger.contains("indirect_call_ret")
                && callbackLedger.contains("== 0x7"), callbackLedger);

        // Nowhere to go: classify() never calls unlock().
        dbg("start", "function", "classify", "args", List.of(Map.of("symbolicInt", 32.0, "name", "v")));
        s = dbg("seek");
        check("an unreachable destination is reported as such", "seek_exhausted".equals(s.get("stop"))
            && "unreachable".equals(((Map<String, Object>) s.get("seek")).get("result"))
            && String.valueOf(s.get("hint")).contains("none reaches"), s);
        check("and says how the paths ended", String.valueOf(((Map<String, Object>) s.get("seek")).get("ended"))
            .contains("returned=3"), s.get("seek"));

        // A search that cannot finish stops on time, keeps what it explored, and resumes.
        dbg("start", "function", "spin", "args", List.of(1.0));
        s = dbg("seek", "timeoutMs", 600.0);
        long explored = num(((Map<String, Object>) s.getOrDefault("seek", Map.of())).get("blocks"));
        check("seek honours timeoutMs", "timeout".equals(s.get("stop")) && "paused".equals(s.get("status"))
            && explored > 10, s);
        s = dbg("seek", "timeoutMs", 400.0);
        check("seeking again resumes the same search",
            num(((Map<String, Object>) s.getOrDefault("seek", Map.of())).get("blocks")) > explored, s.get("seek"));

        // The ledger is kept while stepping by hand too, and records what was fixed by hand.
        dbg("clear_destination");
        dbg("start", "function", "needs_device", "args", List.of());
        s = dbg("continue");
        String symbol = String.valueOf(((List<Map<String, Object>>) s.get("symbols")).get(0).get("name"));
        dbg("concretize", "symbol", symbol);
        Map<String, Object> byHand = dbg("ledger");
        String handKinds = String.valueOf(byHand.get("entries"));
        check("stepping by hand keeps a ledger: the unknown, the branch, the fix",
            handKinds.contains("kind=unknown") && handKinds.contains("kind=branch")
                && handKinds.contains("fixed by hand"), handKinds);
        check("with no destination the ledger says nothing of one", byHand.get("destination") == null, byHand);

        // The one-shot emulator's 'find' carries the ledger as well.
        Map<String, Object> found = (Map<String, Object>) emulate.execute(args("function", "gate",
            "args", List.of(Map.of("symbolicInt", 32.0, "name", "key")), "find", List.of("unlock"),
            "symbolic", true), currentProgram, null);
        check("ghidra_angr_emulate find returns the ledger of the path it found",
            "found".equals(found.get("outcome")) && found.get("ledger") instanceof Map<?, ?> m
                && ((List<?>) m.get("entries")).size() == 5, found.get("ledger"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ret(Map<String, Object> result) {
        Object value = result.get("returnValue");
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    private static long num(Object value) {
        return value instanceof Number n ? n.longValue() : Long.MIN_VALUE;
    }
}
