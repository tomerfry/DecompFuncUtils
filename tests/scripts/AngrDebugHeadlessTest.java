// Headless regression test for the angr debugger's MCP face: AngrDebugTool (ghidra_angr_debug)
// and AngrHookTool (ghidra_angr_hook), and through them the session layer the debugger panel
// shares (AngrDebugger / AngrDebugSession) and the hook store (AngrHooks).
//
// Driven by tests/run_angr_test.ps1 -Script AngrDebugHeadlessTest.java over tests/angr/libangrdemo.so.
// The runner points DFU_ANGR_HOOKS at a scratch folder, so no real hooks are touched.
//@category Test
import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.angr.AngrHooks;
import decompfuncutils.mcp.tools.AngrDebugTool;
import decompfuncutils.mcp.tools.AngrEmulateTool;
import decompfuncutils.mcp.tools.AngrHookTool;
import ghidra.app.script.GhidraScript;

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

        // --- hooks: the import list, templates, saving, effect, reload, removal ---
        Map<String, Object> imports = hook("imports");
        String importText = String.valueOf(imports.get("imports"));
        check("imports says how each one is handled",
            importText.contains("name=mystery_device_read") && importText.contains("handledBy=stub")
                && importText.contains("handledBy=angr model"), imports);
        check("stubs are counted", num(imports.get("stubbed")) == 1, imports.get("stubbed"));

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

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ret(Map<String, Object> result) {
        Object value = result.get("returnValue");
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    private static long num(Object value) {
        return value instanceof Number n ? n.longValue() : Long.MIN_VALUE;
    }
}
