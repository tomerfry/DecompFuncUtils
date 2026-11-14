package decompfuncutils.mcp.tools;

import decompfuncutils.angr.AngrCallSpec;
import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * The angr debugger, driven over MCP: start a function, step it, look at and change its state.
 *
 * <p>The session is the same one the "angr Debugger" panel shows. An agent stepping here moves
 * the program counter the user sees in the Listing, and a user who clicks Step Over in the panel
 * has moved the session the agent reads next.
 */
public class AngrDebugTool implements McpTool {

    private static final List<String> ACTIONS = List.of(
        "start", "state", "step_into", "step_over", "step_out", "continue", "run_to",
        "add_breakpoint", "remove_breakpoint", "clear_breakpoints",
        "select_path", "drop_path", "concretize", "symbolize", "set", "reload_hooks", "stop");

    private static final int DEFAULT_RUN_MS = 30_000;

    /** Calls already reported to the agent, per session, so each response lists only new ones. */
    private final Map<AngrDebugSession, Integer> reportedCalls = new WeakHashMap<>();

    @Override
    public String name() { return "ghidra_angr_debug"; }

    @Override
    public String description() {
        return "Debug a function of this program under angr: start it, step, set breakpoints, inspect " +
            "registers/stack/memory, and change state. One session per program, shared with the " +
            "'angr Debugger' panel in Ghidra, so the user sees what you do and you see what they do.\n" +
            "action=start takes 'function' and 'args' exactly as ghidra_angr_emulate does (plus stubs, " +
            "memory, registers, stdin, strictMemory) and stops at the first instruction. Then: " +
            "step_into / step_over / step_out ('count' to repeat), continue (to a breakpoint, a fork, " +
            "the return, or a fault; 'timeoutMs'), run_to ('address': hex or a function name), " +
            "add_breakpoint / remove_breakpoint ('address') / clear_breakpoints, state, stop.\n" +
            "The binary's shared objects do not need to be in the project. Imports run as angr models " +
            "or your Python hooks (ghidra_angr_hook); anything else returns an UNKNOWN (symbolic) " +
            "value, named like 'read_config_ret_3' ('unmodelledImports':'zero' at start makes them " +
            "return 0 instead). When a branch depends on an unknown, execution stops with " +
            "stop='fork': this path took one side and the others are parked in 'paths' - select_path " +
            "('path') to follow another, drop_path to discard one.\n" +
            "Unknowns are listed in 'symbols'. concretize fixes one: give 'symbol', 'register' or " +
            "'address'(+'size'), and optionally 'value' (omit to take a value the solver finds; it is " +
            "refused if it contradicts the path), or 'all':true to fix every unknown at once. " +
            "symbolize makes a 'register' or 'address' unknown ('name' it). set overwrites a " +
            "'register' or 'address' with 'value' (a number, or a string/bytes/buffer object to point " +
            "it at new memory).\n" +
            "Each response gives pc, why it stopped, the registers that changed, new calls and memory " +
            "writes; pass 'detail':'full' for every register and the stack.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("action", Map.of("type", "string", "enum", ACTIONS,
            "description", "What to do; see the tool description."));
        props.put("function", Map.of("type", "string",
            "description", "start: function name or address to debug"));
        props.put("args", Map.of("type", "array",
            "description", "start: arguments, in the forms ghidra_angr_emulate takes"));
        props.put("stubs", Map.of("type", "object",
            "description", "start: {function or import: return value | \"symbolic\"}"));
        props.put("memory", Map.of("type", "array", "items", Map.of("type", "object"),
            "description", "start: memory to seed, as in ghidra_angr_emulate"));
        props.put("registers", Map.of("type", "object",
            "description", "start: extra registers to set"));
        props.put("stdin", Map.of("type", "string", "description", "start: standard input text"));
        props.put("strictMemory", Map.of("type", "boolean",
            "description", "start: fault on unmapped memory (default true)"));
        props.put("unmodelledImports", Map.of("type", "string", "enum", List.of("symbolic", "zero"),
            "description", "start: what imports with no model and no hook return (default symbolic)"));
        props.put("arch", Map.of("type", "string", "description", "start: override the angr architecture"));
        props.put("count", Map.of("type", "integer", "description", "step_*: how many steps (default 1)"));
        props.put("timeoutMs", Map.of("type", "integer",
            "description", "continue / run_to / step_over / step_out: wall-clock limit (default "
                + DEFAULT_RUN_MS + "). The session stays where it got to."));
        props.put("address", Map.of("type", "string",
            "description", "run_to / breakpoints: a code address or function name. " +
                "concretize / symbolize / set: a data address or symbol name."));
        props.put("size", Map.of("type", "integer",
            "description", "concretize / symbolize / set with 'address': bytes (default pointer size)"));
        props.put("register", Map.of("type", "string", "description", "concretize / symbolize / set: a register"));
        props.put("symbol", Map.of("type", "string", "description", "concretize: a name from 'symbols'"));
        props.put("all", Map.of("type", "boolean", "description", "concretize: fix every unknown"));
        props.put("value", Map.of("description", "concretize: the value to fix (optional). set: the new value."));
        props.put("name", Map.of("type", "string", "description", "symbolize: name for the new unknown"));
        props.put("path", Map.of("type", "integer", "description", "select_path / drop_path: a path id"));
        props.put("watch", Map.of("type", "array", "items", Map.of("type", "string"),
            "description", "Memory to include after every stop: symbol or address, optionally ':length'. " +
                "Replaces the previous list."));
        props.put("detail", Map.of("type", "string", "enum", List.of("summary", "full"),
            "description", "'summary' (default) or 'full' for all registers and the stack"));
        schema.put("properties", props);
        schema.put("required", List.of("action"));
        return schema;
    }

    /** Works in a helper process; changes nothing in the program. */
    @Override public boolean requiresEdt() { return false; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) {
            throw new IllegalStateException("No program is open");
        }
        TaskMonitor monitor = McpUtil.activeMonitor();
        String action = arguments.get("action") == null ? "" : String.valueOf(arguments.get("action"));
        if (!ACTIONS.contains(action)) {
            throw new IllegalArgumentException("action must be one of " + ACTIONS);
        }
        boolean full = "full".equals(arguments.get("detail"));

        switch (action) {
            case "start": {
                Map<String, Object> launch = new LinkedHashMap<>(arguments);
                for (String key : List.of("action", "detail", "watch", "count", "path", "value", "name",
                        "symbol", "register", "address", "size", "all")) {
                    launch.remove(key);
                }
                AngrDebugSession session = AngrDebugger.start(program,
                    AngrEmulateTool.configuredPython(tool), launch, monitor);
                applyWatch(session, arguments, monitor);
                return present(session, full, "Stopped at the first instruction of " + session.call.title + ".");
            }
            case "stop": {
                boolean had = AngrDebugger.stop(program);
                return Map.of("status", had ? "stopped" : "no_session");
            }
            case "add_breakpoint":
            case "remove_breakpoint": {
                Address address = AngrCallSpec.resolveCode(program, required(arguments, "address"), "address");
                AngrDebugger.setBreakpoint(program, address, action.equals("add_breakpoint"));
                return breakpointList(program);
            }
            case "clear_breakpoints":
                AngrDebugger.clearBreakpoints(program);
                return breakpointList(program);
            default:
                break;
        }

        AngrDebugSession session = AngrDebugger.require(program);
        applyWatch(session, arguments, monitor);
        int count = arguments.get("count") instanceof Number n ? Math.max(1, n.intValue()) : 1;
        long budget = arguments.get("timeoutMs") instanceof Number n
            ? Math.max(100, Math.min(n.longValue(), AngrCallSpec.HARD_MAX_TIMEOUT_MS)) : DEFAULT_RUN_MS;

        switch (action) {
            case "state":
                session.refresh(monitor);
                break;
            case "step_into":
                session.step("into", count, null, budget, monitor);
                break;
            case "step_over":
                session.step("over", count, null, budget, monitor);
                break;
            case "step_out":
                session.step("out", 1, null, budget, monitor);
                break;
            case "continue":
                session.step("continue", 1, null, budget, monitor);
                break;
            case "run_to":
                session.step("continue", 1,
                    AngrCallSpec.resolveCode(program, required(arguments, "address"), "address"), budget, monitor);
                break;
            case "select_path":
            case "drop_path": {
                if (!(arguments.get("path") instanceof Number)) {
                    throw new IllegalArgumentException(action + " needs 'path': an id from 'paths'");
                }
                Map<String, Object> edit = new LinkedHashMap<>();
                edit.put("action", action.equals("select_path") ? "select" : "drop");
                edit.put("path", arguments.get("path"));
                session.edit(edit, monitor);
                break;
            }
            case "concretize":
            case "symbolize":
            case "set": {
                Map<String, Object> edit = new LinkedHashMap<>();
                edit.put("action", action);
                for (String key : List.of("register", "address", "size", "symbol", "value", "name", "all")) {
                    if (arguments.get(key) != null) {
                        edit.put(key, arguments.get(key));
                    }
                }
                session.edit(edit, monitor);
                break;
            }
            case "reload_hooks":
                session.reloadHooks(monitor);
                break;
            default:
                throw new IllegalArgumentException("Unhandled action " + action);
        }
        return present(session, full, null);
    }

    private static String required(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        if (value == null || String.valueOf(value).isBlank()) {
            throw new IllegalArgumentException("'" + key + "' is required for this action");
        }
        return String.valueOf(value);
    }

    private static void applyWatch(AngrDebugSession session, Map<String, Object> arguments, TaskMonitor monitor)
            throws Exception {
        if (arguments.get("watch") instanceof List<?> list) {
            List<String> entries = new ArrayList<>();
            for (Object o : list) {
                entries.add(String.valueOf(o));
            }
            session.setWatches(entries);
            session.refresh(monitor);
        }
    }

    private static Map<String, Object> breakpointList(Program program) {
        List<String> out = new ArrayList<>();
        for (Address address : AngrDebugger.breakpoints(program)) {
            out.add(AngrCallSpec.codeLabel(program, "0x" + Long.toHexString(address.getOffset())));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("breakpoints", out);
        return result;
    }

    // ---- what the agent gets back ----

    @SuppressWarnings("unchecked")
    private Map<String, Object> present(AngrDebugSession session, boolean full, String note) {
        Map<String, Object> snapshot = session.snapshot();
        Map<String, Object> out = new LinkedHashMap<>();
        for (String key : List.of("function", "called", "status", "stop", "pc", "location", "path",
                "instructions", "depth", "flags")) {
            if (snapshot.get(key) != null && (full || !key.equals("called") || note != null)) {
                out.put(key, snapshot.get(key));
            }
        }
        String hint = note != null ? note : hint(snapshot);
        if (hint != null) {
            out.put("hint", hint);
        }
        for (String key : List.of("returnValue", "fault", "paths", "symbols")) {
            if (snapshot.get(key) != null) {
                out.put(key, snapshot.get(key));
            }
        }

        List<Map<String, Object>> registers = snapshot.get("registers") instanceof List<?> l
            ? (List<Map<String, Object>>) l : List.of();
        if (full) {
            out.put("registers", registers);
            out.put("stack", snapshot.get("stack"));
        }
        else {
            Map<String, Object> changed = new LinkedHashMap<>();
            for (Map<String, Object> row : registers) {
                if (Boolean.TRUE.equals(row.get("changed")) || note != null && row.get("value") != null
                        && !"0x0".equals(row.get("value"))) {
                    Object shown = row.get("value") != null ? row.get("value") : "<" + row.get("symbolic") + ">";
                    changed.put(String.valueOf(row.get("name")),
                        row.get("label") != null ? shown + " (" + row.get("label") + ")" : shown);
                }
            }
            out.put(note != null ? "registers" : "changedRegisters", changed);
        }

        List<Object> calls = snapshot.get("calls") instanceof List<?> l ? (List<Object>) l : List.of();
        int seen;
        synchronized (reportedCalls) {
            seen = full ? 0 : Math.min(reportedCalls.getOrDefault(session, 0), calls.size());
            // A different path has its own history; start over rather than skip its calls.
            reportedCalls.put(session, calls.size());
        }
        if (calls.size() > seen) {
            out.put(full ? "calls" : "newCalls", new ArrayList<>(calls.subList(seen, calls.size())));
        }
        for (String key : List.of("writes", "memory", "buffers", "stdout", "stderr", "unmodelledExternals",
                "pythonHooks", "hookWarnings", "warnings")) {
            Object value = snapshot.get(key);
            if (value == null || (!full && key.equals("buffers"))) {
                continue;
            }
            if (!full && value instanceof String text && text.length() > 2000) {
                value = "..." + text.substring(text.length() - 2000);
            }
            out.put(key, value);
        }
        List<Address> breakpoints = AngrDebugger.breakpoints(session.program);
        if (!breakpoints.isEmpty()) {
            out.put("breakpoints", breakpointList(session.program).get("breakpoints"));
        }
        return out;
    }

    /** One sentence on what just happened and what the sensible next move is. */
    @SuppressWarnings("unchecked")
    private static String hint(Map<String, Object> snapshot) {
        String stop = String.valueOf(snapshot.get("stop"));
        switch (stop) {
            case "fork": {
                String guard = null;
                if (snapshot.get("paths") instanceof List<?> paths) {
                    for (Object o : paths) {
                        if (o instanceof Map<?, ?> m && Boolean.TRUE.equals(m.get("current"))) {
                            guard = (String) ((Map<String, Object>) m).get("guard");
                        }
                    }
                }
                return "A branch depended on an unknown value, so execution split. This path took the side "
                    + "where " + (guard == null ? "its condition holds" : guard) + ". Keep stepping to follow "
                    + "it, select_path to follow another, or concretize the symbol to decide it.";
            }
            case "returned":
                return "The function returned. Start again to re-run it, or select_path if other paths are parked.";
            case "fault":
                return "Execution cannot go on from here; 'fault' says why. The state is the one just before "
                    + "the failing instruction, so registers and memory can still be inspected or fixed with set.";
            case "exited":
                return "The program terminated itself on this path.";
            case "symbolic_jump":
                return "The next address depends on an unknown value. Concretize what it depends on to go on.";
            case "timeout":
                return "The time limit ran out mid-run; the session is paused where it got to. Continue again "
                    + "or raise timeoutMs.";
            case "breakpoint":
                return "Stopped at a breakpoint.";
            default:
                return null;
        }
    }
}
