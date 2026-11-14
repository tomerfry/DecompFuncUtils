package decompfuncutils.mcp.tools;

import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.angr.AngrHooks;
import decompfuncutils.angr.AngrImports;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Manages the Python replacements angr runs in place of a program's functions - written by the
 * user in the debugger panel or any editor, or by an agent through this tool. Both end up as the
 * same files, so each can read and improve what the other wrote.
 */
public class AngrHookTool implements McpTool {

    private static final List<String> ACTIONS =
        List.of("imports", "list", "get", "template", "set", "enable", "disable", "delete");

    @Override
    public String name() { return "ghidra_angr_hook"; }

    @Override
    public String description() {
        return "Write Python replacements for functions, used whenever this program runs under angr " +
            "(ghidra_angr_emulate and the debugger). This is how a binary is analyzed without its " +
            "shared objects: model the imports that matter and leave the rest unknown.\n" +
            "action=imports lists every import with its library, whether that library is in the " +
            "project, and how a call is handled now: 'python hook', 'angr model' (angr knows the " +
            "function), or 'stub' (returns an unknown value in the debugger, 0 in the emulator) - " +
            "the stubs are the candidates for a hook.\n" +
            "action=set saves a hook: 'name' (file name), 'target' (import name, function name or " +
            "address; defaults to the name), 'code'. The code defines hook(ctx, ...); parameters after " +
            "ctx receive the call's arguments (ints when concrete), and the return value becomes the " +
            "function's result (None is 0):\n" +
            "  def hook(ctx, fd, buf, n):\n" +
            "      ctx.write(buf, b'PING\\n')\n" +
            "      return 5\n" +
            "ctx offers arg(i), string(ptr), read(ptr,n), read_int(ptr,size), write(ptr,data), " +
            "write_int(ptr,value,size), alloc(n), reg(name), set_reg(name,value), log(...), " +
            "symbolic(name) for an unknown value to return or store, constrain(cond), and ctx.state " +
            "(the angr SimState); angr and claripy are imported. 'kind':'inline' instead runs the " +
            "hook when execution reaches the target address and then carries on, skipping 'skip' " +
            "bytes of the original code (0 = observe only).\n" +
            "The code is compiled before it is saved, so a syntax error comes back immediately; a " +
            "running debug session picks the change up at once. action=template returns a starting " +
            "point for a target; get/list/enable/disable/delete manage what is saved. Hooks are files " +
            "under ~/.decompfuncutils/angr-hooks/<program>/ and run as ordinary Python on this " +
            "machine.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("action", Map.of("type", "string", "enum", ACTIONS,
            "description", "What to do; see the tool description."));
        props.put("name", Map.of("type", "string",
            "description", "Hook name: letters, digits, '_', '-', '.'. Becomes <name>.py."));
        props.put("target", Map.of("type", "string",
            "description", "set / template: import name, function name or address the hook attaches to"));
        props.put("code", Map.of("type", "string",
            "description", "set: Python source defining hook(ctx, ...)"));
        props.put("kind", Map.of("type", "string", "enum", List.of(AngrHooks.KIND_REPLACE, AngrHooks.KIND_INLINE),
            "description", "set: 'replace' (default) runs instead of the function; 'inline' runs at the address"));
        props.put("skip", Map.of("type", "integer",
            "description", "set, kind=inline: bytes of original code to skip after the hook (default 0)"));
        props.put("enabled", Map.of("type", "boolean", "description", "set: save it enabled (default true)"));
        schema.put("properties", props);
        schema.put("required", List.of("action"));
        return schema;
    }

    /** Edits files outside the program and talks to a helper process. */
    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) {
            throw new IllegalStateException("No program is open");
        }
        TaskMonitor monitor = McpUtil.activeMonitor();
        String python = AngrEmulateTool.configuredPython(tool);
        String action = arguments.get("action") == null ? "" : String.valueOf(arguments.get("action"));
        String name = arguments.get("name") == null ? null : String.valueOf(arguments.get("name")).strip();

        Map<String, Object> result = new LinkedHashMap<>();
        switch (action) {
            case "imports": {
                List<Map<String, Object>> imports = AngrImports.describe(program, python, monitor);
                int stubs = 0;
                Set<String> missing = new TreeSet<>();
                for (Map<String, Object> row : imports) {
                    if (AngrImports.HANDLED_BY_STUB.equals(row.get("handledBy"))) {
                        stubs++;
                    }
                    if (row.get("library") != null && !Boolean.TRUE.equals(row.get("libraryInProject"))) {
                        missing.add(String.valueOf(row.get("library")));
                    }
                }
                result.put("program", program.getName());
                result.put("imports", imports);
                result.put("stubbed", stubs);
                result.put("librariesNotInProject", new ArrayList<>(missing));
                result.put("note", "Nothing here stops a run: no import is followed into its library. "
                    + "'stub' imports return an unknown value in the debugger and 0 in the emulator; "
                    + "write a hook for the ones whose behaviour matters.");
                return result;
            }
            case "list": {
                List<Map<String, Object>> hooks = new ArrayList<>();
                for (AngrHooks.Hook hook : AngrHooks.list(program)) {
                    hooks.add(hook.describe(false));
                }
                result.put("hooks", hooks);
                result.put("directory", AngrHooks.directory(program).toString());
                return result;
            }
            case "get": {
                AngrHooks.Hook hook = AngrHooks.get(program, require(name, "name"));
                if (hook == null) {
                    throw new IllegalArgumentException("No hook named '" + name + "'. Use action=list.");
                }
                return hook.describe(true);
            }
            case "template": {
                String target = arguments.get("target") != null ? String.valueOf(arguments.get("target")) : name;
                result.put("target", require(target, "target"));
                result.put("code", AngrHooks.template(program, target));
                return result;
            }
            case "set": {
                AngrHooks.Hook hook = new AngrHooks.Hook();
                hook.name = require(name, "name");
                hook.target = arguments.get("target") != null
                    ? String.valueOf(arguments.get("target")).strip() : hook.name;
                hook.code = arguments.get("code") == null ? "" : String.valueOf(arguments.get("code"));
                if (arguments.get("kind") != null) {
                    hook.kind = String.valueOf(arguments.get("kind"));
                }
                if (arguments.get("skip") instanceof Number n) {
                    hook.skip = n.intValue();
                }
                hook.enabled = !Boolean.FALSE.equals(arguments.get("enabled"));
                // Compile first: a hook that cannot load would otherwise fail every later run.
                AngrImports.check(program, python, hook.name, hook.code, monitor);
                AngrHooks.save(program, hook);
                result.put("saved", hook.describe(false));
                result.put("file", AngrHooks.directory(program).resolve(hook.name + ".py").toString());
                break;
            }
            case "enable":
            case "disable": {
                AngrHooks.Hook hook = AngrHooks.get(program, require(name, "name"));
                if (hook == null) {
                    throw new IllegalArgumentException("No hook named '" + name + "'. Use action=list.");
                }
                hook.enabled = action.equals("enable");
                AngrHooks.save(program, hook);
                result.put("saved", hook.describe(false));
                break;
            }
            case "delete":
                result.put("deleted", AngrHooks.delete(program, require(name, "name")));
                break;
            default:
                throw new IllegalArgumentException("action must be one of " + ACTIONS);
        }

        // A change takes effect in a session that is already running, not only in the next one.
        AngrDebugSession session = AngrDebugger.session(program);
        if (session != null && !session.isRunning()) {
            Map<String, Object> snapshot = session.reloadHooks(monitor);
            result.put("appliedToRunningSession", true);
            if (snapshot.get("hookWarnings") != null) {
                result.put("warnings", snapshot.get("hookWarnings"));
            }
        }
        return result;
    }

    private static String require(String value, String key) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("'" + key + "' is required for this action");
        }
        return value;
    }
}
