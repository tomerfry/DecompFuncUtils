package decompfuncutils.mcp.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import decompfuncutils.angr.AngrCallSpec;
import decompfuncutils.angr.AngrWorkers;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Calls a function of the open program under angr and reports what it did.
 *
 * <p>The division of labour is what makes this easy to use: Ghidra supplies everything it already
 * knows - the function by name, where its calling convention puts each argument and the return
 * value, which addresses are imports, and the memory image itself - and angr supplies execution,
 * models of library functions and a constraint solver. The caller therefore writes
 * {@code function: "parse_header", args: ["GET /", 5]} instead of seeding registers, a stack
 * pointer, a return sentinel and hex buffers by hand.
 */
public class AngrEmulateTool implements McpTool {

    public static final String OPTION_CATEGORY = "MCP Server";
    public static final String OPTION_PYTHON = "angr Python Interpreter";

    private static final Gson GSON = new Gson();

    @Override
    public String name() { return "ghidra_angr_emulate"; }

    @Override
    public String description() {
        return "Call a function of this program under angr and see what it does: return value, calls it " +
            "made (library calls with their arguments, so a strcmp shows both strings), text it printed, " +
            "what it wrote into the buffers you passed and into globals. Give the function by name or " +
            "address and its arguments as plain values; the stack, return address and argument " +
            "registers are set up for you from Ghidra's calling convention, library imports run as " +
            "angr models (malloc, strlen, memcpy, printf, ...), and a NULL or wild pointer is reported " +
            "as a fault with a hint instead of silently reading zero.\n" +
            "Arguments: a number is an integer; a string is a pointer to that NUL-terminated text " +
            "(a string like \"0x1F\" is the integer; use {\"string\":\"0x1F\"} for the text). Objects: " +
            "{\"bytes\":\"hex\"} pointer to bytes; {\"buffer\":64} pointer to 64 zero bytes for an " +
            "out-parameter; {\"struct\":[3,4,\"label\"]} pointer to a packed struct (ints are 4 bytes " +
            "unless given {\"int\":v,\"size\":n}; strings/buffers become pointer fields; {\"pad\":n} " +
            "and {\"raw\":\"hex\"} for layout); {\"int\":\"0x..\",\"size\":8}.\n" +
            "Solving for inputs: make an argument unknown with {\"symbolicBytes\":16} (pointer to 16 " +
            "unknown bytes) or {\"symbolicInt\":32}, then either ask for an outcome - 'wantReturn' " +
            "(inputs that make it return that value) or 'find' (inputs that reach an address or " +
            "function) - or ask for nothing and get one example input per distinct path with its " +
            "return value.\n" +
            "Use 'stubs' to give any function, internal or imported, a fixed return value, or " +
            "ghidra_angr_hook to replace one with Python. The program's shared objects do not need to " +
            "be in the project. To step through a function instead, use ghidra_angr_debug. " +
            "Complements ghidra_emulate_function, which steps Ghidra's own p-code emulator from raw " +
            "register state. Needs a Python with angr; if none is set up the error says how.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("function", Map.of("type", "string",
            "description", "Function to call: its name (as Ghidra shows it, optionally namespace-qualified) " +
                "or an address (hex). An address that is not a function start is called as-is."));
        props.put("args", Map.of("type", "array",
            "description", "Arguments in order, in the forms described above. Omit for none."));
        props.put("stubs", Map.of("type", "object",
            "description", "Functions to replace with a fixed result: {name or address: return value}. " +
                "Works for internal functions and imports alike, e.g. {\"check_license\": 1, \"getuid\": 0}. " +
                "Use \"symbolic\" as the value to let the solver choose."));
        props.put("wantReturn", Map.of("type", "string",
            "description", "Solve for symbolic inputs that make the function return this value " +
                "(decimal or 0x-hex)."));
        props.put("find", Map.of("type", "array", "items", Map.of("type", "string"),
            "description", "Stop when execution reaches any of these addresses or functions, and report the " +
                "inputs that get there."));
        props.put("avoid", Map.of("type", "array", "items", Map.of("type", "string"),
            "description", "Abandon paths that reach any of these addresses or functions."));
        props.put("memory", Map.of("type", "array", "items", Map.of("type", "object"),
            "description", "Memory to set before the call: [{address, <one of> bytes | string | int (+size) | " +
                "symbolicBytes | symbolicInt | pointer}]. 'address' is hex or a symbol name such as a global; " +
                "'pointer' takes an argument object and stores a pointer to it."));
        props.put("registers", Map.of("type", "object",
            "description", "Extra registers to set before the call, {name: value}, for values that are not " +
                "ordinary arguments (a 'this' in ECX, a context register) or to override where an argument " +
                "was placed."));
        props.put("readMemory", Map.of("type", "array", "items", Map.of("type", "object"),
            "description", "Ranges to dump after the call: [{address, length}] (address hex or a symbol name, " +
                "length default 64). Buffers you passed as arguments are reported without asking."));
        props.put("stdin", Map.of("type", "string",
            "description", "Text the function can read from standard input. Without it, input is empty in a " +
                "concrete run and unknown in a symbolic one."));
        props.put("strictMemory", Map.of("type", "boolean",
            "description", "Fault on access to memory Ghidra has no block for (default true), which is how a " +
                "missing pointer is found. Set false for firmware that touches unmapped peripherals; such " +
                "reads then return zero."));
        props.put("symbolic", Map.of("type", "boolean",
            "description", "Explore with unknowns even though no argument is symbolic: imports angr cannot " +
                "model then return an unknown value instead of 0, and the values needed are reported " +
                "(default false)."));
        props.put("maxSteps", Map.of("type", "integer",
            "description", "Basic blocks to execute across all paths (default " + AngrCallSpec.DEFAULT_MAX_STEPS + ")"));
        props.put("timeoutMs", Map.of("type", "integer",
            "description", "Wall-clock limit (default " + AngrCallSpec.DEFAULT_TIMEOUT_MS + ", max " + AngrCallSpec.HARD_MAX_TIMEOUT_MS + ")"));
        props.put("maxPaths", Map.of("type", "integer",
            "description", "Paths reported in a symbolic run (default " + AngrCallSpec.DEFAULT_MAX_PATHS + ")"));
        props.put("trace", Map.of("type", "string", "enum", List.of("calls", "none"),
            "description", "'calls' (default) lists the calls made, nested by depth; 'none' omits them."));
        props.put("unmodelledImports", Map.of("type", "string", "enum", List.of("zero", "symbolic"),
            "description", "What an import returns when angr has no model for it and it has no Python hook: " +
                "'zero' (default) or 'symbolic' for an unknown value, reported in assumedReturns."));
        props.put("hooks", Map.of("type", "boolean",
            "description", "Apply the program's saved Python hooks (ghidra_angr_hook). Default true."));
        props.put("arch", Map.of("type", "string",
            "description", "Override the angr architecture when the automatic choice is wrong, e.g. ARMHF, " +
                "ARMCortexM, MIPS32."));
        schema.put("properties", props);
        schema.put("required", List.of("function"));
        return schema;
    }

    /** Runs in a helper process and only reads the program. */
    @Override public boolean requiresEdt() { return false; }

    @Override
    @SuppressWarnings("unchecked")
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        TaskMonitor monitor = McpUtil.activeMonitor();
        AngrCallSpec call = AngrCallSpec.build(program, arguments, monitor);

        monitor.setMessage("Running " + call.title + " under angr");
        JsonObject response;
        try {
            response = AngrWorkers.call(program.getUniqueProgramID(), configuredPython(tool),
                call.callRequest(), call.timeoutMs, monitor);
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
        Map<String, Object> body = GSON.fromJson(AngrWorkers.resultOf(response), Map.class);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", call.title);
        result.put("called", call.called);
        AngrCallSpec.annotate(program, body);
        AngrCallSpec.tidyNumbers(body);
        result.putAll(body);
        if (!call.warnings.isEmpty()) {
            List<Object> warnings = new ArrayList<>(call.warnings);
            if (body.get("warnings") instanceof List<?> existing) {
                warnings.addAll(existing);
            }
            result.put("warnings", warnings);
        }
        if (AngrWorkers.engine() != null) {
            result.put("engine", AngrWorkers.engine());
        }
        return result;
    }

    /** The interpreter set in Tool Options, or null to let discovery find one. */
    public static String configuredPython(PluginTool tool) {
        if (tool == null) {
            return null;
        }
        String configured = tool.getOptions(OPTION_CATEGORY).getString(OPTION_PYTHON, "");
        return configured == null || configured.isBlank() ? null : configured;
    }
}
