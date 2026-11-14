package decompfuncutils.mcp.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import decompfuncutils.angr.AngrImage;
import decompfuncutils.angr.AngrWorkers;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Pattern;

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

    private static final int DEFAULT_MAX_STEPS = 100_000;
    private static final int HARD_MAX_STEPS = 5_000_000;
    private static final int DEFAULT_TIMEOUT_MS = 30_000;
    private static final int HARD_MAX_TIMEOUT_MS = 600_000;
    private static final int DEFAULT_MAX_PATHS = 8;
    private static final int HARD_MAX_PATHS = 64;
    private static final int MAX_ARGS = 32;

    private static final Pattern HEX_INT = Pattern.compile("^-?0[xX][0-9a-fA-F_]+$");
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
            "Use 'stubs' to give any function, internal or imported, a fixed return value. " +
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
            "description", "Basic blocks to execute across all paths (default " + DEFAULT_MAX_STEPS + ")"));
        props.put("timeoutMs", Map.of("type", "integer",
            "description", "Wall-clock limit (default " + DEFAULT_TIMEOUT_MS + ", max " + HARD_MAX_TIMEOUT_MS + ")"));
        props.put("maxPaths", Map.of("type", "integer",
            "description", "Paths reported in a symbolic run (default " + DEFAULT_MAX_PATHS + ")"));
        props.put("trace", Map.of("type", "string", "enum", List.of("calls", "none"),
            "description", "'calls' (default) lists the calls made, nested by depth; 'none' omits them."));
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
        if (program == null) {
            throw new IllegalStateException("No program is open");
        }
        TaskMonitor monitor = McpUtil.activeMonitor();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        // ---- what to call ----
        String functionText = stringArg(arguments, "function");
        if (functionText == null || functionText.isBlank()) {
            throw new IllegalArgumentException("'function' is required: a function name or an address");
        }
        Address entry = resolveCode(program, functionText, "function");
        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function != null && function.isThunk()) {
            Function thunked = function.getThunkedFunction(true);
            if (thunked != null && thunked.isExternal()) {
                throw new IllegalArgumentException("'" + functionText + "' is an import (" + thunked.getName()
                    + "), so its code is not in this program. Open the library that defines it and call it there.");
            }
            if (thunked != null) {
                function = thunked;
                entry = thunked.getEntryPoint();
            }
        }
        if (!entry.getAddressSpace().equals(space) || !program.getMemory().contains(entry)) {
            throw new IllegalArgumentException("'" + functionText + "' resolves to " + entry
                + ", which is not in the program's memory");
        }

        // ---- limits ----
        int maxSteps = (int) Math.min(positive(arguments, "maxSteps", DEFAULT_MAX_STEPS), HARD_MAX_STEPS);
        long timeoutMs = positive(arguments, "timeoutMs", DEFAULT_TIMEOUT_MS);
        if (timeoutMs > HARD_MAX_TIMEOUT_MS) {
            throw new IllegalArgumentException("timeoutMs must be at most " + HARD_MAX_TIMEOUT_MS);
        }
        int maxPaths = (int) Math.min(positive(arguments, "maxPaths", DEFAULT_MAX_PATHS), HARD_MAX_PATHS);

        // ---- arguments and where they go ----
        List<Object> rawArgs = arguments.get("args") instanceof List<?> l ? (List<Object>) l : List.of();
        if (rawArgs.size() > MAX_ARGS) {
            throw new IllegalArgumentException("At most " + MAX_ARGS + " arguments are supported");
        }
        Placement placement = placeArguments(program, function, rawArgs.size());
        List<Map<String, Object>> args = new ArrayList<>();
        for (int i = 0; i < rawArgs.size(); i++) {
            Map<String, Object> arg = new LinkedHashMap<>();
            arg.put("loc", placement.argLocations.get(i));
            arg.put("value", normalizeValue(rawArgs.get(i), "args[" + i + "]"));
            args.add(arg);
        }

        AngrImage image = AngrImage.of(program, monitor);

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("entry", hex(entry.getOffset() | (isThumb(program, entry) ? 1 : 0)));
        spec.put("args", args);
        if (placement.returnLocation != null) {
            spec.put("ret", placement.returnLocation);
        }
        spec.put("maxSteps", maxSteps);
        spec.put("timeoutMs", timeoutMs);
        spec.put("maxPaths", maxPaths);
        spec.put("strictMemory", !Boolean.FALSE.equals(arguments.get("strictMemory")));
        spec.put("symbolicRun", Boolean.TRUE.equals(arguments.get("symbolic")));
        String trace = stringArg(arguments, "trace");
        if (trace != null && !trace.equals("calls") && !trace.equals("none")) {
            throw new IllegalArgumentException("trace must be 'calls' or 'none'");
        }
        spec.put("trace", trace == null ? "calls" : trace);
        if (arguments.get("arch") != null) {
            spec.put("arch", String.valueOf(arguments.get("arch")));
        }
        if (arguments.get("stdin") != null) {
            spec.put("stdin", String.valueOf(arguments.get("stdin")));
        }
        if (arguments.get("wantReturn") != null) {
            spec.put("wantReturn", integerText(arguments.get("wantReturn"), "wantReturn"));
        }
        spec.put("find", codeList(program, arguments.get("find"), "find"));
        spec.put("avoid", codeList(program, arguments.get("avoid"), "avoid"));

        if (arguments.get("registers") instanceof Map<?, ?> registers) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : registers.entrySet()) {
                String regName = String.valueOf(e.getKey());
                if (program.getLanguage().getRegister(regName) == null) {
                    throw new IllegalArgumentException("Unknown register '" + regName + "' for "
                        + program.getLanguage().getLanguageID());
                }
                out.put(regName, normalizeValue(e.getValue(), "registers." + regName));
            }
            spec.put("registers", out);
        }
        spec.put("memory", memorySeeds(program, arguments.get("memory")));
        spec.put("readMemory", memoryReads(program, arguments.get("readMemory")));
        applyStubs(program, image, arguments.get("stubs"), spec);

        // ---- run ----
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("op", "call");
        request.put("imageDir", image.directory.toString());
        request.put("imageKey", image.key);
        request.put("spec", spec);

        String configuredPython = null;
        if (tool != null) {
            configuredPython = tool.getOptions(OPTION_CATEGORY).getString(OPTION_PYTHON, "");
        }
        monitor.setMessage("Running " + functionText + " under angr");
        JsonObject response;
        try {
            response = AngrWorkers.call(program.getUniqueProgramID(), configuredPython, request, timeoutMs, monitor);
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
        if (!response.has("ok") || !response.get("ok").getAsBoolean()) {
            String error = response.has("error") ? response.get("error").getAsString() : "unknown error";
            boolean internal = response.has("kind") && "internal".equals(response.get("kind").getAsString());
            String detail = internal && response.has("traceback")
                ? " | " + response.get("traceback").getAsString().strip().replace("\n", " | ") : "";
            throw new IllegalStateException((internal ? "angr failed: " : "") + error + detail);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", function != null
            ? function.getName(true) + " @ " + entry : "code @ " + entry);
        result.put("called", placement.describe(function, rawArgs.size()));
        Map<String, Object> body = GSON.fromJson(response.get("result"), Map.class);
        annotate(program, body);
        tidyNumbers(body);
        result.putAll(body);
        if (!placement.warnings.isEmpty()) {
            List<Object> warnings = new ArrayList<>(placement.warnings);
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

    // ---------------------------------------------------------------------------------------
    // Calling convention: Ghidra decides where arguments and the return value live
    // ---------------------------------------------------------------------------------------

    private static final class Placement {
        final List<Map<String, Object>> argLocations = new ArrayList<>();
        Map<String, Object> returnLocation;
        String convention;
        boolean fromSignature;
        final List<String> warnings = new ArrayList<>();

        /** One line saying how the call was set up, so a wrong assumption is visible. */
        String describe(Function function, int argCount) {
            StringBuilder sb = new StringBuilder();
            if (function != null && fromSignature) {
                sb.append(function.getPrototypeString(false, true));
            }
            else {
                sb.append(argCount).append(" argument(s), ").append(convention)
                  .append(" (Ghidra has no signature for this function)");
            }
            if (!argLocations.isEmpty()) {
                List<String> places = new ArrayList<>();
                for (Map<String, Object> loc : argLocations) {
                    places.add(loc.containsKey("reg") ? String.valueOf(loc.get("reg"))
                        : loc.containsKey("stack") ? "Stack[" + loc.get("stack") + "]"
                        : "?");
                }
                sb.append("; arguments in ").append(String.join(", ", places));
            }
            if (returnLocation != null) {
                sb.append("; result from ").append(returnLocation.get("reg"));
            }
            return sb.toString();
        }
    }

    private static Placement placeArguments(Program program, Function function, int argCount) {
        Placement placement = new Placement();
        PrototypeModel model = function != null ? function.getCallingConvention() : null;
        if (model == null) {
            model = program.getCompilerSpec().getDefaultCallingConvention();
        }
        placement.convention = model != null ? model.getName() : "default convention";

        Parameter[] params = function != null ? function.getParameters() : new Parameter[0];
        placement.fromSignature = function != null && function.getSignatureSource() != SourceType.DEFAULT;
        int pointerSize = program.getDefaultPointerSize();
        DataType word = AbstractIntegerDataType.getUnsignedDataType(pointerSize, program.getDataTypeManager());
        if (word == null) {
            word = Undefined.getUndefinedDataType(pointerSize);
        }

        // What the convention would assign to this many arguments, typed where Ghidra knows the
        // type and pointer-sized where it does not. Parameters with storage of their own
        // (custom storage, or simply committed) are taken from the function instead.
        DataType[] types = new DataType[argCount + 1];
        DataType returnType = function != null ? function.getReturnType() : null;
        boolean returnKnown = returnType != null && !Undefined.isUndefined(returnType)
            && !(returnType instanceof VoidDataType && !placement.fromSignature);
        types[0] = returnKnown ? returnType : word;
        for (int i = 0; i < argCount; i++) {
            types[i + 1] = i < params.length ? params[i].getDataType() : word;
        }
        VariableStorage[] computed = null;
        if (model != null) {
            try {
                computed = model.getStorageLocations(program, types, false);
            }
            catch (Exception e) {
                placement.warnings.add("Ghidra could not compute argument storage for " + model.getName()
                    + ": " + e.getMessage());
            }
        }

        for (int i = 0; i < argCount; i++) {
            VariableStorage storage = null;
            if (i < params.length) {
                storage = params[i].getVariableStorage();
            }
            if ((storage == null || storage.isUnassignedStorage() || storage.isBadStorage())
                    && computed != null && i + 1 < computed.length) {
                storage = computed[i + 1];
            }
            placement.argLocations.add(location(storage));
        }

        if (returnKnown && returnType instanceof VoidDataType) {
            placement.returnLocation = null;
        }
        else {
            VariableStorage storage = null;
            if (returnKnown && function != null && function.getReturn() != null) {
                storage = function.getReturn().getVariableStorage();
            }
            if ((storage == null || storage.isUnassignedStorage() || storage.isBadStorage()
                    || storage.isVoidStorage()) && computed != null && computed.length > 0) {
                storage = computed[0];
            }
            Map<String, Object> loc = location(storage);
            if (loc.containsKey("reg")) {
                if (returnKnown) {
                    loc.put("type", returnType.getDisplayName());
                }
                placement.returnLocation = loc;
            }
        }

        if (placement.fromSignature && function != null && params.length != argCount
                && !function.hasVarArgs()) {
            placement.warnings.add("Ghidra's signature for " + function.getName() + " has " + params.length
                + " parameter(s) but " + argCount + " argument(s) were given.");
        }
        return placement;
    }

    private static Map<String, Object> location(VariableStorage storage) {
        Map<String, Object> loc = new LinkedHashMap<>();
        if (storage == null) {
            loc.put("unsupported", "no storage");
        }
        else if (storage.isRegisterStorage() && storage.getRegister() != null) {
            Register register = storage.getRegister();
            loc.put("reg", register.getName());
            loc.put("size", storage.size());
        }
        else if (storage.isStackStorage()) {
            loc.put("stack", storage.getStackOffset());
            loc.put("size", storage.size());
        }
        else {
            loc.put("unsupported", storage.toString());
        }
        return loc;
    }

    /** ARM code is entered in Thumb mode by setting bit 0 of the address. */
    private static boolean isThumb(Program program, Address entry) {
        Register tmode = program.getProgramContext().getRegister("TMode");
        if (tmode == null) {
            return false;
        }
        BigInteger value = program.getProgramContext().getValue(tmode, entry, false);
        return value != null && value.signum() != 0;
    }

    // ---------------------------------------------------------------------------------------
    // Resolving names
    // ---------------------------------------------------------------------------------------

    /** A function name or a code address. */
    private static Address resolveCode(Program program, String text, String what) {
        String trimmed = text.strip();
        List<Function> named = functionsNamed(program, trimmed);
        if (named.size() == 1) {
            return named.get(0).getEntryPoint();
        }
        if (named.size() > 1) {
            List<String> where = new ArrayList<>();
            for (Function f : named) {
                where.add(f.getName(true) + " @ " + f.getEntryPoint());
            }
            throw new IllegalArgumentException(what + ": '" + trimmed + "' names " + named.size()
                + " functions (" + String.join(", ", where) + "). Use the address.");
        }
        Address address = tryAddress(program, trimmed);
        if (address != null) {
            return address;
        }
        Address symbol = symbolAddress(program, trimmed);
        if (symbol != null) {
            return symbol;
        }
        for (Symbol external : program.getSymbolTable().getSymbols(trimmed)) {
            if (external.isExternal()) {
                throw new IllegalArgumentException(what + ": '" + trimmed + "' is an import, so its code "
                    + "is not in " + program.getName() + ". Open the library that defines it and call it "
                    + "there, or give it a result with 'stubs'.");
            }
        }
        throw new IllegalArgumentException(what + ": no function, label or address '" + trimmed
            + "' in " + program.getName() + ". Use ghidra_list_functions to find it.");
    }

    /** A data address: a symbol name (a global) or hex. */
    private static Address resolveData(Program program, Object value, String what) {
        if (value == null) {
            throw new IllegalArgumentException(what + ": 'address' is required");
        }
        String text = String.valueOf(value).strip();
        Address symbol = symbolAddress(program, text);
        if (symbol != null) {
            return symbol;
        }
        Address address = tryAddress(program, text);
        if (address != null) {
            return address;
        }
        throw new IllegalArgumentException(what + ": no symbol or address '" + text + "'");
    }

    private static List<Function> functionsNamed(Program program, String name) {
        List<Function> out = new ArrayList<>();
        String simple = name.contains("::") ? name.substring(name.lastIndexOf("::") + 2) : name;
        for (Symbol symbol : program.getSymbolTable().getSymbols(simple)) {
            if (symbol.getSymbolType() != SymbolType.FUNCTION || symbol.isExternal()) {
                continue;
            }
            Function f = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (f == null) {
                continue;
            }
            if (name.contains("::") && !f.getName(true).equals(name)) {
                continue;
            }
            out.add(f);
        }
        // An import and the thunk that reaches it share a name; the caller means the real code.
        if (out.size() > 1) {
            List<Function> real = new ArrayList<>();
            for (Function f : out) {
                if (!f.isThunk()) {
                    real.add(f);
                }
            }
            if (!real.isEmpty()) {
                return real;
            }
        }
        return out;
    }

    private static Address symbolAddress(Program program, String name) {
        Address found = null;
        for (Symbol symbol : program.getSymbolTable().getSymbols(name)) {
            if (symbol.isExternal() || !symbol.getAddress().isMemoryAddress()) {
                continue;
            }
            if (found != null && !found.equals(symbol.getAddress())) {
                throw new IllegalArgumentException("'" + name + "' names more than one address ("
                    + found + ", " + symbol.getAddress() + "). Use the address.");
            }
            found = symbol.getAddress();
        }
        return found;
    }

    private static Address tryAddress(Program program, String text) {
        String cleaned = text.replaceFirst("^0[xX]", "");
        if (!cleaned.matches("[0-9a-fA-F]+")) {
            return null;
        }
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(cleaned);
        }
        catch (Exception e) {
            return null;
        }
    }

    private static List<String> codeList(Program program, Object value, String what) {
        List<String> out = new ArrayList<>();
        if (value == null) {
            return out;
        }
        Collection<?> items = value instanceof Collection<?> c ? c : List.of(value);
        for (Object item : items) {
            out.add(hex(resolveCode(program, String.valueOf(item), what).getOffset()));
        }
        return out;
    }

    // ---------------------------------------------------------------------------------------
    // Request pieces
    // ---------------------------------------------------------------------------------------

    /**
     * Turns what a caller naturally writes into the explicit forms the worker takes: a number
     * becomes an integer, a string becomes a C string unless it reads as a hex literal (JSON has
     * no hex numbers), and nested struct fields get the same treatment.
     */
    @SuppressWarnings("unchecked")
    private static Object normalizeValue(Object value, String where) {
        if (value == null) {
            throw new IllegalArgumentException(where + ": null is not a value; use 0 for a NULL pointer");
        }
        if (value instanceof Boolean b) {
            return Map.of("int", b ? "0x1" : "0x0");
        }
        if (value instanceof Number) {
            return Map.of("int", integerText(value, where));
        }
        if (value instanceof String s) {
            if (HEX_INT.matcher(s.strip()).matches()) {
                return Map.of("int", s.strip());
            }
            return Map.of("string", s);
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = String.valueOf(e.getKey());
                Object v = e.getValue();
                switch (key) {
                    case "struct":
                        if (!(v instanceof List<?> fields)) {
                            throw new IllegalArgumentException(where + ".struct must be a list of fields");
                        }
                        List<Object> normalized = new ArrayList<>();
                        for (int i = 0; i < fields.size(); i++) {
                            Object field = fields.get(i);
                            boolean layout = field instanceof Map<?, ?> m && (m.containsKey("pad") || m.containsKey("raw"));
                            normalized.add(layout ? numbersToText((Map<String, Object>) field, where)
                                : normalizeValue(field, where + ".struct[" + i + "]"));
                        }
                        out.put(key, normalized);
                        break;
                    case "int":
                    case "size":
                    case "buffer":
                    case "fill":
                    case "min":
                    case "max":
                    case "symbolicBytes":
                        out.put(key, integerText(v, where + "." + key));
                        break;
                    case "symbolicInt":
                        out.put(key, v instanceof Boolean ? v : integerText(v, where + "." + key));
                        break;
                    default:
                        out.put(key, v);
                }
            }
            return out;
        }
        throw new IllegalArgumentException(where + ": expected a number, a string or an object, got "
            + value.getClass().getSimpleName());
    }

    private static Map<String, Object> numbersToText(Map<String, Object> map, String where) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) {
            out.put(e.getKey(), e.getValue() instanceof Number ? integerText(e.getValue(), where) : e.getValue());
        }
        return out;
    }

    /** An integer as text the worker parses exactly; JSON numbers arrive here as doubles. */
    private static String integerText(Object value, String where) {
        if (value instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d) || d != Math.rint(d)) {
                throw new IllegalArgumentException(where + ": " + value + " is not an integer "
                    + "(floating-point arguments are not supported)");
            }
            if (Math.abs(d) > 9007199254740992.0) {
                throw new IllegalArgumentException(where + ": " + value + " is too large to be exact as a "
                    + "JSON number; pass it as a hex string like \"0xffffffffffffffff\"");
            }
            return new BigDecimal(d).toBigIntegerExact().toString();
        }
        String text = String.valueOf(value).strip();
        if (!text.matches("-?(0[xX][0-9a-fA-F_]+|[0-9_]+)")) {
            throw new IllegalArgumentException(where + ": '" + text + "' is not an integer (decimal or 0x-hex)");
        }
        return text;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> memorySeeds(Program program, Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) {
            return out;
        }
        for (int i = 0; i < list.size(); i++) {
            if (!(list.get(i) instanceof Map<?, ?> raw)) {
                throw new IllegalArgumentException("memory[" + i + "] must be an object with an 'address'");
            }
            Map<String, Object> seed = new LinkedHashMap<>();
            seed.put("addr", hex(resolveData(program, raw.get("address"), "memory[" + i + "]").getOffset()));
            for (Map.Entry<String, Object> e : ((Map<String, Object>) raw).entrySet()) {
                String key = e.getKey();
                Object v = e.getValue();
                switch (key) {
                    case "address":
                        break;
                    case "pointer":
                        seed.put(key, normalizeValue(v, "memory[" + i + "].pointer"));
                        break;
                    case "int":
                    case "size":
                    case "symbolicBytes":
                    case "min":
                    case "max":
                        seed.put(key, integerText(v, "memory[" + i + "]." + key));
                        break;
                    case "symbolicInt":
                        seed.put(key, v instanceof Boolean ? v : integerText(v, "memory[" + i + "]." + key));
                        break;
                    default:
                        seed.put(key, v);
                }
            }
            out.add(seed);
        }
        return out;
    }

    private static List<Map<String, Object>> memoryReads(Program program, Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) {
            return out;
        }
        if (list.size() > 32) {
            throw new IllegalArgumentException("readMemory takes at most 32 ranges");
        }
        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            Object addressValue = item instanceof Map<?, ?> m ? m.get("address") : item;
            Object lengthValue = item instanceof Map<?, ?> m ? m.get("length") : null;
            Address address = resolveData(program, addressValue, "readMemory[" + i + "]");
            long length = lengthValue instanceof Number n ? n.longValue() : 64;
            if (length < 1 || length > 4096) {
                throw new IllegalArgumentException("readMemory[" + i + "].length must be between 1 and 4096");
            }
            Map<String, Object> read = new LinkedHashMap<>();
            read.put("addr", hex(address.getOffset()));
            read.put("length", length);
            String text = String.valueOf(addressValue).strip();
            if (tryAddress(program, text) == null) {
                read.put("name", text);
            }
            out.add(read);
        }
        return out;
    }

    /** Splits 'stubs' into imports (by name, the worker knows their addresses) and internal functions. */
    private static void applyStubs(Program program, AngrImage image, Object value, Map<String, Object> spec) {
        Map<String, Object> external = new LinkedHashMap<>();
        List<Map<String, Object>> internal = new ArrayList<>();
        if (value instanceof Map<?, ?> stubs) {
            for (Map.Entry<?, ?> e : stubs.entrySet()) {
                String target = String.valueOf(e.getKey()).strip();
                Object returns = e.getValue();
                Object normalized = returns == null ? "0"
                    : "symbolic".equalsIgnoreCase(String.valueOf(returns).strip()) ? "symbolic"
                    : integerText(returns instanceof Boolean b ? (b ? 1 : 0) : returns, "stubs." + target);
                if (image.externalNames.contains(target)) {
                    external.put(target, normalized);
                    continue;
                }
                Address address = resolveCode(program, target, "stubs");
                Function f = program.getFunctionManager().getFunctionAt(address);
                if (f != null && f.isThunk()) {
                    Function thunked = f.getThunkedFunction(true);
                    if (thunked != null && thunked.isExternal() && image.externalNames.contains(thunked.getName())) {
                        external.put(thunked.getName(), normalized);
                        continue;
                    }
                }
                Map<String, Object> stub = new LinkedHashMap<>();
                stub.put("addr", hex(address.getOffset()));
                stub.put("name", f != null ? f.getName() : target);
                stub.put("returns", normalized);
                stub.put("params", f != null && f.getSignatureSource() != SourceType.DEFAULT
                    ? f.getParameterCount() : -1);
                internal.add(stub);
            }
        }
        spec.put("externalStubs", external);
        spec.put("stubs", internal);
    }

    // ---------------------------------------------------------------------------------------
    // Result: put Ghidra's names on the worker's addresses
    // ---------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static void annotate(Program program, Map<String, Object> body) {
        List<Map<String, Object>> paths = new ArrayList<>();
        paths.add(body);
        if (body.get("paths") instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> m) {
                    paths.add((Map<String, Object>) m);
                }
            }
        }
        for (Map<String, Object> path : paths) {
            if (path.get("stoppedAt") instanceof String at) {
                path.put("stoppedAt", codeLabel(program, at));
            }
            if (path.get("fault") instanceof Map<?, ?> fault && path.get("stoppedAt") != null) {
                ((Map<String, Object>) fault).put("inBlockAt", path.remove("stoppedAt"));
            }
            if (path.get("calls") instanceof List<?> calls) {
                for (Object o : calls) {
                    if (!(o instanceof Map<?, ?> m)) {
                        continue;
                    }
                    Map<String, Object> call = (Map<String, Object>) m;
                    if (call.get("call") instanceof String target && target.startsWith("0x")) {
                        Address address = tryAddress(program, target);
                        Function f = address == null ? null : program.getFunctionManager().getFunctionAt(address);
                        if (f != null) {
                            call.put("call", f.getName());
                        }
                    }
                    if (call.get("from") instanceof String from) {
                        call.put("from", codeLabel(program, from));
                    }
                }
            }
            if (path.get("globalWrites") instanceof List<?> writes) {
                for (Object o : writes) {
                    if (o instanceof Map<?, ?> m && m.get("address") instanceof String address) {
                        String label = dataLabel(program, address);
                        if (label != null) {
                            ((Map<String, Object>) m).put("symbol", label);
                        }
                    }
                }
            }
        }
    }

    /** "0x101b00 (deref+0x10)" */
    private static String codeLabel(Program program, String hexAddress) {
        Address address = tryAddress(program, hexAddress);
        if (address == null) {
            return hexAddress;
        }
        Function f = program.getFunctionManager().getFunctionContaining(address);
        if (f == null) {
            return hexAddress;
        }
        long delta = address.subtract(f.getEntryPoint());
        return hexAddress + " (" + f.getName() + (delta == 0 ? "" : "+0x" + Long.toHexString(delta)) + ")";
    }

    /** The symbol a data address belongs to, with its offset inside the data item. */
    private static String dataLabel(Program program, String hexAddress) {
        Address address = tryAddress(program, hexAddress);
        if (address == null) {
            return null;
        }
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            return symbol.getName();
        }
        Data data = program.getListing().getDataContaining(address);
        if (data != null) {
            Symbol base = program.getSymbolTable().getPrimarySymbol(data.getAddress());
            if (base != null) {
                return base.getName() + "+0x" + Long.toHexString(address.subtract(data.getAddress()));
            }
        }
        return null;
    }

    /** Gson reads every JSON number as a double; counts and signed values should print as integers. */
    @SuppressWarnings("unchecked")
    private static void tidyNumbers(Object node) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) map).entrySet()) {
                Object v = e.getValue();
                if (v instanceof Double d && d == Math.rint(d) && !Double.isInfinite(d)) {
                    e.setValue(d.longValue());
                }
                else {
                    tidyNumbers(v);
                }
            }
        }
        else if (node instanceof List<?> list) {
            List<Object> items = (List<Object>) list;
            for (int i = 0; i < items.size(); i++) {
                Object v = items.get(i);
                if (v instanceof Double d && d == Math.rint(d) && !Double.isInfinite(d)) {
                    items.set(i, d.longValue());
                }
                else {
                    tidyNumbers(v);
                }
            }
        }
    }

    // ---- small helpers ----

    private static String stringArg(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static long positive(Map<String, Object> arguments, String key, long fallback) {
        Object value = arguments.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof Number n) || n.longValue() < 1) {
            throw new IllegalArgumentException(key + " must be a positive integer");
        }
        return n.longValue();
    }

    private static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
