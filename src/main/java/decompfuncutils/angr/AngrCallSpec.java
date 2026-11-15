package decompfuncutils.angr;

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
 * Turns "call this function with these arguments" into the request the angr worker runs, using
 * what Ghidra knows: the function by name, where its calling convention puts each argument and
 * the return value, which addresses are imports, the memory image, and the user's Python hooks.
 *
 * <p>One description of a call serves the one-shot emulator ({@code ghidra_angr_emulate}), the
 * debugger's MCP tool and the debugger panel, so a call that works in one works in the others.
 */
public final class AngrCallSpec {

    public static final int DEFAULT_MAX_STEPS = 100_000;
    public static final int HARD_MAX_STEPS = 5_000_000;
    public static final int DEFAULT_TIMEOUT_MS = 30_000;
    public static final int HARD_MAX_TIMEOUT_MS = 600_000;
    public static final int DEFAULT_MAX_PATHS = 8;
    public static final int HARD_MAX_PATHS = 64;
    private static final int MAX_ARGS = 32;

    private static final Pattern HEX_INT = Pattern.compile("^-?0[xX][0-9a-fA-F_]+$");

    /** The function being called, or null when the entry is not a function start. */
    public final Function function;
    public final Address entry;
    /** The exported image the request refers to. */
    public final AngrImage image;
    /** The worker's "spec" object. */
    public final Map<String, Object> spec;
    /** "check_password @ 001019a0" */
    public final String title;
    /** One line saying how the call was set up, so a wrong assumption is visible. */
    public final String called;
    public final long timeoutMs;
    /** Things the caller should know that did not stop the call. */
    public final List<String> warnings;

    private AngrCallSpec(Function function, Address entry, AngrImage image, Map<String, Object> spec,
            String title, String called, long timeoutMs, List<String> warnings) {
        this.function = function;
        this.entry = entry;
        this.image = image;
        this.spec = spec;
        this.title = title;
        this.called = called;
        this.timeoutMs = timeoutMs;
        this.warnings = warnings;
    }

    /**
     * Builds the request for calling {@code arguments.function} with {@code arguments.args}.
     * Recognised keys are those of the {@code ghidra_angr_emulate} tool, plus
     * {@code unmodelledImports} ("symbolic" or "zero"), {@code unknownInputs} (true to leave what
     * was given no value - arguments, registers, memory with no initial contents, what unknown
     * pointers point at - unknown rather than zero) and {@code hooks} (false to leave the
     * program's saved Python hooks out).
     */
    public static AngrCallSpec build(Program program, Map<String, Object> arguments, TaskMonitor monitor)
            throws Exception {
        if (program == null) {
            throw new IllegalStateException("No program is open");
        }
        return build(program, arguments, AngrModules.single(program), monitor);
    }

    /**
     * The same, with libraries of the project loaded next to the program: imports they define
     * run their code. The function called, and every name in the arguments, is still looked up
     * in the program itself.
     *
     * @param modules the program first, then what runs with it
     */
    @SuppressWarnings("unchecked")
    public static AngrCallSpec build(Program program, Map<String, Object> arguments, AngrModules modules,
            TaskMonitor monitor) throws Exception {
        if (program == null) {
            throw new IllegalStateException("No program is open");
        }
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

        AngrImage image = AngrImage.of(modules, monitor);

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
        if (Boolean.TRUE.equals(arguments.get("unknownInputs"))) {
            spec.put("unknownInputs", true);
            spec.put("unknownArgs", unknownArguments(program, function, rawArgs.size()));
        }
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
        String unmodelled = stringArg(arguments, "unmodelledImports");
        if (unmodelled != null) {
            if (!unmodelled.equals("symbolic") && !unmodelled.equals("zero")) {
                throw new IllegalArgumentException("unmodelledImports must be 'symbolic' or 'zero'");
            }
            spec.put("unmodelled", unmodelled);
        }

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

        List<String> warnings = new ArrayList<>(placement.warnings);
        warnings.addAll(image.notes);
        if (!Boolean.FALSE.equals(arguments.get("hooks"))) {
            spec.put("pyHooks", AngrHooks.toSpec(program, image, warnings));
        }

        String title = function != null ? function.getName(true) + " @ " + entry : "code @ " + entry;
        return new AngrCallSpec(function, entry, image, spec, title,
            placement.describe(function, rawArgs.size()), timeoutMs, warnings);
    }

    /** The worker request that runs this call to completion. */
    public Map<String, Object> callRequest() {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("op", "call");
        request.put("imageDir", image.directory.toString());
        request.put("imageKey", image.key);
        request.put("spec", spec);
        return request;
    }

    // ---------------------------------------------------------------------------------------
    // Calling convention: Ghidra decides where arguments and the return value live
    // ---------------------------------------------------------------------------------------

    static final class Placement {
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

    static Placement placeArguments(Program program, Function function, int argCount) {
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

    /** How many argument places are made unknown when Ghidra's signature cannot be relied on. */
    private static final int GUESSED_ARGUMENTS = 6;

    /**
     * Where the arguments nobody gave a value would be, so each can be made an unknown under a
     * name: the parameter's, where Ghidra has one. A signature nobody confirmed often has too few
     * parameters (none at all, before the function was ever decompiled), so beyond the ones it
     * has the places the convention would use next are covered as well, as guesses.
     *
     * @param given how many leading arguments have values already
     */
    static List<Map<String, Object>> unknownArguments(Program program, Function function, int given) {
        Parameter[] params = function != null ? function.getParameters() : new Parameter[0];
        boolean confirmed = function != null
            && function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)
            && !function.hasVarArgs();
        int count = Math.max(given, params.length);
        if (!confirmed) {
            count = Math.max(count, GUESSED_ARGUMENTS);
        }
        count = Math.min(count, MAX_ARGS);
        List<Map<String, Object>> out = new ArrayList<>();
        if (count <= given) {
            return out;
        }
        Placement placement = placeArguments(program, function, count);
        for (int i = given; i < count; i++) {
            Map<String, Object> loc = placement.argLocations.get(i);
            if (!loc.containsKey("reg") && !loc.containsKey("stack")) {
                continue;
            }
            Map<String, Object> unknown = new LinkedHashMap<>();
            unknown.put("loc", loc);
            if (i < params.length) {
                unknown.put("name", params[i].getName());
            }
            else {
                unknown.put("name", "arg" + i);
                unknown.put("guess", true);
            }
            out.add(unknown);
        }
        return out;
    }

    public static Map<String, Object> location(VariableStorage storage) {
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
    public static boolean isThumb(Program program, Address entry) {
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
    public static Address resolveCode(Program program, String text, String what) {
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
    public static Address resolveData(Program program, Object value, String what) {
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

    public static List<Function> functionsNamed(Program program, String name) {
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

    public static Address symbolAddress(Program program, String name) {
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

    public static Address tryAddress(Program program, String text) {
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

    public static List<String> codeList(Program program, Object value, String what) {
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
    public static Object normalizeValue(Object value, String where) {
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

    public static Map<String, Object> numbersToText(Map<String, Object> map, String where) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) {
            out.put(e.getKey(), e.getValue() instanceof Number ? integerText(e.getValue(), where) : e.getValue());
        }
        return out;
    }

    /** An integer as text the worker parses exactly; JSON numbers arrive here as doubles. */
    public static String integerText(Object value, String where) {
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
    public static List<Map<String, Object>> memorySeeds(Program program, Object value) {
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

    public static List<Map<String, Object>> memoryReads(Program program, Object value) {
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
    public static void applyStubs(Program program, AngrImage image, Object value, Map<String, Object> spec) {
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

    public static void annotate(Program program, Map<String, Object> body) {
        annotate(AngrModules.single(program), body);
    }

    /** The same over several programs in one address space; names outside the first say which. */
    @SuppressWarnings("unchecked")
    public static void annotate(AngrModules modules, Map<String, Object> body) {
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
                path.put("stoppedAt", modules.codeLabel(at));
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
                        String name = modules.functionAt(target);
                        if (name != null) {
                            call.put("call", name);
                        }
                    }
                    if (call.get("from") instanceof String from) {
                        call.put("from", modules.codeLabel(from));
                    }
                }
            }
            if (path.get("globalWrites") instanceof List<?> writes) {
                for (Object o : writes) {
                    if (o instanceof Map<?, ?> m && m.get("address") instanceof String address) {
                        String label = modules.dataLabel(address);
                        if (label != null) {
                            ((Map<String, Object>) m).put("symbol", label);
                        }
                    }
                }
            }
        }
    }

    /** "0x101b00 (deref+0x10)" */
    public static String codeLabel(Program program, String hexAddress) {
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
    public static String dataLabel(Program program, String hexAddress) {
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
    public static void tidyNumbers(Object node) {
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

    public static String stringArg(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value == null ? null : String.valueOf(value);
    }

    public static long positive(Map<String, Object> arguments, String key, long fallback) {
        Object value = arguments.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof Number n) || n.longValue() < 1) {
            throw new IllegalArgumentException(key + " must be a positive integer");
        }
        return n.longValue();
    }

    public static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
