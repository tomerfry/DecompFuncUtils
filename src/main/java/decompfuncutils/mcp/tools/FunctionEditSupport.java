package decompfuncutils.mcp.tools;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.*;

/** Strict target selection for edits, including external and namespace-qualified functions. */
final class FunctionEditSupport {
    private FunctionEditSupport() {}

    static Function resolve(Map<String, Object> args, Program program,
                            String addressKey, String nameKey) {
        if (args.containsKey(addressKey)) {
            String address = requiredString(args.get(addressKey), addressKey);
            Function function = DecompileFunctionTool.resolveFunction(Map.of("address", address), program);
            if (function == null) throw new IllegalArgumentException("Function not found at " + address);
            return function;
        }
        String name = requiredString(args.get(nameKey), nameKey);
        List<Function> matches = new ArrayList<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (matches(function, name)) matches.add(function);
        }
        for (Function function : program.getFunctionManager().getExternalFunctions()) {
            if (matches(function, name)) matches.add(function);
        }
        if (matches.isEmpty()) throw new IllegalArgumentException("Function not found: " + name);
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Ambiguous function name: " + name + "; use " + addressKey);
        }
        return matches.get(0);
    }

    private static boolean matches(Function function, String name) {
        return function.getName().equals(name) || function.getName(true).equals(name);
    }

    static String requiredString(Object value, String key) {
        if (!(value instanceof String) || ((String) value).isBlank()) {
            throw new IllegalArgumentException(key + " must be a non-empty string");
        }
        return (String) value;
    }

    static boolean booleanValue(Object value, String key) {
        if (!(value instanceof Boolean)) throw new IllegalArgumentException(key + " must be a boolean");
        return (Boolean) value;
    }
}
