package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

/** Fresh decompilations and exact use selectors shared by inspection and editing tools. */
final class DecompilerEditSupport implements AutoCloseable {
    final DecompInterface decompiler = new DecompInterface();
    final Function function;
    final HighFunction high;

    DecompilerEditSupport(Map<String, Object> args, Program program) throws Exception {
        String address = string(args, "functionAddress");
        function = DecompileFunctionTool.resolveFunction(Map.of("address", address), program);
        if (function == null || function.isExternal()) {
            throw new IllegalArgumentException("No internal function at " + address);
        }
        try {
            decompiler.setOptions(new DecompileOptions());
            if (!decompiler.openProgram(program)) throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(function, 30, McpUtil.activeMonitor());
            McpUtil.activeMonitor().checkCancelled();
            if (!result.decompileCompleted() || result.getHighFunction() == null) {
                throw new IllegalStateException("Decompilation failed: " + result.getErrorMessage());
            }
            high = result.getHighFunction();
        } catch (Exception e) {
            decompiler.dispose();
            throw e;
        }
    }

    static String string(Map<String, Object> args, String key) {
        if (!(args.get(key) instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException(key + " must be a non-empty string");
        }
        return value;
    }

    static int integer(Object value, String key, int min, int max) {
        if (!(value instanceof Number n) || !Double.isFinite(n.doubleValue()) ||
                n.doubleValue() != Math.rint(n.doubleValue()) || n.doubleValue() < min || n.doubleValue() > max) {
            throw new IllegalArgumentException(key + " must be an integer in [" + min + ", " + max + "]");
        }
        return ((Number) value).intValue();
    }

    static Map<String, Object> properties(boolean selector) {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("functionAddress", Map.of("type", "string", "description", "Containing function address (hex)"));
        if (selector) {
            props.put("operationAddress", Map.of("type", "string", "description", "P-code instruction address from ghidra_get_variable_uses"));
            props.put("operationTime", Map.of("type", "integer", "minimum", 0, "description", "P-code sequence number from inspection; refresh after edits"));
            props.put("slot", Map.of("type", "integer", "minimum", -1, "description", "-1 for operation output, otherwise zero-based input index"));
            props.put("expectedVariable", Map.of("type", "string", "description", "Optional stale-selector guard: current high variable name"));
        }
        return props;
    }

    PcodeOpAST operation(Map<String, Object> args, Program program) {
        Address address = McpUtil.parseAddress(string(args, "operationAddress"), program);
        int time = integer(args.get("operationTime"), "operationTime", 0, Integer.MAX_VALUE);
        Iterator<PcodeOpAST> ops = high.getPcodeOps(address);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getSeqnum().getTime() == time) return op;
        }
        throw new IllegalArgumentException("P-code operation not found; refresh ghidra_get_variable_uses");
    }

    static Varnode varnode(PcodeOp op, int slot) {
        if (slot < -1 || slot >= op.getNumInputs()) throw new IllegalArgumentException("Invalid slot for operation");
        Varnode vn = slot == -1 ? op.getOutput() : op.getInput(slot);
        if (vn == null) throw new IllegalArgumentException("Operation has no output");
        return vn;
    }

    static void guard(Map<String, Object> args, Varnode vn) {
        if (args.containsKey("expectedVariable") && (vn.getHigh() == null ||
                !string(args, "expectedVariable").equals(vn.getHigh().getName()))) {
            throw new IllegalArgumentException("Variable changed; refresh ghidra_get_variable_uses");
        }
    }

    static DataType unwrap(DataType type) {
        return type instanceof TypeDef td ? td.getBaseDataType() : type;
    }

    static Union union(DataType type) {
        type = unwrap(type);
        if (type instanceof Pointer pointer) type = pointer.getDataType();
        else if (type instanceof PartialUnion partial) type = partial.getParent();
        type = unwrap(type);
        return type instanceof Union u ? u : null;
    }

    static DataType unionParent(PcodeOp op, int slot) {
        Varnode vn = varnode(op, slot);
        HighVariable high = vn.getHigh();
        if (high != null) {
            if (union(high.getDataType()) != null) return unwrap(high.getDataType());
            if (high.getSymbol() != null && union(high.getSymbol().getDataType()) != null) {
                return unwrap(high.getSymbol().getDataType());
            }
        }
        // SUBPIECE resolves the input union's field on its output edge.
        if (slot == -1 && op.getOpcode() == PcodeOp.SUBPIECE) return unionParent(op, 0);
        return null;
    }

    static boolean canSplit(Varnode vn) {
        HighVariable high = vn.getHigh();
        if (!(high instanceof HighLocal) || high instanceof HighParam || high.getSymbol() == null ||
                high.getSymbol().isIsolated()) return false;
        for (Varnode instance : high.getInstances()) {
            if (instance.getMergeGroup() != vn.getMergeGroup()) return true;
        }
        return false;
    }

    @Override public void close() { decompiler.dispose(); }
}
