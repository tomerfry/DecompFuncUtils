package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

public class SetUnionFieldTool implements McpTool {
    public String name() { return "ghidra_set_union_field"; }
    public String description() {
        return "Force a union member at one decompiler use, using selectors from ghidra_get_variable_uses. " +
            "fieldOrdinal=-1 explicitly selects the whole union (no field); it does not remove the override.";
    }
    public boolean isMutating() { return true; }
    public Map<String, Object> inputSchema() {
        var props = DecompilerEditSupport.properties(true);
        props.put("fieldOrdinal", Map.of("type", "integer", "minimum", -1, "description", "Zero-based field ordinal; -1 means no field"));
        return Map.of("type", "object", "properties", props,
            "required", List.of("functionAddress", "operationAddress", "operationTime", "slot", "fieldOrdinal"));
    }
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        try (var edit = new DecompilerEditSupport(args, program)) {
            PcodeOpAST op = edit.operation(args, program);
            int slot = DecompilerEditSupport.integer(args.get("slot"), "slot", -1, op.getNumInputs() - 1);
            Varnode vn = DecompilerEditSupport.varnode(op, slot);
            DecompilerEditSupport.guard(args, vn);
            DataType parent = DecompilerEditSupport.unionParent(op, slot);
            Union union = DecompilerEditSupport.union(parent);
            if (union == null) throw new IllegalArgumentException("Selected use has no union data type");
            int field = DecompilerEditSupport.integer(args.get("fieldOrdinal"), "fieldOrdinal", -1, union.getNumComponents() - 1);
            Varnode sizedUse = op.getOpcode() == PcodeOp.SUBPIECE && slot == 0 && !(parent instanceof Pointer)
                ? op.getOutput() : vn;
            validateSize(parent, union, field, sizedUse);
            // The decompiler inserts PTRSUB(..., 0) to render a chosen field. These
            // synthetic operations disappear on the next decompile. As in ForceUnionAction,
            // hash the real consuming edge while retaining the original union parent type.
            if (op.getOpcode() == PcodeOp.PTRSUB && slot == 0 && op.getInput(1).getOffset() == 0) {
                do {
                    Varnode output = op.getOutput();
                    PcodeOp next = output.getLoneDescend();
                    if (next == null) break;
                    op = (PcodeOpAST) next;
                    slot = op.getSlot(output);
                } while (op.getOpcode() == PcodeOp.PTRSUB && op.getInput(1).getOffset() == 0);
            } else if (op.getOpcode() == PcodeOp.PTRSUB && slot == -1) {
                PcodeOp next = vn.getLoneDescend();
                if (next != null && next.getOpcode() != PcodeOp.MULTIEQUAL && next.getOpcode() != PcodeOp.INDIRECT) {
                    op = (PcodeOpAST) next;
                    slot = op.getSlot(vn);
                }
            } else if (op.getOpcode() == PcodeOp.SUBPIECE && slot == 0 && !(parent instanceof Pointer)) {
                slot = -1;
            }
            DynamicHash hash = new DynamicHash(op, slot, edit.high);
            if (hash.getHash() == 0 || hash.getAddress() == null || hash.getAddress().equals(Address.NO_ADDRESS)) {
                throw new IllegalArgumentException("Cannot uniquely identify this use; select a different operation edge");
            }
            writeFacet(edit.function, parent, field, hash);
            return Map.of("status", "union_field_set", "functionAddress", edit.function.getEntryPoint().toString(),
                "unionType", union.getPathName(), "fieldOrdinal", field, "firstUseAddress", hash.getAddress().toString(),
                "dynamicHash", Long.toUnsignedString(hash.getHash(), 16));
        }
    }

    private static void validateSize(DataType parent, Union union, int field, Varnode vn) {
        if (parent instanceof Pointer) return;
        int start = parent instanceof PartialUnion partial ? partial.getOffset() : 0;
        long end = (long) start + vn.getSize();
        if (field == -1) {
            if (!(parent instanceof PartialUnion) && vn.getSize() != parent.getLength()) {
                throw new IllegalArgumentException("Whole union does not fit this use");
            }
            return;
        }
        DataTypeComponent component = union.getComponent(field);
        long fieldEnd = (long) component.getOffset() + component.getLength();
        boolean fits = parent instanceof PartialUnion ? start >= component.getOffset() && end <= fieldEnd
            : start == component.getOffset() && end == fieldEnd;
        if (!fits) throw new IllegalArgumentException("Selected union field does not fit this use's size/offset");
    }

    private static void writeFacet(Function function, DataType type, int field, DynamicHash hash) throws Exception {
        // Ghidra 12.1 adds an address-wide mode. Keep exact-edge semantics on both APIs.
        try {
            try {
                HighFunctionDBUtil.class.getMethod("writeUnionFacet", Function.class, DataType.class, int.class,
                    Address.class, long.class, boolean.class, SourceType.class).invoke(null, function, type, field,
                    hash.getAddress(), hash.getHash(), false, SourceType.USER_DEFINED);
            } catch (NoSuchMethodException olderGhidra) {
                HighFunctionDBUtil.class.getMethod("writeUnionFacet", Function.class, DataType.class, int.class,
                    Address.class, long.class, SourceType.class).invoke(null, function, type, field,
                    hash.getAddress(), hash.getHash(), SourceType.USER_DEFINED);
            }
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception cause) throw cause;
            throw e;
        }
    }
}
