package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Scans a vtable at a given address, builds a struct whose fields are function
 * pointers mirroring each virtual slot (named after the resolved callee), and
 * optionally applies that struct as data at the vtable address. Meant to save
 * the two-step scan + hand-built struct workflow.
 */
public class CreateVtableStructTool implements McpTool {

    @Override public String name() { return "ghidra_create_vtable_struct"; }

    @Override
    public String description() {
        return "Scan a vtable and generate a struct whose fields are function pointers named after each virtual method. Handles the Itanium ABI header (offset-to-top + typeinfo) automatically. By default applies the resulting struct as data at the vtable address.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("address", Map.of("type", "string", "description", "Vtable address in hex (canonical base or first method slot)."));
        props.put("structName", Map.of("type", "string", "description", "Name for the generated struct (e.g. 'Shape_vtable')."));
        props.put("category", Map.of("type", "string", "description", "Category path for generated types. Default '/vtables'."));
        props.put("maxEntries", Map.of("type", "integer", "description", "Max method slots to scan (default 100)."));
        props.put("skipHeader", Map.of("type", "string", "description", "Itanium header handling: 'auto' (default), 'always', 'never'."));
        props.put("includeHeader", Map.of("type", "boolean", "description", "If true and header is detected, include offset_to_top / typeinfo as typed fields in the struct. Default false (struct starts at first method)."));
        props.put("applyAtAddress", Map.of("type", "boolean", "description", "Apply the generated struct as data at the vtable address. Default true."));
        props.put("fieldPrefix", Map.of("type", "string", "description", "Prefix for slot field names when the callee has no meaningful name (default 'vfunc_')."));
        schema.put("properties", props);
        schema.put("required", List.of("address", "structName"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        String structName = (String) arguments.get("structName");
        String categoryStr = (String) arguments.getOrDefault("category", "/vtables");
        int maxEntries = ((Number) arguments.getOrDefault("maxEntries", 100)).intValue();
        String skipHeader = ((String) arguments.getOrDefault("skipHeader", "auto")).toLowerCase();
        boolean includeHeader = (Boolean) arguments.getOrDefault("includeHeader", Boolean.FALSE);
        boolean applyAt = (Boolean) arguments.getOrDefault("applyAtAddress", Boolean.TRUE);
        String fieldPrefix = (String) arguments.getOrDefault("fieldPrefix", "vfunc_");

        Address base = McpUtil.parseAddress(addrStr, program);
        int ptrSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager fm = program.getFunctionManager();
        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(categoryStr);

        int skip = detectHeaderSkip(base, ptrSize, memory, fm, program, skipHeader);
        Address methodsStart = base.add((long) skip * ptrSize);

        // Walk the method slots, pulling the callee and its signature.
        List<SlotInfo> slots = new ArrayList<>();
        Address cursor = methodsStart;
        for (int i = 0; i < maxEntries; i++) {
            long value;
            try {
                value = (ptrSize == 8) ? memory.getLong(cursor) : memory.getInt(cursor) & 0xFFFFFFFFL;
            } catch (Exception e) {
                break;
            }
            Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            Function func = fm.getFunctionAt(target);
            if (func == null) break;
            slots.add(new SlotInfo(i, cursor, target, func));
            cursor = cursor.add(ptrSize);
        }

        if (slots.isEmpty()) {
            throw new RuntimeException("No resolvable function entries at " + methodsStart
                + " (skipped " + skip + " header slot(s)).");
        }

        StructureDataType struct = new StructureDataType(catPath, structName, 0, dtm);
        List<Map<String, Object>> fieldReport = new ArrayList<>();

        // Optionally include the Itanium header as typed fields so the resulting
        // struct can be applied at the canonical vtable base instead of just at
        // the methods-start address.
        if (includeHeader && skip > 0) {
            DataType intPtrSized = ptrSize == 8 ? LongLongDataType.dataType : IntegerDataType.dataType;
            PointerDataType voidPtr = new PointerDataType(VoidDataType.dataType, ptrSize, dtm);
            if (skip >= 1) {
                struct.add(intPtrSized, ptrSize, "offset_to_top", null);
                fieldReport.add(headerField("offset_to_top", intPtrSized.getDisplayName()));
            }
            if (skip >= 2) {
                struct.add(voidPtr, ptrSize, "typeinfo", null);
                fieldReport.add(headerField("typeinfo", voidPtr.getDisplayName()));
            }
        }

        Set<String> usedNames = new HashSet<>();
        for (SlotInfo s : slots) {
            FunctionDefinitionDataType funcDef = buildFunctionDefinition(s.func, structName, s.index, catPath, dtm);
            DataType resolvedDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
            PointerDataType fp = new PointerDataType(resolvedDef, ptrSize, dtm);

            String fieldName = sanitizeFieldName(s.func.getName(), s.index, fieldPrefix);
            fieldName = disambiguate(fieldName, usedNames);
            usedNames.add(fieldName);

            struct.add(fp, ptrSize, fieldName, null);

            Map<String, Object> f = new LinkedHashMap<>();
            f.put("index", s.index);
            f.put("fieldName", fieldName);
            f.put("targetAddress", s.target.toString());
            f.put("function", s.func.getName());
            f.put("signature", s.func.getPrototypeString(false, false));
            fieldReport.add(f);
        }

        DataType resolvedStruct = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        String appliedAt = null;
        String applyStatus = "skipped";
        if (applyAt) {
            Address target = includeHeader ? base : methodsStart;
            Listing listing = program.getListing();
            try {
                listing.clearCodeUnits(target, target.add(resolvedStruct.getLength() - 1), false);
                listing.createData(target, resolvedStruct);
                appliedAt = target.toString();
                applyStatus = "applied";
            } catch (Exception e) {
                applyStatus = "failed: " + e.getMessage();
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("structName", resolvedStruct.getName());
        result.put("category", resolvedStruct.getCategoryPath().getPath());
        result.put("structSize", resolvedStruct.getLength());
        result.put("vtableBase", base.toString());
        result.put("methodsStart", methodsStart.toString());
        result.put("headerSkipped", skip);
        result.put("headerIncluded", includeHeader && skip > 0);
        result.put("methodCount", slots.size());
        result.put("fields", fieldReport);
        result.put("applyStatus", applyStatus);
        if (appliedAt != null) result.put("appliedAt", appliedAt);
        return result;
    }

    private int detectHeaderSkip(Address base, int ptrSize, Memory memory, FunctionManager fm,
                                 Program program, String mode) {
        if (mode.equals("never")) return 0;
        if (mode.equals("always")) return 2;
        // auto
        int skip = 0;
        for (int i = 0; i < 2; i++) {
            Address peek = base.add((long) i * ptrSize);
            if (resolveFunctionAt(peek, ptrSize, memory, fm, program) != null) break;
            Address afterPeek = base.add((long) (i + 1) * ptrSize);
            if (resolveFunctionAt(afterPeek, ptrSize, memory, fm, program) != null) {
                skip = i + 1;
                break;
            }
        }
        return skip;
    }

    private static Function resolveFunctionAt(Address slot, int ptrSize, Memory memory,
                                              FunctionManager fm, Program program) {
        try {
            long value = (ptrSize == 8) ? memory.getLong(slot) : memory.getInt(slot) & 0xFFFFFFFFL;
            Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            return fm.getFunctionAt(target);
        } catch (Exception e) {
            return null;
        }
    }

    private FunctionDefinitionDataType buildFunctionDefinition(Function func, String structName,
                                                               int slotIndex, CategoryPath catPath,
                                                               DataTypeManager dtm) {
        // Give each generated FunctionDefinition a unique, deterministic name so
        // that repeated slots with the same callee don't collide in the DTM.
        String defName = structName + "_slot" + slotIndex + "_def";
        FunctionDefinitionDataType def = new FunctionDefinitionDataType(catPath, defName, dtm);
        def.setReturnType(func.getReturnType());

        Parameter[] params = func.getParameters();
        ParameterDefinition[] paramDefs = new ParameterDefinition[params.length];
        for (int i = 0; i < params.length; i++) {
            Parameter p = params[i];
            String pName = p.getName();
            if (pName == null || pName.isEmpty()) pName = "param" + (i + 1);
            paramDefs[i] = new ParameterDefinitionImpl(pName, p.getDataType(), p.getComment());
        }
        def.setArguments(paramDefs);
        return def;
    }

    private static final Pattern ILLEGAL = Pattern.compile("[^A-Za-z0-9_]");

    private String sanitizeFieldName(String rawName, int slotIndex, String prefix) {
        if (rawName == null || rawName.isEmpty() || rawName.startsWith("FUN_")) {
            return prefix + slotIndex;
        }
        String cleaned = ILLEGAL.matcher(rawName).replaceAll("_");
        if (cleaned.isEmpty() || !Character.isJavaIdentifierStart(cleaned.charAt(0))) {
            cleaned = "_" + cleaned;
        }
        return cleaned;
    }

    private String disambiguate(String name, Set<String> used) {
        if (!used.contains(name)) return name;
        int i = 2;
        while (used.contains(name + "_" + i)) i++;
        return name + "_" + i;
    }

    private Map<String, Object> headerField(String name, String type) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fieldName", name);
        m.put("type", type);
        m.put("role", "header");
        return m;
    }

    private static class SlotInfo {
        final int index;
        final Address slotAddress;
        final Address target;
        final Function func;
        SlotInfo(int index, Address slotAddress, Address target, Function func) {
            this.index = index;
            this.slotAddress = slotAddress;
            this.target = target;
            this.func = func;
        }
    }
}
