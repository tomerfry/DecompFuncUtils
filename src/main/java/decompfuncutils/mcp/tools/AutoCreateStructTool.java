package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

import java.util.*;

public class AutoCreateStructTool implements McpTool {

    @Override public String name() { return "ghidra_auto_create_struct"; }

    @Override
    public String description() {
        return "Auto-create a structure from a memory region. Scans the memory for pointer-sized values and attempts to resolve them as symbols, creating named fields.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "address", Map.of("type", "string", "description", "Start address of the memory region in hex"),
            "size", Map.of("type", "integer", "description", "Size of the region in bytes"),
            "name", Map.of("type", "string", "description", "Name for the generated struct (default: auto-generated)")
        ));
        schema.put("required", List.of("address", "size"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        String addrStr = (String) arguments.get("address");
        int size = ((Number) arguments.get("size")).intValue();
        String name = (String) arguments.getOrDefault("name", null);

        if (size < 1 || size > 102400) {
            throw new IllegalArgumentException("Size must be between 1 and 102400 bytes");
        }

        Address addr = McpUtil.parseAddress(addrStr, program);

        if (name == null) {
            name = "AutoStruct_" + addr.toString().replace(":", "_");
        }

        int ptrSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        SymbolTable st = program.getSymbolTable();
        DataTypeManager dtm = program.getDataTypeManager();

        StructureDataType struct = new StructureDataType(name, 0, dtm);

        int offset = 0;
        int fieldIndex = 0;
        while (offset + ptrSize <= size) {
            // Read pointer-sized value
            long value;
            if (ptrSize == 8) {
                value = memory.getLong(addr.add(offset));
            } else {
                value = memory.getInt(addr.add(offset)) & 0xFFFFFFFFL;
            }

            // Try to resolve as a symbol
            Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            Symbol sym = st.getPrimarySymbol(targetAddr);
            Function func = program.getFunctionManager().getFunctionAt(targetAddr);

            String fieldName;
            DataType fieldType;

            if (func != null) {
                fieldName = "pfn_" + sanitize(func.getName());
                fieldType = new PointerDataType(VoidDataType.dataType, ptrSize);
            } else if (sym != null && sym.getSource() != SourceType.DEFAULT) {
                fieldName = "ptr_" + sanitize(sym.getName());
                fieldType = new PointerDataType(VoidDataType.dataType, ptrSize);
            } else {
                fieldName = "field_" + Integer.toHexString(offset);
                fieldType = (ptrSize == 8) ? Undefined8DataType.dataType : Undefined4DataType.dataType;
            }

            struct.add(fieldType, ptrSize, fieldName, null);
            offset += ptrSize;
            fieldIndex++;
        }

        // Add remaining bytes
        while (offset < size) {
            struct.add(Undefined1DataType.dataType, 1, "field_" + Integer.toHexString(offset), null);
            offset++;
        }

        DataType resolved = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", resolved.getName());
        result.put("size", resolved.getLength());
        result.put("fieldCount", fieldIndex);
        result.put("status", "created");
        return result;
    }

    private String sanitize(String name) {
        return name.replaceAll("[^a-zA-Z0-9_]", "_");
    }
}
