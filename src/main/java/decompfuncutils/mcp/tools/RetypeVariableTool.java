package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;
import java.util.Iterator;

public class RetypeVariableTool implements McpTool {

    @Override public String name() { return "ghidra_retype_variable"; }

    @Override
    public String description() {
        return "Change the data type of a local variable or parameter within a function. Use standard C types or types defined in the program.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of(
            "functionAddress", Map.of("type", "string", "description", "Address of the containing function in hex"),
            "functionName", Map.of("type", "string", "description", "Name of the containing function"),
            "variableName", Map.of("type", "string", "description", "Variable name to retype"),
            "newType", Map.of("type", "string", "description", "New data type (e.g. 'int', 'char *', 'MyStruct *')")
        ));
        schema.put("required", List.of("variableName", "newType"));
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));
        Function func = DecompileFunctionTool.resolveFunction(funcArgs, program);
        if (func == null) throw new IllegalArgumentException("Function not found");

        String varName = (String) arguments.get("variableName");
        String newTypeName = (String) arguments.get("newType");

        DataType newType = resolveDataType(newTypeName, program);
        if (newType == null) {
            throw new IllegalArgumentException("Unknown data type: " + newTypeName);
        }

        // Search parameters
        for (Parameter param : func.getParameters()) {
            if (param.getName().equals(varName)) {
                String oldType = param.getDataType().getDisplayName();
                param.setDataType(newType, SourceType.USER_DEFINED);
                return successResult(func, varName, oldType, newType.getDisplayName(), "parameter");
            }
        }

        // Search local variables
        for (Variable var : func.getLocalVariables()) {
            if (var.getName().equals(varName)) {
                String oldType = var.getDataType().getDisplayName();
                var.setDataType(newType, SourceType.USER_DEFINED);
                return successResult(func, varName, oldType, newType.getDisplayName(), "local_variable");
            }
        }

        throw new IllegalArgumentException("Variable '" + varName + "' not found in function " + func.getName());
    }

    static DataType resolveDataType(String typeName, Program program) {
        if (typeName == null) return null;
        typeName = typeName.trim();
        if (typeName.isEmpty()) return null;

        DataTypeManager dtm = program.getDataTypeManager();

        // Array syntax: "T[N]" or "T [N]"
        int lb = typeName.lastIndexOf('[');
        int rb = typeName.lastIndexOf(']');
        if (lb > 0 && rb == typeName.length() - 1 && rb > lb) {
            String baseName = typeName.substring(0, lb).trim();
            String lenStr = typeName.substring(lb + 1, rb).trim();
            try {
                int n = Integer.parseInt(lenStr);
                if (n <= 0) return null;
                DataType baseType = resolveDataType(baseName, program);
                if (baseType == null) return null;
                int elemLen = baseType.getLength();
                if (elemLen <= 0) elemLen = 1;
                return new ArrayDataType(baseType, n, elemLen);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // Pointer types: "T *" / "T**"
        if (typeName.endsWith("*")) {
            String baseName = typeName.substring(0, typeName.lastIndexOf('*')).trim();
            DataType baseType = resolveDataType(baseName, program);
            if (baseType != null) {
                return new PointerDataType(baseType, program.getDefaultPointerSize());
            }
            return null;
        }

        // Canonical aliases — check first so uint64_t etc. resolve consistently
        DataType aliased = resolveAlias(typeName);
        if (aliased != null) return aliased;

        // Pointer-sized aliases (size_t, ssize_t, etc.)
        DataType ptrSized = resolvePointerSizedAlias(typeName, program);
        if (ptrSized != null) return ptrSized;

        // Try exact match in program DTM
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName)) return dt;
        }

        // Try built-in types
        DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        Iterator<DataType> builtInIter = builtIn.getAllDataTypes();
        while (builtInIter.hasNext()) {
            DataType dt = builtInIter.next();
            if (dt.getName().equals(typeName)) return dt;
        }

        return null;
    }

    private static DataType resolveAlias(String typeName) {
        switch (typeName) {
            // C stdint (case-sensitive — these have canonical casing)
            case "uint8_t": case "u8":   return UnsignedCharDataType.dataType;
            case "int8_t":  case "i8": case "s8": return SignedCharDataType.dataType;
            case "uint16_t": case "u16": return UnsignedShortDataType.dataType;
            case "int16_t":  case "i16": case "s16": return ShortDataType.dataType;
            case "uint32_t": case "u32": return UnsignedIntegerDataType.dataType;
            case "int32_t":  case "i32": case "s32": return IntegerDataType.dataType;
            case "uint64_t": case "u64": return UnsignedLongLongDataType.dataType;
            case "int64_t":  case "i64": case "s64": return LongLongDataType.dataType;
        }
        switch (typeName.toLowerCase()) {
            case "int": return IntegerDataType.dataType;
            case "uint": case "unsigned": case "unsigned int": return UnsignedIntegerDataType.dataType;
            case "long": return LongDataType.dataType;
            case "ulong": case "unsigned long": return UnsignedLongDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "ushort": case "unsigned short": return UnsignedShortDataType.dataType;
            case "char": return CharDataType.dataType;
            case "uchar": case "unsigned char": return UnsignedCharDataType.dataType;
            case "signed char": case "schar": return SignedCharDataType.dataType;
            case "byte": return ByteDataType.dataType;
            case "ubyte": return UnsignedCharDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "bool": case "_bool": return BooleanDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "longlong": case "long long": return LongLongDataType.dataType;
            case "ulonglong": case "unsigned long long": return UnsignedLongLongDataType.dataType;
            case "undefined": return Undefined1DataType.dataType;
            case "undefined1": return Undefined1DataType.dataType;
            case "undefined2": return Undefined2DataType.dataType;
            case "undefined4": return Undefined4DataType.dataType;
            case "undefined8": return Undefined8DataType.dataType;
        }
        return null;
    }

    private static DataType resolvePointerSizedAlias(String typeName, Program program) {
        int ptrSize = program.getDefaultPointerSize();
        boolean is64 = ptrSize == 8;
        switch (typeName.toLowerCase()) {
            case "size_t": case "usize":
                return is64 ? UnsignedLongLongDataType.dataType : UnsignedIntegerDataType.dataType;
            case "ssize_t": case "isize":
                return is64 ? LongLongDataType.dataType : IntegerDataType.dataType;
            case "ptrdiff_t":
                return is64 ? LongLongDataType.dataType : IntegerDataType.dataType;
            case "intptr_t":
                return is64 ? LongLongDataType.dataType : IntegerDataType.dataType;
            case "uintptr_t":
                return is64 ? UnsignedLongLongDataType.dataType : UnsignedIntegerDataType.dataType;
            case "off_t":
                return is64 ? LongLongDataType.dataType : IntegerDataType.dataType;
            default:
                return null;
        }
    }

    private Map<String, Object> successResult(Function func, String varName, String oldType, String newType, String varKind) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("variable", varName);
        result.put("oldType", oldType);
        result.put("newType", newType);
        result.put("variableKind", varKind);
        result.put("status", "retyped");
        return result;
    }
}
