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
        DataTypeManager dtm = program.getDataTypeManager();

        // Check for pointer types
        if (typeName.endsWith("*")) {
            String baseName = typeName.substring(0, typeName.lastIndexOf('*')).trim();
            DataType baseType = resolveDataType(baseName, program);
            if (baseType != null) {
                return new PointerDataType(baseType, program.getDefaultPointerSize());
            }
            return null;
        }

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

        // Common aliases
        switch (typeName.toLowerCase()) {
            case "int": return IntegerDataType.dataType;
            case "uint": return UnsignedIntegerDataType.dataType;
            case "long": return LongDataType.dataType;
            case "ulong": return UnsignedLongDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "ushort": return UnsignedShortDataType.dataType;
            case "char": return CharDataType.dataType;
            case "uchar": return UnsignedCharDataType.dataType;
            case "byte": return ByteDataType.dataType;
            case "ubyte": return UnsignedCharDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "bool": return BooleanDataType.dataType;
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
