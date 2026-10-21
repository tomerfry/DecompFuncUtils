package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.*;
import java.util.*;

/** Changes instance settings, independently of memory-block permissions. */
public class SetDataMutabilityTool implements McpTool {
    private static final List<String> MODES = List.of("normal", "volatile", "constant", "writable");
    public String name() { return "ghidra_set_data_mutability"; }
    public String description() {
        return "Set per-data mutability (including constant for ARM literal pools), without changing block flags. " +
            "Targets must already be defined data at exact start addresses. The batch is atomic.";
    }
    public Map<String, Object> inputSchema() {
        return Map.of("type", "object", "properties", Map.of(
            "addresses", Map.of("type", "array", "minItems", 1, "maxItems", 4096, "items", Map.of("type", "string")),
            "mutability", Map.of("type", "string", "enum", MODES)), "required", List.of("addresses", "mutability"));
    }
    public boolean isMutating() { return true; }
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        int mode = MODES.indexOf(DecompilerEditSupport.string(args, "mutability"));
        if (mode < 0) throw new IllegalArgumentException("mutability must be one of " + MODES);
        if (!(args.get("addresses") instanceof List<?> addresses) || addresses.isEmpty() || addresses.size() > 4096) {
            throw new IllegalArgumentException("addresses must contain 1 to 4096 data start addresses");
        }
        List<Data> targets = new ArrayList<>();
        for (Object value : addresses) {
            if (!(value instanceof String address)) throw new IllegalArgumentException("Each address must be a string");
            Data data = program.getListing().getDefinedDataAt(McpUtil.parseAddress(address, program));
            if (data == null) throw new IllegalArgumentException("No defined data starts at " + address);
            if (!targets.contains(data)) targets.add(data);
        }
        List<Map<String, Object>> changes = new ArrayList<>();
        for (Data data : targets) {
            McpUtil.activeMonitor().checkCancelled();
            var def = MutabilitySettingsDefinition.DEF;
            String before = def.getValueString(data);
            def.setChoice(data, mode);
            changes.add(Map.of("address", data.getAddress().toString(), "oldMutability", before,
                "mutability", def.getValueString(data), "changed", !before.equals(MODES.get(mode))));
        }
        return Map.of("status", "data_mutability_set", "data", changes);
    }
}
