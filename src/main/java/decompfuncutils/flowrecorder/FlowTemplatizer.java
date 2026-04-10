package decompfuncutils.flowrecorder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Replaces concrete reverser-session values (addresses, discovered names) with
 * generic placeholders like $addr1, $func1 so a recorded flow can be replayed
 * on a different binary. The first time a concrete value is seen it's assigned
 * a placeholder; subsequent references reuse that placeholder so relationships
 * between steps are preserved (e.g. "the same function gets renamed and then
 * commented").
 *
 * Policy:
 *   - Targets of an operation (things the reverser is acting on) become placeholders.
 *   - Values the reverser supplied from their own judgment (new name, new type,
 *     comment text) are preserved verbatim since they carry the intent of the
 *     template itself. The user can always hand-edit the markdown to
 *     parameterize those further.
 */
public class FlowTemplatizer {

    public static class Placeholder {
        public final String name;
        public final String kind;
        public final String capturedValue;
        public String description;

        Placeholder(String name, String kind, String capturedValue) {
            this.name = name;
            this.kind = kind;
            this.capturedValue = capturedValue;
            this.description = "";
        }
    }

    private final Map<String, Placeholder> byKey = new LinkedHashMap<>();
    private final Map<String, Integer> counters = new LinkedHashMap<>();

    public Map<String, Placeholder> getPlaceholders() {
        return byKey;
    }

    private String assign(String kind, String concreteValue) {
        String key = kind + ":" + concreteValue;
        Placeholder existing = byKey.get(key);
        if (existing != null) return existing.name;

        int idx = counters.getOrDefault(kind, 0) + 1;
        counters.put(kind, idx);
        String name = "$" + kind + idx;
        byKey.put(key, new Placeholder(name, kind, concreteValue));
        return name;
    }

    private String addr(String concrete) { return assign("addr", concrete); }
    private String func(String concrete) { return assign("func", concrete); }
    private String var(String concrete)  { return assign("var",  concrete); }
    private String type(String concrete) { return assign("type", concrete); }
    private String ns(String concrete)   { return assign("ns",   concrete); }

    /**
     * Produce a templated copy of the step's args based on which tool it is.
     * Per-tool logic here is kept small and explicit — easier to read than a
     * reflective schema walker.
     */
    public Map<String, Object> templatize(String toolName, Map<String, Object> rawArgs) {
        Map<String, Object> out = new LinkedHashMap<>(rawArgs);
        switch (toolName) {
            case "ghidra_rename_function": {
                if (out.containsKey("address"))
                    out.put("address", addr((String) out.get("address")));
                if (out.containsKey("name"))
                    out.put("name", func((String) out.get("name")));
                // newName preserved verbatim — it's the reverser's intent
                break;
            }
            case "ghidra_rename_label": {
                if (out.containsKey("address"))
                    out.put("address", addr((String) out.get("address")));
                // oldName may be brittle across binaries, but leaving it helps
                // disambiguate when multiple labels sit at the same address.
                break;
            }
            case "ghidra_rename_variable": {
                if (out.containsKey("functionAddress"))
                    out.put("functionAddress", addr((String) out.get("functionAddress")));
                if (out.containsKey("functionName"))
                    out.put("functionName", func((String) out.get("functionName")));
                if (out.containsKey("oldName"))
                    out.put("oldName", var((String) out.get("oldName")));
                break;
            }
            case "ghidra_retype_variable": {
                if (out.containsKey("functionAddress"))
                    out.put("functionAddress", addr((String) out.get("functionAddress")));
                if (out.containsKey("functionName"))
                    out.put("functionName", func((String) out.get("functionName")));
                if (out.containsKey("variableName"))
                    out.put("variableName", var((String) out.get("variableName")));
                // newType preserved verbatim
                break;
            }
            case "ghidra_set_comment": {
                if (out.containsKey("address"))
                    out.put("address", addr((String) out.get("address")));
                // comment text preserved verbatim
                break;
            }
            case "ghidra_set_function_signature": {
                if (out.containsKey("address"))
                    out.put("address", addr((String) out.get("address")));
                if (out.containsKey("name"))
                    out.put("name", func((String) out.get("name")));
                break;
            }
            case "ghidra_create_struct":
            case "ghidra_create_class": {
                // name + fields are the reverser's intent — leave untouched.
                // But if a field type references a previously-captured type,
                // swap in the placeholder so linked types stay linked.
                Object fields = out.get("fields");
                if (fields instanceof List) {
                    for (Object f : (List<?>) fields) {
                        if (f instanceof Map) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> fm = (Map<String, Object>) f;
                            Object t = fm.get("type");
                            if (t instanceof String) {
                                String existing = lookup("type", (String) t);
                                if (existing != null) fm.put("type", existing);
                            }
                        }
                    }
                }
                break;
            }
            case "ghidra_assign_namespace": {
                if (out.containsKey("address"))
                    out.put("address", addr((String) out.get("address")));
                if (out.containsKey("namespace"))
                    out.put("namespace", ns((String) out.get("namespace")));
                break;
            }
            default: {
                // Best-effort: templatize any field named "address" or "functionAddress"
                if (out.containsKey("address") && out.get("address") instanceof String)
                    out.put("address", addr((String) out.get("address")));
                if (out.containsKey("functionAddress") && out.get("functionAddress") instanceof String)
                    out.put("functionAddress", addr((String) out.get("functionAddress")));
            }
        }
        return out;
    }

    private String lookup(String kind, String concrete) {
        Placeholder p = byKey.get(kind + ":" + concrete);
        return p != null ? p.name : null;
    }

    /**
     * Attach a human-readable description to a placeholder the first time
     * it's encountered — e.g. "function at 0x401000" for $func1.
     */
    public void describe(String kind, String concreteValue, String description) {
        Placeholder p = byKey.get(kind + ":" + concreteValue);
        if (p != null && (p.description == null || p.description.isEmpty())) {
            p.description = description;
        }
    }
}
