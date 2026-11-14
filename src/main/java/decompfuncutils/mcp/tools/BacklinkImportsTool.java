package decompfuncutils.mcp.tools;

import decompfuncutils.crossmodule.CrossModuleLinker;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * MCP front end for {@link CrossModuleLinker#backlinkImports}: writes reverse cross-module links
 * into the shared objects a program imports from. The same engine runs as the "Cross-Module Import
 * Linker" analyzer.
 */
public class BacklinkImportsTool implements McpTool {

    private static final int DEFAULT_MAX_CALL_SITES = CrossModuleLinker.DEFAULT_MAX_CALL_SITES;

    @Override public String name() { return "ghidra_backlink_imports"; }

    @Override
    public String description() {
        return "Make imports navigable in both directions. For every external function this program " +
            "resolves to a project library, annotate the exporting function inside that library with a " +
            "clickable list of this program's call sites, and bookmark it under category " +
            "'imported-by:<program>'. Ghidra stores references per program, so a library's Incoming " +
            "References can never list a caller from another module; a '{@program path@addr label}' " +
            "comment annotation is the one cross-program link Ghidra follows, and it is what this tool " +
            "writes. Each importing program owns a delimited comment block, so re-runs are idempotent " +
            "and several importers of one library coexist. Run ghidra_resolve_externals first so the " +
            "imports are attributed to libraries; targets are taken from each external location's " +
            "address, or looked up by name in the library when no address was stored. Writes to and " +
            "saves the LIBRARY programs, not this one.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("dryRun", Map.of("type", "boolean",
            "description", "Report what would be written without changing any program (default false)"));
        props.put("remove", Map.of("type", "boolean",
            "description", "Remove this program's back-link blocks and bookmarks instead of writing " +
                "them (default false)"));
        props.put("libraries", Map.of("type", "array",
            "items", Map.of("type", "string"),
            "description", "Restrict the work to these library names as they appear in DT_NEEDED " +
                "(e.g. 'libatalk.so.18'). Omit for every resolved library."));
        props.put("comments", Map.of("type", "boolean",
            "description", "Write the plate-comment block of clickable call-site links (default true)"));
        props.put("bookmarks", Map.of("type", "boolean",
            "description", "Set an Info bookmark in category 'imported-by:<program>' at each annotated " +
                "function, giving a filterable index of cross-module entry points (default true)"));
        props.put("includeDataRefs", Map.of("type", "boolean",
            "description", "Also link non-call references — where the import's address is taken rather " +
                "than called (default false)"));
        props.put("maxCallSites", Map.of("type", "integer",
            "description", "Links listed per function before the block says '... and N more' " +
                "(default " + DEFAULT_MAX_CALL_SITES + ")"));
        props.put("save", Map.of("type", "boolean",
            "description", "Save each modified library program (default true). With false the edits " +
                "stay in memory for whoever has the library open."));
        props.put("listFunctions", Map.of("type", "boolean",
            "description", "Include per-function detail in the result (default false)"));
        schema.put("properties", props);
        return schema;
    }

    /** Serialized with other mutations; the library edits get their own transactions. */
    @Override public boolean isMutating() { return true; }

    /** Opening, editing and saving library programs is slow and touches no Swing. */
    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        CrossModuleLinker.BacklinkOptions options = new CrossModuleLinker.BacklinkOptions();
        options.dryRun = asBool(arguments.get("dryRun"), false);
        options.remove = asBool(arguments.get("remove"), false);
        options.comments = asBool(arguments.get("comments"), true);
        options.bookmarks = asBool(arguments.get("bookmarks"), true);
        options.includeDataRefs = asBool(arguments.get("includeDataRefs"), false);
        options.save = asBool(arguments.get("save"), true);
        options.listFunctions = asBool(arguments.get("listFunctions"), false);
        options.maxCallSites = asInt(arguments.get("maxCallSites"), DEFAULT_MAX_CALL_SITES);
        options.libraries = asNameSet(arguments.get("libraries"));

        return CrossModuleLinker.backlinkImports(program,
            CrossModuleLinker.projectDataFor(program, tool), options, McpUtil.activeMonitor(), this);
    }

    /** See {@link CrossModuleLinker#mergeBlock}. */
    public static String mergeBlock(String existing, String startMarker, String endMarker,
            String block) {
        return CrossModuleLinker.mergeBlock(existing, startMarker, endMarker, block);
    }

    // ---- argument helpers ----

    private static boolean asBool(Object value, boolean fallback) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof String s) {
            return Boolean.parseBoolean(s);
        }
        return fallback;
    }

    private static int asInt(Object value, int fallback) {
        if (value instanceof Number n) {
            return n.intValue();
        }
        if (value instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    @SuppressWarnings("unchecked")
    private static Set<String> asNameSet(Object value) {
        if (!(value instanceof Collection)) {
            return null;
        }
        Set<String> names = new LinkedHashSet<>();
        for (Object o : (Collection<Object>) value) {
            if (o != null) {
                names.add(String.valueOf(o));
            }
        }
        return names.isEmpty() ? null : names;
    }
}
