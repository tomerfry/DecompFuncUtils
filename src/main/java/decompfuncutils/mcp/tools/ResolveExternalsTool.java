package decompfuncutils.mcp.tools;

import decompfuncutils.crossmodule.CrossModuleLinker;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * MCP front end for {@link CrossModuleLinker#resolveExternals}: links dangling
 * {@code <EXTERNAL>} function symbols to the project library that actually exports them. The same
 * engine runs as the "Cross-Module Import Linker" analyzer.
 */
public class ResolveExternalsTool implements McpTool {

    @Override public String name() { return "ghidra_resolve_externals"; }

    @Override
    public String description() {
        return "Link unresolved <EXTERNAL> function symbols to the project library that exports them, " +
            "and point each external location at the defining address so calls navigate across programs. " +
            "Works around a bug in Ghidra 12.2's own External Symbol Resolver, which tests whether the " +
            "program being repaired exports the symbol instead of the library, and so resolves nothing " +
            "for an ELF whose imports are not also its exports. Libraries already associated via import " +
            "are used as-is; by default any library with no associated program is looked up in the project " +
            "by file name (exact, then prefix, which catches DT_NEEDED 'libfoo.so.1' vs file 'libfoo.so.1.2.3'). " +
            "Run it after importing the dependencies; it is idempotent and safe to re-run as more are added. " +
            "The same linking also runs as the 'Cross-Module Import Linker' analyzer during auto-analysis " +
            "and from Analysis > One Shot.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("dryRun", Map.of("type", "boolean",
            "description", "Report what would be linked without changing the program (default false)"));
        props.put("setAddress", Map.of("type", "boolean",
            "description", "Also store the exporting address in each external location, enabling cross-program " +
                "navigation. Ghidra's own resolver does not do this. Default true."));
        props.put("searchProject", Map.of("type", "boolean",
            "description", "For libraries with no associated program, search the project for a program file " +
                "of that name and associate it (default true)"));
        props.put("libraries", Map.of("type", "array",
            "items", Map.of("type", "string"),
            "description", "Restrict the work to these library names, as they appear in DT_NEEDED " +
                "(e.g. 'libatalk.so.18'). Omit to use every library the program requires."));
        props.put("listSymbols", Map.of("type", "boolean",
            "description", "Include the resolved symbol names per library, and the names still unresolved, " +
                "in the result (default false)"));
        schema.put("properties", props);
        return schema;
    }

    @Override public boolean isMutating() { return true; }

    /** Opening library programs can be slow; nothing here touches Swing. */
    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        CrossModuleLinker.ResolveOptions options = new CrossModuleLinker.ResolveOptions();
        options.dryRun = asBool(arguments.get("dryRun"), false);
        options.setAddress = asBool(arguments.get("setAddress"), true);
        options.searchProject = asBool(arguments.get("searchProject"), true);
        options.listSymbols = asBool(arguments.get("listSymbols"), false);
        options.libraries = asNameSet(arguments.get("libraries"));

        return CrossModuleLinker.resolveExternals(program,
            CrossModuleLinker.projectDataFor(program, tool), options, McpUtil.activeMonitor(), this);
    }

    private static boolean asBool(Object value, boolean fallback) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof String s) {
            return Boolean.parseBoolean(s);
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
