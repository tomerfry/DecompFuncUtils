package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Links dangling {@code <EXTERNAL>} function symbols to the project library that actually
 * exports them, and (optionally) points each external location at the defining address so
 * the decompiler can navigate across programs.
 *
 * <p>This exists because Ghidra's own {@code ExternalSymbolResolver} (12.2) tests the wrong
 * program. In {@code resolveSymbolsToLibrary} it calls {@code isExportedSymbol(program, name)}
 * where {@code program} is the binary being repaired rather than the library — and
 * {@code ExtLibInfo} never carries the library's {@code Program} at all, since
 * {@code getLibsToSearch} opens it only to record whether it opens. The question asked is
 * therefore "does afpd export dsi_getsession?", which for an {@code UND} import is always no.
 * The result is {@code 0 external symbols resolved} on every ELF whose imports are not also
 * its own exports, regardless of import options or search paths.
 */
public class ResolveExternalsTool implements McpTool {

    /** Upper bound on project files visited while hunting for a library by name. */
    private static final int MAX_PROJECT_FILES = 20000;

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
            "Run it after importing the dependencies; it is idempotent and safe to re-run as more are added.";
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
        boolean dryRun = asBool(arguments.get("dryRun"), false);
        boolean setAddress = asBool(arguments.get("setAddress"), true);
        boolean searchProject = asBool(arguments.get("searchProject"), true);
        boolean listSymbols = asBool(arguments.get("listSymbols"), false);
        Set<String> only = asNameSet(arguments.get("libraries"));

        // A freshly imported program is still a proxy with no parent folder (headless, and
        // between import and first save), so fall back to the project itself before giving up.
        DomainFile programFile = program.getDomainFile();
        DomainFolder programFolder = programFile != null ? programFile.getParent() : null;
        ProjectData projectData = programFolder != null ? programFolder.getProjectData() : null;
        if (projectData == null && tool != null && tool.getProject() != null) {
            projectData = tool.getProject().getProjectData();
        }
        if (projectData == null) {
            Project active = AppInfo.getActiveProject();
            if (active != null) {
                projectData = active.getProjectData();
            }
        }
        if (projectData == null) {
            throw new IllegalStateException(
                "No project is open, so the required libraries cannot be looked up. " +
                "Open the program in a Ghidra project and import its dependencies first.");
        }
        if (programFolder == null) {
            programFolder = projectData.getRootFolder();
        }
        TaskMonitor monitor = McpUtil.activeMonitor();

        ExternalManager em = program.getExternalManager();
        SymbolTable st = program.getSymbolTable();

        // The work set: external functions still parked in <EXTERNAL>, exactly as
        // Ghidra's resolver defines them (DEFAULT-source symbols are thunk artifacts).
        List<Symbol> pending = new ArrayList<>();
        Library unknown = em.getExternalLibrary(Library.UNKNOWN);
        if (unknown != null) {
            for (Symbol s : st.getSymbols(unknown)) {
                if (s.getSymbolType() == SymbolType.FUNCTION && s.getSource() != SourceType.DEFAULT) {
                    pending.add(s);
                }
            }
        }
        int unresolvedBefore = pending.size();

        List<Map<String, Object>> libReports = new ArrayList<>();
        int resolved = 0;
        int withAddress = 0;

        for (Library lib : em.getLibraries()) {
            monitor.checkCancelled();
            String libName = lib.getName();
            if (Library.UNKNOWN.equals(libName)) {
                continue;
            }
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("name", libName);

            if (only != null && !only.contains(libName)) {
                report.put("status", "skipped_not_requested");
                libReports.add(report);
                continue;
            }
            if (pending.isEmpty()) {
                report.put("status", "skipped_nothing_left");
                libReports.add(report);
                continue;
            }

            String libPath = lib.getAssociatedProgramPath();
            if (libPath == null && searchProject) {
                DomainFile found = findLibraryFile(projectData, programFolder, libName, monitor);
                if (found != null) {
                    libPath = found.getPathname();
                    report.put("associatedBy",
                        found.getName().equals(libName) ? "project_search_exact" : "project_search_prefix");
                    report.put("matchedFile", found.getName());
                    if (!dryRun) {
                        em.setExternalPath(libName, libPath, false);
                    }
                }
            }
            report.put("path", libPath);

            if (libPath == null) {
                report.put("status", "no_associated_program");
                libReports.add(report);
                continue;
            }

            DomainFile libFile = projectData.getFile(libPath);
            if (libFile == null) {
                report.put("status", "dangling_path");
                libReports.add(report);
                continue;
            }

            Program libProgram;
            try {
                Object obj = libFile.getDomainObject(this, false, false, monitor);
                if (!(obj instanceof Program)) {
                    ((ghidra.framework.model.DomainObject) obj).release(this);
                    report.put("status", "not_a_program");
                    libReports.add(report);
                    continue;
                }
                libProgram = (Program) obj;
            } catch (Exception e) {
                report.put("status", "open_failed");
                report.put("error", String.valueOf(e.getMessage()));
                libReports.add(report);
                continue;
            }

            List<String> matched = new ArrayList<>();
            int addressed = 0;
            try {
                for (Iterator<Symbol> it = pending.iterator(); it.hasNext();) {
                    monitor.checkCancelled();
                    Symbol s = it.next();
                    ExternalLocation extLoc = em.getExternalLocation(s);
                    if (extLoc == null) {
                        it.remove();
                        continue;
                    }
                    String lookupName = extLoc.getOriginalImportedName() != null
                        ? extLoc.getOriginalImportedName()
                        : extLoc.getLabel();

                    Address exportAddr = exportedAddress(libProgram, lookupName);
                    if (exportAddr == null) {
                        continue;
                    }

                    matched.add(s.getName());
                    it.remove();
                    resolved++;

                    if (dryRun) {
                        continue;
                    }
                    extLoc.setLibrary(lib);
                    if (setAddress && applyTargetAddress(program, em, s, exportAddr)) {
                        addressed++;
                        withAddress++;
                    }
                }
            } finally {
                libProgram.release(this);
            }

            report.put("status", "searched");
            report.put("resolved", matched.size());
            if (setAddress && !dryRun) {
                report.put("withTargetAddress", addressed);
            }
            if (listSymbols) {
                report.put("symbols", matched);
            }
            libReports.add(report);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("dryRun", dryRun);
        result.put("unresolvedBefore", unresolvedBefore);
        result.put("resolved", resolved);
        if (setAddress && !dryRun) {
            result.put("withTargetAddress", withAddress);
        }
        result.put("unresolvedAfter", pending.size());
        result.put("libraries", libReports);
        if (listSymbols) {
            List<String> remaining = new ArrayList<>();
            for (Symbol s : pending) {
                remaining.add(s.getName());
            }
            Collections.sort(remaining);
            result.put("unresolvedSymbols", remaining);
        }
        result.put("status", dryRun ? "dry_run"
            : (resolved > 0 ? "resolved" : "nothing_resolved"));
        if (resolved == 0 && unresolvedBefore > 0) {
            result.put("hint", "No library in the project exports these names. Import the remaining " +
                "dependencies as programs (ghidra_open_program) and re-run.");
        }
        return result;
    }

    /**
     * The address of an exported (external entry point) label or function of the given name,
     * or null when the program does not publish it.
     */
    private static Address exportedAddress(Program program, String name) {
        if (name == null) {
            return null;
        }
        for (Symbol s : program.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
            if (s.isExternalEntryPoint()) {
                return s.getAddress();
            }
        }
        return null;
    }

    /**
     * Stores the exporting address in the external location. The address belongs to the library's
     * image, so it is re-created in this program's address factory the same way Ghidra's
     * "Edit External Location" dialog does.
     *
     * @return true when the address was stored
     */
    private static boolean applyTargetAddress(Program program, ExternalManager em, Symbol symbol,
            Address exportAddr) {
        ExternalLocation extLoc = em.getExternalLocation(symbol);
        if (extLoc == null) {
            return false;
        }
        Address target = null;
        try {
            target = program.getAddressFactory().getAddress(exportAddr.toString());
        } catch (Exception ignored) {
            // fall through to the offset form below
        }
        if (target == null) {
            try {
                target = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(exportAddr.getOffset());
            } catch (Exception ignored) {
                return false;
            }
        }
        try {
            extLoc.setLocation(extLoc.getLabel(), target, SourceType.IMPORTED);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Finds a program file named after a required library. The program's own folder is searched
     * first, then the whole project; an exact name wins over a prefix match, which is what links
     * a DT_NEEDED "libfoo.so.1" to a file imported as "libfoo.so.1.2.3".
     */
    private static DomainFile findLibraryFile(ProjectData projectData, DomainFolder preferred,
            String libName, TaskMonitor monitor) throws Exception {
        DomainFile prefixHit = null;

        for (DomainFile df : preferred.getFiles()) {
            monitor.checkCancelled();
            if (!isProgram(df)) {
                continue;
            }
            if (df.getName().equals(libName)) {
                return df;
            }
            if (prefixHit == null && df.getName().startsWith(libName)) {
                prefixHit = df;
            }
        }

        Deque<DomainFolder> queue = new ArrayDeque<>();
        queue.add(projectData.getRootFolder());
        int visited = 0;
        while (!queue.isEmpty() && visited < MAX_PROJECT_FILES) {
            monitor.checkCancelled();
            DomainFolder folder = queue.removeFirst();
            for (DomainFile df : folder.getFiles()) {
                if (++visited >= MAX_PROJECT_FILES) {
                    break;
                }
                if (!isProgram(df)) {
                    continue;
                }
                if (df.getName().equals(libName)) {
                    return df;
                }
                if (prefixHit == null && df.getName().startsWith(libName)) {
                    prefixHit = df;
                }
            }
            Collections.addAll(queue, folder.getFolders());
        }
        return prefixHit;
    }

    private static boolean isProgram(DomainFile df) {
        return "Program".equals(df.getContentType());
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
