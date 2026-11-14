package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Writes reverse cross-module links into the shared objects a program imports from: at each
 * exported function, a managed plate-comment block naming the importing program and listing its
 * call sites as clickable {@code {@program ...}} annotations, plus a bookmark so the whole set is
 * one filterable list.
 *
 * <p>Ghidra cannot do this with references. A {@link Reference} is a from-address and a
 * to-address in one program's address factory, and the XRefs / "Incoming References" field is
 * built from that per-program table — there is no cross-program reference storage, so no API can
 * place an {@code afpd} call site in {@code libatalk.so.18}'s incoming references. Comment
 * annotations are the one mechanism Ghidra does carry across programs:
 * {@code ProgramAnnotatedStringHandler} opens another project program and navigates to a symbol
 * or, failing that, a raw address. Any word after the target becomes the rendered label, so a
 * link reads {@code afp_opensession+0x24} while pointing at an address.
 *
 * <p>Each importing program owns a delimited block, so re-runs replace only their own block and
 * several importers of the same library coexist. Idempotent; {@code remove} takes a block out
 * again.
 */
public class BacklinkImportsTool implements McpTool {

    private static final String CATEGORY_PREFIX = "imported-by";
    private static final int DEFAULT_MAX_CALL_SITES = 25;

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
        boolean dryRun = asBool(arguments.get("dryRun"), false);
        boolean remove = asBool(arguments.get("remove"), false);
        boolean comments = asBool(arguments.get("comments"), true);
        boolean bookmarks = asBool(arguments.get("bookmarks"), true);
        boolean includeDataRefs = asBool(arguments.get("includeDataRefs"), false);
        boolean save = asBool(arguments.get("save"), true);
        boolean listFunctions = asBool(arguments.get("listFunctions"), false);
        int maxCallSites = asInt(arguments.get("maxCallSites"), DEFAULT_MAX_CALL_SITES);
        Set<String> only = asNameSet(arguments.get("libraries"));

        if (!comments && !bookmarks) {
            throw new IllegalArgumentException("Nothing to do: both 'comments' and 'bookmarks' are false.");
        }

        ProjectData projectData = resolveProjectData(program, tool);
        if (projectData == null) {
            throw new IllegalStateException(
                "No project is open, so the libraries cannot be opened for writing.");
        }

        DomainFile programFile = program.getDomainFile();
        String importerPath = programFile != null ? programFile.getPathname() : null;
        if (importerPath == null || importerPath.isEmpty()) {
            throw new IllegalStateException(
                "This program has no project path yet, so a link back to it cannot be written. " +
                "Save it first (ghidra_save_program).");
        }
        String importerName = program.getName();
        String startMarker = "[" + CATEGORY_PREFIX + ": " + importerName + "]";
        String endMarker = "[/" + CATEGORY_PREFIX + ": " + importerName + "]";
        String category = CATEGORY_PREFIX + ":" + importerName;

        TaskMonitor monitor = McpUtil.activeMonitor();
        ExternalManager em = program.getExternalManager();
        SymbolTable st = program.getSymbolTable();
        ReferenceManager refMgr = program.getReferenceManager();

        List<Map<String, Object>> libReports = new ArrayList<>();
        int totalFunctions = 0;
        int totalCallSites = 0;

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

            // Only functions this program has already attributed to this library.
            List<Symbol> imports = new ArrayList<>();
            for (Symbol s : st.getSymbols(lib)) {
                if (s.getSymbolType() == SymbolType.FUNCTION && s.getSource() != SourceType.DEFAULT) {
                    imports.add(s);
                }
            }
            report.put("imports", imports.size());
            if (imports.isEmpty()) {
                report.put("status", "no_imports_attributed");
                report.put("hint", "Run ghidra_resolve_externals first.");
                libReports.add(report);
                continue;
            }

            String libPath = lib.getAssociatedProgramPath();
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
            if (!dryRun && libFile.isReadOnly()) {
                report.put("status", "library_is_read_only");
                libReports.add(report);
                continue;
            }

            Program libProgram;
            try {
                DomainObject obj = libFile.getDomainObject(this, false, false, monitor);
                if (!(obj instanceof Program)) {
                    obj.release(this);
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

            int annotated = 0;
            int linked = 0;
            int noTarget = 0;
            int noCallSites = 0;
            List<Map<String, Object>> functionDetail = listFunctions ? new ArrayList<>() : null;
            int txId = dryRun ? -1
                : libProgram.startTransaction("Back-links from " + importerName);
            boolean committed = false;
            try {
                Listing libListing = libProgram.getListing();
                BookmarkManager bookmarkMgr = libProgram.getBookmarkManager();

                for (Symbol importSymbol : imports) {
                    monitor.checkCancelled();
                    ExternalLocation extLoc = em.getExternalLocation(importSymbol);
                    if (extLoc == null) {
                        continue;
                    }
                    Address targetAddr = resolveTarget(libProgram, extLoc);
                    if (targetAddr == null) {
                        noTarget++;
                        continue;
                    }
                    Function libFunction = libProgram.getFunctionManager().getFunctionAt(targetAddr);
                    Address commentAddr =
                        libFunction != null ? libFunction.getEntryPoint() : targetAddr;

                    List<Address> callSites =
                        collectCallSites(program, refMgr, importSymbol, includeDataRefs);
                    if (callSites.isEmpty() && !remove) {
                        noCallSites++;
                        continue;
                    }

                    if (listFunctions) {
                        Map<String, Object> detail = new LinkedHashMap<>();
                        detail.put("symbol", importSymbol.getName());
                        detail.put("libraryAddress", commentAddr.toString());
                        detail.put("callSites", callSites.size());
                        functionDetail.add(detail);
                    }

                    annotated++;
                    linked += callSites.size();
                    if (dryRun) {
                        continue;
                    }

                    if (comments) {
                        String block = remove ? null
                            : buildBlock(startMarker, endMarker, importerName, importerPath,
                                program, callSites, maxCallSites);
                        String existing = libListing.getComment(CommentType.PLATE, commentAddr);
                        String merged = mergeBlock(existing, startMarker, endMarker, block);
                        libListing.setComment(commentAddr, CommentType.PLATE,
                            merged.isEmpty() ? null : merged);
                    }
                    if (bookmarks) {
                        Bookmark existing =
                            bookmarkMgr.getBookmark(commentAddr, BookmarkType.INFO, category);
                        if (remove) {
                            if (existing != null) {
                                bookmarkMgr.removeBookmark(existing);
                            }
                        } else {
                            bookmarkMgr.setBookmark(commentAddr, BookmarkType.INFO, category,
                                importerName + ": " + callSites.size() + " call site"
                                    + (callSites.size() == 1 ? "" : "s"));
                        }
                    }
                }
                committed = true;
            } finally {
                if (txId != -1) {
                    libProgram.endTransaction(txId, committed);
                }
                try {
                    if (committed && !dryRun && save && libFile.canSave()) {
                        libFile.save(monitor);
                        report.put("saved", true);
                    } else if (committed && !dryRun && save) {
                        report.put("saved", false);
                        report.put("saveSkipped", "file cannot be saved (read-only or not checked out)");
                    }
                } catch (Exception e) {
                    report.put("saved", false);
                    report.put("saveError", String.valueOf(e.getMessage()));
                } finally {
                    libProgram.release(this);
                }
            }

            totalFunctions += annotated;
            totalCallSites += linked;
            report.put("status", dryRun ? "dry_run" : (remove ? "removed" : "written"));
            report.put("functions", annotated);
            report.put("callSitesLinked", linked);
            if (noTarget > 0) {
                report.put("noTargetInLibrary", noTarget);
            }
            if (noCallSites > 0) {
                report.put("noCallSitesInImporter", noCallSites);
            }
            if (listFunctions) {
                report.put("detail", functionDetail);
            }
            libReports.add(report);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", importerName);
        result.put("programPath", importerPath);
        result.put("dryRun", dryRun);
        result.put("remove", remove);
        result.put("functions", totalFunctions);
        result.put("callSitesLinked", totalCallSites);
        result.put("bookmarkCategory", category);
        result.put("libraries", libReports);
        result.put("status", dryRun ? "dry_run"
            : (totalFunctions > 0 ? (remove ? "removed" : "written") : "nothing_written"));
        if (totalFunctions == 0 && !dryRun) {
            result.put("hint", "No import is attributed to a library with a reachable target. " +
                "Run ghidra_resolve_externals first, and import the dependencies as programs.");
        }
        return result;
    }

    // ---- target and call-site resolution ----

    /**
     * The address inside the library that an import refers to: the address stored in the external
     * location when there is one (translated into the library's factory), else the library's own
     * exported symbol of that name — Ghidra's resolver attributes a namespace without ever storing
     * an address, so the name lookup is the common path.
     */
    private static Address resolveTarget(Program libProgram, ExternalLocation extLoc) {
        Address stored = extLoc.getAddress();
        if (stored != null) {
            Address translated = translate(libProgram, stored);
            if (translated != null && libProgram.getMemory().contains(translated)) {
                return translated;
            }
        }
        String name = extLoc.getOriginalImportedName() != null
            ? extLoc.getOriginalImportedName() : extLoc.getLabel();
        if (name == null) {
            return null;
        }
        for (Symbol s : libProgram.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
            if (s.isExternalEntryPoint()) {
                return s.getAddress();
            }
        }
        return null;
    }

    private static Address translate(Program target, Address address) {
        try {
            Address a = target.getAddressFactory().getAddress(address.toString());
            if (a != null) {
                return a;
            }
        } catch (Exception ignored) {
            // fall through
        }
        try {
            return target.getAddressFactory().getDefaultAddressSpace().getAddress(address.getOffset());
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Where the importing program actually reaches an import. The call does not reference the
     * external symbol directly: it calls a PLT thunk, which thunks a stub in the synthetic
     * EXTERNAL block, which thunks the external location — so every thunk entry point in that
     * chain has to be asked for its references too.
     */
    private static List<Address> collectCallSites(Program program, ReferenceManager refMgr,
            Symbol importSymbol, boolean includeDataRefs) {
        Set<Address> entryPoints = new LinkedHashSet<>();
        entryPoints.add(importSymbol.getAddress());
        if (importSymbol.getObject() instanceof Function extFunction) {
            Address[] thunks = extFunction.getFunctionThunkAddresses(true);
            if (thunks != null) {
                Collections.addAll(entryPoints, thunks);
            }
        }

        Set<Address> fromAddresses = new TreeSet<>();
        for (Address entryPoint : entryPoints) {
            for (Reference ref : refMgr.getReferencesTo(entryPoint)) {
                RefType type = ref.getReferenceType();
                if (!type.isCall() && !includeDataRefs) {
                    continue;
                }
                Address from = ref.getFromAddress();
                // Skip the thunk-to-thunk hops themselves; they are not call sites.
                if (from == null || entryPoints.contains(from) || !from.isMemoryAddress()) {
                    continue;
                }
                Function containing = program.getFunctionManager().getFunctionContaining(from);
                if (containing != null && entryPoints.contains(containing.getEntryPoint())) {
                    continue;
                }
                fromAddresses.add(from);
            }
        }
        return new ArrayList<>(fromAddresses);
    }

    // ---- comment block text ----

    private static String buildBlock(String startMarker, String endMarker, String importerName,
            String importerPath, Program program, List<Address> callSites, int maxCallSites) {
        StringBuilder sb = new StringBuilder();
        sb.append(startMarker).append('\n');
        sb.append(callSites.size()).append(" call site")
            .append(callSites.size() == 1 ? "" : "s").append(" in ").append(importerName)
            .append(" (click to navigate):").append('\n');
        int shown = Math.min(callSites.size(), Math.max(1, maxCallSites));
        for (int i = 0; i < shown; i++) {
            Address from = callSites.get(i);
            sb.append("  {@program ").append(importerPath).append('@').append(from)
                .append(' ').append(label(program, from)).append("}").append('\n');
        }
        if (callSites.size() > shown) {
            sb.append("  ... and ").append(callSites.size() - shown).append(" more").append('\n');
        }
        sb.append(endMarker);
        return sb.toString();
    }

    /**
     * Short rendered label for a link. Any word after the target in a {@code {@program ...}}
     * annotation becomes the display text, so this is what the reader sees instead of a path.
     */
    private static String label(Program program, Address from) {
        Function containing = program.getFunctionManager().getFunctionContaining(from);
        if (containing == null) {
            return from.toString();
        }
        long delta = from.subtract(containing.getEntryPoint());
        String name = containing.getName().replace('{', '_').replace('}', '_');
        return delta == 0 ? name : name + "+0x" + Long.toHexString(delta);
    }

    /**
     * Replaces this importer's block inside an existing comment, leaving any other text — and any
     * other importer's block — untouched. A null block removes it.
     */
    public static String mergeBlock(String existing, String startMarker, String endMarker,
            String block) {
        if (existing == null || existing.isEmpty()) {
            return block == null ? "" : block;
        }
        int start = existing.indexOf(startMarker);
        if (start < 0) {
            return block == null ? existing : existing + "\n" + block;
        }
        int end = existing.indexOf(endMarker, start);
        end = end < 0 ? existing.length() : end + endMarker.length();
        String before = existing.substring(0, start);
        String after = existing.substring(end);
        String merged = block == null ? before + after : before + block + after;
        // Collapse the blank lines left behind by a removal.
        return merged.replaceAll("\n{3,}", "\n\n").strip();
    }

    // ---- argument helpers ----

    private static ProjectData resolveProjectData(Program program, PluginTool tool) {
        DomainFile file = program.getDomainFile();
        DomainFolder folder = file != null ? file.getParent() : null;
        if (folder != null) {
            return folder.getProjectData();
        }
        if (tool != null && tool.getProject() != null) {
            return tool.getProject().getProjectData();
        }
        Project active = AppInfo.getActiveProject();
        return active != null ? active.getProjectData() : null;
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
