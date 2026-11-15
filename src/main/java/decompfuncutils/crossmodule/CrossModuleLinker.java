package decompfuncutils.crossmodule;

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
 * Cross-module linking of imported and exported symbols between the programs of one project.
 * This is the engine behind the {@code ghidra_resolve_externals} and
 * {@code ghidra_backlink_imports} MCP tools and behind {@link CrossModuleLinkAnalyzer}; it has no
 * dependency on either, so all three report the same thing for the same program.
 *
 * <p>Two directions:
 * <ul>
 * <li>{@link #resolveExternals} — importer to library: attribute {@code <EXTERNAL>} function
 * symbols to the project library that exports them, and store the exporting address.</li>
 * <li>{@link #backlinkImports} — library to importer: write the importer's call sites into the
 * library as clickable {@code {@program ...}} annotations plus a bookmark.</li>
 * </ul>
 *
 * <p>Both must run inside an open transaction on the importing program. The back-link direction
 * opens its own transactions on the library programs it edits.
 */
public final class CrossModuleLinker {

    /** Upper bound on project files visited while hunting for a library by name. */
    private static final int MAX_PROJECT_FILES = 20000;

    public static final String BACKLINK_CATEGORY_PREFIX = "imported-by";
    public static final int DEFAULT_MAX_CALL_SITES = 25;

    private CrossModuleLinker() {
    }

    // ---------------------------------------------------------------------------------------
    // Options
    // ---------------------------------------------------------------------------------------

    /** What {@link #resolveExternals} should do; the defaults are the tool's defaults. */
    public static final class ResolveOptions {
        /** Report what would be linked without changing the program. */
        public boolean dryRun = false;
        /** Also store the exporting address in each external location. */
        public boolean setAddress = true;
        /** Look up libraries with no associated program by file name in the project. */
        public boolean searchProject = true;
        /** Include resolved and still-unresolved symbol names in the report. */
        public boolean listSymbols = false;
        /** Restrict the work to these library names; null for every required library. */
        public Set<String> libraries = null;
    }

    /** What {@link #backlinkImports} should do; the defaults are the tool's defaults. */
    public static final class BacklinkOptions {
        /** Report what would be written without changing any program. */
        public boolean dryRun = false;
        /** Remove this importer's blocks and bookmarks instead of writing them. */
        public boolean remove = false;
        /** Write the plate-comment block of clickable call-site links. */
        public boolean comments = true;
        /** Set an Info bookmark at each annotated function. */
        public boolean bookmarks = true;
        /** Also link references where the import's address is taken rather than called. */
        public boolean includeDataRefs = false;
        /** Save each modified library program. */
        public boolean save = true;
        /** Include per-function detail in the report. */
        public boolean listFunctions = false;
        /** Links listed per function before the block says "... and N more". */
        public int maxCallSites = DEFAULT_MAX_CALL_SITES;
        /** Restrict the work to these library names; null for every resolved library. */
        public Set<String> libraries = null;
    }

    // ---------------------------------------------------------------------------------------
    // Project lookup
    // ---------------------------------------------------------------------------------------

    /**
     * The project a program's libraries are looked up in. A freshly imported program is still a
     * proxy with no parent folder (headless, and between import and first save), so this falls
     * back to the tool's project and then the active project before giving up.
     *
     * @param tool may be null
     * @return the project data, or null when no project is open
     */
    public static ProjectData projectDataFor(Program program, PluginTool tool) {
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

    /** Whether the program names any library it could be linked against. */
    public static boolean hasLinkableLibraries(Program program) {
        for (String name : program.getExternalManager().getExternalLibraryNames()) {
            if (!Library.UNKNOWN.equals(name)) {
                return true;
            }
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Importer -> library
    // ---------------------------------------------------------------------------------------

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
     *
     * @param consumer the object that holds the library programs open while they are read
     * @return the report, in the shape the MCP tool returns
     */
    public static Map<String, Object> resolveExternals(Program program, ProjectData projectData,
            ResolveOptions options, TaskMonitor monitor, Object consumer) throws Exception {
        if (projectData == null) {
            throw new IllegalStateException(
                "No project is open, so the required libraries cannot be looked up. " +
                "Open the program in a Ghidra project and import its dependencies first.");
        }
        boolean dryRun = options.dryRun;
        boolean setAddress = options.setAddress;
        Set<String> only = options.libraries;

        DomainFile programFile = program.getDomainFile();
        DomainFolder programFolder = programFile != null ? programFile.getParent() : null;
        if (programFolder == null) {
            programFolder = projectData.getRootFolder();
        }

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
            if (libPath == null && options.searchProject) {
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
                DomainObject obj = libFile.getDomainObject(consumer, false, false, monitor);
                if (!(obj instanceof Program)) {
                    obj.release(consumer);
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
                    Address exportAddr = exportedAddress(libProgram, importedName(extLoc));
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
                libProgram.release(consumer);
            }

            report.put("status", "searched");
            report.put("resolved", matched.size());
            if (setAddress && !dryRun) {
                report.put("withTargetAddress", addressed);
            }
            if (options.listSymbols) {
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
        if (options.listSymbols) {
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

    // ---------------------------------------------------------------------------------------
    // Library -> importer
    // ---------------------------------------------------------------------------------------

    /**
     * Writes reverse cross-module links into the shared objects a program imports from: at each
     * exported function, a managed plate-comment block naming the importing program and listing
     * its call sites as clickable {@code {@program ...}} annotations, plus a bookmark so the whole
     * set is one filterable list.
     *
     * <p>Ghidra cannot do this with references. A {@link Reference} is a from-address and a
     * to-address in one program's address factory, and the XRefs / "Incoming References" field is
     * built from that per-program table — there is no cross-program reference storage, so no API
     * can place an {@code afpd} call site in {@code libatalk.so.18}'s incoming references. Comment
     * annotations are the one mechanism Ghidra does carry across programs:
     * {@code ProgramAnnotatedStringHandler} opens another project program and navigates to a
     * symbol or, failing that, a raw address. Any word after the target becomes the rendered
     * label, so a link reads {@code afp_opensession+0x24} while pointing at an address.
     *
     * <p>Each importing program owns a delimited block, so re-runs replace only their own block
     * and several importers of the same library coexist. Idempotent; {@code remove} takes a block
     * out again.
     *
     * @param consumer the object that holds the library programs open while they are edited
     * @return the report, in the shape the MCP tool returns
     */
    public static Map<String, Object> backlinkImports(Program program, ProjectData projectData,
            BacklinkOptions options, TaskMonitor monitor, Object consumer) throws Exception {
        boolean dryRun = options.dryRun;
        boolean remove = options.remove;
        Set<String> only = options.libraries;

        if (!options.comments && !options.bookmarks) {
            throw new IllegalArgumentException("Nothing to do: both 'comments' and 'bookmarks' are false.");
        }
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
        String startMarker = "[" + BACKLINK_CATEGORY_PREFIX + ": " + importerName + "]";
        String endMarker = "[/" + BACKLINK_CATEGORY_PREFIX + ": " + importerName + "]";
        String category = backlinkCategory(importerName);

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
                DomainObject obj = libFile.getDomainObject(consumer, false, false, monitor);
                if (!(obj instanceof Program)) {
                    obj.release(consumer);
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
            List<Map<String, Object>> functionDetail = options.listFunctions ? new ArrayList<>() : null;
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
                        collectCallSites(program, refMgr, importSymbol, options.includeDataRefs);
                    if (callSites.isEmpty() && !remove) {
                        noCallSites++;
                        continue;
                    }

                    if (functionDetail != null) {
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

                    if (options.comments) {
                        String block = remove ? null
                            : buildBlock(startMarker, endMarker, importerName, importerPath,
                                program, callSites, options.maxCallSites);
                        String existing = libListing.getComment(CommentType.PLATE, commentAddr);
                        String merged = mergeBlock(existing, startMarker, endMarker, block);
                        libListing.setComment(commentAddr, CommentType.PLATE,
                            merged.isEmpty() ? null : merged);
                    }
                    if (options.bookmarks) {
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
                    if (committed && !dryRun && options.save && libFile.canSave()) {
                        libFile.save(monitor);
                        report.put("saved", true);
                    } else if (committed && !dryRun && options.save) {
                        report.put("saved", false);
                        report.put("saveSkipped", "file cannot be saved (read-only or not checked out)");
                    }
                } catch (Exception e) {
                    report.put("saved", false);
                    report.put("saveError", String.valueOf(e.getMessage()));
                } finally {
                    libProgram.release(consumer);
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
            if (functionDetail != null) {
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

    /** The bookmark category an importing program's back-links are filed under. */
    public static String backlinkCategory(String importerName) {
        return BACKLINK_CATEGORY_PREFIX + ":" + importerName;
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

    // ---------------------------------------------------------------------------------------
    // Shared lookups
    // ---------------------------------------------------------------------------------------

    public static String importedName(ExternalLocation extLoc) {
        return extLoc.getOriginalImportedName() != null
            ? extLoc.getOriginalImportedName()
            : extLoc.getLabel();
    }

    /**
     * The address of an exported (external entry point) label or function of the given name,
     * or null when the program does not publish it.
     */
    public static Address exportedAddress(Program program, String name) {
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
     * Re-creates an address of one program in another program's address factory, the same way
     * Ghidra's "Edit External Location" dialog does: by its text form, then by raw offset.
     */
    private static Address translate(Program target, Address address) {
        try {
            Address a = target.getAddressFactory().getAddress(address.toString());
            if (a != null) {
                return a;
            }
        } catch (Exception ignored) {
            // fall through to the offset form below
        }
        try {
            return target.getAddressFactory().getDefaultAddressSpace().getAddress(address.getOffset());
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Stores the exporting address in the external location. The address belongs to the library's
     * image, so it is re-created in this program's address factory.
     *
     * @return true when the address was stored
     */
    private static boolean applyTargetAddress(Program program, ExternalManager em, Symbol symbol,
            Address exportAddr) {
        ExternalLocation extLoc = em.getExternalLocation(symbol);
        if (extLoc == null) {
            return false;
        }
        Address target = translate(program, exportAddr);
        if (target == null) {
            return false;
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
    public static DomainFile findLibraryFile(ProjectData projectData, DomainFolder preferred,
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

    /**
     * The address inside the library that an import refers to: the address stored in the external
     * location when there is one (translated into the library's factory), else the library's own
     * exported symbol of that name — Ghidra's resolver attributes a namespace without ever storing
     * an address, so the name lookup is the common path.
     */
    public static Address resolveTarget(Program libProgram, ExternalLocation extLoc) {
        Address stored = extLoc.getAddress();
        if (stored != null) {
            Address translated = translate(libProgram, stored);
            if (translated != null && libProgram.getMemory().contains(translated)) {
                return translated;
            }
        }
        return exportedAddress(libProgram, importedName(extLoc));
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
}
