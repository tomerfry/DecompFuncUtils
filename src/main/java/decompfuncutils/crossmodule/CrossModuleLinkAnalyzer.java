package decompfuncutils.crossmodule;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.ProjectData;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;
import java.util.Map;

/**
 * Runs {@link CrossModuleLinker} as part of auto-analysis: imports are attributed to the project
 * libraries that export them, and the program's call sites are written back into those libraries
 * as clickable links.
 *
 * <p>It is scheduled at {@link AnalysisPriority#LOW_PRIORITY}, after disassembly, function
 * creation and reference analysis have settled, because the back-link half needs the call sites
 * those passes produce. It also supports one-time analysis, so it can be invoked at any point
 * after analysis from <b>Analysis &gt; One Shot &gt; Cross-Module Import Linker</b> — the way to
 * pick up a library that was imported into the project after this program was analyzed.
 *
 * <p>Everything it does is idempotent: links already made are left alone and each back-link
 * block is replaced in place, so re-running costs nothing but time.
 */
public class CrossModuleLinkAnalyzer extends AbstractAnalyzer {

    public static final String NAME = "Cross-Module Import Linker";

    private static final String DESCRIPTION =
        "Links this program's imports to the libraries in the project that export them, and writes " +
        "its call sites back into those libraries as clickable {@program} links with a bookmark per " +
        "exported function. Runs last, once call sites exist. Re-run it after importing more " +
        "libraries with Analysis > One Shot.";

    public static final String OPTION_LINK_IMPORTS = "Link imports to project libraries";
    public static final String OPTION_SET_ADDRESS = "Store target addresses";
    public static final String OPTION_SEARCH_PROJECT = "Search project for unassociated libraries";
    public static final String OPTION_BACKLINKS = "Write back-links into libraries";
    public static final String OPTION_MAX_CALL_SITES = "Back-link call sites per function";
    public static final String OPTION_SAVE_LIBRARIES = "Save modified libraries";

    private boolean linkImports = true;
    private boolean setAddress = true;
    private boolean searchProject = true;
    private boolean writeBacklinks = true;
    private int maxCallSites = CrossModuleLinker.DEFAULT_MAX_CALL_SITES;
    private boolean saveLibraries = true;

    public CrossModuleLinkAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    /** Only programs that name at least one library have anything to link. */
    @Override
    public boolean canAnalyze(Program program) {
        return CrossModuleLinker.hasLinkableLibraries(program);
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_LINK_IMPORTS, linkImports, null,
            "Attribute <EXTERNAL> function symbols to the project library that exports them.");
        options.registerOption(OPTION_SET_ADDRESS, setAddress, null,
            "When linking an import, also store the exporting address in its external location, so " +
            "calls navigate across programs.");
        options.registerOption(OPTION_SEARCH_PROJECT, searchProject, null,
            "For a required library with no associated program, look for a program file of that name " +
            "in the project (exact, then prefix: 'libfoo.so.1' matches 'libfoo.so.1.2.3').");
        options.registerOption(OPTION_BACKLINKS, writeBacklinks, null,
            "Annotate each exported function in the library with a clickable list of this program's " +
            "call sites, and bookmark it under 'imported-by:<program>'. This edits the LIBRARY " +
            "programs, not this one.");
        options.registerOption(OPTION_MAX_CALL_SITES, maxCallSites, null,
            "Links listed per library function before the block says '... and N more'.");
        options.registerOption(OPTION_SAVE_LIBRARIES, saveLibraries, null,
            "Save each library program after writing back-links into it. When off, the edits stay " +
            "in memory for whoever has the library open and are lost otherwise.");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        linkImports = options.getBoolean(OPTION_LINK_IMPORTS, linkImports);
        setAddress = options.getBoolean(OPTION_SET_ADDRESS, setAddress);
        searchProject = options.getBoolean(OPTION_SEARCH_PROJECT, searchProject);
        writeBacklinks = options.getBoolean(OPTION_BACKLINKS, writeBacklinks);
        maxCallSites = Math.max(1, options.getInt(OPTION_MAX_CALL_SITES, maxCallSites));
        saveLibraries = options.getBoolean(OPTION_SAVE_LIBRARIES, saveLibraries);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (!linkImports && !writeBacklinks) {
            return false;
        }
        ProjectData projectData = CrossModuleLinker.projectDataFor(program, null);
        if (projectData == null) {
            // Not an error: a program analyzed outside a project simply has nothing to link to.
            Msg.info(this, NAME + ": no project is open, nothing to link for " + program.getName());
            return false;
        }

        boolean changed = false;
        if (linkImports) {
            monitor.setMessage(NAME + ": linking imports");
            try {
                CrossModuleLinker.ResolveOptions options = new CrossModuleLinker.ResolveOptions();
                options.setAddress = setAddress;
                options.searchProject = searchProject;
                Map<String, Object> report =
                    CrossModuleLinker.resolveExternals(program, projectData, options, monitor, this);
                int resolved = intOf(report.get("resolved"));
                changed |= resolved > 0;
                Msg.info(this, NAME + ": " + program.getName() + " - linked " + resolved +
                    " import(s), " + report.get("unresolvedAfter") + " still unresolved" +
                    libraryStatuses(report));
            }
            catch (CancelledException e) {
                throw e;
            }
            catch (Exception e) {
                log.appendMsg(NAME, "Linking imports failed: " + e.getMessage());
                Msg.error(this, NAME + ": linking imports failed for " + program.getName(), e);
            }
        }

        if (writeBacklinks) {
            monitor.setMessage(NAME + ": writing back-links into libraries");
            try {
                CrossModuleLinker.BacklinkOptions options = new CrossModuleLinker.BacklinkOptions();
                options.maxCallSites = maxCallSites;
                options.save = saveLibraries;
                Map<String, Object> report =
                    CrossModuleLinker.backlinkImports(program, projectData, options, monitor, this);
                Msg.info(this, NAME + ": " + program.getName() + " - " + report.get("callSitesLinked") +
                    " call site(s) linked into " + report.get("functions") + " library function(s)" +
                    libraryStatuses(report));
                reportUnsaved(report, log);
            }
            catch (CancelledException e) {
                throw e;
            }
            catch (IllegalStateException e) {
                // The program has no project path yet (never saved). Nothing is wrong with it;
                // the links simply cannot point anywhere until it has one.
                Msg.info(this, NAME + ": back-links skipped for " + program.getName() + " - " +
                    e.getMessage());
            }
            catch (Exception e) {
                log.appendMsg(NAME, "Writing back-links failed: " + e.getMessage());
                Msg.error(this, NAME + ": writing back-links failed for " + program.getName(), e);
            }
        }
        return changed;
    }

    /** " [libfoo.so.1: searched, libc.so.6: no_associated_program]" for the log line. */
    @SuppressWarnings("unchecked")
    private static String libraryStatuses(Map<String, Object> report) {
        Object libs = report.get("libraries");
        if (!(libs instanceof List<?> list) || list.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(" [");
        for (Object o : list) {
            Map<String, Object> lib = (Map<String, Object>) o;
            if (sb.length() > 2) {
                sb.append(", ");
            }
            sb.append(lib.get("name")).append(": ").append(lib.get("status"));
        }
        return sb.append(']').toString();
    }

    /** A library whose back-links could not be saved is worth the user's attention. */
    @SuppressWarnings("unchecked")
    private static void reportUnsaved(Map<String, Object> report, MessageLog log) {
        Object libs = report.get("libraries");
        if (!(libs instanceof List<?> list)) {
            return;
        }
        for (Object o : list) {
            Map<String, Object> lib = (Map<String, Object>) o;
            Object reason = lib.get("saveError") != null ? lib.get("saveError") : lib.get("saveSkipped");
            if (Boolean.FALSE.equals(lib.get("saved")) && reason != null) {
                log.appendMsg(NAME, "Back-links written into " + lib.get("name") +
                    " were not saved: " + reason);
            }
            else if ("library_is_read_only".equals(lib.get("status"))) {
                log.appendMsg(NAME, "No back-links written into " + lib.get("name") +
                    ": the library file is read-only.");
            }
        }
    }

    private static int intOf(Object value) {
        return value instanceof Number n ? n.intValue() : 0;
    }
}
