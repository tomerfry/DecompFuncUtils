// Headless regression test for CrossModuleLinkAnalyzer ("Cross-Module Import Linker").
//
// Driven by tests/run_resolve_externals_test.ps1 -Script CrossModuleAnalyzerHeadlessTest.java
// -Analyze, over the tests/extlink pair. Auto-analysis has already run by the time this
// post-script fires, so the first half checks what the analyzer left behind WITHOUT calling any
// tool: the library must already carry this program's back-links. The second half drives the
// "invoke after analysis" path the way Analysis > One Shot does, and the analysis options.
//@category Test
import decompfuncutils.crossmodule.CrossModuleLinkAnalyzer;
import decompfuncutils.crossmodule.CrossModuleLinker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class CrossModuleAnalyzerHeadlessTest extends GhidraScript {

    private static final String MAIN = "testmain";
    private static final String LIB = "libtestdep.so.1";
    private static final String NAME = CrossModuleLinkAnalyzer.NAME;
    private static final String START = "[imported-by: testmain]";
    private static final String CATEGORY = "imported-by:testmain";

    private int failures = 0;

    private void check(String label, boolean ok, String detail) {
        println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (detail == null || detail.isEmpty() ? "" : "  (" + detail + ")"));
        if (!ok) {
            failures++;
        }
    }

    @Override
    public void run() throws Exception {
        if (!MAIN.equals(currentProgram.getName())) {
            println("CrossModuleAnalyzerHeadlessTest: skipping " + currentProgram.getName());
            return;
        }

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Analyzer analyzer = mgr.getAnalyzer(NAME);

        // --- registration ---
        check("analyzer is discovered by Ghidra", analyzer != null, null);
        if (analyzer == null) {
            println("HEADLESS_TEST_SUMMARY failures=" + failures);
            println("HEADLESS_TEST_RESULT FAIL");
            return;
        }
        check("it is our class", analyzer instanceof CrossModuleLinkAnalyzer,
            analyzer.getClass().getName());
        check("supports one-shot (Analysis > One Shot)", analyzer.supportsOneTimeAnalysis(), null);
        check("enabled by default", analyzer.getDefaultEnablement(currentProgram), null);
        check("can analyze a program with libraries", analyzer.canAnalyze(currentProgram), null);
        check("runs last", analyzer.getPriority().priority() >= AnalysisPriority.LOW_PRIORITY.priority(),
            "priority=" + analyzer.getPriority().priority());

        // --- analysis options ---
        Options analysis = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        check("listed in the analysis options", analysis.contains(NAME), null);
        check("switched on in the analysis options", analysis.getBoolean(NAME, false), null);
        List<String> missing = new ArrayList<>();
        for (String option : List.of(CrossModuleLinkAnalyzer.OPTION_LINK_IMPORTS,
                CrossModuleLinkAnalyzer.OPTION_SET_ADDRESS, CrossModuleLinkAnalyzer.OPTION_SEARCH_PROJECT,
                CrossModuleLinkAnalyzer.OPTION_BACKLINKS, CrossModuleLinkAnalyzer.OPTION_MAX_CALL_SITES,
                CrossModuleLinkAnalyzer.OPTION_SAVE_LIBRARIES)) {
            if (!analysis.contains(NAME + "." + option)) {
                missing.add(option);
            }
        }
        check("its options are registered", missing.isEmpty(), "missing=" + missing);

        // --- what auto-analysis left behind, with no tool call from this script ---
        String afterAnalysis = plateCommentAt("dep_exported_func");
        check("auto-analysis wrote the back-link block",
            afterAnalysis != null && afterAnalysis.contains(START), String.valueOf(afterAnalysis));
        check("the block links back to this program",
            afterAnalysis != null && afterAnalysis.contains("{@program /" + MAIN + "@"),
            String.valueOf(afterAnalysis));
        check("auto-analysis set the bookmark", bookmarkAt("dep_exported_func") != null, null);
        check("the import is attributed to the library",
            LIB.equals(libraryOf("dep_exported_func")), "library=" + libraryOf("dep_exported_func"));

        // --- one-shot: put the program back to "library not linked yet", then invoke ---
        CrossModuleLinker.BacklinkOptions remove = new CrossModuleLinker.BacklinkOptions();
        remove.remove = true;
        CrossModuleLinker.backlinkImports(currentProgram, state.getProject().getProjectData(), remove,
            monitor, this);
        int movedBack = resetToUnresolved();
        currentProgram.getExternalManager().setExternalPath(LIB, null, false);
        check("fixture reset: block removed", !contains(plateCommentAt("dep_exported_func"), START),
            String.valueOf(plateCommentAt("dep_exported_func")));
        check("fixture reset: imports back in <EXTERNAL>",
            movedBack >= 2 && Library.UNKNOWN.equals(libraryOf("dep_exported_func")),
            "movedBack=" + movedBack + " library=" + libraryOf("dep_exported_func"));

        oneShot(mgr, analyzer);

        check("one-shot re-attributes the import", LIB.equals(libraryOf("dep_exported_func")),
            "library=" + libraryOf("dep_exported_func"));
        check("one-shot finds the library by project search",
            String.valueOf(currentProgram.getExternalManager().getExternalLibraryPath(LIB)).endsWith(LIB),
            "path=" + currentProgram.getExternalManager().getExternalLibraryPath(LIB));
        ExternalLocation loc = externalLocation("dep_exported_func");
        Address expected = libAddressOf("dep_exported_func");
        check("one-shot stores the exporting address",
            loc != null && loc.getAddress() != null && expected != null
                && loc.getAddress().getOffset() == expected.getOffset(),
            "stored=" + (loc == null ? null : loc.getAddress()) + " library=" + expected);
        String afterOneShot = plateCommentAt("dep_exported_func");
        check("one-shot writes the back-link block again", contains(afterOneShot, START),
            String.valueOf(afterOneShot));
        check("one-shot sets the bookmark again", bookmarkAt("dep_exported_func") != null, null);

        // --- idempotence: a second one-shot must not duplicate anything ---
        oneShot(mgr, analyzer);
        String twice = plateCommentAt("dep_exported_func");
        check("a second one-shot does not duplicate the block",
            twice != null && countOccurrences(twice, START) == 1,
            "blocks=" + (twice == null ? "none" : countOccurrences(twice, START)));

        // --- options are honoured: back-links off, linking still on ---
        CrossModuleLinker.backlinkImports(currentProgram, state.getProject().getProjectData(), remove,
            monitor, this);
        resetToUnresolved();
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_BACKLINKS, false);
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_SET_ADDRESS, false);
        clearExternalAddress("dep_exported_func");
        mgr.initializeOptions();
        oneShot(mgr, analyzer);
        check("with back-links off, no block is written",
            !contains(plateCommentAt("dep_exported_func"), START),
            String.valueOf(plateCommentAt("dep_exported_func")));
        check("with back-links off, imports are still linked",
            LIB.equals(libraryOf("dep_exported_func")), "library=" + libraryOf("dep_exported_func"));
        ExternalLocation noAddr = externalLocation("dep_exported_func");
        check("with addresses off, none is stored", noAddr != null && noAddr.getAddress() == null,
            noAddr == null ? "no location" : String.valueOf(noAddr.getAddress()));

        // --- options are honoured: everything off does nothing at all ---
        resetToUnresolved();
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_LINK_IMPORTS, false);
        mgr.initializeOptions();
        oneShot(mgr, analyzer);
        check("with both halves off, nothing is linked",
            Library.UNKNOWN.equals(libraryOf("dep_exported_func")),
            "library=" + libraryOf("dep_exported_func"));

        // Leave the program the way the defaults would have.
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_LINK_IMPORTS, true);
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_BACKLINKS, true);
        analysis.setBoolean(NAME + "." + CrossModuleLinkAnalyzer.OPTION_SET_ADDRESS, true);
        mgr.initializeOptions();
        oneShot(mgr, analyzer);
        check("defaults restored: linked and back-linked again",
            LIB.equals(libraryOf("dep_exported_func"))
                && contains(plateCommentAt("dep_exported_func"), START), null);

        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    /** What Analysis > One Shot > Cross-Module Import Linker does. */
    private void oneShot(AutoAnalysisManager mgr, Analyzer analyzer) {
        mgr.scheduleOneTimeAnalysis(analyzer, currentProgram.getMemory());
        mgr.startAnalysis(monitor);
    }

    // ---- this program's externals ----

    private ExternalLocation externalLocation(String name) {
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) {
            if (s.isExternal()) {
                return currentProgram.getExternalManager().getExternalLocation(s);
            }
        }
        return null;
    }

    private String libraryOf(String name) {
        ExternalLocation loc = externalLocation(name);
        return loc == null ? null : loc.getLibraryName();
    }

    private void clearExternalAddress(String name) throws Exception {
        ExternalLocation loc = externalLocation(name);
        if (loc != null) {
            loc.setLocation(loc.getLabel(), null, SourceType.IMPORTED);
        }
    }

    /** Moves every import attributed to a real library back into {@code <EXTERNAL>}. */
    private int resetToUnresolved() throws Exception {
        ExternalManager em = currentProgram.getExternalManager();
        Library unknown = em.addExternalLibraryName(Library.UNKNOWN, SourceType.IMPORTED);
        int moved = 0;
        for (Library lib : em.getLibraries()) {
            if (Library.UNKNOWN.equals(lib.getName())) {
                continue;
            }
            List<Symbol> attributed = new ArrayList<>();
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(lib)) {
                if (s.getSymbolType() == SymbolType.FUNCTION && s.getSource() != SourceType.DEFAULT) {
                    attributed.add(s);
                }
            }
            for (Symbol s : attributed) {
                ExternalLocation extLoc = em.getExternalLocation(s);
                if (extLoc != null) {
                    extLoc.setLibrary(unknown);
                    moved++;
                }
            }
        }
        return moved;
    }

    // ---- helpers that reach into the library program ----

    private Address libAddressOf(String name) throws Exception {
        DomainFile libFile = state.getProject().getProjectData().getFile("/" + LIB);
        if (libFile == null) {
            return null;
        }
        Program lib = (Program) libFile.getDomainObject(this, false, false, monitor);
        try {
            for (Symbol s : lib.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
                if (s.isExternalEntryPoint()) {
                    return s.getAddress();
                }
            }
            return null;
        } finally {
            lib.release(this);
        }
    }

    private String plateCommentAt(String name) throws Exception {
        DomainFile libFile = state.getProject().getProjectData().getFile("/" + LIB);
        Address addr = libAddressOf(name);
        if (libFile == null || addr == null) {
            return null;
        }
        Program lib = (Program) libFile.getDomainObject(this, false, false, monitor);
        try {
            return lib.getListing().getComment(CommentType.PLATE, addr);
        } finally {
            lib.release(this);
        }
    }

    private String bookmarkAt(String name) throws Exception {
        DomainFile libFile = state.getProject().getProjectData().getFile("/" + LIB);
        Address addr = libAddressOf(name);
        if (libFile == null || addr == null) {
            return null;
        }
        Program lib = (Program) libFile.getDomainObject(this, false, false, monitor);
        try {
            Bookmark b = lib.getBookmarkManager().getBookmark(addr, BookmarkType.INFO, CATEGORY);
            return b == null ? null : b.getComment();
        } finally {
            lib.release(this);
        }
    }

    private static boolean contains(String haystack, String needle) {
        return haystack != null && haystack.contains(needle);
    }

    private static int countOccurrences(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }
}
