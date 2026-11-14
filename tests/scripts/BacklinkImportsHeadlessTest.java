// Headless regression test for BacklinkImportsTool (ghidra_backlink_imports).
//
// Driven by tests/run_resolve_externals_test.ps1 -Script BacklinkImportsHeadlessTest.java, over the
// same tests/extlink pair. Resolves the imports first (ghidra_resolve_externals), then checks that
// the library program comes back with a clickable block and a bookmark per exported function, that
// re-running replaces rather than appends, and that remove takes it out again.
//@category Test
import decompfuncutils.mcp.tools.BacklinkImportsTool;
import decompfuncutils.mcp.tools.ResolveExternalsTool;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class BacklinkImportsHeadlessTest extends GhidraScript {

    private static final String MAIN = "testmain";
    private static final String LIB = "libtestdep.so.1";
    private static final String START = "[imported-by: testmain]";
    private static final String END = "[/imported-by: testmain]";
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
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        if (!MAIN.equals(currentProgram.getName())) {
            println("BacklinkImportsHeadlessTest: skipping " + currentProgram.getName());
            return;
        }

        // Back-links start from imports already attributed to the library. On a Ghidra whose
        // External Symbol Resolver works, the import itself did that and this resolves 0 — what
        // matters is the end state, not who got there.
        Map<String, Object> resolved = (Map<String, Object>) new ResolveExternalsTool()
            .execute(Map.of(), currentProgram, null);
        println("RESOLVE " + resolved);

        BacklinkImportsTool tool = new BacklinkImportsTool();
        check("tool name", "ghidra_backlink_imports".equals(tool.name()), tool.name());
        check("declared mutating", tool.isMutating(), null);
        Map<String, Object> props = (Map<String, Object>) tool.inputSchema().get("properties");
        check("schema declares options",
            props != null && props.keySet().containsAll(
                List.of("dryRun", "remove", "libraries", "comments", "bookmarks",
                    "includeDataRefs", "maxCallSites", "save", "listFunctions")),
            props == null ? "no properties" : String.valueOf(props.keySet()));

        // --- dry run writes nothing ---
        Map<String, Object> dry = (Map<String, Object>) tool.execute(
            Map.of("dryRun", true, "listFunctions", true), currentProgram, null);
        println("DRY " + dry);
        int dryFunctions = intOf(dry.get("functions"));
        List<Map<String, Object>> dryLibs = (List<Map<String, Object>>) dry.get("libraries");
        int attributed = 0;
        for (Map<String, Object> libReport : dryLibs) {
            if (LIB.equals(libReport.get("name"))) {
                attributed = intOf(libReport.get("imports"));
            }
        }
        check("imports are attributed to the library", attributed >= 2, "imports=" + attributed);
        check("dryRun finds functions to annotate", dryFunctions >= 1,
            "functions=" + dryFunctions);
        check("dryRun links call sites", intOf(dry.get("callSitesLinked")) >= 1,
            "callSitesLinked=" + dry.get("callSitesLinked"));
        check("dryRun wrote no comment", plateCommentAt("dep_exported_func") == null,
            String.valueOf(plateCommentAt("dep_exported_func")));

        // --- real run ---
        Map<String, Object> real = (Map<String, Object>) tool.execute(
            Map.of("listFunctions", true), currentProgram, null);
        println("REAL " + real);
        check("status written", "written".equals(real.get("status")), String.valueOf(real.get("status")));
        check("real agrees with dry run", intOf(real.get("functions")) == dryFunctions,
            "dry=" + dryFunctions + " real=" + real.get("functions"));

        String comment = plateCommentAt("dep_exported_func");
        check("library function carries a block", comment != null && comment.contains(START)
            && comment.contains(END), String.valueOf(comment));
        if (comment != null) {
            check("block links back to this program with an annotation",
                comment.contains("{@program /" + MAIN + "@"),
                firstLink(comment));
            check("annotation carries a display label",
                comment.matches("(?s).*\\{@program /" + MAIN + "@[0-9a-fA-F]+ \\S+\\}.*"),
                firstLink(comment));
            check("block names the call-site count", comment.contains("call site"), null);
        }
        check("bookmark set in its own category", bookmarkAt("dep_exported_func") != null,
            String.valueOf(bookmarkAt("dep_exported_func")));

        // --- re-run must replace, not append ---
        tool.execute(Map.of(), currentProgram, null);
        String twice = plateCommentAt("dep_exported_func");
        check("re-run does not duplicate the block",
            twice != null && countOccurrences(twice, START) == 1,
            "blocks=" + (twice == null ? "none" : countOccurrences(twice, START)));

        // --- a foreign block must survive our rewrite ---
        setPlateCommentAt("dep_exported_func",
            "[imported-by: other]\nkeep me\n[/imported-by: other]\n" + twice);
        tool.execute(Map.of(), currentProgram, null);
        String coexist = plateCommentAt("dep_exported_func");
        check("another importer's block is preserved",
            coexist != null && coexist.contains("[imported-by: other]") && coexist.contains("keep me")
                && countOccurrences(coexist, START) == 1,
            String.valueOf(coexist));

        // --- remove ---
        Map<String, Object> removed = (Map<String, Object>) tool.execute(
            Map.of("remove", true), currentProgram, null);
        println("REMOVE " + removed);
        String after = plateCommentAt("dep_exported_func");
        check("remove status", "removed".equals(removed.get("status")),
            String.valueOf(removed.get("status")));
        check("our block is gone", after == null || !after.contains(START), String.valueOf(after));
        check("the other importer's block still stands",
            after != null && after.contains("[imported-by: other]"), String.valueOf(after));
        check("bookmark removed", bookmarkAt("dep_exported_func") == null,
            String.valueOf(bookmarkAt("dep_exported_func")));

        // --- library filter ---
        Map<String, Object> filtered = (Map<String, Object>) tool.execute(
            Map.of("libraries", List.of("libnosuch.so.9")), currentProgram, null);
        boolean skipped = false;
        for (Map<String, Object> libReport : (List<Map<String, Object>>) filtered.get("libraries")) {
            if (LIB.equals(libReport.get("name"))) {
                skipped = "skipped_not_requested".equals(libReport.get("status"));
            }
        }
        check("libraries filter skips others", skipped, String.valueOf(filtered.get("libraries")));

        // --- mergeBlock unit cases, which the above cannot reach ---
        check("mergeBlock on empty", "B".equals(BacklinkImportsTool.mergeBlock(null, "S", "E", "B")),
            BacklinkImportsTool.mergeBlock(null, "S", "E", "B"));
        check("mergeBlock appends when absent",
            "keep\nB".equals(BacklinkImportsTool.mergeBlock("keep", "S", "E", "B")),
            BacklinkImportsTool.mergeBlock("keep", "S", "E", "B"));
        check("mergeBlock replaces in place",
            "aXc".equals(BacklinkImportsTool.mergeBlock("aSbEc", "S", "E", "X")),
            BacklinkImportsTool.mergeBlock("aSbEc", "S", "E", "X"));
        check("mergeBlock removes",
            "ac".equals(BacklinkImportsTool.mergeBlock("aSbEc", "S", "E", null)),
            BacklinkImportsTool.mergeBlock("aSbEc", "S", "E", null));

        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
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

    private void setPlateCommentAt(String name, String text) throws Exception {
        DomainFile libFile = state.getProject().getProjectData().getFile("/" + LIB);
        Address addr = libAddressOf(name);
        Program lib = (Program) libFile.getDomainObject(this, false, false, monitor);
        int tx = lib.startTransaction("test seed");
        try {
            lib.getListing().setComment(addr, CommentType.PLATE, text);
        } finally {
            lib.endTransaction(tx, true);
            // Must be saved: releasing the last consumer discards an unsaved program, and the
            // next read opens a fresh instance that would not see the seed.
            try {
                libFile.save(monitor);
            } catch (Exception e) {
                println("seed save failed: " + e);
            }
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

    private static int countOccurrences(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }

    private static String firstLink(String comment) {
        int i = comment.indexOf("{@program");
        return i < 0 ? "no annotation" : comment.substring(i, Math.min(comment.length(), i + 70));
    }

    private static int intOf(Object o) {
        return o instanceof Number n ? n.intValue() : -1;
    }
}
