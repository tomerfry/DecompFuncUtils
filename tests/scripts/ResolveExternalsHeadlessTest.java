// Headless regression test for ResolveExternalsTool (ghidra_resolve_externals).
//
// Driven by tests/run_resolve_externals_test.ps1, which imports tests/extlink/libtestdep.so.1
// and tests/extlink/testmain into one project with analysis off. The ELF loader alone produces
// everything the tool needs: UND imports parked in <EXTERNAL> on the main binary, and exported
// entry points on the library.
//
// Guards the bug this tool exists for: Ghidra 12.2's own ExternalSymbolResolver asks whether the
// program being repaired exports the symbol, not whether the library does, so it resolves nothing.
//@category Test
import decompfuncutils.mcp.tools.ResolveExternalsTool;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

import java.util.*;

public class ResolveExternalsHeadlessTest extends GhidraScript {

    private static final String MAIN = "testmain";
    private static final String LIB = "libtestdep.so.1";

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
        // The post-script fires once per imported program; only the importer is interesting,
        // and by then the library is already in the project for the tool to find.
        if (!MAIN.equals(currentProgram.getName())) {
            println("ResolveExternalsHeadlessTest: skipping " + currentProgram.getName());
            return;
        }

        ResolveExternalsTool tool = new ResolveExternalsTool();

        check("tool name", "ghidra_resolve_externals".equals(tool.name()), tool.name());
        check("declared mutating", tool.isMutating(), null);
        Map<String, Object> schema = tool.inputSchema();
        check("schema type is object", "object".equals(schema.get("type")),
            String.valueOf(schema.get("type")));
        Map<String, Object> props = (Map<String, Object>) schema.get("properties");
        check("schema declares options",
            props != null && props.keySet().containsAll(
                List.of("dryRun", "setAddress", "searchProject", "libraries", "listSymbols")),
            props == null ? "no properties" : String.valueOf(props.keySet()));

        check("import did link the library path",
            currentProgram.getExternalManager().getExternalLibraryPath(LIB) != null,
            "path=" + currentProgram.getExternalManager().getExternalLibraryPath(LIB));

        // How the import left things. On a Ghidra whose External Symbol Resolver is broken both
        // imports are still stranded in <EXTERNAL>; on a fixed one they are already attributed.
        int strandedByImport = countUnknownExternals();
        println("INFO stranded in <EXTERNAL> after import: " + strandedByImport);

        // Reset to the pre-resolve state, so what is tested is this tool rather than whichever
        // Ghidra happens to be installed: move every attributed import back into <EXTERNAL> and
        // drop the library association, which also forces the project-search fallback below.
        int movedBack = resetToUnresolved();
        currentProgram.getExternalManager().setExternalPath(LIB, null, false);
        int before = countUnknownExternals();
        check("imports available to resolve", before >= 2,
            "stranded=" + strandedByImport + " movedBack=" + movedBack + " total=" + before);
        check("association cleared for the search test",
            currentProgram.getExternalManager().getExternalLibraryPath(LIB) == null, null);

        // The exact predicate Ghidra 12.2 uses: does the *importing* program export these names?
        int selfExported = 0;
        for (String name : unknownExternalNames()) {
            for (Symbol s : currentProgram.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
                if (s.isExternalEntryPoint()) {
                    selfExported++;
                    break;
                }
            }
        }
        check("importer exports none of them (why Ghidra resolves 0)", selfExported == 0,
            "selfExported=" + selfExported);

        // --- dry run must report matches and change nothing ---
        Map<String, Object> dry =
            (Map<String, Object>) tool.execute(Map.of("dryRun", true), currentProgram, null);
        println("DRY " + dry);
        int dryResolved = intOf(dry.get("resolved"));
        check("dryRun finds matches", dryResolved >= 2, "resolved=" + dryResolved);
        check("dryRun status", "dry_run".equals(dry.get("status")), String.valueOf(dry.get("status")));
        check("dryRun leaves <EXTERNAL> alone", countUnknownExternals() == before,
            before + " -> " + countUnknownExternals());
        check("dryRun does not associate the library",
            currentProgram.getExternalManager().getExternalLibraryPath(LIB) == null, null);

        // --- real run ---
        Map<String, Object> real =
            (Map<String, Object>) tool.execute(Map.of("listSymbols", true), currentProgram, null);
        println("REAL " + real);
        int resolved = intOf(real.get("resolved"));
        check("real run agrees with dry run", resolved == dryResolved,
            "dry=" + dryResolved + " real=" + resolved);
        check("status is resolved", "resolved".equals(real.get("status")),
            String.valueOf(real.get("status")));
        check("symbols left <EXTERNAL>", countUnknownExternals() == before - resolved,
            before + " - " + resolved + " vs " + countUnknownExternals());
        check("library found by project search",
            LIB.equals(currentProgram.getExternalManager().getExternalLibraryPath(LIB)) ||
                String.valueOf(currentProgram.getExternalManager().getExternalLibraryPath(LIB))
                    .endsWith(LIB),
            "path=" + currentProgram.getExternalManager().getExternalLibraryPath(LIB));
        check("addresses stored", intOf(real.get("withTargetAddress")) == resolved,
            "withTargetAddress=" + real.get("withTargetAddress"));

        // --- the individual symbol ---
        Symbol target = null;
        for (Symbol s : currentProgram.getSymbolTable().getSymbols("dep_exported_func")) {
            if (s.isExternal()) {
                target = s;
                break;
            }
        }
        check("dep_exported_func is external", target != null, null);
        if (target != null) {
            ExternalLocation loc = currentProgram.getExternalManager().getExternalLocation(target);
            // Library is not a Namespace in Ghidra 12.3, so the parent namespace stays Global
            // and the attribution lives on the external location.
            check("attributed to the library",
                loc != null && LIB.equals(loc.getLibraryName()),
                loc == null ? "no location" : "library=" + loc.getLibraryName()
                    + " namespace=" + target.getParentNamespace().getName());
            check("external location has a target address",
                loc != null && loc.getAddress() != null,
                loc == null ? "no location" : String.valueOf(loc.getAddress()));
            if (loc != null && loc.getAddress() != null) {
                // Compare against the library program's own address for the symbol, rather than
                // the ELF file offset: Ghidra rebases the PIE image (0x1320 -> 0x101320).
                Address expected = exportAddressInLibrary("dep_exported_func");
                check("target address is the exporting address",
                    expected != null && loc.getAddress().getOffset() == expected.getOffset(),
                    "stored=" + loc.getAddress() + " library=" + expected);
            }
        }

        // --- idempotence ---
        Map<String, Object> again = (Map<String, Object>) tool.execute(Map.of(), currentProgram, null);
        check("re-run resolves nothing new", intOf(again.get("resolved")) == 0,
            "resolved=" + again.get("resolved"));

        // --- library filter is honoured ---
        Map<String, Object> filtered = (Map<String, Object>) tool.execute(
            Map.of("libraries", List.of("libnosuch.so.9")), currentProgram, null);
        boolean skipped = false;
        for (Map<String, Object> libReport : (List<Map<String, Object>>) filtered.get("libraries")) {
            if (LIB.equals(libReport.get("name"))) {
                skipped = "skipped_not_requested".equals(libReport.get("status"));
            }
        }
        check("libraries filter skips others", skipped, String.valueOf(filtered.get("libraries")));

        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    private static int intOf(Object o) {
        return o instanceof Number n ? n.intValue() : -1;
    }

    /**
     * Puts every import attributed to a real library back into {@code <EXTERNAL>}, undoing
     * whatever the import's own resolver managed. Returns how many were moved.
     */
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
                // Library is not a Namespace here, so the move goes through the external
                // location rather than Symbol.setNamespace.
                ExternalLocation extLoc = em.getExternalLocation(s);
                if (extLoc != null) {
                    extLoc.setLibrary(unknown);
                    moved++;
                }
            }
        }
        return moved;
    }

    /** The address the library program itself publishes for {@code name}, or null. */
    private Address exportAddressInLibrary(String name) throws Exception {
        DomainFile libFile = state.getProject().getProjectData().getFile("/" + LIB);
        if (libFile == null) {
            return null;
        }
        Program libProgram = (Program) libFile.getDomainObject(this, false, false, monitor);
        try {
            for (Symbol s : libProgram.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
                if (s.isExternalEntryPoint()) {
                    return s.getAddress();
                }
            }
            return null;
        } finally {
            libProgram.release(this);
        }
    }

    private List<String> unknownExternalNames() {
        List<String> names = new ArrayList<>();
        Library unknown = currentProgram.getExternalManager().getExternalLibrary(Library.UNKNOWN);
        if (unknown == null) {
            return names;
        }
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(unknown)) {
            if (s.getSymbolType() == SymbolType.FUNCTION && s.getSource() != SourceType.DEFAULT) {
                names.add(s.getName());
            }
        }
        return names;
    }

    private int countUnknownExternals() {
        return unknownExternalNames().size();
    }
}
