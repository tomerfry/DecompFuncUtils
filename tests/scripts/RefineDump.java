import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import decompfuncutils.refine.ast.*;
import java.util.*;

/**
 * Diagnostic helper: checks, for every function (or those named as script arguments), that the
 * refinement AST printed back matches the decompiler's C, and reports the differences and any
 * statement the parser had to keep as raw text. Not a regression test; run it with
 *
 *   tests/run_refine_test.ps1 -Script RefineDump.java -ShowAll [-Binary some.exe]
 *
 * Set REFINE_DUMP_OUT to a file path to get the full side-by-side text there instead of in the log.
 */
public class RefineDump extends GhidraScript {
    private StringBuilder out;

    @Override public void run() throws Exception {
        Set<String> only = new HashSet<>(Arrays.asList(getScriptArgs()));
        DecompInterface d = new DecompInterface();
        d.setOptions(new DecompileOptions());
        d.toggleSyntaxTree(true);
        d.toggleCCode(true);
        d.openProgram(currentProgram);
        int same = 0, different = 0, raw = 0, failed = 0;
        String path = System.getenv("REFINE_DUMP_OUT");
        if (path != null) out = new StringBuilder();
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            if (fn.isThunk() || fn.isExternal()) continue;
            if (!only.isEmpty() && !only.contains(fn.getName())) continue;
            DecompileResults r = d.decompileFunction(fn, 30, monitor);
            if (!r.decompileCompleted()) continue;
            try {
                CFunction f = new ClangAstBuilder(currentProgram).build(r);
                CPrinter.Options o = new CPrinter.Options();
                o.clarifyParens = false;
                o.dropUnusedLocals = false;
                String mine = new CPrinter(o).print(f).text;
                String theirs = r.getDecompiledFunction().getC();
                raw += f.rawStatements;
                if (f.rawStatements > 0) raws(f.body, fn.getName());
                if (normalize(mine).equals(normalize(theirs))) same++;
                else {
                    different++;
                    emit("=====DIFF " + fn.getName());
                    emit(theirs);
                    emit("-----REPRINTED (raw statements: " + f.rawStatements + ")");
                    emit(mine);
                }
            } catch (Exception e) {
                failed++;
                emit("=====FAILED " + fn.getName() + ": " + e);
                java.io.StringWriter sw = new java.io.StringWriter();
                e.printStackTrace(new java.io.PrintWriter(sw));
                emit(sw.toString());
            }
        }
        d.dispose();
        println("ROUNDTRIP same=" + same + " different=" + different + " rawStatements=" + raw + " failed=" + failed);
        if (path != null) java.nio.file.Files.writeString(java.nio.file.Path.of(path), out.toString());
    }

    private void emit(String s) {
        if (out != null) out.append(s).append(System.lineSeparator());
        else println(s);
    }

    private void raws(Stmt s, String fn) {
        if (s instanceof Stmt.Raw r) emit("RAW in " + fn + " [" + r.reason + "]: " + String.join(" // ", r.lines));
        if (s instanceof Stmt.Block b) for (Stmt c : b.body) raws(c, fn);
        for (Stmt.Block b : s.blocks()) raws(b, fn);
    }

    private static String normalize(String s) { return s.replaceAll("\\s+", ""); }
}
