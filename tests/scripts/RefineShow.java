import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import decompfuncutils.refine.*;
import java.util.*;

/**
 * Diagnostic helper: prints the refined code and the rewrite log for every function, or for those
 * named as script arguments. An argument of the form key=value is not a function name; "config=PATH"
 * loads a configuration from a JSON file. Not a regression test; run it with
 *
 *   tests/run_refine_test.ps1 -Script RefineShow.java -ShowAll [-ScriptArgs name1,name2]
 *
 * Set REFINE_DUMP_OUT to a file path to get the text there instead of in the log.
 */
public class RefineShow extends GhidraScript {
    @Override public void run() throws Exception {
        Set<String> only = new LinkedHashSet<>();
        RefineConfig config = RefineConfig.defaults();
        for (String arg : getScriptArgs()) {
            if (arg.startsWith("config=")) config = RefineConfig.fromJson(java.nio.file.Files.readString(java.nio.file.Path.of(arg.substring(7))));
            else only.add(arg);
        }
        // REFINE_SIGS holds C prototypes separated by ';', applied first the way an analyst would
        // fix a signature up. REFINE_TRACE=1 makes passes explain what they declined to rewrite.
        if (System.getenv("REFINE_TRACE") != null) config.trace = true;
        String sigs = System.getenv("REFINE_SIGS");
        for (String sig : sigs == null ? new String[0] : sigs.split(";")) {
            if (sig.isBlank()) continue;
            var parser = new ghidra.app.util.parser.FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
            var def = parser.parse(null, sig.strip());
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!fn.getName().equals(def.getName())) continue;
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(fn.getEntryPoint(), def,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
            }
        }
        StringBuilder out = new StringBuilder();
        try (RefineEngine engine = new RefineEngine(currentProgram)) {
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (fn.isThunk() || fn.isExternal()) continue;
                if (!only.isEmpty() && !only.contains(fn.getName())) continue;
                out.append("===== ").append(fn.getName()).append(" @").append(fn.getEntryPoint()).append('\n');
                try {
                    RefineResult r = engine.refine(fn, config, monitor);
                    out.append(r.original.strip()).append("\n----- refined: ").append(r.summary()).append('\n');
                    out.append(r.text());
                    for (Rewrite rw : r.log) out.append("  ").append(rw).append('\n');
                    for (String m : r.messages) out.append("  ! ").append(m).append('\n');
                } catch (Throwable t) {
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    out.append("FAILED: ").append(sw).append('\n');
                }
            }
        }
        String path = System.getenv("REFINE_DUMP_OUT");
        if (path != null) java.nio.file.Files.writeString(java.nio.file.Path.of(path), out.toString());
        else for (String line : out.toString().split("\n")) println(line);
        println("REFINE_SHOW done");
    }
}
