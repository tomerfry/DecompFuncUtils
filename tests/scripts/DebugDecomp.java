import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;

import decompfuncutils.TaintQuery;
import decompfuncutils.TaintQueryParser;
import decompfuncutils.TaintQueryMatcher;
import decompfuncutils.TaintQueryMatcher.QueryMatch;
import decompfuncutils.mcp.StringTaintLog;

import java.util.*;

public class DebugDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("DBG_START");
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try {
            for (String fn : new String[]{"uaf", "cp", "fmt"}) {
                Function f = func(fn);
                if (f == null) { println("DBG no func " + fn); continue; }
                DecompileResults r = decomp.decompileFunction(f, 30, monitor);
                println("=== DECOMP " + fn + " completed=" + (r != null && r.decompileCompleted()) + " ===");
                if (r != null && r.decompileCompleted()) {
                    println(r.getDecompiledFunction().getC());
                }
            }
            dbgQuery(decomp, "UAF", "PATTERN p { free($ptr); ...; *$ptr; }", "uaf");
            dbgQuery(decomp, "MEMCPY_NOWHERE", "PATTERN p { memcpy($dst, $src, $len); }", "cp");
            dbgQuery(decomp, "PRINTF_NOWHERE", "PATTERN p { printf($fmt); }", "fmt");
            dbgQuery(decomp, "MEMCPY_TAINT", "PATTERN p { memcpy($dst, $src, $len); } WHERE tainted($len)", "cp");
        } finally {
            decomp.dispose();
        }
        println("DBG_END");
    }

    private void dbgQuery(DecompInterface decomp, String tag, String q, String fn) {
        try {
            Function f = func(fn);
            DecompileResults r = decomp.decompileFunction(f, 30, monitor);
            if (r == null || !r.decompileCompleted()) { println("DBG " + tag + ": decompile failed"); return; }
            HighFunction hf = r.getHighFunction();
            ClangTokenGroup markup = r.getCCodeMarkup();
            TaintQuery query = new TaintQueryParser().parse(q);
            StringTaintLog log = new StringTaintLog(null);
            TaintQueryMatcher m = new TaintQueryMatcher(currentProgram, log);
            List<QueryMatch> ms = m.matchInFunctionWithMarkup(query, hf, markup, true);
            println("DBG " + tag + " matches=" + (ms == null ? "null" : ms.size()));
            println("---- LOG[" + tag + "] ----");
            println(log.getOutput());
            println("---- END LOG ----");
        } catch (Exception e) {
            println("DBG " + tag + " ERROR: " + e);
        }
    }

    private Function func(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true))
            if (f.getName().equals(name)) return f;
        return null;
    }
}
