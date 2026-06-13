import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;

import decompfuncutils.TaintQuery;
import decompfuncutils.TaintQueryParser;
import decompfuncutils.TaintQueryMatcher;
import decompfuncutils.TaintQueryMatcher.QueryMatch;
import decompfuncutils.mcp.StringTaintLog;
import decompfuncutils.mcp.tools.EmulateFunctionTool;

import java.util.*;

/**
 * Headless regression test for the taint-query engine and the p-code emulator.
 * Run via analyzeHeadless against tests/test_vuln.o. Prints CHECK lines and a
 * final HEADLESS_TEST_SUMMARY that the runner parses for pass/fail.
 */
public class TaintHeadlessTest extends GhidraScript {

    private int passed = 0;
    private int failed = 0;

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START prog=" + currentProgram.getName());

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try {
            // --- Structural multi-element patterns (exercise statement indexing) ---
            Set<String> uaf = runQuery("PATTERN p { free($ptr); ...; *$ptr; }", decomp);
            check("uaf_detects_use_after_free", uaf.contains("uaf"), "hits=" + uaf);

            Set<String> df = runQuery("PATTERN p { free($ptr); ...; free($ptr); }", decomp);
            check("double_free_detects_df", df.contains("df"), "hits=" + df);

            // --- Taint constraint (taint flows through getenv() return value) ---
            Set<String> memcpyTainted = runQuery(
                "PATTERN p { memcpy($dst, $src, $len); } WHERE tainted($len)", decomp);
            check("memcpy_tainted_len_matches_cp", memcpyTainted.contains("cp"), "hits=" + memcpyTainted);
            check("memcpy_tainted_len_skips_safe_cp", !memcpyTainted.contains("safe_cp"), "hits=" + memcpyTainted);

            Set<String> fmt = runQuery(
                "PATTERN p { printf($fmt); } WHERE tainted($fmt)", decomp);
            check("printf_tainted_fmt_matches_fmt", fmt.contains("fmt"), "hits=" + fmt);

            // --- Source-specific taint: tainted($v, "getenv") vs a different source ---
            Set<String> byGetenv = runQuery(
                "PATTERN p { printf($fmt); } WHERE tainted($fmt, \"getenv\")", decomp);
            check("source_specific_getenv_matches_fmt", byGetenv.contains("fmt"), "hits=" + byGetenv);

            Set<String> byRead = runQuery(
                "PATTERN p { printf($fmt); } WHERE tainted($fmt, \"read\")", decomp);
            check("source_specific_read_excludes_fmt", !byRead.contains("fmt"), "hits=" + byRead);

            // --- Emulation: pure arithmetic (a+3)*2-1, a=10 -> 25 (0x19) ---
            Function add3 = func("add3");
            if (add3 != null) {
                Map<String, Object> r = emulate(add3,
                    Map.of("RDI", "10"), false);
                String rax = reg(r, "RAX");
                check("emulate_add3_returns_25",
                    rax != null && lo32(rax) == 0x19,
                    "stop=" + r.get("stopReason") + " RAX=" + rax);
            } else check("emulate_add3_returns_25", false, "add3 not found");

            // --- Emulation skipCalls: with_call(7) -> printf skipped -> 8 (0x8) ---
            Function withCall = func("with_call");
            if (withCall != null) {
                Map<String, Object> r = emulate(withCall, Map.of("RDI", "7"), true);
                String rax = reg(r, "RAX");
                Object skipped = r.get("skippedCallCount");
                int nSkipped = (skipped instanceof Number) ? ((Number) skipped).intValue() : 0;
                check("emulate_skipcalls_steps_over_printf", nSkipped >= 1,
                    "stop=" + r.get("stopReason") + " skipped=" + skipped + " calls=" + r.get("skippedCalls"));
                check("emulate_skipcalls_returns_8",
                    rax != null && lo32(rax) == 0x8,
                    "stop=" + r.get("stopReason") + " RAX=" + rax);

                // Without skipCalls, the same function should NOT cleanly return.
                Map<String, Object> r2 = emulate(withCall, Map.of("RDI", "7"), false);
                println("INFO with_call no-skip stop=" + r2.get("stopReason"));
            } else check("emulate_skipcalls_returns_8", false, "with_call not found");

        } finally {
            decomp.dispose();
        }

        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println(failed == 0 ? "HEADLESS_TEST_RESULT PASS" : "HEADLESS_TEST_RESULT FAIL");
    }

    private Set<String> runQuery(String q, DecompInterface decomp) {
        Set<String> hits = new LinkedHashSet<>();
        try {
            TaintQuery query = new TaintQueryParser().parse(q);
            TaintQueryMatcher matcher = new TaintQueryMatcher(currentProgram, new StringTaintLog(null));
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                DecompileResults r = decomp.decompileFunction(f, 30, monitor);
                if (r == null || !r.decompileCompleted()) continue;
                HighFunction hf = r.getHighFunction();
                ClangTokenGroup markup = r.getCCodeMarkup();
                if (hf == null || markup == null) continue;
                List<QueryMatch> ms = matcher.matchInFunctionWithMarkup(query, hf, markup, true);
                if (ms != null && !ms.isEmpty()) hits.add(f.getName());
            }
        } catch (Exception e) {
            println("QUERY ERROR for [" + q + "]: " + e);
        }
        return hits;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> emulate(Function f, Map<String, String> regs, boolean skipCalls) {
        try {
            Map<String, Object> args = new HashMap<>();
            args.put("entry", f.getEntryPoint().toString());
            args.put("registers", regs);
            args.put("stackPointer", "0x00200000");
            args.put("returnAddressSentinel", "0x00c0ffee");
            if (skipCalls) args.put("skipCalls", Boolean.TRUE);
            Object out = new EmulateFunctionTool().execute(args, currentProgram, null);
            return (Map<String, Object>) out;
        } catch (Exception e) {
            println("EMULATE ERROR for " + f.getName() + ": " + e);
            return Collections.emptyMap();
        }
    }

    private Function func(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String reg(Map<String, Object> r, String name) {
        Object regs = r.get("registers");
        if (regs instanceof Map) {
            Object v = ((Map<String, Object>) regs).get(name);
            return v == null ? null : v.toString();
        }
        return null;
    }

    private long lo32(String hex) {
        String h = hex.startsWith("0x") ? hex.substring(2) : hex;
        return Long.parseLong(h, 16) & 0xFFFFFFFFL;
    }

    private void check(String name, boolean cond, String detail) {
        if (cond) { passed++; println("CHECK " + name + ": PASS"); }
        else { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }
}
