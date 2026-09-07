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

        testReachability();
        testQueryMcp();
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

            testBuiltinAccuracy(decomp);

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

    private void testBuiltinAccuracy(DecompInterface decomp) throws Exception {
        for (String name : TaintQueryParser.getBuiltinPatternNames()) {
            new TaintQueryParser().parse(name);
        }
        check("all_builtins_parse", true, "catalog parsed");
        Map<String, List<String>> positives = Map.of(
            "memcpy_overflow", List.of("cp", "numeric_cp"),
            "format_string", List.of("fmt", "checked_format", "wrapped_format", "read_format"),
            "snprintf_format", List.of("bounded_bad_format"),
            "double_free", List.of("df"),
            "double_free_like", List.of("df"),
            "use_after_free_as_arg", List.of("freed_argument"));
        Map<String, List<String>> negatives = Map.of(
            "memcpy_overflow", List.of("safe_cp", "fixed_input_copy", "safe_crt_copy"),
            "format_string", List.of("safe_format", "safe_checked_format", "safe_wrapped_format", "read_after_format", "read_other_buffer"),
            "sprintf_overflow", List.of("safe_sprintf_destination"),
            "double_free", List.of("branch_free", "reallocated_free", "null_free"),
            "double_free_like", List.of("repeated_use", "branch_free", "reallocated_free", "null_free"),
            "use_after_free_as_arg", List.of("df", "repeated_use"));
        Set<String> names = new TreeSet<>(positives.keySet());
        names.addAll(negatives.keySet());
        for (String name : names) {
            Set<String> hits = runQuery(name, decomp);
            for (String function : positives.getOrDefault(name, List.of())) {
                check(name + "_detects_" + function, hits.contains(function), "hits=" + hits);
            }
            for (String function : negatives.getOrDefault(name, List.of())) {
                check(name + "_excludes_" + function, !hits.contains(function), "hits=" + hits);
            }
        }
        Set<String> named = runQuery(
            "printf($fmt) WHERE tainted($fmt, \"getenv\")", decomp);
        check("named_source_tracks_wrapper_return", named.contains("wrapped_format"), "hits=" + named);
        check("named_source_rejects_unrelated_return", !named.contains("safe_wrapped_format"), "hits=" + named);
        Set<String> read = runQuery("printf($fmt) WHERE tainted($fmt, \"read\")", decomp);
        check("read_source_buffer_reaches_format", read.contains("read_format"), "hits=" + read);
        check("read_source_respects_order", !read.contains("read_after_format"), "hits=" + read);
        check("read_source_distinguishes_buffers", !read.contains("read_other_buffer"), "hits=" + read);
        Set<String> literals = runQuery("memcpy($dst, $src, 16)", decomp);
        check("literal_argument_matches", literals.contains("safe_cp"), "hits=" + literals);
        check("literal_argument_rejects_other_value", !literals.contains("fixed_input_copy"), "hits=" + literals);
    }

    private void testReachability() {
        int n = 64;
        int[] rows = new int[n + 1];
        int[] cols = new int[n - 1];
        float[] weights = new float[n - 1];
        Arrays.fill(weights, 1.0f);
        for (int i = 1; i <= n; i++) rows[i] = i - 1;
        for (int i = 0; i < n - 1; i++) cols[i] = i;
        float[] seeds = new float[n];
        seeds[0] = 1;
        new decompfuncutils.Nd4jTaintEngine().computeReachability(n, rows, cols, seeds);
        check("nd4j_reaches_end_of_long_chain", seeds[n - 1] == 1, "tail=" + seeds[n - 1]);
        Arrays.fill(seeds, 0);
        seeds[0] = 1;
        new decompfuncutils.GpuTaintEngine().computeTransitiveClosure(n, rows, cols, weights, seeds);
        check("gpu_reaches_end_of_long_chain", seeds[n - 1] == 1, "tail=" + seeds[n - 1]);
    }

    @SuppressWarnings("unchecked")
    private void testQueryMcp() throws Exception {
        decompfuncutils.mcp.tools.TaintQueryTool queryTool = new decompfuncutils.mcp.tools.TaintQueryTool();
        Map<String, Object> preset = (Map<String, Object>) queryTool.execute(
            Map.of("preset", "tainted_format", "functionName", "fmt"), currentProgram, null);
        check("mcp_preset_finds_format", ((Number) preset.get("matchCount")).intValue() > 0, preset.toString());
        check("mcp_reports_complete_scope", Boolean.TRUE.equals(preset.get("complete")), preset.toString());
        Set<String> cursors = new HashSet<>();
        String cursor = null;
        int scanned = 0;
        do {
            Map<String, Object> args = new HashMap<>();
            args.put("preset", "double_free");
            args.put("maxFunctions", 1);
            if (cursor != null) args.put("startAfter", cursor);
            Map<String, Object> page = (Map<String, Object>) queryTool.execute(args, currentProgram, null);
            scanned += ((Number) page.get("functionsScanned")).intValue();
            cursor = (String) page.get("nextStartAfter");
            if (cursor != null && !cursors.add(cursor)) throw new AssertionError("Repeated cursor: " + cursor);
        } while (cursor != null);
        // getFunctionCount also includes external functions, unlike getFunctions(true).
        int expected = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) { functions.next(); expected++; }
        check("mcp_pages_cover_functions_once", scanned == expected, "scanned=" + scanned + " expected=" + expected);
        for (Map<String, Object> bad : List.<Map<String, Object>>of(
                Map.of("preset", "missing"), Map.of("preset", "double_free", "maxFunctions", 0),
                Map.of("preset", "double_free", "query", "PATTERN p { free($p); }"))) {
            boolean rejected = false;
            try { queryTool.execute(bad, currentProgram, null); }
            catch (IllegalArgumentException invalidArgument) { rejected = true; }
            check("mcp_rejects_invalid_" + bad, rejected, bad.toString());
        }
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
