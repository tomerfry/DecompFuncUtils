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
    private int queryErrors = 0;

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START prog=" + currentProgram.getName());

        testReachability();
        testQueryMcp();
        testBranchWitnesses();
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
            testEngineRegressions(decomp);
            check("queries_ran_without_errors", queryErrors == 0, "errors=" + queryErrors);

            // --- Emulation: pure arithmetic (a+3)*2-1, a=10 -> 25 (0x19) ---
            Function add3 = func("add3");
            if (add3 != null) {
                testEmulationLimits(add3);
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

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void testBranchWitnesses() throws Exception {
        Class<?> analysis = Class.forName("decompfuncutils.mcp.tools.SuggestBranchFlipTool$Analysis");
        Class<? extends Enum> cmpClass = (Class<? extends Enum>) Class.forName(
            "decompfuncutils.mcp.tools.SuggestBranchFlipTool$Cmp");
        var ctor = analysis.getDeclaredConstructor();
        ctor.setAccessible(true);
        var trueMethod = analysis.getDeclaredMethod("valuesForTrue");
        var falseMethod = analysis.getDeclaredMethod("valuesForFalse");
        trueMethod.setAccessible(true);
        falseMethod.setAccessible(true);
        Map<String, java.lang.reflect.Field> fields = new HashMap<>();
        for (var field : analysis.getDeclaredFields()) {
            field.setAccessible(true);
            fields.put(field.getName(), field);
        }
        int cases = 0;
        for (String op : List.of("EQ", "NEQ", "ULT", "ULE", "UGT", "UGE", "SLT", "SLE", "SGT", "SGE")) {
            for (int mask : (op.equals("EQ") || op.equals("NEQ") ? new int[]{-1, 0, 1, 85, 255} : new int[]{-1})) {
                for (int constant = 0; constant < 256; constant++) {
                    for (boolean negated : new boolean[]{false, true}) {
                        Object a = ctor.newInstance();
                        fields.get("leafSize").set(a, 1);
                        fields.get("cmp").set(a, Enum.valueOf(cmpClass, op));
                        fields.get("signed").set(a, op.startsWith("S"));
                        fields.get("constant").set(a, java.math.BigInteger.valueOf(constant));
                        fields.get("mask").set(a, mask < 0 ? null : java.math.BigInteger.valueOf(mask));
                        fields.get("negated").set(a, negated);
                        for (boolean wanted : new boolean[]{false, true}) {
                            List<java.math.BigInteger> values = (List<java.math.BigInteger>)
                                (wanted ? trueMethod : falseMethod).invoke(a);
                            boolean possible = false;
                            for (int x = 0; x < 256; x++) {
                                if ((predicate(op, mask < 0 ? x : x & mask, constant) ^ negated) == wanted) {
                                    possible = true;
                                }
                            }
                            if (possible != !values.isEmpty()) throw new AssertionError("Missing/invalid feasibility: " + op + " c=" + constant + " mask=" + mask);
                            for (var value : values) {
                                int x = value.intValueExact();
                                if (x < 0 || x > 255 || (predicate(op, mask < 0 ? x : x & mask, constant) ^ negated) != wanted) {
                                    throw new AssertionError("Invalid witness: " + op + " c=" + constant + " value=" + value);
                                }
                            }
                            cases++;
                        }
                    }
                }
            }
        }
        check("branch_witnesses_exhaustive_8bit", true, "cases=" + cases);
        for (int size : new int[]{4, 8}) {
            Object a = ctor.newInstance();
            fields.get("leafSize").set(a, size);
            fields.get("cmp").set(a, Enum.valueOf(cmpClass, "SLT"));
            fields.get("signed").set(a, true);
            fields.get("constant").set(a, java.math.BigInteger.ZERO);
            List<java.math.BigInteger> values = (List<java.math.BigInteger>) trueMethod.invoke(a);
            check("branch_signed_" + (size * 8) + "_unsigned_encoding",
                values.equals(List.of(java.math.BigInteger.ONE.shiftLeft(size * 8 - 1))), values.toString());
            fields.get("cmp").set(a, Enum.valueOf(cmpClass, "ULE"));
            fields.get("signed").set(a, false);
            fields.get("constant").set(a, java.math.BigInteger.ONE.shiftLeft(size * 8).subtract(java.math.BigInteger.ONE));
            check("branch_unsigned_" + (size * 8) + "_max_no_false_witness",
                ((List<?>) falseMethod.invoke(a)).isEmpty(), "unsigned <= max");
        }
    }

    private boolean predicate(String op, int x, int c) {
        if (op.startsWith("S")) { x = (byte) x; c = (byte) c; }
        return switch (op) {
            case "EQ" -> x == c;
            case "NEQ" -> x != c;
            case "ULT", "SLT" -> x < c;
            case "ULE", "SLE" -> x <= c;
            case "UGT", "SGT" -> x > c;
            case "UGE", "SGE" -> x >= c;
            default -> throw new AssertionError(op);
        };
    }

    @SuppressWarnings("unchecked")
    private void testEmulationLimits(Function f) throws Exception {
        Map<String, Object> args = new HashMap<>();
        args.put("entry", f.getEntryPoint().toString());
        args.put("stackPointer", "0x00200000");
        args.put("maxSteps", 1);
        EmulateFunctionTool emulator = new EmulateFunctionTool();
        Map<String, Object> result = (Map<String, Object>) emulator.execute(args, currentProgram, null);
        String pc = result.get("pcAtStop").toString();
        check("emulate_limit_reports_current_pc", "max_steps".equals(result.get("stopReason"))
            && currentProgram.getAddressFactory().getAddress(pc).getOffset() == loAddress(reg(result, "RIP")), result.toString());
        args.put("stopAddresses", List.of(pc));
        result = (Map<String, Object>) emulator.execute(args, currentProgram, null);
        check("emulate_breakpoint_on_last_step", "breakpoint".equals(result.get("stopReason")), result.toString());
        for (Map<String, Object> invalid : List.of(Map.<String, Object>of("maxSteps", 0),
                Map.<String, Object>of("stackPointerRegister", "NOT_A_REGISTER"),
                Map.<String, Object>of("skipCalls", true, "skipCallReturnRegister", "NOT_A_REGISTER"))) {
            Map<String, Object> bad = new HashMap<>(args);
            bad.putAll(invalid);
            boolean rejected = false;
            try { emulator.execute(bad, currentProgram, null); }
            catch (IllegalArgumentException expected) { rejected = true; }
            check("emulate_rejects_" + invalid.keySet(), rejected, invalid.toString());
        }
    }

    private long loAddress(String hex) {
        return Long.parseUnsignedLong(hex.substring(2), 16);
    }

    private void testBuiltinAccuracy(DecompInterface decomp) throws Exception {
        for (String name : TaintQueryParser.getBuiltinPatternNames()) {
            new TaintQueryParser().parse(name);
        }
        check("all_builtins_parse", true, "catalog parsed");
        for (String name : TaintQueryParser.getRecommendedPatterns().keySet()) {
            check("recommended_preset_defined_" + name,
                TaintQueryParser.getBuiltinPattern(name) != null, name);
        }
        // Every pattern is paired with safe lookalikes that must not match.
        Map<String, List<String>> positives = Map.ofEntries(
            Map.entry("memcpy_overflow", List.of("cp", "numeric_cp", "long_chain")),
            Map.entry("format_string", List.of("fmt", "checked_format", "wrapped_format", "read_format",
                "fmt_build_unsafe", "vfmt_unsafe")),
            Map.entry("unbounded_copy_length", List.of("cp", "numeric_cp", "long_chain", "alloc_copy_mismatch",
                "read_len_unchecked")),
            Map.entry("snprintf_format", List.of("bounded_bad_format")),
            Map.entry("double_free", List.of("df")),
            Map.entry("double_free_like", List.of("df")),
            Map.entry("use_after_free", List.of("uaf", "loop_uaf")),
            Map.entry("use_after_free_simple", List.of("uaf", "loop_uaf")),
            Map.entry("use_after_free_as_arg", List.of("freed_argument")),
            Map.entry("strcpy_overflow", List.of("env_copy", "nested_call", "cmd_build_strcat", "fmt_build_unsafe")),
            Map.entry("command_injection", List.of("cmd_build_unsafe", "cmd_build_strcat", "cmd_build_chain",
                "cmd_read_unsafe", "cond_call", "loop_cond_call")),
            Map.entry("popen_injection", List.of("cmd_build_snprintf")),
            Map.entry("command_injection_buffer", List.of("cmd_build_unsafe", "cmd_build_snprintf",
                "cmd_build_strcat", "cmd_build_chain", "cmd_read_unsafe")),
            Map.entry("format_string_buffer", List.of("fmt_build_unsafe")),
            Map.entry("exec_injection", List.of("exec_unsafe")),
            Map.entry("winexec_injection", List.of("winexec_unsafe")),
            Map.entry("alloc_mul_overflow", List.of("alloc_mul_unsafe", "alloc_mul_const_unsafe", "shift_alloc")),
            Map.entry("alloc_add_overflow", List.of("alloc_add_unsafe")),
            Map.entry("alloc_copy_mismatch", List.of("alloc_copy_mismatch")),
            Map.entry("unchecked_alloc_deref", List.of("alloc_unchecked", "alloc_unchecked_field")),
            Map.entry("null_deref_after_malloc", List.of("alloc_unchecked")),
            Map.entry("unchecked_alloc_use", List.of("alloc_unchecked_arg")),
            Map.entry("signed_length_copy", List.of("signed_len_unsafe")),
            Map.entry("signed_length_alloc", List.of("signed_alloc_unsafe")),
            Map.entry("realloc_misuse", List.of("realloc_unsafe")),
            Map.entry("toctou_file_access", List.of("toctou_unsafe")),
            Map.entry("unchecked_read_length", List.of("read_len_unchecked")),
            Map.entry("stack_buffer_const_overflow", List.of("stack_const_overflow")),
            Map.entry("stack_buffer_const_read", List.of("stack_read_overflow")));
        Map<String, List<String>> negatives = Map.ofEntries(
            Map.entry("memcpy_overflow", List.of("safe_cp", "fixed_input_copy", "safe_crt_copy", "read_len_ignored",
                "stack_const_ok")),
            Map.entry("format_string", List.of("safe_format", "safe_checked_format", "safe_wrapped_format",
                "read_after_format", "read_other_buffer", "fmt_build_safe", "vfmt_safe")),
            Map.entry("sprintf_overflow", List.of("safe_sprintf_destination", "cmd_build_unsafe")),
            Map.entry("double_free", List.of("branch_free", "reallocated_free", "null_free", "list_free",
                "list_free_offset")),
            Map.entry("double_free_like", List.of("repeated_use", "branch_free", "reallocated_free", "null_free",
                "list_free_offset")),
            Map.entry("unbounded_copy_length", List.of("safe_cp", "fixed_input_copy", "signed_len_unsafe",
                "signed_len_safe", "read_len_checked", "alloc_copy_compared", "stack_const_overflow",
                "copy_min_len", "copy_strlen")),
            Map.entry("use_after_free", List.of("list_free", "list_free_offset", "df", "alloc_unchecked",
                "reallocated_free")),
            Map.entry("use_after_free_simple", List.of("list_free", "list_free_offset", "df")),
            Map.entry("winexec_injection", List.of("winexec_safe", "cmd_build_snprintf")),
            Map.entry("use_after_free_as_arg", List.of("df", "repeated_use")),
            Map.entry("strcpy_overflow", List.of("param_copy", "cmd_build_other")),
            Map.entry("command_injection", List.of("cmd_build_safe", "cmd_build_late", "cmd_build_other",
                "cmd_build_rewritten")),
            Map.entry("popen_injection", List.of("cmd_build_unsafe")),
            Map.entry("command_injection_buffer", List.of("cmd_build_safe", "cmd_build_late", "cmd_build_other",
                "cmd_build_rewritten", "cond_call")),
            Map.entry("format_string_buffer", List.of("fmt_build_safe", "read_format")),
            Map.entry("exec_injection", List.of("exec_safe")),
            Map.entry("alloc_mul_overflow", List.of("alloc_mul_checked", "alloc_mul_bounded", "plain_alloc",
                "nested_alloc", "alloc_add_unsafe")),
            Map.entry("alloc_add_overflow", List.of("alloc_add_checked", "alloc_add_strlen", "plain_alloc")),
            Map.entry("alloc_copy_mismatch", List.of("alloc_copy_same", "alloc_copy_derived", "alloc_copy_compared",
                "alloc_copy_field", "copy_strlen")),
            Map.entry("unchecked_alloc_deref", List.of("alloc_checked", "alloc_checked_nested", "plain_alloc")),
            Map.entry("null_deref_after_malloc", List.of("alloc_checked")),
            Map.entry("unchecked_alloc_use", List.of("alloc_checked_arg", "alloc_copy_same")),
            Map.entry("signed_length_copy", List.of("signed_len_safe", "signed_len_unsigned", "signed_len_strlen",
                "cp", "numeric_cp")),
            Map.entry("signed_length_alloc", List.of("signed_alloc_safe", "alloc_mul_unsafe", "plain_alloc")),
            Map.entry("realloc_misuse", List.of("realloc_safe")),
            Map.entry("toctou_file_access", List.of("toctou_other", "toctou_reversed")),
            Map.entry("unchecked_read_length", List.of("read_len_checked", "read_len_ignored")),
            Map.entry("stack_buffer_const_overflow", List.of("stack_const_ok", "safe_cp", "fixed_input_copy")),
            Map.entry("stack_buffer_const_read", List.of("stack_read_ok", "read_format", "read_len_ignored")));
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

    /** Regressions for the matching engine itself (ordering, nesting, syntax, sites). */
    private void testEngineRegressions(DecompInterface decomp) throws Exception {
        // A; ...; B; ...; C: C must come after B, not merely after A.
        Set<String> order = runQuery("PATTERN p { puts($p); ...; strlen($p); ...; atoi($p); }", decomp);
        check("order_three_elements_matches_abc", order.contains("order_abc"), "hits=" + order);
        check("order_three_elements_rejects_c_before_b", !order.contains("order_acb"), "hits=" + order);

        // Consecutive elements without "..." also follow control flow.
        Set<String> adjacent = runQuery("PATTERN p { free($ptr); free($ptr); }", decomp);
        check("adjacent_elements_match_sequence", adjacent.contains("df"), "hits=" + adjacent);
        check("adjacent_elements_respect_cfg", !adjacent.contains("branch_free"), "hits=" + adjacent);

        // Calls nested in arguments, in the source and in the pattern.
        Set<String> nestedPattern = runQuery("malloc(strlen($s))", decomp);
        check("nested_call_pattern_matches", nestedPattern.contains("nested_alloc"), "hits=" + nestedPattern);
        check("nested_call_pattern_rejects_plain", !nestedPattern.contains("plain_alloc")
            && !nestedPattern.contains("alloc_add_strlen"), "hits=" + nestedPattern);
        Set<String> nestedSource = runQuery("puts(strcpy($d, $s)) WHERE tainted_ext($s)", decomp);
        check("nested_call_in_argument_is_seen", nestedSource.contains("nested_call"), "hits=" + nestedSource);
        check("nested_call_requires_inner_call", !nestedSource.contains("env_copy"), "hits=" + nestedSource);

        // Calls that only appear inside a condition.
        Set<String> conditionCalls = runQuery("system($c) WHERE tainted_ext($c)", decomp);
        check("call_in_if_condition_matches", conditionCalls.contains("cond_call"), "hits=" + conditionCalls);
        check("call_in_loop_condition_matches", conditionCalls.contains("loop_cond_call"), "hits=" + conditionCalls);
        Set<String> conditionAssign = runQuery("$p = malloc($a * $b)", decomp);
        check("assignment_inside_condition_matches", conditionAssign.contains("alloc_mul_checked")
            && conditionAssign.contains("alloc_mul_unsafe"), "hits=" + conditionAssign);

        // Dereference without a gap, "..." in a right-hand-side call, stores.
        Set<String> deref = runQuery("PATTERN p { $p = malloc($n); *$p; }", decomp);
        check("dereference_without_gap_matches", deref.contains("alloc_unchecked")
            && deref.contains("alloc_unchecked_field") && deref.contains("alloc_checked"), "hits=" + deref);
        check("dereference_needs_a_dereference", !deref.contains("plain_alloc"), "hits=" + deref);
        Set<String> rest = runQuery("$p = malloc(...)", decomp);
        check("rest_in_rhs_call_matches", rest.contains("plain_alloc") && rest.contains("df"), "hits=" + rest);
        Set<String> store = runQuery("PATTERN p { $p = malloc(_); *$p = 0x61; }", decomp);
        check("store_pattern_matches", store.contains("alloc_unchecked") && store.contains("alloc_unchecked_field"),
            "hits=" + store);
        check("store_pattern_rejects_no_store", !store.contains("plain_alloc"), "hits=" + store);

        // Operators and literal / wildcard operands in argument patterns.
        Set<String> addLiteral = runQuery("malloc($n + 16)", decomp);
        check("binop_literal_operand_matches", addLiteral.contains("alloc_add_unsafe"), "hits=" + addLiteral);
        check("binop_literal_operand_rejects_other", !addLiteral.contains("alloc_add_strlen")
            && !addLiteral.contains("alloc_mul_unsafe"), "hits=" + addLiteral);
        Set<String> addAny = runQuery("malloc($n + _)", decomp);
        check("binop_wildcard_operand_matches", addAny.contains("alloc_add_unsafe")
            && addAny.contains("alloc_add_strlen") && !addAny.contains("plain_alloc"), "hits=" + addAny);
        Set<String> bits = runQuery("malloc(($n & 0xff) | 0x100)", decomp);
        check("bit_operators_match", bits.contains("bitops_alloc"), "hits=" + bits);
        check("bit_operators_reject_other", !bits.contains("alloc_add_unsafe") && !bits.contains("plain_alloc"),
            "hits=" + bits);
        Set<String> shift = runQuery("malloc($n * 8)", decomp);
        check("shift_counts_as_multiplication", shift.contains("shift_alloc"), "hits=" + shift);
        check("shift_literal_is_checked", !shift.contains("alloc_mul_const_unsafe"), "hits=" + shift);

        // Conditions as pattern elements.
        Set<String> condition = runQuery("PATTERN p { $p = malloc(_); $p == 0; }", decomp);
        check("condition_element_matches", condition.contains("alloc_checked") && condition.contains("plain_alloc"),
            "hits=" + condition);
        check("condition_element_needs_branch", !condition.contains("alloc_unchecked"), "hits=" + condition);

        // Gap forms: statement distance, single-statement wildcard, required guard.
        Set<String> tight = runQuery("PATTERN p { puts($p); ...{0,0}; strlen($p); }", decomp);
        check("gap_distance_zero_matches_adjacent", tight.contains("order_abc"), "hits=" + tight);
        check("gap_distance_zero_rejects_separated", !tight.contains("order_acb")
            && !tight.contains("neg_call_other"), "hits=" + tight);
        Set<String> one = runQuery("PATTERN p { puts($p); _; strlen($p); }", decomp);
        check("single_wildcard_needs_one_statement", one.contains("order_acb") && one.contains("neg_call_other")
            && !one.contains("order_abc"), "hits=" + one);
        Set<String> guarded = runQuery("PATTERN p { $p = malloc(_); ... guard:($p == 0); free($p); }", decomp);
        check("guard_clause_requires_check", guarded.contains("plain_alloc") && guarded.contains("alloc_checked")
            && !guarded.contains("df") && !guarded.contains("alloc_unchecked"), "hits=" + guarded);

        // Unknown syntax is an error, never a silent wildcard.
        for (String bad : List.of("foo bar baz", "strcpy($a, b)", "$a ! $b",
                "PATTERN p { free($p); ... nope:$p; free($p); }", "printf($f) WHERE bogus($f)",
                "printf($f) WHERE tainted($f) junk", "PATTERN p { free($p) } trailing",
                "printf($f) WHERE const_eq($f)", "PATTERN p { }")) {
            boolean rejected = false;
            try { new TaintQueryParser().parse(bad); }
            catch (TaintQueryParser.ParseException expected) { rejected = true; }
            check("parser_rejects[" + bad + "]", rejected, bad);
        }
        for (String good : List.of("PATTERN p { $a != 0; }", "malloc($a << 2)", "$x = $a + _",
                "f(($a & 0xff) | $b, ...)", "$fn(..., $x, ...) WHERE in_loop($fn)",
                "{ free($p); ... not:free($p) not:$p=_; *$p; } WHERE NOT is_constant($p)",
                "PATTERN p { char $buf[$n]; gets($buf); } WHERE const_ge($n, 8)")) {
            boolean parsed = true;
            try { new TaintQueryParser().parse(good); }
            catch (TaintQueryParser.ParseException unexpected) { parsed = false; println("PARSE: " + unexpected.getMessage()); }
            check("parser_accepts[" + good + "]", parsed, good);
        }

        // Parameters are sources for tainted(), not for tainted_ext().
        Set<String> anyTaint = runQuery("strcpy($d, $s) WHERE tainted($s)", decomp);
        check("tainted_counts_parameters", anyTaint.contains("param_copy") && anyTaint.contains("env_copy"),
            "hits=" + anyTaint);
        Set<String> extTaint = runQuery("strcpy($d, $s) WHERE tainted_ext($s)", decomp);
        check("tainted_ext_matches_real_input", extTaint.contains("env_copy"), "hits=" + extTaint);
        check("tainted_ext_ignores_parameters", !extTaint.contains("param_copy"), "hits=" + extTaint);

        // NULL checks are found wherever the decompiler prints them.
        Set<String> guard = runQuery("PATTERN p { $p = malloc(_); ... not:($p == 0); *$p; }", decomp);
        check("guard_negative_matches_unchecked", guard.contains("alloc_unchecked"), "hits=" + guard);
        check("guard_negative_sees_null_check", !guard.contains("alloc_checked")
            && !guard.contains("alloc_checked_nested"), "hits=" + guard);
        Set<String> unchecked = runQuery("$p = malloc(_) WHERE unchecked($p)", decomp);
        check("unchecked_constraint_matches", unchecked.contains("alloc_unchecked") && unchecked.contains("df"),
            "hits=" + unchecked);
        check("unchecked_constraint_sees_check", !unchecked.contains("alloc_checked")
            && !unchecked.contains("plain_alloc") && !unchecked.contains("alloc_mul_checked"), "hits=" + unchecked);

        // Gap negatives match a call with its arguments, not a name substring.
        Set<String> negCall = runQuery("PATTERN p { puts($p); ... not:atoi($p); strlen($p); }", decomp);
        check("gap_negative_call_allows_clean_path", negCall.contains("order_abc"), "hits=" + negCall);
        check("gap_negative_call_blocks_same_argument", !negCall.contains("order_acb"), "hits=" + negCall);
        check("gap_negative_call_ignores_other_argument", negCall.contains("neg_call_other"), "hits=" + negCall);

        // Buffer contents are judged at the sink, in program order.
        Set<String> sinkSite = runQuery("system($c) WHERE tainted($c)", decomp);
        check("buffer_taint_reaches_later_sink", sinkSite.contains("cmd_build_unsafe"), "hits=" + sinkSite);
        check("buffer_taint_ignores_later_write", !sinkSite.contains("cmd_build_late"), "hits=" + sinkSite);
        check("buffer_taint_cleared_by_overwrite", !sinkSite.contains("cmd_build_rewritten"), "hits=" + sinkSite);

        // Remaining constraints.
        Set<String> loop = runQuery("strcat($d, $s) WHERE in_loop()", decomp);
        check("in_loop_matches_loop_body", loop.contains("loop_append"), "hits=" + loop);
        check("in_loop_rejects_straight_line", !loop.contains("cmd_build_strcat"), "hits=" + loop);
        Set<String> constant = runQuery("memcpy($d, $s, $n) WHERE const_eq($n, 16)", decomp);
        check("const_eq_matches", constant.contains("safe_cp") && !constant.contains("fixed_input_copy"),
            "hits=" + constant);
        Set<String> declared = runQuery("PATTERN p { char $buf[_]; strcpy($buf, $src); } WHERE tainted($src)", decomp);
        check("declaration_binds_stack_array", declared.contains("env_copy"), "hits=" + declared);
        check("declaration_rejects_non_local", !declared.contains("param_copy"), "hits=" + declared);
        Set<String> returned = runQuery("malloc($n + _) WHERE returned_by($n, \"strlen\")", decomp);
        check("returned_by_matches", returned.contains("alloc_add_strlen") && !returned.contains("alloc_add_unsafe"),
            "hits=" + returned);
        Set<String> signed = runQuery("memcpy(_, _, $n) WHERE signed($n)", decomp);
        check("signed_matches_sign_extended_length", signed.contains("signed_len_unsafe")
            && signed.contains("signed_len_safe") && !signed.contains("signed_len_unsigned"), "hits=" + signed);

        // Matches report where the sink is.
        QueryMatch buffered = firstMatch("command_injection_buffer", "cmd_build_unsafe", decomp);
        check("match_reports_sink_location", buffered != null && buffered.sinkAddress != null
            && !buffered.sinkAddress.equals(buffered.address) && buffered.sinkCode.contains("system")
            && buffered.matchedCode.contains("sprintf") && buffered.trace.size() == 2,
            buffered == null ? "no match" : buffered.toString());
        check("match_hides_internal_bindings", buffered != null
            && buffered.bindings.keySet().stream().noneMatch(k -> k.startsWith("#")),
            buffered == null ? "no match" : buffered.bindings.keySet().toString());
    }

    private QueryMatch firstMatch(String q, String functionName, DecompInterface decomp) throws Exception {
        Function f = func(functionName);
        if (f == null) return null;
        DecompileResults r = decomp.decompileFunction(f, 30, monitor);
        TaintQueryMatcher matcher = new TaintQueryMatcher(currentProgram, new StringTaintLog(null));
        List<QueryMatch> found = matcher.matchInFunctionWithMarkup(new TaintQueryParser().parse(q),
            r.getHighFunction(), r.getCCodeMarkup(), true);
        return found.isEmpty() ? null : found.get(0);
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
        Map<String, Object> buffered = (Map<String, Object>) queryTool.execute(
            Map.of("preset", "command_injection_buffer", "functionName", "cmd_build_unsafe"), currentProgram, null);
        List<Map<String, Object>> bufferedMatches = (List<Map<String, Object>>) buffered.get("matches");
        check("mcp_new_preset_reports_sink", bufferedMatches.size() == 1
            && String.valueOf(bufferedMatches.get(0).get("sinkCode")).contains("system")
            && bufferedMatches.get(0).get("sinkAddress") != null
            && !bufferedMatches.get(0).get("sinkAddress").equals(bufferedMatches.get(0).get("matchAddress")),
            buffered.toString());
        Map<String, Object> custom = (Map<String, Object>) queryTool.execute(
            Map.of("query", "$p = malloc(_) WHERE unchecked($p)", "functionName", "alloc_checked"),
            currentProgram, null);
        check("mcp_custom_constraint_runs", ((Number) custom.get("matchCount")).intValue() == 0, custom.toString());
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
            if (matcher.getSearchErrorCount() > 0) {
                queryErrors += matcher.getSearchErrorCount();
                println("QUERY ERROR for [" + q + "]: " + matcher.getLastSearchError());
            }
        } catch (Exception e) {
            // An exception leaves the hit set empty, which would let "excludes"
            // checks pass for the wrong reason: count it as a failure instead.
            queryErrors++;
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
