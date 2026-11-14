import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitorAdapter;
import decompfuncutils.mcp.*;
import decompfuncutils.mcp.tools.RefineFunctionTool;
import decompfuncutils.refine.*;
import decompfuncutils.refine.ast.*;
import decompfuncutils.refine.rules.RuleSet;
import decompfuncutils.refine.ui.RefinedCodeView;
import decompfuncutils.refine.ui.RefinedDecompilerView;
import com.google.gson.*;
import java.util.*;

/**
 * Regression test for the refinement engine over tests/refine/librefinedemo.so, an optimized
 * build in which every function has one obvious source-level meaning the engine should recover.
 * Run with tests/run_refine_test.ps1.
 */
public class RefineEngineHeadlessTest extends GhidraScript {
    private int passed, failed;
    private RefineEngine engine;

    @Override public void run() throws Exception {
        // What an analyst would fix first: the three signatures the decompiler cannot guess,
        // because without them the values these functions compute look unused.
        for (String sig : new String[] {
                "unsigned long my_strlen(char *s)",
                "unsigned int hash_bytes(unsigned char *p, unsigned long n)",
                "void my_zero(char *p, unsigned long n)" }) {
            var def = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null).parse(null, sig);
            new ApplyFunctionSignatureCmd(fn(def.getName()).getEntryPoint(), def, SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
        }
        engine = new RefineEngine(currentProgram);
        try {
            parserTests();
            recoveryTests();
            verificationTests();
            configurationTests();
            ruleTests();
            validationTests();
            mcpTests();
            uiTests();
        } finally {
            engine.close();
        }
        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println("HEADLESS_TEST_RESULT " + (failed == 0 ? "PASS" : "FAIL"));
    }

    // ------------------------------------------------------------------ the AST layer

    private void parserTests() throws Exception {
        DecompInterface d = RefineEngine.openDecompiler(currentProgram);
        int different = 0, raw = 0, functions = 0;
        String firstDiff = "";
        try {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) continue;
                DecompileResults r = d.decompileFunction(f, 30, monitor);
                if (!r.decompileCompleted()) continue;
                functions++;
                CFunction ast = new ClangAstBuilder(currentProgram).build(r);
                raw += ast.rawStatements;
                CPrinter.Options o = new CPrinter.Options();
                o.clarifyParens = false;
                o.dropUnusedLocals = false;
                String mine = new CPrinter(o).print(ast).text.replaceAll("\\s+", "");
                String theirs = r.getDecompiledFunction().getC().replaceAll("\\s+", "");
                if (!mine.equals(theirs)) {
                    different++;
                    if (firstDiff.isEmpty()) firstDiff = f.getName();
                }
            }
        } finally {
            d.dispose();
        }
        check("ast_covers_every_function", functions >= 25, "functions=" + functions);
        check("ast_reprints_decompiler_output_exactly", different == 0, different + " differ, first " + firstDiff);
        check("ast_has_no_unparsed_statements", raw == 0, "raw=" + raw);

        // With every pass off the engine is a faithful second view of the decompiler.
        RefineResult plain = engine.refine(fn("digit_sum"), RefineConfig.passthrough(), monitor);
        check("passthrough_changes_nothing", plain.log.isEmpty() && plain.text().contains("do {") && plain.validation == null, plain.text());

        // Types come from p-code, not from C's promotion rules.
        CFunction udiv = ast("udiv10");
        Stmt.Return ret = (Stmt.Return) udiv.body.body.get(udiv.body.body.size() - 1);
        check("types_from_pcode", ret.e instanceof Expr.Bin b && b.o.equals("/") && !b.sgn && b.type.bits == 64 && b.l instanceof Expr.Cast,
            CPrinter.text(ret.e));
        CFunction sdiv = ast("sdiv7");
        Stmt.Return sret = (Stmt.Return) sdiv.body.body.get(sdiv.body.body.size() - 1);
        check("signedness_from_pcode", sret.e instanceof Expr.Bin b && b.sgn && b.type.bits == 32, CPrinter.text(sret.e));
        check("statements_carry_addresses", sret.addr != null && fn("sdiv7").getBody().contains(sret.addr), String.valueOf(sret.addr));
    }

    // ------------------------------------------------------------------ what the engine recovers

    private void recoveryTests() {
        RefineConfig c = RefineConfig.defaults();
        has("sdiv_by_power_of_two", "sdiv8", c, "param_1 / 8", ">> 3");
        has("loop_rotation_undone", "digit_sum", c, "while (param_1 != 0)", "do {");
        lacks("rotated_loop_temp_removed", "digit_sum", c, "bVar1");
        has("abs_from_select", "abs_val", c, "abs(param_1)", "if (");
        has("min_from_cmov", "min_s", c, "MIN(param_1, param_2)", "if (");
        has("max_from_cmov", "max_u", c, "MAX(param_1, param_2)", "if (");
        has("rotate", "rotl13", c, "rotl(param_1, 0xd)", ">>");
        has("rotate_with_multiply_folded_in", "mix", c, "rotl((param_1 ^ param_2) * 0x1000193, 13)", "0x326000");
        has("range_check", "is_digit", c, "(param_1 >= 0x30) && (param_1 < 0x3a)", "0x30U");
        has("sign_idiom", "sign_of", c, "(param_1 > 0) - (param_1 < 0)", ">> 0x1f");
        has("strlen_loop", "my_strlen", c, "return strlen(s);", "do {");
        has("memset_loop", "my_zero", c, "memset(p, 0, n);", "do {");
        has("memcpy_loop", "my_copy", c, "memcpy((void *)param_1, (void *)param_2, param_3);", "do {");
        has("merged_stores_to_string", "init_header", c, "strncpy((char *)param_1, \"DFU1\", 12);", "0x31554644");
        has("inlined_helper_three_deep", "hash3", c, "return mix(mix(mix(param_1, 0x811c9dc5), param_2), param_3);", "0x1000193");
        has("inlined_helper_in_loop", "hash_bytes", c, "uVar1 = mix(p[uVar2], uVar1);", "0x1000193");
        has("counted_loop_is_for", "hash_bytes", c, "for (uVar2 = 0; uVar2 != n; uVar2 = uVar2 + 1) {", "do {");
        has("opaque_predicate_removed", "opaque", c, "return param_2 + 1;", "if (");
        lacks("dead_branch_value_removed", "opaque", c, "0x4d");
        has("select_feeds_expression", "poly", c, "return param_1 % 10 + MIN(param_2, param_1 / 10) * 8;", "if (");
        has("unsigned_min_is_cast", "scale_clamped", c, "MIN((uint)(param_1 * 3), 0xff)", "if (");

        // decode_key(0x1234), computed here the way the source does.
        long r = 0x1234;
        for (int i = 0; i < 5; i++) r = (((r ^ 0x5a5a5a5aL) * 33L) + i) & 0xffffffffL;
        has("constant_call_evaluated", "use_decode", c, "return 0x" + Long.toHexString(r) + " ^ param_1;", "decode_key(");

        // Functions the decompiler already shows as the source had them stay as they are.
        for (String name : new String[] {"udiv10", "umod10", "sdiv7", "smod100", "udiv1000", "mul8", "mul9", "mul_mix"}) {
            RefineResult res = engine.refine(fn(name), c, monitor);
            check("untouched_" + name, res.applied() == 0 && norm(res.text()).equals(norm(res.original)), res.summary());
        }
    }

    // ------------------------------------------------------------------ how rewrites are justified

    private void verificationTests() {
        RefineConfig c = RefineConfig.defaults();
        RefineResult sdiv = engine.refine(fn("sdiv8"), c, monitor);
        check("idiom_rule_is_proved", status(sdiv, "sdiv-pow2") == Rewrite.Status.PROVEN, log(sdiv));
        RefineResult digits = engine.refine(fn("digit_sum"), c, monitor);
        Rewrite derotate = find(digits, "derotate");
        check("loop_guard_equivalence_is_proved", derotate != null && derotate.status == Rewrite.Status.PROVEN
            && derotate.detail.contains("equals the guard"), log(digits));
        check("dead_store_is_structural", status(digits, "dead-store") == Rewrite.Status.STRUCTURAL, log(digits));
        RefineResult strlen = engine.refine(fn("my_strlen"), c, monitor);
        check("loop_idiom_is_tested", status(strlen, "strlen") == Rewrite.Status.TESTED, log(strlen));
        RefineResult min = engine.refine(fn("min_s"), c, monitor);
        check("min_is_proved", status(min, "min-max-abs") == Rewrite.Status.PROVEN, log(min));
        RefineResult opaque = engine.refine(fn("opaque"), c, monitor);
        check("opaque_predicate_is_proved", status(opaque, "always-true") == Rewrite.Status.PROVEN, log(opaque));
        Rewrite rotl = find(engine.refine(fn("rotl13"), c, monitor), "rotl");
        check("rewrites_carry_disassembly", rotl != null && rotl.address != null && rotl.evidence != null
            && rotl.evidence.toUpperCase().contains("ROL"), rotl == null ? "none" : rotl.evidence);
        check("rewrites_marked_in_output", engine.refine(fn("rotl13"), c, monitor).printed.spans.stream()
            .anyMatch(s -> s.kind.equals("rewrite") && s.note instanceof Rewrite), "no rewrite span");

        int assumed = 0, refuted = 0, total = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            RefineResult r = engine.refine(f, c, monitor);
            total += r.applied();
            assumed += r.count(Rewrite.Status.ASSUMED);
            refuted += r.count(Rewrite.Status.REFUTED);
        }
        check("every_fixture_rewrite_is_justified", total > 40 && assumed == 0 && refuted == 0,
            "applied=" + total + " assumed=" + assumed + " refuted=" + refuted);

        // With verification off the same rewrites happen, and say that nothing checked them.
        RefineConfig off = RefineConfig.defaults();
        off.verification = "off";
        off.validate = false;
        RefineResult unchecked = engine.refine(fn("rotl13"), off, monitor);
        check("verification_off_is_labelled", unchecked.text().contains("rotl(") && status(unchecked, "rotl") == Rewrite.Status.ASSUMED, log(unchecked));

        // Testing alone still accepts a correct rewrite, as TESTED rather than PROVEN.
        RefineConfig test = RefineConfig.defaults();
        test.verification = "test";
        check("test_mode_is_labelled", status(engine.refine(fn("rotl13"), test, monitor), "rotl") == Rewrite.Status.TESTED, "status");
    }

    // ------------------------------------------------------------------ configuration drives the output

    private void configurationTests() {
        RefineConfig c = RefineConfig.defaults();
        c.pass("rules").enabled = false;
        has("pass_off_keeps_original", "rotl13", c, "<< 0xd", "rotl(");

        c = RefineConfig.defaults();
        c.ruleGroups.put("bit-idioms", false);
        has("rule_group_off_keeps_original", "rotl13", c, "<< 0xd", "rotl(");
        has("other_groups_still_apply", "is_digit", c, "&&", "0x30U");

        c = RefineConfig.defaults();
        c.ruleGroups.put("strength", true);
        has("optional_group_on", "rotl13", RefineConfig.defaults(), "rotl(param_1, 0xd)", "* 0x2000");

        c = RefineConfig.defaults();
        c.pass("select").enabled = false;
        has("select_off_keeps_if", "min_s", c, "if (param_1 < param_2)", "MIN(");

        c = RefineConfig.defaults();
        c.pass("select").params.put("idioms", false);
        has("pass_parameter_changes_output", "min_s", c, "if (param_1 < param_2)", "MIN(");
        has("pass_parameter_keeps_plain_select", "sdiv8", c, "param_1 / 8", "if (");

        c = RefineConfig.defaults();
        c.pass("loops").params.put("forLoops", false);
        c.pass("loop-idioms").enabled = false;
        has("for_loops_off", "my_zero", c, "while (", "for (");

        c = RefineConfig.defaults();
        c.pass("loops").enabled = false;
        has("loop_idioms_do_not_need_loops_pass", "my_zero", c, "memset(p, 0, n);", "do {");

        c = RefineConfig.defaults();
        c.pass("inline").enabled = false;
        has("inline_off_keeps_body", "hash3", c, "rotl(", "mix(");

        c = RefineConfig.defaults();
        c.pass("inline").params.put("minSize", 60);
        has("inline_min_size", "hash3", c, "rotl(", "mix(");

        c = RefineConfig.defaults();
        c.pass("const-calls").enabled = false;
        has("const_calls_off_keeps_call", "use_decode", c, "decode_key(0x1234)", "0x4ede");

        c = RefineConfig.defaults();
        c.pass("stores").params.put("minString", 5);
        has("store_parameter", "init_header", c, "0x31554644", "strncpy");

        c = RefineConfig.defaults();
        c.literals = "dec";
        has("literal_style", "sdiv8", c, "param_1 / 8", "0x");
        c.clarifyParens = false;
        has("paren_style", "mix", RefineConfig.defaults(), "rotl((param_1 ^ param_2) * 0x1000193, 13)", "<<");

        // Order matters and is configurable: with rules ahead of fold-temps and a single round,
        // the shift idiom is still spread over two statements when the rules look.
        c = RefineConfig.defaults();
        c.maxRounds = 1;
        List<RefineConfig.PassSetting> order = new ArrayList<>(c.passes);
        RefineConfig.PassSetting rules = c.pass("rules");
        order.remove(rules);
        order.add(0, rules);
        c.passes = order;
        has("pass_order_matters", "sdiv8", c, ">> 3", "param_1 / 8");

        // A configuration survives the trip through JSON, and a stale one is repaired.
        RefineConfig custom = RefineConfig.defaults();
        custom.pass("inline").enabled = false;
        custom.pass("select").params.put("maxSize", 7);
        custom.ruleGroups.put("strength", true);
        custom.userRules = "r: $x * 9 => nine($x)";
        RefineConfig back = RefineConfig.fromJson(custom.toJson());
        check("config_json_round_trip", back.toJson().equals(custom.toJson()), back.toJson());
        RefineConfig stale = RefineConfig.fromJson("{\"passes\":[{\"id\":\"no-such-pass\",\"enabled\":true},{\"id\":\"rules\",\"enabled\":false}],"
            + "\"verification\":\"bogus\",\"trials\":-5}");
        check("config_is_normalized", stale.pass("no-such-pass") == null && !stale.pass("rules").enabled && stale.pass("loops") != null
            && stale.passes.get(0).id.equals("rules") && stale.verification.equals("prove") && stale.trials == 1, stale.toJson());

        // Cancelling stops between passes and says so; what comes back is still the function's code.
        ghidra.util.task.TaskMonitor cancelledMonitor = new TaskMonitorAdapter(true) {
            @Override public boolean isCancelled() { return true; }
        };
        DecompInterface d = RefineEngine.openDecompiler(currentProgram);
        try {
            RefineResult cancelled = engine.refine(d.decompileFunction(fn("hash3"), 30, monitor), RefineConfig.defaults(), cancelledMonitor);
            check("cancel_between_passes_is_reported", cancelled.text().contains("hash3") && cancelled.log.isEmpty()
                && cancelled.validation == null && cancelled.messages.stream().anyMatch(m -> m.contains("Cancelled")), cancelled.messages.toString());
        } finally {
            d.dispose();
        }
        boolean threw = false;
        try {
            engine.refine(fn("hash3"), RefineConfig.defaults(), cancelledMonitor);
        } catch (java.util.concurrent.CancellationException e) {
            threw = true;
        }
        check("cancel_before_decompiling_throws", threw, "no CancellationException");
        check("engine_usable_after_cancel", engine.refine(fn("hash3"), RefineConfig.defaults(), monitor).text().contains("mix(mix(mix("), "after cancel");

        // Tracing explains what was left alone.
        c = RefineConfig.defaults();
        c.trace = true;
        RefineResult traced = engine.refine(fn("decode_key"), c, monitor);
        check("trace_explains_declined_loop", traced.messages.stream().anyMatch(m -> m.startsWith("loop-idioms:")), traced.messages.toString());
        check("trace_is_off_by_default", engine.refine(fn("decode_key"), RefineConfig.defaults(), monitor).messages.isEmpty(), "messages");
    }

    // ------------------------------------------------------------------ user rules

    private void ruleTests() {
        // A correct rule is applied and proved.
        RefineConfig c = RefineConfig.defaults();
        c.userRules = "# mine\nshift-it: $x * $c:const => $x << eval(log2($c)) where is_pow2($c)";
        RefineResult r = engine.refine(fn("mul8"), c, monitor);
        check("user_rule_applied_and_proved", r.text().contains("param_1 << 3") && status(r, "shift-it") == Rewrite.Status.PROVEN, r.text() + log(r));

        // A rule that is wrong is refused where it is wrong, with a counterexample, and changes nothing.
        c = RefineConfig.defaults();
        c.userRules = "bad: $x / 7 => $x / 8";
        r = engine.refine(fn("sdiv7"), c, monitor);
        Rewrite bad = find(r, "bad");
        check("wrong_rule_is_refuted", bad != null && bad.status == Rewrite.Status.REFUTED && !bad.detail.isEmpty()
            && r.text().contains("param_1 / 7") && r.applied() == 0, r.text() + log(r));

        // A rule naming a function the engine has no model of is applied, labelled as assumed...
        c = RefineConfig.defaults();
        c.userRules = "name-it: $x * 9 => times_nine($x)";
        c.validate = false;
        r = engine.refine(fn("mul9"), c, monitor);
        check("unmodelled_rule_is_assumed", r.text().contains("times_nine(param_1)") && status(r, "name-it") == Rewrite.Status.ASSUMED, r.text() + log(r));
        // ... unless the configuration demands verification.
        c.rejectUnverified = true;
        r = engine.refine(fn("mul9"), c, monitor);
        check("reject_unverified", r.text().contains("param_1 * 9") && r.applied() == 0, r.text() + log(r));

        // Guards, constant metavariables and eval().
        c = RefineConfig.defaults();
        c.userRules = "g: $x * $c:const => $x * eval($c + 1) - $x where $c == 9";
        check("guard_selects_instances", engine.refine(fn("mul9"), c, monitor).text().contains("param_1 * 10 - param_1")
            && engine.refine(fn("mul8"), c, monitor).text().contains("param_1 * 8"), "guard");

        // Rule text that does not parse is reported with its line, and the rest still works.
        c = RefineConfig.defaults();
        c.userRules = "ok: $x * 9 => $x * 8 + $x\nbroken: $x * => 3\nnoarrow: $x + 1\nunbound: $x + 1 => $y";
        r = engine.refine(fn("mul9"), c, monitor);
        long problems = r.messages.stream().filter(m -> m.startsWith("Rule line")).count();
        check("rule_errors_reported", problems == 3 && r.messages.stream().anyMatch(m -> m.contains("line 2"))
            && r.messages.stream().anyMatch(m -> m.contains("$y")) && r.text().contains("param_1 * 8 + param_1"), r.messages + r.text());

        RuleSet builtin = RuleSet.builtin();
        check("builtin_rules_parse", builtin.problems.isEmpty() && builtin.size() >= 15 && builtin.groups.containsKey("bit-idioms")
            && !builtin.groups.get("strength").enabledByDefault, builtin.problems.toString());
    }

    // ------------------------------------------------------------------ the emulator has the last word

    private void validationTests() {
        RefineConfig c = RefineConfig.defaults();
        int agree = 0, differ = 0, unchecked = 0;
        StringBuilder detail = new StringBuilder();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            RefineResult r = engine.refine(f, c, monitor);
            switch (r.validation.outcome) {
                case AGREES -> agree++;
                case DIFFERS -> { differ++; detail.append(f.getName()).append(": ").append(r.validation.detail).append("; "); }
                default -> { unchecked++; detail.append(f.getName()).append(" unchecked: ").append(r.validation.detail).append("; "); }
            }
        }
        check("emulator_agrees_with_refined_code", agree >= 29 && differ == 0 && unchecked <= 1, "agree=" + agree + " differ=" + differ + " " + detail);

        // The check is real: apply a wrong rule with verification off and the emulator objects.
        c = RefineConfig.defaults();
        c.verification = "off";
        c.userRules = "wrong: $x / 7 => $x / 8";
        RefineResult r = engine.refine(fn("sdiv7"), c, monitor);
        check("emulator_catches_wrong_output", r.text().contains("param_1 / 8") && r.validation.outcome == RefineResult.Validation.Outcome.DIFFERS
            && r.validation.detail.contains("param_1=") && r.summary().contains("EMULATOR DISAGREES"), r.summary());

        // It follows calls into the program (hash3 calls mix after refinement; the machine code has it inlined).
        r = engine.refine(fn("hash3"), RefineConfig.defaults(), monitor);
        check("emulator_check_follows_recovered_calls", r.validation.outcome == RefineResult.Validation.Outcome.AGREES && r.validation.agreed >= 8, r.summary());

        c = RefineConfig.defaults();
        c.validate = false;
        check("validation_can_be_switched_off", engine.refine(fn("hash3"), c, monitor).validation == null, "validation");
    }

    // ------------------------------------------------------------------ the MCP tool

    private void mcpTests() {
        McpToolRegistry registry = new McpToolRegistry();
        registry.register(new RefineFunctionTool());
        McpProtocolHandler handler = new McpProtocolHandler(registry, () -> currentProgram, () -> null);
        JsonObject res = call(handler, Map.of("name", "hash3"));
        check("mcp_refines", res.get("refined").getAsString().contains("mix(mix(mix(") && res.getAsJsonArray("rewrites").size() >= 5
            && res.getAsJsonObject("validation").get("outcome").getAsString().equals("agrees") && !res.has("original"), res.toString());
        JsonObject first = res.getAsJsonArray("rewrites").get(0).getAsJsonObject();
        check("mcp_rewrite_fields", first.has("pass") && first.has("rule") && first.has("status") && first.has("before") && first.has("after")
            && first.has("address") && first.has("disassembly"), first.toString());
        res = call(handler, Map.of("name", "hash3", "disable", List.of("inline"), "includeOriginal", true));
        check("mcp_disable_pass", !res.get("refined").getAsString().contains("mix(") && res.has("original"), res.toString());
        res = call(handler, Map.of("name", "rotl13", "only", List.of("simplify")));
        check("mcp_only", !res.get("refined").getAsString().contains("rotl("), res.toString());
        res = call(handler, Map.of("name", "mul9", "rules", "r: $x * 9 => $x * 8 + $x", "validate", false));
        check("mcp_user_rules", res.get("refined").getAsString().contains("param_1 * 8 + param_1") && !res.has("validation"), res.toString());
        res = call(handler, Map.of("name", "rotl13", "ruleGroups", Map.of("bit-idioms", false)));
        check("mcp_rule_groups", !res.get("refined").getAsString().contains("rotl("), res.toString());
        res = call(handler, Map.of("name", "min_s", "config", Map.of("passes", List.of(Map.of("id", "select", "enabled", false)))));
        check("mcp_config_object", res.get("refined").getAsString().contains("if (param_1 < param_2)"), res.toString());
        res = call(handler, Map.of("describe", true));
        check("mcp_describe", res.getAsJsonArray("passes").size() == 11 && res.getAsJsonArray("ruleGroups").size() >= 5
            && res.has("defaultConfig") && res.has("ruleSyntax"), res.toString().substring(0, 200));
        check("mcp_unknown_pass", error(handler, Map.of("name", "hash3", "disable", List.of("nope"))).contains("Unknown pass"), "error");
        check("mcp_unknown_function", error(handler, Map.of("name", "no_such_function")).contains("not found"), "error");
        check("mcp_bad_argument", error(handler, Map.of("name", "hash3", "validate", "yes")).contains("boolean"), "error");
    }

    // ------------------------------------------------------------------ the window's contents

    private void uiTests() throws Exception {
        String[] failure = new String[1];
        // The engine is not run on the Swing thread, here or in the product: results are computed
        // first, the way the window's worker thread would, and handed to the view.
        RefineResult r = engine.refine(fn("hash3"), RefineConfig.defaults(), monitor);
        RefineConfig withoutInline = RefineConfig.defaults();
        withoutInline.pass("inline").enabled = false;
        RefineResult plainer = engine.refine(fn("hash3"), withoutInline, monitor);
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            try {
                int[] changes = new int[1];
                ghidra.program.model.address.Address[] went = new ghidra.program.model.address.Address[1];
                RefinedDecompilerView view = new RefinedDecompilerView(RefineConfig.defaults(), () -> changes[0]++, a -> went[0] = a);
                check("view_starts_with_a_hint", view.code().getText().contains("Place the cursor") && view.rewriteRows() == 0, view.code().getText());

                view.showResult(r);
                String text = view.code().getText();
                check("view_shows_refined_code", text.contains("mix(mix(mix(") && view.statusText().contains("emulator agrees")
                    && view.rewriteRows() == r.log.size() + r.messages.size(), view.statusText());
                Rewrite at = view.code().rewriteAt(text.indexOf("mix("));
                check("view_maps_text_to_rewrite", at != null && at.rule.startsWith("inlined mix"), String.valueOf(at));
                check("view_plain_text_has_no_rewrite", view.code().rewriteAt(text.indexOf("hash3")) == null, "prototype");
                String tip = RefinedCodeView.describe(at);
                check("view_tooltip_explains", tip.contains("tested on concrete runs") && tip.contains("<pre>") && tip.contains("rotl("), tip);
                var where = view.code().addressAt(text.indexOf("return"));
                check("view_lines_have_addresses", where != null && fn("hash3").getBody().contains(where), String.valueOf(where));
                check("view_follows_listing", view.code().highlightAddress(fn("hash3").getEntryPoint().add(4))
                    && !view.code().highlightAddress(fn("hash3").getEntryPoint().subtract(64)), "highlight");
                view.showOriginal(true);
                check("view_compare_shows_decompiler_output", view.code().getText().replaceAll("\\s+", "").equals(r.original.replaceAll("\\s+", "")),
                    view.code().getText());
                view.showOriginal(false);

                // Every control writes into the configuration and reports the change.
                javax.swing.JCheckBox inline = find(view, javax.swing.JCheckBox.class, b -> b.getText().equals("Recover inlined helper functions"));
                inline.doClick();
                check("config_checkbox_edits_config", changes[0] == 1 && view.configPanel().config().toJson().equals(withoutInline.toJson()),
                    "changes=" + changes[0]);
                view.showResult(plainer);
                check("view_follows_configuration", !view.code().getText().contains("mix(") && view.code().getText().contains("rotl("), view.code().getText());

                javax.swing.JTextArea rules = find(view, javax.swing.JTextArea.class, a -> a.isEditable());
                rules.setText("mine: $x * 9 => $x * 8 + $x");
                check("config_rule_editor_edits_config", view.configPanel().config().userRules.contains("mine:") && changes[0] > 1, "changes=" + changes[0]);
                javax.swing.JLabel parsed = find(view, javax.swing.JLabel.class, l -> l.getText() != null && l.getText().contains("parsed"));
                check("config_rule_editor_reports_parse", parsed != null && parsed.getText().startsWith("1 rule"), String.valueOf(parsed));
                rules.setText("oops: $x * =>");
                javax.swing.JLabel problem = find(view, javax.swing.JLabel.class, l -> l.getText() != null && l.getText().contains("line 1"));
                check("config_rule_editor_reports_error", problem != null, "no error label");
                rules.setText("mine: $x * 9 => $x * 8 + $x");

                @SuppressWarnings("unchecked")
                javax.swing.JComboBox<String> preset = find(view, javax.swing.JComboBox.class, c -> c.getItemCount() > 0 && "(custom)".equals(c.getItemAt(0)));
                check("config_edit_leaves_preset", preset.getSelectedIndex() == 0, String.valueOf(preset.getSelectedItem()));
                preset.setSelectedItem("Decompiler output (no passes)");
                RefineConfig none = view.configPanel().config();
                check("config_preset_applies", none.passes.stream().noneMatch(p -> p.enabled) && none.userRules.contains("mine:"), none.toJson());
                // The panel is rebuilt for a preset; its controls must reflect the new configuration.
                javax.swing.JCheckBox rebuilt = find(view, javax.swing.JCheckBox.class, b -> b.getText().equals("Recover inlined helper functions"));
                check("config_panel_reflects_preset", !rebuilt.isSelected(), "inline checkbox");

                view.configPanel().setConfig(RefineConfig.defaults());
                javax.swing.JButton later = find(view, javax.swing.JButton.class, b -> "Run later".equals(b.getToolTipText()) && b.isEnabled());
                String firstBefore = view.configPanel().config().passes.get(0).id;
                later.doClick();
                check("config_reorder_edits_config", view.configPanel().config().passes.get(1).id.equals(firstBefore), view.configPanel().config().passes.get(0).id);

                view.showFailure("f", new IllegalStateException("boom"));
                check("view_reports_failure", view.code().getText().contains("could not be refined") && view.statusText().contains("boom"), view.statusText());
            } catch (Throwable t) {
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                failure[0] = sw.toString();
            }
        });
        check("ui_tests_ran", failure[0] == null, failure[0]);
    }

    @SuppressWarnings("unchecked")
    private static <T extends java.awt.Component> T find(java.awt.Container rootComponent, Class<? super T> type, java.util.function.Predicate<T> test) {
        for (java.awt.Component c : rootComponent.getComponents()) {
            if (type.isInstance(c) && test.test((T) c)) return (T) c;
            if (c instanceof java.awt.Container inner) {
                T hit = find(inner, type, test);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ helpers

    private Function fn(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name) && !f.isThunk() && !f.isExternal()) return f;
        }
        throw new IllegalStateException("fixture has no function " + name);
    }

    private CFunction ast(String name) throws Exception {
        DecompInterface d = RefineEngine.openDecompiler(currentProgram);
        try {
            return new ClangAstBuilder(currentProgram).build(d.decompileFunction(fn(name), 30, monitor));
        } finally {
            d.dispose();
        }
    }

    private void has(String check, String function, RefineConfig config, String want, String gone) {
        String text = engine.refine(fn(function), config, monitor).text();
        check(check, text.contains(want) && !text.contains(gone), text);
    }

    private void lacks(String check, String function, RefineConfig config, String gone) {
        String text = engine.refine(fn(function), config, monitor).text();
        check(check, !text.contains(gone), text);
    }

    private static Rewrite find(RefineResult r, String rule) {
        for (Rewrite w : r.log) if (w.rule.equals(rule)) return w;
        return null;
    }

    private static Rewrite.Status status(RefineResult r, String rule) {
        Rewrite w = find(r, rule);
        return w == null ? null : w.status;
    }

    private static String log(RefineResult r) { return " log=" + r.log; }
    private static String norm(String s) { return s.replaceAll("\\s+", ""); }

    private final Gson gson = new Gson();

    private JsonObject rpc(McpProtocolHandler handler, Map<String, Object> args) {
        return JsonParser.parseString(handler.handleRequest(gson.toJson(Map.of("jsonrpc", "2.0", "id", 1,
            "method", "tools/call", "params", Map.of("name", "ghidra_refine_function", "arguments", args))), null)).getAsJsonObject();
    }

    private JsonObject call(McpProtocolHandler handler, Map<String, Object> args) {
        JsonObject response = rpc(handler, args);
        if (response.has("error")) throw new AssertionError(response.toString());
        return JsonParser.parseString(response.getAsJsonObject("result").getAsJsonArray("content")
            .get(0).getAsJsonObject().get("text").getAsString()).getAsJsonObject();
    }

    private String error(McpProtocolHandler handler, Map<String, Object> args) {
        JsonObject response = rpc(handler, args);
        return response.has("error") ? response.getAsJsonObject("error").get("message").getAsString() : "no error: " + response;
    }

    private void check(String name, boolean ok, Object detail) {
        if (ok) { passed++; println("CHECK " + name + ": PASS"); }
        else {
            failed++;
            String d = String.valueOf(detail).replaceAll("\\s+", " ");
            println("CHECK " + name + ": FAIL (" + (d.length() > 700 ? d.substring(0, 700) + "..." : d) + ")");
        }
    }
}
