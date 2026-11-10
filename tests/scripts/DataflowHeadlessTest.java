import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;

import decompfuncutils.DataflowSlicer;
import decompfuncutils.DataflowSlicer.Item;
import decompfuncutils.DataflowSlicer.Result;
import decompfuncutils.DataflowSlicer.Seed;
import decompfuncutils.DataflowSlicer.SeedKind;
import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.tools.GetDataflowTool;

import java.util.*;
import java.util.function.Predicate;

/**
 * Headless regression test for DataflowSlicer (the analysis behind the Decompiler
 * data-flow hover) and the ghidra_get_dataflow MCP tool. Run via analyzeHeadless
 * against tests/test_vuln.o.
 *
 * Seeds are taken from real decompiler tokens, exactly as the hover does, so token
 * classification is covered too. The hover's Swing wiring is not: it needs the GUI.
 */
public class DataflowHeadlessTest extends GhidraScript {

    private int passed = 0;
    private int failed = 0;
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        println("HEADLESS_TEST_START prog=" + currentProgram.getName());
        decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.openProgram(currentProgram);
        try {
            testReturnValueFlow();
            testCallSeed();
            testParameterToArgument();
            testArithmetic();
            testConstantsAndLoads();
            testBranchCondition();
            testSideEffects();
            testIgnoredTokens();
            testCaps();
            testSweepAllTokens();
            testHtml();
            testMcpTool();
            testPluginDeclaration();
        } catch (Exception e) {
            check("no_unexpected_exception", false, e.toString());
            e.printStackTrace();
        } finally {
            decomp.dispose();
        }
        println("HEADLESS_TEST_SUMMARY passed=" + passed + " failed=" + failed);
        println(failed == 0 ? "HEADLESS_TEST_RESULT PASS" : "HEADLESS_TEST_RESULT FAIL");
    }

    // ---- fmt(): s = getenv("X"); printf(s);

    private void testReturnValueFlow() throws Exception {
        Decompiled d = decompile("fmt");
        ClangToken read = d.token(t -> t instanceof ClangVariableToken && isCallTo(t.getPcodeOp(), "printf")
            && t.getVarnode() != null && !t.getVarnode().isConstant());
        check("fmt_has_variable_read_at_printf", read != null, d.c);
        if (read != null) {
            Result r = d.slice(read);
            check("read_is_marked_read_here", "read here".equals(r.seed.access), "access=" + r.seed.access);
            check("read_affected_by_getenv_result", has(r.affectedBy, "call result", "getenv()"), r.affectedBy.toString());
            check("read_affects_printf_argument", has(r.affects, "call argument", "printf() argument 1"), r.affects.toString());
            check("read_header_has_type_and_kind", r.seed.dataType != null && "local".equals(r.seed.variableKind),
                r.seed.toMap().toString());
        }
        ClangToken assigned = d.token(t -> t instanceof ClangVariableToken && isCallTo(t.getPcodeOp(), "getenv")
            && t.getVarnode() != null && t.getVarnode().getDef() == t.getPcodeOp());
        check("fmt_has_assignment_target", assigned != null, d.c);
        if (assigned != null) {
            Result r = d.slice(assigned);
            check("target_is_marked_assigned_here", "assigned here".equals(r.seed.access), "access=" + r.seed.access);
            check("target_affected_by_getenv_result", has(r.affectedBy, "call result", "getenv()"), r.affectedBy.toString());
            check("target_affects_printf_argument", has(r.affects, "call argument", "printf() argument 1"), r.affects.toString());
        }
    }

    private void testCallSeed() throws Exception {
        Decompiled d = decompile("fmt");
        ClangToken call = d.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "getenv"));
        check("fmt_has_getenv_call_token", call != null, d.c);
        if (call == null) return;
        Result r = d.slice(call);
        check("call_seed_kind", r.seed.kind == SeedKind.CALL && "getenv()".equals(r.seed.label), r.seed.toMap().toString());
        check("call_header_has_signature", r.seed.signature != null && r.seed.signature.contains("getenv"),
            "signature=" + r.seed.signature);
        check("call_affected_by_string_argument", has(r.affectedBy, "constant", "\"X\""), r.affectedBy.toString());
        check("call_result_affects_printf_argument", has(r.affects, "call argument", "printf() argument 1"), r.affects.toString());
    }

    // ---- cp(dst, src): len = getenv("N"); memcpy(dst, src, len);

    private void testParameterToArgument() throws Exception {
        Decompiled d = decompile("cp");
        ClangToken call = d.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "getenv"));
        if (call != null) {
            Result r = d.slice(call);
            check("getenv_result_affects_memcpy_length", has(r.affects, "call argument", "memcpy() argument 3"), r.affects.toString());
        } else check("getenv_result_affects_memcpy_length", false, d.c);

        HighVariable dst = d.param(0);
        check("cp_has_first_parameter", dst != null, d.c);
        if (dst != null) {
            Result r = d.slicer.slice(d.slicer.seedForVariable(dst));
            check("param_affects_memcpy_destination", has(r.affects, "call argument", "memcpy() argument 1"), r.affects.toString());
            check("param_affected_by_caller", has(r.affectedBy, "input", "caller-supplied argument #1"), r.affectedBy.toString());
            check("param_seed_covers_all_uses", "all uses".equals(r.seed.access) && "param".equals(r.seed.variableKind),
                r.seed.toMap().toString());
            // The prototype declaration token must resolve to the same thing.
            ClangToken decl = d.token(t -> t instanceof ClangVariableToken && t.getVarnode() == null
                && t.getText().equals(dst.getName()));
            if (decl != null) {
                Result viaToken = d.slice(decl);
                check("declaration_token_matches_variable_seed", texts(viaToken.affects).equals(texts(r.affects)),
                    texts(viaToken.affects) + " vs " + texts(r.affects));
            } else check("declaration_token_matches_variable_seed", false, "no declaration token for " + dst.getName());
        }
        // A call's inputs stop at the nearest named variable; hovering that variable goes further.
        ClangToken memcpy = d.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "memcpy"));
        if (memcpy != null && dst != null) {
            Result r = d.slice(memcpy);
            check("memcpy_affected_by_params_and_length_variable", has(r.affectedBy, "param", dst.getName())
                && hasKind(r.affectedBy, "local") && r.affectedBy.size() == 3, r.affectedBy.toString());
            // The read of the length sits under a cast, so match it by being a read of a local.
            ClangToken len = d.token(t -> t instanceof ClangVariableToken && t.getVarnode() != null
                && t.getVarnode().getDef() != t.getPcodeOp()
                && "local".equals(DataflowSlicer.kindOf(t.getVarnode().getHigh())));
            check("length_variable_affected_by_getenv", len != null
                && has(d.slice(len).affectedBy, "call result", "getenv()"), "token=" + len);
        } else check("memcpy_affected_by_params_and_length_variable", false, d.c);
    }

    // ---- add3(a): return (a + 3) * 2 - 1;

    private void testArithmetic() throws Exception {
        Decompiled d = decompile("add3");
        HighVariable a = d.param(0);
        check("add3_has_parameter", a != null, d.c);
        if (a == null) return;
        Result r = d.slicer.slice(d.slicer.seedForVariable(a));
        check("param_affects_return_value", has(r.affects, "return", "return value"), r.affects.toString());

        PcodeOp ret = d.op(PcodeOp.RETURN);
        Result back = d.slicer.slice(d.slicer.seedForOp(ret));
        check("return_affected_by_param", has(back.affectedBy, "param", a.getName()), back.affectedBy.toString());
        check("return_affected_by_constant", hasKind(back.affectedBy, "constant"), back.affectedBy.toString());

        ClangToken operator = d.token(t -> t instanceof ClangOpToken && t.getPcodeOp() != null
            && t.getPcodeOp().getOutput() != null && t.getPcodeOp().getOpcode() != PcodeOp.RETURN);
        check("add3_has_operator_token", operator != null, d.c);
        if (operator != null) {
            Result op = d.slice(operator);
            check("operator_seed_kind", op.seed.kind == SeedKind.OPERATOR, op.seed.toMap().toString());
            check("operator_affected_by_param", has(op.affectedBy, "param", a.getName()), op.affectedBy.toString());
            check("operator_affects_return_value", has(op.affects, "return", "return value"), op.affects.toString());
        }
    }

    private void testConstantsAndLoads() throws Exception {
        Decompiled safe = decompile("safe_cp");
        ClangToken memcpy = safe.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "memcpy"));
        if (memcpy != null) {
            Result r = safe.slice(memcpy);
            check("constant_length_reported", has(r.affectedBy, "constant", "0x10"), r.affectedBy.toString());
            check("safe_cp_not_affected_by_any_call", !hasKind(r.affectedBy, "call result"), r.affectedBy.toString());
        } else check("constant_length_reported", false, safe.c);

        // uaf(): p = malloc(64); free(p); return *p;
        Decompiled uaf = decompile("uaf");
        Result ret = uaf.slicer.slice(uaf.slicer.seedForOp(uaf.op(PcodeOp.RETURN)));
        check("return_affected_by_memory_read", hasKind(ret.affectedBy, "memory read"), ret.affectedBy.toString());
        ClangToken malloc = uaf.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "malloc"));
        if (malloc != null) {
            Result r = uaf.slice(malloc);
            check("malloc_result_affects_free_argument", has(r.affects, "call argument", "free() argument 1"), r.affects.toString());
            check("malloc_affected_by_size_constant", has(r.affectedBy, "constant", "0x40"), r.affectedBy.toString());
        } else check("malloc_result_affects_free_argument", false, uaf.c);
    }

    // ---- branch_free(cond): if (cond) ...

    private void testBranchCondition() throws Exception {
        Decompiled d = decompile("branch_free");
        HighVariable cond = d.param(0);
        check("branch_free_has_parameter", cond != null, d.c);
        if (cond == null) return;
        Result r = d.slicer.slice(d.slicer.seedForVariable(cond));
        check("param_affects_branch_condition", hasKind(r.affects, "branch"), r.affects.toString());
        PcodeOp branch = d.op(PcodeOp.CBRANCH);
        Result back = d.slicer.slice(d.slicer.seedForOp(branch));
        check("branch_affected_by_param", has(back.affectedBy, "param", cond.getName()), back.affectedBy.toString());
        check("branch_seed_reports_own_effect", hasKind(back.affects, "branch"), back.affects.toString());
    }

    /** A value that lives in memory across a call is reported as possibly modified by it. */
    private void testSideEffects() throws Exception {
        int withCause = 0;
        String sample = "";
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            Decompiled d = decompile(f.getName());
            Iterator<PcodeOpAST> ops = d.high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() != PcodeOp.INDIRECT || op.getOutput() == null) continue;
                Result r = d.slicer.slice(d.slicer.seedForVarnode(op.getOutput(), null, null));
                if (!r.mayBeModifiedBy.isEmpty()) {
                    withCause++;
                    if (sample.isEmpty()) sample = f.getName() + ": " + r.seed.label + " <- " + r.mayBeModifiedBy;
                }
            }
        }
        println("INFO side_effect sample=" + sample);
        check("indirect_names_the_causing_call", withCause > 0 && sample.contains("()"), "withCause=" + withCause + " " + sample);
    }

    private void testIgnoredTokens() throws Exception {
        Decompiled d = decompile("safe_cp");
        ClangToken constant = d.token(t -> t instanceof ClangVariableToken && t.getVarnode() != null && t.getVarnode().isConstant());
        check("constant_token_left_to_scalar_hover", constant != null && d.slicer.seedFromToken(constant) == null,
            "token=" + constant);
        ClangToken ownName = d.token(t -> t instanceof ClangFuncNameToken && t.getPcodeOp() == null);
        check("own_function_name_left_to_signature_hover", ownName != null && d.slicer.seedFromToken(ownName) == null,
            "token=" + ownName);
        ClangToken type = d.token(t -> t instanceof ClangTypeToken);
        check("type_token_left_to_datatype_hover", type != null && d.slicer.seedFromToken(type) == null, "token=" + type);
        check("null_token_ignored", d.slicer.seedFromToken(null) == null, "");
    }

    private void testCaps() throws Exception {
        Decompiled d = decompile("add3");
        HighVariable a = d.param(0);
        if (a == null) { check("depth_cap_truncates", false, d.c); return; }
        Result full = d.slicer.slice(d.slicer.seedForVariable(a));
        check("default_caps_do_not_truncate_small_function", !full.forwardTruncated && !full.backwardTruncated,
            "fwd=" + full.forwardTruncated + " back=" + full.backwardTruncated);

        DataflowSlicer shallow = new DataflowSlicer(currentProgram, d.high, 1, DataflowSlicer.DEFAULT_MAX_VISITED);
        Result cut = shallow.slice(shallow.seedForVariable(a));
        check("depth_cap_truncates", cut.forwardTruncated && !has(cut.affects, "return", "return value"),
            "truncated=" + cut.forwardTruncated + " " + cut.affects);

        DataflowSlicer tiny = new DataflowSlicer(currentProgram, d.high, DataflowSlicer.DEFAULT_MAX_DEPTH, 1);
        Result small = tiny.slice(tiny.seedForOp(d.op(PcodeOp.RETURN)));
        check("visited_cap_truncates", small.backwardTruncated, "items=" + small.affectedBy);
        check("truncation_shown_in_tooltip", String.valueOf(DataflowSlicer.toHtml(small, 12)).contains("limit")
            || small.isEmpty(), String.valueOf(DataflowSlicer.toHtml(small, 12)));
    }

    /** Every token of every function: no exception, bounded time, dedupe holds. */
    private void testSweepAllTokens() throws Exception {
        long start = System.nanoTime();
        int tokens = 0, seeds = 0, duplicates = 0, failures = 0;
        String firstFailure = "";
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            Decompiled d = decompile(f.getName());
            for (ClangToken t : d.tokens) {
                tokens++;
                try {
                    Seed seed = d.slicer.seedFromToken(t);
                    if (seed == null) continue;
                    seeds++;
                    Result r = d.slicer.slice(seed);
                    DataflowSlicer.toHtml(r, DataflowSlicer.DEFAULT_MAX_ITEMS);
                    if (new HashSet<>(keys(r.affectedBy)).size() != r.affectedBy.size()) duplicates++;
                    if (new HashSet<>(keys(r.affects)).size() != r.affects.size()) duplicates++;
                } catch (RuntimeException e) {
                    failures++;
                    if (firstFailure.isEmpty()) firstFailure = f.getName() + " '" + t.getText() + "': " + e;
                }
            }
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        println("INFO sweep tokens=" + tokens + " seeds=" + seeds + " ms=" + ms);
        check("sweep_no_exceptions", failures == 0, failures + " failures, first: " + firstFailure);
        check("sweep_seeds_found", seeds > 50, "seeds=" + seeds);
        check("sweep_items_deduplicated", duplicates == 0, "duplicates=" + duplicates);
        check("sweep_is_fast", ms < 20_000, "ms=" + ms);
    }

    private void testHtml() throws Exception {
        Decompiled d = decompile("fmt");
        ClangToken read = d.token(t -> t instanceof ClangVariableToken && isCallTo(t.getPcodeOp(), "printf")
            && t.getVarnode() != null && !t.getVarnode().isConstant());
        ClangToken call = d.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "getenv"));
        if (read == null || call == null) { check("tooltip_html", false, d.c); return; }
        String varHtml = DataflowSlicer.toHtml(d.slice(read), DataflowSlicer.DEFAULT_MAX_ITEMS);
        String callHtml = DataflowSlicer.toHtml(d.slice(call), DataflowSlicer.DEFAULT_MAX_ITEMS);
        println("INFO tooltip_variable " + varHtml);
        println("INFO tooltip_call " + callHtml);
        check("tooltip_has_both_sections", varHtml.startsWith("<html>") && varHtml.contains("<b>Affected by</b> (1)")
            && varHtml.contains("<b>Affects</b> (1)") && varHtml.contains("getenv()"), varHtml);
        check("tooltip_header_has_type_and_access", varHtml.contains("char *") && varHtml.contains("read here"), varHtml);
        check("tooltip_call_has_signature_line", callHtml.contains("getenv(") && callHtml.contains("call"), callHtml);

        // read_format(): char buf[64]; read(0, buf, 63); ... printf(buf);  -> "&buf" must be escaped
        Decompiled rf = decompile("read_format");
        ClangToken readCall = rf.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "read"));
        Result readResult = rf.slice(readCall);
        String readHtml = DataflowSlicer.toHtml(readResult, 12);
        println("INFO tooltip_read " + readHtml);
        check("stack_buffer_reported_as_address", hasKind(readResult.affectedBy, "address"), readResult.affectedBy.toString());
        check("tooltip_escapes_text", readHtml.contains("&amp;") && !readHtml.contains("<td>&buf"), readHtml);

        // A call with no result and nothing after it still explains its inputs.
        Decompiled df = decompile("null_free");
        ClangToken free = df.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "free"));
        String freeHtml = free == null ? null : DataflowSlicer.toHtml(df.slice(free), 12);
        check("tooltip_shows_none_for_empty_section", freeHtml != null && freeHtml.contains("(none)"), String.valueOf(freeHtml));

        // Item cap: a longer list is cut with a "+N more" line.
        Decompiled cp = decompile("cp");
        ClangToken memcpy = cp.token(t -> t instanceof ClangFuncNameToken && isCallTo(t.getPcodeOp(), "memcpy"));
        Result r = cp.slice(memcpy);
        String capped = DataflowSlicer.toHtml(r, 1);
        check("tooltip_caps_items", r.affectedBy.size() == 3 && capped.contains("+2 more"), capped);
    }

    @SuppressWarnings("unchecked")
    private void testMcpTool() throws Exception {
        DecompInterfacePool pool = new DecompInterfacePool();
        try {
            GetDataflowTool tool = new GetDataflowTool(pool);
            Decompiled d = decompile("cp");
            HighVariable dst = d.param(0);
            Result direct = d.slicer.slice(d.slicer.seedForVariable(dst));
            Map<String, Object> byName = (Map<String, Object>) tool.execute(
                Map.of("function", "cp", "variable", dst.getName()), currentProgram, null);
            check("mcp_variable_matches_slicer", mapTexts(byName, "affects").equals(texts(direct.affects))
                && mapTexts(byName, "affectedBy").equals(texts(direct.affectedBy)),
                byName + " vs " + direct.toMap(50));
            check("mcp_reports_function_and_seed", "cp".equals(byName.get("function"))
                && ((Map<String, Object>) byName.get("seed")).get("label").equals(dst.getName()), byName.toString());

            PcodeOp memcpy = d.call("memcpy");
            String at = memcpy.getSeqnum().getTarget().toString();
            Result directCall = d.slicer.slice(d.slicer.seedForOp(memcpy));
            Map<String, Object> byAddress = (Map<String, Object>) tool.execute(Map.of("address", at), currentProgram, null);
            check("mcp_address_finds_call", "call".equals(((Map<String, Object>) byAddress.get("seed")).get("kind"))
                && mapTexts(byAddress, "affectedBy").equals(texts(directCall.affectedBy)), byAddress.toString());

            Map<String, Object> both = (Map<String, Object>) tool.execute(
                Map.of("function", d.function.getEntryPoint().toString(), "address", at, "variable", dst.getName()),
                currentProgram, null);
            check("mcp_variable_at_address_is_a_read", "read here".equals(((Map<String, Object>) both.get("seed")).get("access"))
                && mapTexts(both, "affects").toString().contains("memcpy() argument 1"), both.toString());

            Map<String, Object> capped = (Map<String, Object>) tool.execute(
                Map.of("address", at, "maxItems", 1), currentProgram, null);
            check("mcp_max_items_keeps_total", GetDataflowTool.list(capped, "affectedBy").size() == 1
                && ((Number) capped.get("affectedByTotal")).intValue() == 3, capped.toString());

            check("mcp_rejects_missing_selector", rejects(tool, Map.of("function", "cp")), "");
            check("mcp_rejects_unknown_variable", rejects(tool, Map.of("function", "cp", "variable", "no_such_var")), "");
            check("mcp_rejects_unknown_function", rejects(tool, Map.of("function", "no_such_fn", "variable", "x")), "");
            check("mcp_rejects_bad_max_items", rejects(tool, Map.of("address", at, "maxItems", 0)), "");
            check("mcp_tool_metadata", "ghidra_get_dataflow".equals(tool.name()) && !tool.isMutating()
                && !tool.requiresEdt() && tool.inputSchema().containsKey("properties"), tool.name());
        } finally {
            pool.disposeAll();
        }
    }

    /** Static shape only: the classes load and declare the hover service. No popup is shown. */
    private void testPluginDeclaration() throws Exception {
        Class<?> plugin = Class.forName("decompfuncutils.DataflowDecompilerHoverPlugin");
        Class<?> hover = Class.forName("decompfuncutils.DataflowDecompilerHover");
        Class<?> service = Class.forName("ghidra.app.decompiler.component.hover.DecompilerHoverService");
        var info = plugin.getAnnotation(ghidra.framework.plugintool.PluginInfo.class);
        check("plugin_declares_hover_service", info != null && Arrays.asList(info.servicesProvided()).contains(service)
            && service.isAssignableFrom(hover) && ghidra.framework.plugintool.Plugin.class.isAssignableFrom(plugin),
            "info=" + info);
    }

    private boolean rejects(GetDataflowTool tool, Map<String, Object> args) {
        try {
            tool.execute(args, currentProgram, null);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        } catch (Exception other) {
            println("INFO unexpected rejection type: " + other);
            return false;
        }
    }

    // ---- helpers

    private final class Decompiled {
        Function function;
        HighFunction high;
        String c;
        List<ClangToken> tokens = new ArrayList<>();
        DataflowSlicer slicer;

        ClangToken token(Predicate<ClangToken> p) {
            for (ClangToken t : tokens) if (p.test(t)) return t;
            return null;
        }

        Result slice(ClangToken t) {
            Seed seed = slicer.seedFromToken(t);
            if (seed == null) throw new IllegalStateException("no seed for token '" + t.getText() + "'");
            return slicer.slice(seed);
        }

        HighVariable param(int slot) {
            Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighVariable hv = it.next().getHighVariable();
                if (hv instanceof HighParam && ((HighParam) hv).getSlot() == slot) return hv;
            }
            return null;
        }

        PcodeOp op(int opcode) {
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() == opcode) return op;
            }
            throw new IllegalStateException("no " + PcodeOp.getMnemonic(opcode) + " in " + function.getName());
        }

        PcodeOp call(String callee) {
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (isCallTo(op, callee)) return op;
            }
            throw new IllegalStateException("no call to " + callee + " in " + function.getName());
        }
    }

    private final Map<String, Decompiled> cache = new HashMap<>();

    private Decompiled decompile(String name) throws Exception {
        Decompiled cached = cache.get(name);
        if (cached != null) return cached;
        Function f = null;
        for (Function candidate : currentProgram.getFunctionManager().getFunctions(true)) {
            if (candidate.getName().equals(name) && !candidate.isExternal()) f = candidate;
        }
        if (f == null) throw new IllegalStateException("function not found: " + name);
        DecompileResults res = decomp.decompileFunction(f, 60, monitor);
        if (!res.decompileCompleted() || res.getHighFunction() == null) {
            throw new IllegalStateException("decompile failed: " + name + ": " + res.getErrorMessage());
        }
        Decompiled d = new Decompiled();
        d.function = f;
        d.high = res.getHighFunction();
        d.c = res.getDecompiledFunction().getC().replaceAll("\\s+", " ");
        List<ClangNode> nodes = new ArrayList<>();
        res.getCCodeMarkup().flatten(nodes);
        for (ClangNode n : nodes) if (n instanceof ClangToken) d.tokens.add((ClangToken) n);
        d.slicer = new DataflowSlicer(currentProgram, d.high);
        cache.put(name, d);
        return d;
    }

    private boolean isCallTo(PcodeOp op, String callee) {
        if (op == null || op.getOpcode() != PcodeOp.CALL) return false;
        Function f = currentProgram.getFunctionManager().getFunctionAt(op.getInput(0).getAddress());
        if (f != null && f.isThunk()) f = f.getThunkedFunction(true);
        return f != null && f.getName().equals(callee);
    }

    private static boolean has(List<Item> items, String kind, String textPrefix) {
        for (Item i : items) if (i.kind.equals(kind) && i.text.startsWith(textPrefix)) return true;
        return false;
    }

    private static boolean hasKind(List<Item> items, String kind) {
        for (Item i : items) if (i.kind.equals(kind)) return true;
        return false;
    }

    private static List<String> texts(List<Item> items) {
        List<String> out = new ArrayList<>();
        for (Item i : items) out.add(i.text);
        return out;
    }

    private static List<String> keys(List<Item> items) {
        List<String> out = new ArrayList<>();
        for (Item i : items) out.add(i.kind + "|" + i.text);
        return out;
    }

    private static List<String> mapTexts(Map<String, Object> result, String key) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> m : GetDataflowTool.list(result, key)) out.add(String.valueOf(m.get("text")));
        return out;
    }

    private void check(String name, boolean cond, String detail) {
        if (cond) { passed++; println("CHECK " + name + ": PASS"); }
        else { failed++; println("CHECK " + name + ": FAIL (" + detail + ")"); }
    }
}
