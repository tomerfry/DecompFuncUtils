package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Static path-condition extraction. Decompiles the enclosing function, enumerates
 * control-flow paths from the entry block to the block containing a target address,
 * and for each path returns the conjunction of branch conditions that must hold.
 *
 * Loops are handled by visit-count capping (loopUnroll). The result is an
 * under-approximation when loops are present — surfaced via 'truncated' flags.
 */
public class PathConstraintsTool implements McpTool {

    private static final int DEFAULT_MAX_PATHS = 16;
    private static final int HARD_MAX_PATHS = 256;
    private static final int DEFAULT_LOOP_UNROLL = 1;
    private static final int DEFAULT_MAX_EXPR_DEPTH = 8;
    private static final int DEFAULT_DECOMPILE_TIMEOUT = 30;

    private final DecompInterfacePool decompPool;

    public PathConstraintsTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override public String name() { return "ghidra_path_constraints"; }

    @Override
    public String description() {
        return "Static extraction of path conditions: enumerates control-flow paths from the " +
               "enclosing function's entry to a target address and returns the conjunction of " +
               "conditional-branch conditions each path requires. Conditions are rendered as " +
               "expressions in terms of decompiler-named variables (params, locals, globals) " +
               "when available. Loops are bounded by 'loopUnroll' (visits per block per path); " +
               "results are an under-approximation when unroll is exceeded (see 'truncated' flag).";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("function", Map.of("type", "string",
            "description", "Entry address (hex) of the enclosing function"));
        props.put("targetAddress", Map.of("type", "string",
            "description", "Address (hex) whose containing basic block we want to reach"));
        props.put("maxPaths", Map.of("type", "integer",
            "description", "Max number of paths to enumerate (default 16, hard cap 256)"));
        props.put("loopUnroll", Map.of("type", "integer",
            "description", "Max times a block may appear in one path minus 1 (default 1 → block can appear twice; 0 → acyclic only)"));
        props.put("maxExpressionDepth", Map.of("type", "integer",
            "description", "Max recursion depth when rendering a condition expression (default 8)"));
        schema.put("properties", props);
        schema.put("required", List.of("function", "targetAddress"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalStateException("No program is open");

        Address funcAddr = McpUtil.parseAddress((String) arguments.get("function"), program);
        Address target = McpUtil.parseAddress((String) arguments.get("targetAddress"), program);
        int maxPaths = Math.min(
            ((Number) arguments.getOrDefault("maxPaths", DEFAULT_MAX_PATHS)).intValue(),
            HARD_MAX_PATHS);
        int loopUnroll = Math.max(0,
            ((Number) arguments.getOrDefault("loopUnroll", DEFAULT_LOOP_UNROLL)).intValue());
        int maxExprDepth = ((Number) arguments.getOrDefault("maxExpressionDepth",
            DEFAULT_MAX_EXPR_DEPTH)).intValue();

        Function func = program.getFunctionManager().getFunctionAt(funcAddr);
        if (func == null) {
            // Fall back to containing function
            func = program.getFunctionManager().getFunctionContaining(funcAddr);
        }
        if (func == null) throw new IllegalArgumentException("No function at or containing " + funcAddr);

        DecompInterface decomp = decompPool.acquire(program);
        try {
            DecompileResults results = decomp.decompileFunction(func, DEFAULT_DECOMPILE_TIMEOUT, TaskMonitor.DUMMY);
            if (results == null || !results.decompileCompleted()) {
                throw new RuntimeException("Decompilation failed: "
                    + (results != null ? results.getErrorMessage() : "null result"));
            }
            HighFunction hf = results.getHighFunction();
            if (hf == null) throw new RuntimeException("No HighFunction produced");

            ArrayList<PcodeBlockBasic> blocks = hf.getBasicBlocks();
            if (blocks == null || blocks.isEmpty()) {
                throw new RuntimeException("Function has no basic blocks");
            }

            PcodeBlockBasic entry = blocks.get(0);

            // Find all blocks containing the target address (there may be none if target
            // sits between instructions, or multiple if overlapping — take the exact hit first).
            List<PcodeBlockBasic> targetBlocks = new ArrayList<>();
            for (PcodeBlockBasic b : blocks) {
                if (b.contains(target)) targetBlocks.add(b);
            }
            if (targetBlocks.isEmpty()) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("function", func.getName());
                out.put("functionAddress", func.getEntryPoint().toString());
                out.put("targetAddress", target.toString());
                out.put("paths", Collections.emptyList());
                out.put("note", "No basic block in this function contains the target address.");
                return out;
            }

            Set<PcodeBlockBasic> targetSet = new HashSet<>(targetBlocks);

            PcodeExpressionRenderer renderer = new PcodeExpressionRenderer(program, maxExprDepth);

            List<Map<String, Object>> paths = new ArrayList<>();
            boolean[] truncated = new boolean[] { false };
            Deque<PcodeBlockBasic> stack = new ArrayDeque<>();
            Map<PcodeBlockBasic, Integer> visitCount = new HashMap<>();
            dfs(entry, targetSet, stack, visitCount, loopUnroll, maxPaths, paths, truncated, renderer);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("function", func.getName());
            out.put("functionAddress", func.getEntryPoint().toString());
            out.put("targetAddress", target.toString());
            out.put("targetBlocks", targetBlocks.size());
            out.put("pathCount", paths.size());
            out.put("paths", paths);
            if (truncated[0]) {
                out.put("truncated", true);
                out.put("truncatedNote",
                    "Path enumeration hit maxPaths or loopUnroll limit. Returned paths are a " +
                    "subset — conditions are under-approximate. Increase maxPaths or loopUnroll to see more.");
            }
            return out;
        } finally {
            decompPool.release(program, decomp);
        }
    }

    private void dfs(PcodeBlockBasic current,
                     Set<PcodeBlockBasic> targetSet,
                     Deque<PcodeBlockBasic> stack,
                     Map<PcodeBlockBasic, Integer> visitCount,
                     int loopUnroll,
                     int maxPaths,
                     List<Map<String, Object>> paths,
                     boolean[] truncated,
                     PcodeExpressionRenderer renderer) {
        if (paths.size() >= maxPaths) { truncated[0] = true; return; }

        int cnt = visitCount.getOrDefault(current, 0);
        if (cnt > loopUnroll) { truncated[0] = true; return; }

        stack.push(current);
        visitCount.put(current, cnt + 1);
        try {
            if (targetSet.contains(current)) {
                paths.add(buildPathRecord(stack, renderer));
                return;
            }
            int outN = current.getOutSize();
            for (int i = 0; i < outN; i++) {
                if (paths.size() >= maxPaths) { truncated[0] = true; return; }
                var next = current.getOut(i);
                if (next instanceof PcodeBlockBasic nb) {
                    dfs(nb, targetSet, stack, visitCount, loopUnroll, maxPaths, paths, truncated, renderer);
                }
            }
        } finally {
            stack.pop();
            visitCount.put(current, cnt);
        }
    }

    private Map<String, Object> buildPathRecord(Deque<PcodeBlockBasic> stack,
                                                PcodeExpressionRenderer renderer) {
        // Stack top = current (target) block; walk from bottom (entry) to top.
        List<PcodeBlockBasic> seq = new ArrayList<>(stack);
        Collections.reverse(seq);

        List<Map<String, Object>> blocks = new ArrayList<>();
        List<Map<String, Object>> conditions = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            PcodeBlockBasic b = seq.get(i);
            Map<String, Object> bi = new LinkedHashMap<>();
            bi.put("index", b.getIndex());
            bi.put("start", b.getStart() != null ? b.getStart().toString() : null);
            bi.put("stop", b.getStop() != null ? b.getStop().toString() : null);
            blocks.add(bi);

            if (i + 1 < seq.size()) {
                PcodeBlockBasic next = seq.get(i + 1);
                Map<String, Object> cond = edgeCondition(b, next, renderer);
                if (cond != null) conditions.add(cond);
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("blocks", blocks);
        out.put("blockCount", seq.size());
        out.put("conditions", conditions);
        out.put("conditionSummary", summarize(conditions));
        return out;
    }

    private Map<String, Object> edgeCondition(PcodeBlockBasic from, PcodeBlockBasic to,
                                              PcodeExpressionRenderer renderer) {
        PcodeOp last = from.getLastOp();
        if (last == null || last.getOpcode() != PcodeOp.CBRANCH) return null;
        // CBRANCH inputs: [0] = branch target offset, [1] = condition varnode
        // from.getTrueOut() is the block taken when condition != 0.
        var trueOut = from.getTrueOut();
        var falseOut = from.getFalseOut();
        boolean taken;
        if (to.equals(trueOut)) taken = true;
        else if (to.equals(falseOut)) taken = false;
        else return null; // edge isn't a CBRANCH branch edge (shouldn't normally happen)

        String rendered = renderer.render(last.getInput(1));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("fromBlock", from.getIndex());
        out.put("toBlock", to.getIndex());
        out.put("pc", last.getSeqnum() != null && last.getSeqnum().getTarget() != null
            ? last.getSeqnum().getTarget().toString() : null);
        out.put("taken", taken);
        out.put("condition", taken ? rendered : "!(" + rendered + ")");
        out.put("rawCondition", rendered);
        return out;
    }

    private static String summarize(List<Map<String, Object>> conditions) {
        if (conditions.isEmpty()) return "true";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < conditions.size(); i++) {
            if (i > 0) sb.append(" && ");
            sb.append(conditions.get(i).get("condition"));
        }
        return sb.toString();
    }
}
