package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;
import java.util.Map;

/**
 * Lazily decompiles functions encountered during emulation and indexes
 * CBRANCH pcode ops by their instruction address, so the emulator can
 * attach a symbolic condition to each concrete conditional branch it records.
 */
public class SymbolicBranchResolver {

    public static class Result {
        public final String rawCondition;
        public Result(String rawCondition) { this.rawCondition = rawCondition; }
    }

    private final Program program;
    private final DecompInterfacePool pool;
    private final PcodeExpressionRenderer renderer;

    // Per-function index: instruction address -> CBRANCH pcode op.
    private final Map<Function, Map<Address, PcodeOp>> indexByFunction = new HashMap<>();
    // Per-function failure reason cache (so we don't redecompile).
    private final Map<Function, String> failureReason = new HashMap<>();
    // Last resolution miss reason keyed by pc (for diagnostics).
    private String lastMissReason = null;

    public SymbolicBranchResolver(Program program, DecompInterfacePool pool, int maxExprDepth) {
        this.program = program;
        this.pool = pool;
        this.renderer = new PcodeExpressionRenderer(program, maxExprDepth);
    }

    public Result resolve(Address pc) {
        Function func = program.getFunctionManager().getFunctionContaining(pc);
        if (func == null) { lastMissReason = "no containing function"; return null; }

        Map<Address, PcodeOp> index = ensureIndexed(func);
        if (index == null) {
            lastMissReason = failureReason.getOrDefault(func, "decompilation failed");
            return null;
        }
        PcodeOp cbranch = index.get(pc);
        if (cbranch == null) {
            lastMissReason = "no CBRANCH at this address in HighFunction";
            return null;
        }
        String rendered = renderer.render(cbranch.getInput(1));
        return new Result(rendered);
    }

    public String lastReason(Address pc) {
        return lastMissReason;
    }

    private Map<Address, PcodeOp> ensureIndexed(Function func) {
        Map<Address, PcodeOp> existing = indexByFunction.get(func);
        if (existing != null) return existing;
        if (failureReason.containsKey(func)) return null;

        DecompInterface decomp = pool.acquire(program);
        try {
            DecompileResults res = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
            if (res == null || !res.decompileCompleted()) {
                failureReason.put(func, res != null && res.getErrorMessage() != null
                    ? "decompile error: " + res.getErrorMessage() : "decompile failed");
                return null;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                failureReason.put(func, "no HighFunction produced");
                return null;
            }
            Map<Address, PcodeOp> idx = new HashMap<>();
            for (PcodeBlockBasic b : hf.getBasicBlocks()) {
                PcodeOp last = b.getLastOp();
                if (last != null && last.getOpcode() == PcodeOp.CBRANCH) {
                    Address target = (last.getSeqnum() != null) ? last.getSeqnum().getTarget() : null;
                    if (target != null) idx.put(target, last);
                }
            }
            indexByFunction.put(func, idx);
            return idx;
        } catch (Exception e) {
            failureReason.put(func, "exception: " + e.getMessage());
            return null;
        } finally {
            pool.release(program, decomp);
        }
    }
}
