package decompfuncutils.angr;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * What Ghidra's control-flow graph says about getting to a destination: which blocks, in the
 * functions on the way there, cannot lead to it.
 *
 * <p>A search for a destination that follows every fork wastes most of its time on paths that
 * have already left the way - an error exit, the wrong arm of a switch. Ghidra knows the shape of
 * the code, so the search can be told. Starting from the destination, this walks the call graph
 * upwards to find every function from which it can be reached by direct calls, and in each of
 * those marks the blocks from which neither the destination nor a call towards it is reachable.
 *
 * <p>The answer is advice, not a verdict. Static analysis misses indirect calls and anything
 * Ghidra did not disassemble, so the search sets such paths aside rather than discarding them,
 * and comes back to them when nothing else is left.
 */
public final class AngrReach {

    /** Upper bounds that keep a pathological program from stalling the search before it starts. */
    private static final int MAX_FUNCTIONS = 400;
    private static final int MAX_BLOCKS = 60_000;
    private static final int MAX_RANGES = 20_000;

    /** Address ranges (inclusive) of blocks that cannot lead to the destination. */
    public final List<long[]> nonReach;
    /** Functions from which the destination can be reached by direct calls, the destination's own included. */
    public final int functions;
    public final int blocks;
    public final int blocksSetAside;

    private AngrReach(List<long[]> nonReach, int functions, int blocks, int blocksSetAside) {
        this.nonReach = nonReach;
        this.functions = functions;
        this.blocks = blocks;
        this.blocksSetAside = blocksSetAside;
    }

    /** One sentence for whoever reads the result. */
    public String describe() {
        return "Guided by Ghidra's control-flow graph: " + functions + " function(s) lead to the destination, "
            + blocksSetAside + " of their " + blocks + " blocks cannot reach it and are tried last.";
    }

    /**
     * @param entry the function the session started in
     * @return the guidance, or null when the graph has nothing useful to say - the destination is
     *         not inside a function, or no chain of direct calls connects the entry to it
     */
    public static AngrReach compute(Program program, Function entry, Address destination, TaskMonitor monitor)
            throws CancelledException {
        FunctionManager functions = program.getFunctionManager();
        Function target = functions.getFunctionContaining(destination);
        if (target == null || entry == null) {
            return null;
        }
        ReferenceManager references = program.getReferenceManager();

        // Every function that can get to the destination's function by direct calls, with the
        // call sites that take it one step closer.
        Map<Function, Set<Address>> towards = new LinkedHashMap<>();
        towards.put(target, new HashSet<>());
        Deque<Function> queue = new ArrayDeque<>(List.of(target));
        while (!queue.isEmpty() && towards.size() < MAX_FUNCTIONS) {
            monitor.checkCancelled();
            Function callee = queue.removeFirst();
            List<Address> entries = new ArrayList<>(List.of(callee.getEntryPoint()));
            // A call usually lands on a thunk (a PLT stub) rather than on the function itself.
            Address[] thunks = callee.getFunctionThunkAddresses(true);
            if (thunks != null) {
                entries.addAll(Arrays.asList(thunks));
            }
            for (Address callTarget : entries) {
                for (Reference reference : references.getReferencesTo(callTarget)) {
                    if (!reference.getReferenceType().isFlow()) {
                        continue;
                    }
                    Address site = reference.getFromAddress();
                    Function caller = site == null ? null : functions.getFunctionContaining(site);
                    if (caller == null || caller.isThunk()) {
                        continue;
                    }
                    Set<Address> sites = towards.get(caller);
                    if (sites == null) {
                        sites = new HashSet<>();
                        towards.put(caller, sites);
                        queue.add(caller);
                    }
                    sites.add(site);
                }
            }
        }
        if (!towards.containsKey(entry)) {
            return null;
        }

        BasicBlockModel model = new BasicBlockModel(program);
        List<long[]> nonReach = new ArrayList<>();
        int total = 0;
        int setAside = 0;
        for (Map.Entry<Function, Set<Address>> item : towards.entrySet()) {
            monitor.checkCancelled();
            Function function = item.getKey();
            List<CodeBlock> blocks = new ArrayList<>();
            CodeBlockIterator iterator = model.getCodeBlocksContaining(function.getBody(), monitor);
            while (iterator.hasNext()) {
                blocks.add(iterator.next());
            }
            total += blocks.size();
            if (total > MAX_BLOCKS) {
                return null;
            }

            // Blocks that are a way forward by themselves: the destination, and each call that
            // goes one function closer to it.
            Set<Address> reaching = new HashSet<>();
            Deque<CodeBlock> work = new ArrayDeque<>();
            for (CodeBlock block : blocks) {
                boolean forward = function.equals(target) && block.contains(destination);
                for (Address site : item.getValue()) {
                    forward |= block.contains(site);
                }
                if (forward && reaching.add(block.getFirstStartAddress())) {
                    work.add(block);
                }
            }
            while (!work.isEmpty()) {
                monitor.checkCancelled();
                CodeBlock block = work.removeFirst();
                CodeBlockReferenceIterator sources = block.getSources(monitor);
                while (sources.hasNext()) {
                    CodeBlockReference source = sources.next();
                    // Callers also count as "sources" of a function's first block; only flow
                    // inside the function says anything about reaching the destination from it.
                    if (source.getFlowType().isCall()
                            || !function.getBody().contains(source.getSourceAddress())) {
                        continue;
                    }
                    CodeBlock previous = source.getSourceBlock();
                    if (previous != null && reaching.add(previous.getFirstStartAddress())) {
                        work.add(previous);
                    }
                }
            }
            for (CodeBlock block : blocks) {
                if (reaching.contains(block.getFirstStartAddress())) {
                    continue;
                }
                setAside++;
                for (AddressRange range : block.getAddressRanges()) {
                    if (nonReach.size() >= MAX_RANGES) {
                        return null;
                    }
                    nonReach.add(new long[] { range.getMinAddress().getOffset(), range.getMaxAddress().getOffset() });
                }
            }
        }
        return new AngrReach(nonReach, towards.size(), total, setAside);
    }
}
