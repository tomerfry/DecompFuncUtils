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
 * <p>The walk does not stop at the edge of a program. When the function it has reached is one
 * another loaded module imports, it carries on from that module's calls to the import, so a
 * destination inside a library guides the search from the first instruction of the program that
 * uses the library.
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

    /** Address ranges (inclusive, as the worker sees them) of blocks that cannot lead to a destination. */
    public final List<long[]> nonReach;
    /** Functions from which a destination can be reached by direct calls, the destinations' own included. */
    public final int functions;
    /** How many programs those functions are spread over. */
    public final int programs;
    public final int blocks;
    public final int blocksSetAside;

    private AngrReach(List<long[]> nonReach, int functions, int programs, int blocks, int blocksSetAside) {
        this.nonReach = nonReach;
        this.functions = functions;
        this.programs = programs;
        this.blocks = blocks;
        this.blocksSetAside = blocksSetAside;
    }

    /** One sentence for whoever reads the result. */
    public String describe() {
        return "Guided by Ghidra's control-flow graph: " + functions + " function(s)"
            + (programs > 1 ? " in " + programs + " modules" : "") + " lead to the destination, "
            + blocksSetAside + " of their " + blocks + " blocks cannot reach it and are tried last.";
    }

    /** A function, told apart from the function at the same address of another program. */
    private record Node(Program program, Address entry) {
    }

    /** The guidance for one destination in the program the session runs. */
    public static AngrReach compute(Program program, Function entry, Address destination, TaskMonitor monitor)
            throws CancelledException {
        return compute(AngrModules.single(program), entry,
            List.of(new AngrModules.Location(program, destination)), monitor);
    }

    /**
     * @param entry        the function the session started in, in the first module
     * @param destinations where to get to, each in one of the modules
     * @return the guidance, or null when the graph has nothing useful to say - no destination is
     *         inside a function, or no chain of direct calls connects the entry to one
     */
    public static AngrReach compute(AngrModules modules, Function entry,
            List<AngrModules.Location> destinations, TaskMonitor monitor) throws CancelledException {
        if (entry == null) {
            return null;
        }
        // Every function that can get to a destination's function by direct calls, with the
        // call sites that take it one step closer, and the destinations it holds itself.
        Map<Node, Set<Address>> towards = new LinkedHashMap<>();
        Map<Node, Set<Address>> arrivals = new HashMap<>();
        Deque<Node> queue = new ArrayDeque<>();
        for (AngrModules.Location destination : destinations) {
            if (!modules.contains(destination.program())) {
                continue;
            }
            Function target = destination.program().getFunctionManager()
                .getFunctionContaining(destination.address());
            if (target == null) {
                continue;
            }
            Node node = new Node(destination.program(), target.getEntryPoint());
            if (towards.putIfAbsent(node, new HashSet<>()) == null) {
                queue.add(node);
            }
            arrivals.computeIfAbsent(node, n -> new HashSet<>()).add(destination.address());
        }
        if (towards.isEmpty()) {
            return null;
        }
        while (!queue.isEmpty() && towards.size() < MAX_FUNCTIONS) {
            monitor.checkCancelled();
            Node node = queue.removeFirst();
            Function callee = node.program().getFunctionManager().getFunctionAt(node.entry());
            if (callee == null) {
                continue;
            }
            callers(node.program(), callee, towards, queue);
            // Where another module imports this function, its calls to the import lead here too.
            for (AngrModules.Link link : modules.importersOf(node.program(), node.entry())) {
                callers(link.importer.program, link.external, towards, queue);
            }
        }
        if (!towards.containsKey(new Node(modules.main(), entry.getEntryPoint()))) {
            return null;
        }

        Map<Program, BasicBlockModel> models = new IdentityHashMap<>();
        Set<Program> programs = Collections.newSetFromMap(new IdentityHashMap<>());
        List<long[]> nonReach = new ArrayList<>();
        int total = 0;
        int setAside = 0;
        for (Map.Entry<Node, Set<Address>> item : towards.entrySet()) {
            monitor.checkCancelled();
            Program program = item.getKey().program();
            Function function = program.getFunctionManager().getFunctionAt(item.getKey().entry());
            AngrModules.Module module = modules.moduleOf(program);
            if (function == null || module == null) {
                continue;
            }
            programs.add(program);
            BasicBlockModel model = models.computeIfAbsent(program, BasicBlockModel::new);
            List<CodeBlock> blocks = new ArrayList<>();
            CodeBlockIterator iterator = model.getCodeBlocksContaining(function.getBody(), monitor);
            while (iterator.hasNext()) {
                blocks.add(iterator.next());
            }
            total += blocks.size();
            if (total > MAX_BLOCKS) {
                return null;
            }

            // Blocks that are a way forward by themselves: a destination, and each call that
            // goes one function closer to one.
            Set<Address> forwards = new HashSet<>(item.getValue());
            forwards.addAll(arrivals.getOrDefault(item.getKey(), Set.of()));
            Set<Address> reaching = new HashSet<>();
            Deque<CodeBlock> work = new ArrayDeque<>();
            for (CodeBlock block : blocks) {
                boolean forward = false;
                for (Address address : forwards) {
                    forward |= block.contains(address);
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
                    nonReach.add(new long[] { module.toAngr(range.getMinAddress()),
                        module.toAngr(range.getMaxAddress()) });
                }
            }
        }
        return new AngrReach(nonReach, towards.size(), programs.size(), total, setAside);
    }

    /** Adds the functions of a program that call {@code callee} directly, with where they do. */
    private static void callers(Program program, Function callee, Map<Node, Set<Address>> towards,
            Deque<Node> queue) {
        FunctionManager functions = program.getFunctionManager();
        ReferenceManager references = program.getReferenceManager();
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
                Node node = new Node(program, caller.getEntryPoint());
                Set<Address> sites = towards.get(node);
                if (sites == null) {
                    sites = new HashSet<>();
                    towards.put(node, sites);
                    queue.add(node);
                }
                sites.add(site);
            }
        }
    }
}
