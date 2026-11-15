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
 * What Ghidra's control-flow graph says about getting to a destination: in the functions on the
 * way there, which blocks cannot lead to it, and from the others how far it is.
 *
 * <p>A search for a destination that follows every fork wastes most of its time on paths that
 * have already left the way - an error exit, the wrong arm of a switch - and, where a loop forks
 * on every iteration, on following all of them abreast. Ghidra knows the shape of the code, so
 * the search can be told. Starting from the destination, this walks the call graph upwards to
 * find every function from which it can be reached by direct calls. In each of those it marks
 * the blocks from which neither the destination nor a call towards it is reachable, and gives
 * every other block the number of blocks still to go: to the destination itself, or to the call
 * that leads on plus what remains inside the function called.
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
    /** What a call towards the destination costs when the way through the function called is not known. */
    private static final int UNKNOWN_CALL = 64;
    private static final int UNREACHED = Integer.MAX_VALUE;

    /** Address ranges (inclusive, as the worker sees them) of blocks that cannot lead to a destination. */
    public final List<long[]> nonReach;
    /**
     * Address ranges (inclusive) of blocks that can, each with the number of blocks still to go:
     * {@code {low, high, blocks}}. Empty when there are too many to be worth sending; the search
     * then still knows which blocks to set aside, just not which of the others to prefer.
     */
    public final List<long[]> ranks;
    /** Functions from which a destination can be reached by direct calls, the destinations' own included. */
    public final int functions;
    /** How many programs those functions are spread over. */
    public final int programs;
    public final int blocks;
    public final int blocksSetAside;

    private AngrReach(List<long[]> nonReach, List<long[]> ranks, int functions, int programs, int blocks,
            int blocksSetAside) {
        this.nonReach = nonReach;
        this.ranks = ranks;
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

    /** One function on the way: its blocks, how they follow each other, and where the way forward is. */
    private static final class Graph {
        final AngrModules.Module module;
        final List<CodeBlock> blocks = new ArrayList<>();
        /** For each block, the blocks of the same function that flow into it. */
        final List<List<Integer>> predecessors = new ArrayList<>();
        /** Blocks holding a destination. */
        final Set<Integer> arrivals = new HashSet<>();
        /** Blocks holding a call one function closer to a destination, with the functions called. */
        final Map<Integer, Set<Node>> calls = new HashMap<>();
        int entry = -1;
        int[] cost;

        Graph(AngrModules.Module module) {
            this.module = module;
        }
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
        // call sites that take it one step closer (and where each leads), and the destinations
        // it holds itself.
        Map<Node, Map<Address, Node>> towards = new LinkedHashMap<>();
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
            if (towards.putIfAbsent(node, new HashMap<>()) == null) {
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
            callers(node.program(), callee, node, towards, queue);
            // Where another module imports this function, its calls to the import lead here too.
            for (AngrModules.Link link : modules.importersOf(node.program(), node.entry())) {
                callers(link.importer.program, link.external, node, towards, queue);
            }
        }
        if (!towards.containsKey(new Node(modules.main(), entry.getEntryPoint()))) {
            return null;
        }

        // The shape of each of those functions.
        Map<Program, BasicBlockModel> models = new IdentityHashMap<>();
        Set<Program> programs = Collections.newSetFromMap(new IdentityHashMap<>());
        Map<Node, Graph> graphs = new LinkedHashMap<>();
        int total = 0;
        for (Map.Entry<Node, Map<Address, Node>> item : towards.entrySet()) {
            monitor.checkCancelled();
            Program program = item.getKey().program();
            Function function = program.getFunctionManager().getFunctionAt(item.getKey().entry());
            AngrModules.Module module = modules.moduleOf(program);
            if (function == null || module == null) {
                continue;
            }
            programs.add(program);
            BasicBlockModel model = models.computeIfAbsent(program, BasicBlockModel::new);
            Graph graph = new Graph(module);
            Map<Address, Integer> index = new HashMap<>();
            CodeBlockIterator iterator = model.getCodeBlocksContaining(function.getBody(), monitor);
            while (iterator.hasNext()) {
                CodeBlock block = iterator.next();
                index.put(block.getFirstStartAddress(), graph.blocks.size());
                graph.blocks.add(block);
            }
            total += graph.blocks.size();
            if (total > MAX_BLOCKS) {
                return null;
            }
            Set<Address> here = arrivals.getOrDefault(item.getKey(), Set.of());
            for (int i = 0; i < graph.blocks.size(); i++) {
                monitor.checkCancelled();
                CodeBlock block = graph.blocks.get(i);
                if (block.contains(function.getEntryPoint())) {
                    graph.entry = i;
                }
                for (Address address : here) {
                    if (block.contains(address)) {
                        graph.arrivals.add(i);
                    }
                }
                for (Map.Entry<Address, Node> site : item.getValue().entrySet()) {
                    if (block.contains(site.getKey())) {
                        graph.calls.computeIfAbsent(i, k -> new HashSet<>()).add(site.getValue());
                    }
                }
                List<Integer> before = new ArrayList<>();
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
                    Integer from = previous == null ? null : index.get(previous.getFirstStartAddress());
                    if (from != null) {
                        before.add(from);
                    }
                }
                graph.predecessors.add(before);
            }
            graphs.put(item.getKey(), graph);
        }

        // How far it is from each block. What a call towards the destination costs depends on
        // the function called, which may be one not measured yet (the functions come in the
        // order they were found, callee before caller, but calls go every which way): a few
        // rounds settle it.
        Map<Node, Integer> fromEntry = new HashMap<>();
        for (int round = 0; round < 4; round++) {
            boolean changed = false;
            for (Map.Entry<Node, Graph> item : graphs.entrySet()) {
                monitor.checkCancelled();
                Graph graph = item.getValue();
                graph.cost = distances(graph, fromEntry);
                Integer cost = graph.entry >= 0 && graph.cost[graph.entry] != UNREACHED
                    ? Integer.valueOf(graph.cost[graph.entry]) : null;
                if (!Objects.equals(cost, fromEntry.get(item.getKey()))) {
                    fromEntry.put(item.getKey(), cost);
                    changed = true;
                }
            }
            if (!changed) {
                break;
            }
        }

        List<long[]> nonReach = new ArrayList<>();
        List<long[]> ranks = new ArrayList<>();
        int setAside = 0;
        for (Graph graph : graphs.values()) {
            for (int i = 0; i < graph.blocks.size(); i++) {
                boolean reaches = graph.cost[i] != UNREACHED;
                if (!reaches) {
                    setAside++;
                }
                for (AddressRange range : graph.blocks.get(i).getAddressRanges()) {
                    long low = graph.module.toAngr(range.getMinAddress());
                    long high = graph.module.toAngr(range.getMaxAddress());
                    if (reaches) {
                        ranks.add(new long[] { low, high, graph.cost[i] });
                        continue;
                    }
                    if (nonReach.size() >= MAX_RANGES) {
                        return null;
                    }
                    nonReach.add(new long[] { low, high });
                }
            }
        }
        if (ranks.size() > MAX_RANGES) {
            ranks = List.of();
        }
        return new AngrReach(nonReach, ranks, towards.size(), programs.size(), total, setAside);
    }

    /**
     * The number of blocks from each block of a function to the nearest way forward: zero in a
     * block holding a destination; in a block calling a function one step closer, one more than
     * it is from that function's entry.
     */
    private static int[] distances(Graph graph, Map<Node, Integer> fromEntry) {
        int[] cost = new int[graph.blocks.size()];
        Arrays.fill(cost, UNREACHED);
        PriorityQueue<int[]> queue = new PriorityQueue<>(Comparator.comparingInt(item -> item[0]));
        for (int block : graph.arrivals) {
            cost[block] = 0;
            queue.add(new int[] { 0, block });
        }
        for (Map.Entry<Integer, Set<Node>> call : graph.calls.entrySet()) {
            int best = UNREACHED;
            for (Node callee : call.getValue()) {
                Integer inside = fromEntry.get(callee);
                best = Math.min(best, 1 + (inside == null ? UNKNOWN_CALL : inside));
            }
            if (best < cost[call.getKey()]) {
                cost[call.getKey()] = best;
                queue.add(new int[] { best, call.getKey() });
            }
        }
        while (!queue.isEmpty()) {
            int[] item = queue.remove();
            if (item[0] > cost[item[1]]) {
                continue;
            }
            for (int previous : graph.predecessors.get(item[1])) {
                if (item[0] + 1 < cost[previous]) {
                    cost[previous] = item[0] + 1;
                    queue.add(new int[] { cost[previous], previous });
                }
            }
        }
        return cost;
    }

    /**
     * Adds the functions of a program that call {@code callee} directly, with where they do.
     *
     * @param leadsTo the function those calls end up in: {@code callee} itself, or - when
     *                {@code callee} is an import - the function of another module it stands for
     */
    private static void callers(Program program, Function callee, Node leadsTo,
            Map<Node, Map<Address, Node>> towards, Deque<Node> queue) {
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
                Map<Address, Node> sites = towards.get(node);
                if (sites == null) {
                    sites = new HashMap<>();
                    towards.put(node, sites);
                    queue.add(node);
                }
                sites.put(site, leadsTo);
            }
        }
    }
}
