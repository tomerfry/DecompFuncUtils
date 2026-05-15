package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Automates the "audit integer truncation by hand" workflow described in the
 * 2026-04-17 field note. The DSL forms `(int)$big` and `$big & 0xffffffff` do
 * not reliably match real SUBPIECE / INT_AND-low-mask p-code because the
 * narrowing cast is almost never emitted as a stand-alone decompiled
 * statement — it is folded into the malloc/memcpy argument and only shows
 * up at the p-code level. This tool walks the def-use chain of every
 * allocation-size and copy-length argument directly in p-code, detects any
 * narrowing op (SUBPIECE, INT_AND with a 0xff/0xffff/0xffffffff mask,
 * CAST/COPY with a smaller output), and pairs alloc-side narrowed sources
 * against same-source copy-length arguments at a wider width.
 *
 * Returns a structured report so callers do not have to eyeball decomp.
 */
public class FindIntegerTruncationTool implements McpTool {

    private static final int DEFAULT_DEF_CHAIN_DEPTH = 24;

    private final DecompInterfacePool decompPool;

    public FindIntegerTruncationTool(DecompInterfacePool decompPool) {
        this.decompPool = decompPool;
    }

    @Override public String name() { return "ghidra_find_integer_truncation"; }

    @Override
    public String description() {
        return "Find integer-truncation → heap-overflow candidates by walking p-code from every "
            + "malloc/realloc/calloc/memalign/operator.new and memcpy/memmove/mempcpy/__memcpy_chk "
            + "size or length argument. Detects SUBPIECE, INT_AND-with-low-mask, and narrowing "
            + "CAST/COPY ops directly (works where the DSL `(int)$x` and `$x & 0xffffffff` patterns "
            + "miss because the cast is inlined into the call argument). Cross-references alloc and "
            + "copy sinks: a shared underlying source used at different widths is flagged as a "
            + "high-confidence overflow candidate.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("functionAddress", Map.of("type", "string",
            "description", "Function address in hex. Omit (with no name) to scan the whole program."));
        props.put("functionName", Map.of("type", "string",
            "description", "Function name. Omit (with no address) to scan the whole program."));
        props.put("maxFunctions", Map.of("type", "integer",
            "description", "Cap on functions scanned in whole-program mode (default 500)."));
        props.put("defChainDepth", Map.of("type", "integer",
            "description", "Max def-use chain depth when walking back from a size/length arg (default 24)."));
        props.put("decompileTimeout", Map.of("type", "integer",
            "description", "Per-function decompile timeout in seconds. Pass -1 or 0 to disable."));
        props.put("includeNarrowedSingletons", Map.of("type", "boolean",
            "description", "Also return alloc/copy sinks that have a narrowing in their def chain but no matching wider use on the other side (default true)."));
        schema.put("properties", props);
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalArgumentException("No program is open");

        int defChainDepth = ((Number) arguments.getOrDefault("defChainDepth", DEFAULT_DEF_CHAIN_DEPTH)).intValue();
        int maxFunctions = ((Number) arguments.getOrDefault("maxFunctions", 500)).intValue();
        boolean includeSingletons = (boolean) arguments.getOrDefault("includeNarrowedSingletons", true);
        int decompileTimeout = McpUtil.resolveDecompileTimeout(arguments.get("decompileTimeout"), 30);
        TaskMonitor monitor = McpUtil.activeMonitor();

        List<Function> targets = resolveTargets(arguments, program, maxFunctions);

        List<Map<String, Object>> findings = new ArrayList<>();
        int scanned = 0;
        int allocSinksSeen = 0;
        int copySinksSeen = 0;
        int truncatedAllocCount = 0;
        int truncatedCopyCount = 0;

        DecompInterface decomp = decompPool.acquire(program);
        try {
            for (Function func : targets) {
                if (monitor.isCancelled()) break;
                scanned++;
                monitor.setMessage("Trunc scan: " + func.getName() + " (" + scanned + "/" + targets.size() + ")");

                DecompileResults results = decomp.decompileFunction(func, decompileTimeout, monitor);
                if (results == null || !results.decompileCompleted()) continue;
                HighFunction hf = results.getHighFunction();
                if (hf == null) continue;

                FuncScanResult res = scanFunction(program, func, hf, defChainDepth);
                allocSinksSeen += res.allocSinks.size();
                copySinksSeen += res.copySinks.size();
                for (SinkRecord r : res.allocSinks) if (!r.narrowings.isEmpty()) truncatedAllocCount++;
                for (SinkRecord r : res.copySinks) if (!r.narrowings.isEmpty()) truncatedCopyCount++;

                emitFindings(program, res, includeSingletons, findings);
            }
        } finally {
            decompPool.release(program, decomp);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("scope", targets.size() == 1 ? "function" : "program");
        out.put("scannedFunctions", scanned);
        out.put("allocSinks", allocSinksSeen);
        out.put("copySinks", copySinksSeen);
        out.put("truncatedAllocSinks", truncatedAllocCount);
        out.put("truncatedCopySinks", truncatedCopyCount);
        out.put("findings", findings);
        out.put("cancelled", monitor.isCancelled());
        return out;
    }

    // ------------------------------------------------------------------
    // Target resolution
    // ------------------------------------------------------------------
    private List<Function> resolveTargets(Map<String, Object> arguments, Program program, int cap) {
        Map<String, Object> funcArgs = new HashMap<>();
        if (arguments.containsKey("functionAddress")) funcArgs.put("address", arguments.get("functionAddress"));
        if (arguments.containsKey("functionName")) funcArgs.put("name", arguments.get("functionName"));

        if (funcArgs.containsKey("address") || funcArgs.containsKey("name")) {
            Function f = DecompileFunctionTool.resolveFunction(funcArgs, program);
            if (f == null) throw new IllegalArgumentException("Function not found");
            return List.of(f);
        }

        List<Function> all = new ArrayList<>();
        Set<String> sinkNames = new HashSet<>(ALLOC_SIZE_ARG.keySet());
        sinkNames.addAll(COPY_LEN_ARG.keySet());

        FunctionManager fm = program.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            if (callsAnyOf(program, f, sinkNames)) {
                all.add(f);
                if (all.size() >= cap) break;
            }
        }
        return all;
    }

    private boolean callsAnyOf(Program program, Function func, Set<String> sinkNames) {
        for (Reference ref : referencesFrom(program, func)) {
            if (!ref.getReferenceType().isCall()) continue;
            Function tgt = program.getFunctionManager().getFunctionAt(ref.getToAddress());
            String n = tgt != null ? canonicalName(tgt.getName()) : null;
            if (n != null && sinkNames.contains(n)) return true;
            Symbol sym = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
            if (sym != null && sinkNames.contains(canonicalName(sym.getName()))) return true;
        }
        return false;
    }

    private static Iterable<Reference> referencesFrom(Program program, Function func) {
        return () -> {
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();
            ReferenceIterator it = program.getReferenceManager().getReferenceIterator(start);
            return new Iterator<Reference>() {
                Reference next = advance();
                Reference advance() {
                    while (it.hasNext()) {
                        Reference r = it.next();
                        if (r.getFromAddress().compareTo(end) > 0) return null;
                        return r;
                    }
                    return null;
                }
                @Override public boolean hasNext() { return next != null; }
                @Override public Reference next() {
                    Reference r = next;
                    next = advance();
                    return r;
                }
            };
        };
    }

    // ------------------------------------------------------------------
    // Sink classification
    // ------------------------------------------------------------------
    /** Allocation-size sinks: callee name → 0-based index of size arg. */
    private static final Map<String, Integer> ALLOC_SIZE_ARG;
    /** Copy-length sinks: callee name → 0-based index of length arg. */
    private static final Map<String, Integer> COPY_LEN_ARG;
    /** Allocators where size is a product of two args (calloc-like): name → [count_idx, size_idx]. */
    private static final Map<String, int[]> ALLOC_PRODUCT_ARGS;
    static {
        Map<String, Integer> a = new HashMap<>();
        a.put("malloc", 0);
        a.put("realloc", 1);
        a.put("reallocarray", 1); // also a product, but the trunc usually hits arg 1
        a.put("memalign", 1);
        a.put("aligned_alloc", 1);
        a.put("posix_memalign", 2);
        a.put("valloc", 0);
        a.put("pvalloc", 0);
        a.put("xmalloc", 0);
        a.put("g_malloc", 0);
        a.put("g_malloc0", 0);
        a.put("g_try_malloc", 0);
        a.put("operator.new", 0);
        a.put("operator.new[]", 0);
        a.put("_Znwm", 0);
        a.put("_Znam", 0);
        a.put("alloca", 0);
        ALLOC_SIZE_ARG = Map.copyOf(a);

        Map<String, Integer> c = new HashMap<>();
        c.put("memcpy", 2);
        c.put("memmove", 2);
        c.put("mempcpy", 2);
        c.put("bcopy", 2);
        c.put("memcpy_s", 3);   // memcpy_s(dst, dstsz, src, n)
        c.put("memmove_s", 3);
        c.put("strncpy", 2);
        c.put("strncat", 2);
        c.put("strlcpy", 2);
        c.put("strlcat", 2);
        c.put("read", 2);
        c.put("pread", 2);
        c.put("recv", 2);
        c.put("recvfrom", 2);
        c.put("fread", 1);      // fread(ptr, size, nmemb, stream) — size is the trunc-relevant one
        c.put("write", 2);
        COPY_LEN_ARG = Map.copyOf(c);

        Map<String, int[]> p = new HashMap<>();
        p.put("calloc", new int[]{0, 1});
        p.put("reallocarray", new int[]{1, 2});
        ALLOC_PRODUCT_ARGS = Map.copyOf(p);
    }

    /**
     * Canonicalise a callee name: strip @plt/version, __imp_, __wrap_, _, __,
     * isoc99/isoc23, and trailing _chk so memcpy_chk / __memcpy_chk / memcpy@plt
     * all reduce to "memcpy".
     */
    private static String canonicalName(String name) {
        if (name == null) return "";
        String n = name;
        int at = n.indexOf('@');
        if (at > 0) n = n.substring(0, at);
        String[] prefixes = {"__imp_", "__wrap_", "__isoc99_", "__isoc23_", "__", "_"};
        for (String pfx : prefixes) {
            if (n.startsWith(pfx) && n.length() > pfx.length()) { n = n.substring(pfx.length()); break; }
        }
        if (n.endsWith("_chk") && n.length() > 4) n = n.substring(0, n.length() - 4);
        return n;
    }

    // ------------------------------------------------------------------
    // Per-function scan
    // ------------------------------------------------------------------
    private static final class SinkRecord {
        final String kind;            // "alloc" | "copy"
        final String calleeName;      // canonical
        final Address callAddress;
        final int argIndex;
        final Varnode argVarnode;
        final int argWidth;           // bytes
        final List<NarrowingOp> narrowings;
        final SourceKey sourceKey;
        final int sourceWidth;        // bytes, max width seen on the source side
        final String renderedSource;
        SinkRecord(String kind, String calleeName, Address callAddress, int argIndex,
                   Varnode argVarnode, int argWidth, List<NarrowingOp> narrowings,
                   SourceKey sourceKey, int sourceWidth, String renderedSource) {
            this.kind = kind;
            this.calleeName = calleeName;
            this.callAddress = callAddress;
            this.argIndex = argIndex;
            this.argVarnode = argVarnode;
            this.argWidth = argWidth;
            this.narrowings = narrowings;
            this.sourceKey = sourceKey;
            this.sourceWidth = sourceWidth;
            this.renderedSource = renderedSource;
        }
    }

    private static final class NarrowingOp {
        final String opName;     // SUBPIECE, INT_AND, CAST, COPY
        final Address address;
        final int srcWidth;
        final int dstWidth;
        final Long mask;         // for INT_AND, else null
        NarrowingOp(String opName, Address address, int srcWidth, int dstWidth, Long mask) {
            this.opName = opName;
            this.address = address;
            this.srcWidth = srcWidth;
            this.dstWidth = dstWidth;
            this.mask = mask;
        }
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("op", opName);
            m.put("address", address == null ? null : address.toString());
            m.put("fromWidth", srcWidth);
            m.put("toWidth", dstWidth);
            if (mask != null) m.put("mask", "0x" + Long.toHexString(mask));
            return m;
        }
    }

    private static final class FuncScanResult {
        final Function function;
        final List<SinkRecord> allocSinks = new ArrayList<>();
        final List<SinkRecord> copySinks = new ArrayList<>();
        FuncScanResult(Function f) { this.function = f; }
    }

    private FuncScanResult scanFunction(Program program, Function func, HighFunction hf, int depth) {
        FuncScanResult res = new FuncScanResult(func);
        PcodeExpressionRenderer renderer = new PcodeExpressionRenderer(program, 6);

        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) continue;

            String callee = resolveCalleeName(program, op);
            if (callee == null) continue;
            String canon = canonicalName(callee);

            Integer allocIdx = ALLOC_SIZE_ARG.get(canon);
            Integer copyIdx = COPY_LEN_ARG.get(canon);
            int[] productIdx = ALLOC_PRODUCT_ARGS.get(canon);

            if (productIdx != null) {
                for (int idx : productIdx) {
                    SinkRecord r = buildSinkRecord(op, canon, idx, depth, "alloc", renderer);
                    if (r != null) res.allocSinks.add(r);
                }
            } else if (allocIdx != null) {
                SinkRecord r = buildSinkRecord(op, canon, allocIdx, depth, "alloc", renderer);
                if (r != null) res.allocSinks.add(r);
            }

            if (copyIdx != null) {
                SinkRecord r = buildSinkRecord(op, canon, copyIdx, depth, "copy", renderer);
                if (r != null) res.copySinks.add(r);
            }
        }
        return res;
    }

    private SinkRecord buildSinkRecord(PcodeOp callOp, String canonName, int argIdx,
                                       int depth, String kind, PcodeExpressionRenderer renderer) {
        // callOp inputs are [target, arg0, arg1, ...]
        int inputIdx = argIdx + 1;
        Varnode[] inputs = callOp.getInputs();
        if (inputIdx >= inputs.length) return null;
        Varnode arg = inputs[inputIdx];
        if (arg == null) return null;

        TruncWalker walker = new TruncWalker(depth);
        walker.walk(arg);

        return new SinkRecord(
            kind, canonName, callOp.getSeqnum().getTarget(), argIdx,
            arg, arg.getSize(), walker.narrowings,
            walker.sourceKey, walker.maxSourceWidth,
            renderer.render(walker.deepestSource != null ? walker.deepestSource : arg)
        );
    }

    /**
     * Resolve the callee name from a CALL/CALLIND op. For CALL, inputs[0] is a
     * constant address; for CALLIND we render the indirect target as an
     * expression. Returns null when unresolved.
     */
    private static String resolveCalleeName(Program program, PcodeOp callOp) {
        Varnode target = callOp.getInput(0);
        if (target == null) return null;
        if (callOp.getOpcode() == PcodeOp.CALL && target.isAddress()) {
            Address addr = target.getAddress();
            Function f = program.getFunctionManager().getFunctionAt(addr);
            if (f != null) return f.getName();
            Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
            if (sym != null) return sym.getName();
        }
        // Indirect — try the target HighVariable name (will likely fail the
        // sink-name lookup, which is fine for now).
        HighVariable hv = target.getHigh();
        if (hv != null && hv.getName() != null) return hv.getName();
        return null;
    }

    // ------------------------------------------------------------------
    // Def-chain walker
    // ------------------------------------------------------------------
    /**
     * Walks back from a varnode through COPY/CAST/PHI/arithmetic ops, recording
     * any narrowing operation it crosses. Stops when it hits a load, call,
     * parameter, constant, or PHI cycle, or when depth is exhausted.
     */
    private static final class TruncWalker {
        final int maxDepth;
        final List<NarrowingOp> narrowings = new ArrayList<>();
        final Set<Varnode> visited = new HashSet<>();
        Varnode deepestSource;
        int maxSourceWidth = 0;
        SourceKey sourceKey;

        TruncWalker(int maxDepth) { this.maxDepth = maxDepth; }

        void walk(Varnode start) {
            walkInner(start, 0);
            if (deepestSource == null) deepestSource = start;
            if (sourceKey == null) sourceKey = SourceKey.of(deepestSource);
            maxSourceWidth = Math.max(maxSourceWidth, deepestSource.getSize());
        }

        private void walkInner(Varnode vn, int depth) {
            if (vn == null) return;
            if (!visited.add(vn)) return;
            if (depth >= maxDepth) { remember(vn); return; }

            if (vn.isConstant()) { remember(vn); return; }

            PcodeOp def = vn.getDef();
            if (def == null) { remember(vn); return; }

            int oc = def.getOpcode();
            Varnode out = def.getOutput();
            int outSize = out != null ? out.getSize() : vn.getSize();

            switch (oc) {
                case PcodeOp.COPY:
                case PcodeOp.CAST: {
                    Varnode src = def.getInput(0);
                    if (src != null && src.getSize() > outSize) {
                        narrowings.add(new NarrowingOp(oc == PcodeOp.CAST ? "CAST" : "COPY",
                            def.getSeqnum().getTarget(), src.getSize(), outSize, null));
                    }
                    walkInner(src, depth + 1);
                    return;
                }
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_SEXT: {
                    // Widening — the *upstream* value is narrower, so any
                    // earlier narrow is already accounted for. Follow through.
                    walkInner(def.getInput(0), depth + 1);
                    return;
                }
                case PcodeOp.SUBPIECE: {
                    Varnode src = def.getInput(0);
                    Varnode lowOff = def.getInput(1);
                    long off = (lowOff != null && lowOff.isConstant()) ? lowOff.getOffset() : -1;
                    if (src != null && off == 0 && src.getSize() > outSize) {
                        narrowings.add(new NarrowingOp("SUBPIECE",
                            def.getSeqnum().getTarget(), src.getSize(), outSize, null));
                    }
                    walkInner(src, depth + 1);
                    return;
                }
                case PcodeOp.INT_AND: {
                    Varnode a = def.getInput(0);
                    Varnode b = def.getInput(1);
                    Varnode maskVn = (b != null && b.isConstant()) ? b
                                   : (a != null && a.isConstant()) ? a : null;
                    Varnode srcVn = (maskVn == b) ? a : b;
                    if (maskVn != null && srcVn != null) {
                        long mask = maskVn.getOffset() & ((maskVn.getSize() >= 8) ? -1L
                                    : (1L << (8 * maskVn.getSize())) - 1L);
                        int maskBits = lowMaskBits(mask);
                        if (maskBits > 0 && maskBits < 8 * srcVn.getSize()) {
                            narrowings.add(new NarrowingOp("INT_AND",
                                def.getSeqnum().getTarget(), srcVn.getSize(), maskBits / 8, mask));
                        }
                        walkInner(srcVn, depth + 1);
                        return;
                    }
                    remember(out != null ? out : vn);
                    return;
                }
                case PcodeOp.MULTIEQUAL: {
                    // PHI — explore all inputs but bound recursion via the
                    // shared `visited` set to avoid blowups on loops.
                    for (int i = 0; i < def.getNumInputs(); i++) {
                        walkInner(def.getInput(i), depth + 1);
                    }
                    return;
                }
                case PcodeOp.INT_ADD: case PcodeOp.INT_SUB:
                case PcodeOp.INT_MULT: case PcodeOp.INT_DIV: case PcodeOp.INT_SDIV:
                case PcodeOp.INT_REM:  case PcodeOp.INT_SREM:
                case PcodeOp.INT_OR:   case PcodeOp.INT_XOR:
                case PcodeOp.INT_LEFT: case PcodeOp.INT_RIGHT: case PcodeOp.INT_SRIGHT:
                case PcodeOp.PTRADD:   case PcodeOp.PTRSUB: {
                    // Walk both operands — a trunc on either side still
                    // ultimately shrinks what reaches the size argument.
                    walkInner(def.getInput(0), depth + 1);
                    if (def.getNumInputs() > 1) walkInner(def.getInput(1), depth + 1);
                    return;
                }
                case PcodeOp.LOAD:
                case PcodeOp.CALL:
                case PcodeOp.CALLIND:
                case PcodeOp.CALLOTHER:
                default:
                    remember(out != null ? out : vn);
            }
        }

        private void remember(Varnode vn) {
            if (vn == null) return;
            if (deepestSource == null || vn.getSize() > deepestSource.getSize()) {
                deepestSource = vn;
            }
            if (sourceKey == null) sourceKey = SourceKey.of(vn);
            if (vn.getSize() > maxSourceWidth) maxSourceWidth = vn.getSize();
        }

        /**
         * Returns the bit width of mask when mask is `(1<<n)-1` for some n>0,
         * else 0. This is the only mask shape that corresponds to a narrowing
         * truncation; e.g. 0xff→8, 0xffff→16, 0xffffffff→32.
         */
        private static int lowMaskBits(long mask) {
            if (mask <= 0) return 0;
            // mask must be 2^n - 1
            if (((mask + 1) & mask) != 0) return 0;
            return Long.numberOfTrailingZeros(mask + 1);
        }
    }

    /**
     * Identity-style key for the "ultimate source" of a sink argument. Two
     * sinks that share a SourceKey are reading from the same underlying
     * variable / parameter / load.
     */
    private static final class SourceKey {
        final String tag;
        SourceKey(String tag) { this.tag = tag; }
        static SourceKey of(Varnode vn) {
            if (vn == null) return new SourceKey("null");
            HighVariable hv = vn.getHigh();
            if (hv != null) {
                HighSymbol sym = hv.getSymbol();
                if (sym != null) return new SourceKey("sym:" + sym.getId());
                if (hv.getName() != null && !hv.getName().isEmpty()) return new SourceKey("hv:" + hv.getName());
            }
            if (vn.isConstant()) return new SourceKey("const:" + vn.getOffset());
            if (vn.getAddress() != null) return new SourceKey("vn:" + vn.getAddress() + ":" + vn.getSize());
            return new SourceKey("vn:" + System.identityHashCode(vn));
        }
        @Override public boolean equals(Object o) {
            return o instanceof SourceKey && ((SourceKey) o).tag.equals(tag);
        }
        @Override public int hashCode() { return tag.hashCode(); }
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------
    private void emitFindings(Program program, FuncScanResult res, boolean includeSingletons,
                              List<Map<String, Object>> out) {
        // 1) Cross-correlated alloc/copy pairs sharing a source.
        Map<SourceKey, List<SinkRecord>> byKey = new HashMap<>();
        for (SinkRecord r : res.allocSinks) byKey.computeIfAbsent(r.sourceKey, k -> new ArrayList<>()).add(r);
        for (SinkRecord r : res.copySinks)  byKey.computeIfAbsent(r.sourceKey, k -> new ArrayList<>()).add(r);

        Set<SinkRecord> reported = new HashSet<>();
        for (Map.Entry<SourceKey, List<SinkRecord>> e : byKey.entrySet()) {
            List<SinkRecord> group = e.getValue();
            List<SinkRecord> allocs = new ArrayList<>();
            List<SinkRecord> copies = new ArrayList<>();
            for (SinkRecord r : group) {
                if (r.kind.equals("alloc")) allocs.add(r); else copies.add(r);
            }
            if (allocs.isEmpty() || copies.isEmpty()) continue;
            for (SinkRecord a : allocs) {
                for (SinkRecord c : copies) {
                    // Same source flows to alloc-size and copy-length. Flag when:
                    //   - alloc side has any narrowing AND copy side has a wider source, OR
                    //   - alloc-arg width is strictly smaller than copy-arg width.
                    boolean allocNarrows = !a.narrowings.isEmpty();
                    boolean widthMismatch = a.argWidth < c.argWidth;
                    if (allocNarrows || widthMismatch) {
                        out.add(buildMismatchFinding(res.function, a, c));
                        reported.add(a); reported.add(c);
                    }
                }
            }
        }

        if (!includeSingletons) return;

        // 2) Standalone narrowed alloc/copy sinks (no matching peer).
        for (SinkRecord r : res.allocSinks) {
            if (reported.contains(r) || r.narrowings.isEmpty()) continue;
            out.add(buildSingletonFinding(res.function, r, "alloc_size_truncated",
                "Allocation size has a narrowing op in its def chain but no matching wider "
                + "use was found in this function. Audit callers to see whether the original "
                + "wide value also reaches a copy length elsewhere."));
        }
        for (SinkRecord r : res.copySinks) {
            if (reported.contains(r) || r.narrowings.isEmpty()) continue;
            out.add(buildSingletonFinding(res.function, r, "copy_length_truncated",
                "Copy length passes through a narrowing op. Usually benign (the copy itself "
                + "won't overflow because the length is now small), but a tainted upstream "
                + "value at a wider width may still reach a separate sink — worth a glance."));
        }
    }

    private Map<String, Object> buildMismatchFinding(Function func, SinkRecord alloc, SinkRecord copy) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "alloc_copy_width_mismatch");
        m.put("severity", alloc.narrowings.isEmpty() ? "medium" : "high");
        m.put("function", func.getName());
        m.put("functionAddress", func.getEntryPoint().toString());
        m.put("allocSink", sinkMap(alloc));
        m.put("copySink", sinkMap(copy));
        m.put("sharedSource", alloc.renderedSource);
        m.put("note", "Same underlying source reaches both the allocation size (width "
            + alloc.argWidth + " bytes) and the copy length (width " + copy.argWidth
            + " bytes). If the source can carry a value > 2^" + (alloc.argWidth * 8)
            + ", the alloc wraps to a small size but the copy uses the full wide value — "
            + "classic integer-truncation heap overflow.");
        return m;
    }

    private Map<String, Object> buildSingletonFinding(Function func, SinkRecord r,
                                                      String type, String note) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("severity", "low");
        m.put("function", func.getName());
        m.put("functionAddress", func.getEntryPoint().toString());
        m.put("sink", sinkMap(r));
        m.put("note", note);
        return m;
    }

    private Map<String, Object> sinkMap(SinkRecord r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", r.kind);
        m.put("callee", r.calleeName);
        m.put("callAddress", r.callAddress == null ? null : r.callAddress.toString());
        m.put("argIndex", r.argIndex);
        m.put("argWidth", r.argWidth);
        m.put("sourceWidth", r.sourceWidth);
        m.put("sourceExpression", r.renderedSource);
        List<Map<String, Object>> narrows = new ArrayList<>();
        for (NarrowingOp n : r.narrowings) narrows.add(n.toMap());
        m.put("narrowingOps", narrows);
        return m;
    }
}
