package decompfuncutils;

import decompfuncutils.mcp.tools.PcodeExpressionRenderer;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HTMLUtilities;

import java.util.*;

/**
 * Bounded intraprocedural data-dependency slicer over the decompiler's SSA p-code.
 *
 * Given a seed (a variable use, a call, or an operator) it answers two questions:
 * what the seed is <em>affected by</em> (walking {@link Varnode#getDef()} backward)
 * and what it <em>affects</em> (walking {@link Varnode#getDescendants()} forward).
 * The walk stops at things a reader recognises - named variables, constants, call
 * results, memory reads, function inputs, call arguments, stores, returns and
 * branch conditions - and reports those instead of raw temporaries.
 *
 * Pure analysis: no Swing, no decompiler process. It only reads an already built
 * {@link HighFunction}, so it is safe to call from a hover on the Swing thread and
 * from headless tests.
 */
public final class DataflowSlicer {

    public static final int DEFAULT_MAX_DEPTH = 8;
    public static final int DEFAULT_MAX_VISITED = 400;
    public static final int DEFAULT_MAX_ITEMS = 12;

    /** One reported dependency. Two items are the same when kind and text match. */
    public static final class Item {
        public final String kind;
        public final String text;
        /** Optional qualifier such as a data type or "via +"; may be null. */
        public final String detail;
        /** Instruction address the dependency was found at; may be null. */
        public final Address address;

        Item(String kind, String text, String detail, Address address) {
            this.kind = kind;
            this.text = text;
            this.detail = detail;
            this.address = address;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind);
            m.put("text", text);
            if (detail != null) m.put("detail", detail);
            if (address != null) m.put("address", address.toString());
            return m;
        }

        @Override public String toString() {
            return kind + ": " + text + (detail == null ? "" : " [" + detail + "]");
        }
    }

    public enum SeedKind { VARIABLE, FIELD, CALL, OPERATOR }

    /** What the question is being asked about. */
    public static final class Seed {
        public SeedKind kind;
        public String label;
        /** Display name of the data type; may be null. */
        public String dataType;
        /** param / local / global / temp for variables; null otherwise. */
        public String variableKind;
        /** "read here", "assigned here", "all uses" or null. */
        public String access;
        /** Callee prototype for call seeds; may be null. */
        public String signature;
        public Address address;
        final List<Varnode> backwardRoots = new ArrayList<>();
        final List<Varnode> forwardRoots = new ArrayList<>();
        /** Effects of the seed operation itself (a store writes memory, ...). */
        final List<Item> ownEffects = new ArrayList<>();
        /** Instances of this variable are walked through instead of being reported. */
        HighVariable self;

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind.name().toLowerCase(Locale.ROOT));
            m.put("label", label);
            if (dataType != null) m.put("dataType", dataType);
            if (variableKind != null) m.put("variableKind", variableKind);
            if (access != null) m.put("access", access);
            if (signature != null) m.put("signature", signature);
            if (address != null) m.put("address", address.toString());
            return m;
        }
    }

    public static final class Result {
        public final Seed seed;
        public final List<Item> affectedBy;
        public final List<Item> affects;
        /** Calls / stores whose side effects may change the value on the way. */
        public final List<String> mayBeModifiedBy;
        public final boolean backwardTruncated;
        public final boolean forwardTruncated;

        Result(Seed seed, List<Item> affectedBy, List<Item> affects, List<String> mayBeModifiedBy,
                boolean backwardTruncated, boolean forwardTruncated) {
            this.seed = seed;
            this.affectedBy = affectedBy;
            this.affects = affects;
            this.mayBeModifiedBy = mayBeModifiedBy;
            this.backwardTruncated = backwardTruncated;
            this.forwardTruncated = forwardTruncated;
        }

        public boolean isEmpty() {
            return affectedBy.isEmpty() && affects.isEmpty() && mayBeModifiedBy.isEmpty();
        }

        /** JSON-ready form; lists are cut at {@code maxItems} with the full counts kept. */
        public Map<String, Object> toMap(int maxItems) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seed", seed.toMap());
            m.put("affectedBy", maps(affectedBy, maxItems));
            m.put("affectedByTotal", affectedBy.size());
            m.put("affects", maps(affects, maxItems));
            m.put("affectsTotal", affects.size());
            m.put("mayBeModifiedBy", new ArrayList<>(mayBeModifiedBy));
            m.put("backwardTruncated", backwardTruncated);
            m.put("forwardTruncated", forwardTruncated);
            return m;
        }

        private static List<Map<String, Object>> maps(List<Item> items, int maxItems) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Item item : items) {
                if (out.size() >= maxItems) break;
                out.add(item.toMap());
            }
            return out;
        }
    }

    private final Program program;
    private final HighFunction high;
    private final int maxDepth;
    private final int maxVisited;
    private final PcodeExpressionRenderer renderer;

    public DataflowSlicer(Program program, HighFunction high) {
        this(program, high, DEFAULT_MAX_DEPTH, DEFAULT_MAX_VISITED);
    }

    public DataflowSlicer(Program program, HighFunction high, int maxDepth, int maxVisited) {
        this.program = program;
        this.high = high;
        this.maxDepth = Math.max(1, maxDepth);
        this.maxVisited = Math.max(1, maxVisited);
        this.renderer = new PcodeExpressionRenderer(program, 3);
    }

    // ------------------------------------------------------------------ seeds

    /**
     * Seed for the decompiler token under the cursor, or null when the token is not
     * something with data flow (keywords, types, constants, the function's own name).
     */
    public Seed seedFromToken(ClangToken token) {
        if (token == null) return null;
        if (token instanceof ClangFuncNameToken) {
            PcodeOp op = token.getPcodeOp();
            return op == null || !isCall(op.getOpcode()) ? null : seedForOp(op);
        }
        if (token instanceof ClangOpToken) {
            PcodeOp op = token.getPcodeOp();
            return op == null ? null : seedForOp(op);
        }
        if (token instanceof ClangFieldToken) {
            PcodeOp op = token.getPcodeOp();   // getVarnode() dereferences it unchecked
            if (op == null) return null;
            if (op.getOutput() == null) return seedForOp(op);
            Seed seed = seedForVarnode(op.getOutput(), null, token.getText());
            seed.kind = SeedKind.FIELD;
            return seed;
        }
        if (token instanceof ClangVariableToken) {
            Varnode vn = token.getVarnode();
            if (vn != null) {
                if (vn.isConstant() || vn.getHigh() instanceof HighConstant) return null;
                return seedForVarnode(vn, token.getPcodeOp(), token.getText());
            }
            // A declaration has no single varnode: describe every instance.
            HighVariable hv = token.getHighVariable();
            if (hv == null || hv instanceof HighConstant) return null;
            return seedForVariable(hv);
        }
        return null;
    }

    /** Seed for one SSA instance; {@code contextOp} is the operation the token belongs to. */
    public Seed seedForVarnode(Varnode vn, PcodeOp contextOp, String label) {
        Seed seed = new Seed();
        seed.kind = SeedKind.VARIABLE;
        HighVariable hv = vn.getHigh();
        seed.self = isNamed(hv) ? hv : null;
        seed.label = label != null ? label : seed.self != null ? hv.getName() : renderer.render(vn);
        seed.dataType = typeName(hv);
        seed.variableKind = kindOf(hv);
        if (contextOp != null) {
            seed.access = vn.getDef() == contextOp ? "assigned here" : "read here";
            seed.address = contextOp.getSeqnum().getTarget();
        }
        seed.backwardRoots.add(vn);
        seed.forwardRoots.add(vn);
        return seed;
    }

    /** Seed covering every instance of a variable (declarations, lookups by name). */
    public Seed seedForVariable(HighVariable hv) {
        Seed seed = new Seed();
        seed.kind = SeedKind.VARIABLE;
        seed.self = hv;
        seed.label = hv.getName() != null ? hv.getName() : "<unnamed>";
        seed.dataType = typeName(hv);
        seed.variableKind = kindOf(hv);
        seed.access = "all uses";
        Varnode[] instances = hv.getInstances();
        if (instances != null) {
            for (Varnode vn : instances) {
                if (vn == null) continue;
                seed.backwardRoots.add(vn);
                seed.forwardRoots.add(vn);
            }
        }
        return seed;
    }

    /** Seed for a variable by its decompiler name, or null when there is none in use. */
    public Seed seedForVariable(String name) {
        HighVariable hv = findVariable(name);
        return hv == null ? null : seedForVariable(hv);
    }

    /** Seed for a call (arguments in, result out) or an operator (inputs in, output out). */
    public Seed seedForOp(PcodeOp op) {
        Seed seed = new Seed();
        int opc = op.getOpcode();
        Address at = op.getSeqnum().getTarget();
        seed.address = at;
        Varnode out = op.getOutput();
        if (isCall(opc)) {
            seed.kind = SeedKind.CALL;
            seed.label = calleeName(op) + "()";
            Function callee = callee(op);
            if (callee != null) seed.signature = callee.getPrototypeString(false, false);
            if (opc == PcodeOp.CALLIND && op.getNumInputs() > 0) seed.backwardRoots.add(op.getInput(0));
        } else {
            seed.kind = SeedKind.OPERATOR;
            seed.label = opSymbol(opc) + " (" + op.getMnemonic() + ")";
            if (out != null) seed.dataType = typeName(out.getHigh());
        }
        for (int slot : dataSlots(op)) {
            Varnode in = op.getInput(slot);
            if (in != null) seed.backwardRoots.add(in);
        }
        if (out != null) seed.forwardRoots.add(out);
        switch (opc) {
            case PcodeOp.STORE:
                seed.ownEffects.add(new Item("memory write", deref(op.getInput(1)), null, at));
                break;
            case PcodeOp.CBRANCH:
                seed.ownEffects.add(new Item("branch", renderer.render(op.getInput(1)), "condition", at));
                break;
            case PcodeOp.BRANCHIND:
                seed.ownEffects.add(new Item("switch", "switch / indirect jump target", null, at));
                break;
            case PcodeOp.RETURN:
                if (op.getNumInputs() > 1) seed.ownEffects.add(new Item("return", "return value", null, at));
                break;
            default:
                break;
        }
        return seed;
    }

    /**
     * Seed for an instruction address. With a variable name it is that variable's
     * instance read or written there; without one it is the call at that address,
     * or failing that the most telling operation (store, return, branch, assignment).
     * Returns null when nothing matches.
     */
    public Seed seedForAddress(Address address, String variableName) {
        List<PcodeOp> ops = new ArrayList<>();
        Iterator<PcodeOpAST> it = high.getPcodeOps(address);
        while (it.hasNext()) ops.add(it.next());
        if (ops.isEmpty()) return null;

        if (variableName != null) {
            Varnode read = null;
            PcodeOp readOp = null;
            for (PcodeOp op : ops) {
                Varnode out = op.getOutput();
                if (out != null && hasName(out, variableName)) return seedForVarnode(out, op, variableName);
                for (int i = 0; i < op.getNumInputs() && read == null; i++) {
                    Varnode in = op.getInput(i);
                    if (in != null && hasName(in, variableName)) {
                        read = in;
                        readOp = op;
                    }
                }
            }
            return read == null ? null : seedForVarnode(read, readOp, variableName);
        }

        PcodeOp best = null;
        int bestRank = -1;
        for (PcodeOp op : ops) {
            int rank = addressRank(op);
            if (rank >= bestRank) {     // later ops win ties: they complete the statement
                best = op;
                bestRank = rank;
            }
        }
        return seedForOp(best);
    }

    private static int addressRank(PcodeOp op) {
        int opc = op.getOpcode();
        if (isCall(opc)) return 5;
        if (opc == PcodeOp.STORE || opc == PcodeOp.RETURN || opc == PcodeOp.CBRANCH || opc == PcodeOp.BRANCHIND) return 4;
        if (opc == PcodeOp.INDIRECT || opc == PcodeOp.MULTIEQUAL) return 0;
        Varnode out = op.getOutput();
        if (out == null) return 1;
        return isNamed(out.getHigh()) ? 3 : 2;
    }

    private static boolean hasName(Varnode vn, String name) {
        HighVariable hv = vn.getHigh();
        return isNamed(hv) && name.equals(hv.getName());
    }

    private HighVariable findVariable(String name) {
        if (name == null) return null;
        List<Iterator<HighSymbol>> maps = new ArrayList<>();
        if (high.getLocalSymbolMap() != null) maps.add(high.getLocalSymbolMap().getSymbols());
        if (high.getGlobalSymbolMap() != null) maps.add(high.getGlobalSymbolMap().getSymbols());
        for (Iterator<HighSymbol> it : maps) {
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                if (name.equals(sym.getName()) && sym.getHighVariable() != null) return sym.getHighVariable();
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ slicing

    public Result slice(Seed seed) {
        Collector back = new Collector();
        Set<String> modifiedBy = new LinkedHashSet<>();
        backward(seed, back, modifiedBy);

        Collector fwd = new Collector();
        for (Item item : seed.ownEffects) fwd.add(item);
        forward(seed, fwd);

        return new Result(seed, back.items(), fwd.items(), new ArrayList<>(modifiedBy),
            back.truncated, fwd.truncated);
    }

    private static final class Collector {
        private final Map<String, Item> items = new LinkedHashMap<>();
        boolean truncated;

        void add(Item item) { items.putIfAbsent(item.kind + "|" + item.text, item); }
        void add(String kind, String text, String detail, Address at) { add(new Item(kind, text, detail, at)); }
        List<Item> items() { return new ArrayList<>(items.values()); }
    }

    private static final class Work {
        final Varnode vn;
        final int depth;
        Work(Varnode vn, int depth) { this.vn = vn; this.depth = depth; }
    }

    private void backward(Seed seed, Collector out, Set<String> modifiedBy) {
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Work> queue = new ArrayDeque<>();
        for (Varnode root : seed.backwardRoots) queue.add(new Work(root, 0));

        while (!queue.isEmpty()) {
            Work w = queue.poll();
            Varnode vn = w.vn;
            if (vn == null || !visited.add(vn)) continue;
            if (visited.size() > maxVisited) { out.truncated = true; break; }

            if (vn.isConstant()) {
                out.add("constant", describeConstant(vn), null, null);
                continue;
            }
            HighVariable hv = vn.getHigh();
            boolean named = isNamed(hv);
            if (named && hv != seed.self) {
                out.add(kindOf(hv), hv.getName(), typeName(hv), null);
                continue;
            }
            PcodeOp def = vn.getDef();
            if (def == null) {
                if (hv instanceof HighParam) {
                    out.add("input", "caller-supplied argument #" + (((HighParam) hv).getSlot() + 1), hv.getName(), null);
                } else if (hv instanceof HighGlobal && named) {
                    out.add("input", "value of " + hv.getName() + " on entry", "global", null);
                } else if (named) {
                    out.add("input", "value of " + hv.getName() + " on entry", "not assigned in this function", null);
                } else {
                    out.add("input", renderer.render(vn), "function input", null);
                }
                continue;
            }
            Address at = def.getSeqnum().getTarget();
            int opc = def.getOpcode();
            switch (opc) {
                case PcodeOp.MULTIEQUAL:
                    for (int i = 0; i < def.getNumInputs(); i++) queue.add(new Work(def.getInput(i), w.depth));
                    continue;
                case PcodeOp.INDIRECT: {
                    String cause = indirectCause(def);
                    if (cause != null) modifiedBy.add(cause);
                    Varnode before = def.getInput(0);
                    // A constant here marks a value the call creates rather than changes.
                    if (before != null && !before.isConstant()) queue.add(new Work(before, w.depth));
                    continue;
                }
                case PcodeOp.CALL:
                case PcodeOp.CALLIND:
                case PcodeOp.CALLOTHER:
                    out.add("call result", calleeName(def) + "()", null, at);
                    continue;
                case PcodeOp.LOAD:
                    out.add("memory read", deref(def.getInput(1)), null, at);
                    continue;
                case PcodeOp.PTRSUB: {
                    String addressOf = addressOf(def);
                    if (addressOf != null) {
                        out.add("address", addressOf, null, at);
                        continue;
                    }
                    break;
                }
                default:
                    break;
            }
            if (w.depth >= maxDepth) { out.truncated = true; continue; }
            for (int slot : dataSlots(def)) queue.add(new Work(def.getInput(slot), w.depth + 1));
        }
    }

    private void forward(Seed seed, Collector out) {
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Work> queue = new ArrayDeque<>();
        for (Varnode root : seed.forwardRoots) queue.add(new Work(root, 0));

        while (!queue.isEmpty()) {
            Work w = queue.poll();
            Varnode vn = w.vn;
            if (vn == null || !visited.add(vn)) continue;
            if (visited.size() > maxVisited) { out.truncated = true; break; }
            Iterator<PcodeOp> uses = vn.getDescendants();
            if (uses == null) continue;
            while (uses.hasNext()) {
                PcodeOp use = uses.next();
                if (use == null) continue;
                Address at = use.getSeqnum().getTarget();
                int opc = use.getOpcode();
                for (int slot = 0; slot < use.getNumInputs(); slot++) {
                    if (use.getInput(slot) != vn) continue;
                    switch (opc) {
                        case PcodeOp.CALL:
                        case PcodeOp.CALLIND:
                        case PcodeOp.CALLOTHER:
                            if (slot == 0) {
                                if (opc == PcodeOp.CALLIND) out.add("call target", "indirect call target", null, at);
                            } else {
                                out.add("call argument", describeArgument(use, slot), null, at);
                            }
                            break;
                        case PcodeOp.STORE:
                            if (slot == 2) {
                                out.add("memory write", deref(use.getInput(1)), "stored value", at);
                            } else if (slot == 1) {
                                out.add("write address", deref(use.getInput(1)) + " = " + renderer.render(use.getInput(2)),
                                    "used as the address", at);
                            }
                            break;
                        case PcodeOp.RETURN:
                            if (slot >= 1) out.add("return", "return value", null, at);
                            break;
                        case PcodeOp.CBRANCH:
                            if (slot == 1) out.add("branch", renderer.render(vn), "condition", at);
                            break;
                        case PcodeOp.BRANCHIND:
                            out.add("switch", "switch / indirect jump target", null, at);
                            break;
                        case PcodeOp.BRANCH:
                            break;
                        case PcodeOp.INDIRECT:
                            if (slot == 0) flowInto(use, w.depth, seed, queue, out);
                            break;
                        case PcodeOp.MULTIEQUAL:
                            flowInto(use, w.depth, seed, queue, out);
                            break;
                        default:
                            if (w.depth + 1 > maxDepth) out.truncated = true;
                            else flowInto(use, w.depth + 1, seed, queue, out);
                            break;
                    }
                }
            }
        }
    }

    /** The value reaches {@code use}'s output: report a named variable, keep walking a temporary. */
    private void flowInto(PcodeOp use, int depth, Seed seed, Deque<Work> queue, Collector out) {
        Varnode result = use.getOutput();
        if (result == null) return;
        HighVariable hv = result.getHigh();
        if (isNamed(hv) && hv != seed.self) {
            out.add(kindOf(hv), hv.getName(), "via " + opSymbol(use.getOpcode()), use.getSeqnum().getTarget());
            return;
        }
        queue.add(new Work(result, depth));
    }

    // ------------------------------------------------------------------ p-code helpers

    private static boolean isCall(int opc) {
        return opc == PcodeOp.CALL || opc == PcodeOp.CALLIND || opc == PcodeOp.CALLOTHER;
    }

    /** Input slots that carry data, leaving out targets, space ids and shape constants. */
    private static List<Integer> dataSlots(PcodeOp op) {
        int n = op.getNumInputs();
        int from = 0;
        int to = n;
        switch (op.getOpcode()) {
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
            case PcodeOp.CALLOTHER:
            case PcodeOp.LOAD:
            case PcodeOp.STORE:
            case PcodeOp.CBRANCH:
            case PcodeOp.RETURN:
                from = 1;
                break;
            case PcodeOp.BRANCH:
                to = 0;
                break;
            case PcodeOp.INDIRECT:
            case PcodeOp.SUBPIECE:
            case PcodeOp.PTRSUB:
                to = Math.min(n, 1);
                break;
            case PcodeOp.PTRADD:
                to = Math.min(n, 2);
                break;
            default:
                break;
        }
        List<Integer> slots = new ArrayList<>();
        for (int i = from; i < to; i++) slots.add(i);
        return slots;
    }

    private Function callee(PcodeOp call) {
        if (call.getOpcode() != PcodeOp.CALL || program == null) return null;
        Address target = call.getInput(0).getAddress();
        Function f = program.getFunctionManager().getFunctionAt(target);
        if (f == null) f = program.getFunctionManager().getReferencedFunction(target);
        if (f != null && f.isThunk()) {
            Function thunked = f.getThunkedFunction(true);
            if (thunked != null) f = thunked;
        }
        return f;
    }

    private String calleeName(PcodeOp call) {
        switch (call.getOpcode()) {
            case PcodeOp.CALL: {
                Function f = callee(call);
                return f != null ? f.getName() : "func_" + call.getInput(0).getAddress();
            }
            case PcodeOp.CALLIND:
                return "(*" + renderer.render(call.getInput(0)) + ")";
            default: {
                String name = null;
                try {
                    name = program.getLanguage().getUserDefinedOpName((int) call.getInput(0).getOffset());
                } catch (RuntimeException ignored) {
                    // fall through to the generic name
                }
                return name != null ? name : "userop";
            }
        }
    }

    private String describeArgument(PcodeOp call, int slot) {
        StringBuilder sb = new StringBuilder(calleeName(call)).append("() argument ").append(slot);
        Function f = callee(call);
        if (f != null && slot - 1 < f.getParameterCount()) {
            Parameter p = f.getParameter(slot - 1);
            if (p != null && p.getName() != null) sb.append(" (").append(p.getName()).append(")");
        }
        return sb.toString();
    }

    /** The call or store an INDIRECT stands for, phrased for the "may be modified by" line. */
    private String indirectCause(PcodeOp indirect) {
        if (indirect.getNumInputs() < 2 || indirect.getInput(1) == null) return null;
        PcodeOp cause = high.getOpRef((int) indirect.getInput(1).getOffset());
        if (cause == null) return null;
        if (isCall(cause.getOpcode())) return calleeName(cause) + "()";
        if (cause.getOpcode() == PcodeOp.STORE) return "write to " + deref(cause.getInput(1));
        return cause.getMnemonic();
    }

    private String deref(Varnode pointer) {
        String p = renderer.render(pointer);
        return p.matches("[A-Za-z_][A-Za-z0-9_]*") ? "*" + p : "*(" + stripParens(p) + ")";
    }

    private static String stripParens(String s) {
        if (s.length() < 2 || s.charAt(0) != '(' || s.charAt(s.length() - 1) != ')') return s;
        int depth = 0;
        for (int i = 0; i < s.length() - 1; i++) {
            char c = s.charAt(i);
            if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return s;   // the first '(' closes early
        }
        return s.substring(1, s.length() - 1);
    }

    /** "&name" when a PTRSUB takes the address of a global or of a stack local, else null. */
    private String addressOf(PcodeOp ptrsub) {
        Varnode base = ptrsub.getInput(0);
        Varnode off = ptrsub.getInput(1);
        if (base == null || off == null || !off.isConstant()) return null;
        if (base.isConstant()) return describeAddress(off.getOffset());
        if (!base.isRegister() || program == null) return null;
        Register sp = program.getCompilerSpec().getStackPointer();
        if (sp == null || !sp.getAddress().equals(base.getAddress())) return null;
        long stackOffset = off.getOffset();
        int bits = off.getSize() * 8;
        if (bits < 64 && bits > 0) stackOffset = (stackOffset << (64 - bits)) >> (64 - bits);
        if (high.getLocalSymbolMap() != null) {
            Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                VariableStorage storage = sym.getStorage();
                if (storage == null || !storage.isStackStorage()) continue;
                long start = storage.getStackOffset();
                if (stackOffset >= start && stackOffset < start + Math.max(1, sym.getSize())) {
                    return "&" + sym.getName() + (stackOffset == start ? "" : "[" + (stackOffset - start) + "]");
                }
            }
        }
        return "&stack[" + (stackOffset < 0 ? "-0x" + Long.toHexString(-stackOffset) : "0x" + Long.toHexString(stackOffset)) + "]";
    }

    private String describeConstant(Varnode vn) {
        long value = vn.getOffset();
        HighVariable hv = vn.getHigh();
        if (value != 0 && hv != null && hv.getDataType() instanceof Pointer) {
            String target = describeAddress(value);
            if (target != null) return target;
        }
        int size = vn.getSize();
        if (size > 0 && size < 8) value &= (1L << (size * 8)) - 1L;
        return value >= 0 && value < 10 ? Long.toString(value) : "0x" + Long.toHexString(value);
    }

    /** A string literal or "&symbol" for a constant that is a memory address; null if unknown. */
    private String describeAddress(long offset) {
        if (program == null) return null;
        try {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
            if (!program.getMemory().contains(addr)) return null;
            Data data = program.getListing().getDataAt(addr);
            if (data != null && data.hasStringValue()) {
                String s = String.valueOf(data.getValue());
                if (s.length() > 40) s = s.substring(0, 37) + "...";
                return "\"" + s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
            }
            Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
            return "&" + (sym != null ? sym.getName() : addr.toString());
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static boolean isNamed(HighVariable hv) {
        if (!(hv instanceof HighLocal) && !(hv instanceof HighGlobal)) return false;  // HighParam is a HighLocal
        String n = hv.getName();
        return n != null && !n.isEmpty() && !n.equals("UNNAMED");
    }

    /** param / local / global / constant / temp. */
    public static String kindOf(HighVariable hv) {
        if (hv instanceof HighParam) return "param";
        if (hv instanceof HighLocal) return "local";
        if (hv instanceof HighGlobal) return "global";
        if (hv instanceof HighConstant) return "constant";
        return "temp";
    }

    private static String typeName(HighVariable hv) {
        if (hv == null) return null;
        DataType dt = hv.getDataType();
        return dt == null ? null : dt.getDisplayName();
    }

    private static String opSymbol(int opc) {
        switch (opc) {
            case PcodeOp.COPY: return "copy";
            case PcodeOp.CAST: return "cast";
            case PcodeOp.LOAD: return "*";
            case PcodeOp.STORE: return "*=";
            case PcodeOp.INT_ADD: case PcodeOp.FLOAT_ADD: return "+";
            case PcodeOp.INT_SUB: case PcodeOp.FLOAT_SUB: return "-";
            case PcodeOp.INT_MULT: case PcodeOp.FLOAT_MULT: return "*";
            case PcodeOp.INT_DIV: case PcodeOp.INT_SDIV: case PcodeOp.FLOAT_DIV: return "/";
            case PcodeOp.INT_REM: case PcodeOp.INT_SREM: return "%";
            case PcodeOp.INT_AND: return "&";
            case PcodeOp.INT_OR: return "|";
            case PcodeOp.INT_XOR: return "^";
            case PcodeOp.INT_LEFT: return "<<";
            case PcodeOp.INT_RIGHT: case PcodeOp.INT_SRIGHT: return ">>";
            case PcodeOp.INT_EQUAL: case PcodeOp.FLOAT_EQUAL: return "==";
            case PcodeOp.INT_NOTEQUAL: case PcodeOp.FLOAT_NOTEQUAL: return "!=";
            case PcodeOp.INT_LESS: case PcodeOp.INT_SLESS: case PcodeOp.FLOAT_LESS: return "<";
            case PcodeOp.INT_LESSEQUAL: case PcodeOp.INT_SLESSEQUAL: case PcodeOp.FLOAT_LESSEQUAL: return "<=";
            case PcodeOp.BOOL_AND: return "&&";
            case PcodeOp.BOOL_OR: return "||";
            case PcodeOp.BOOL_XOR: return "^^";
            case PcodeOp.BOOL_NEGATE: return "!";
            case PcodeOp.INT_NEGATE: return "~";
            case PcodeOp.INT_2COMP: case PcodeOp.FLOAT_NEG: return "negate";
            case PcodeOp.INT_ZEXT: return "zero-extend";
            case PcodeOp.INT_SEXT: return "sign-extend";
            case PcodeOp.SUBPIECE: return "truncate";
            case PcodeOp.PIECE: return "concat";
            case PcodeOp.PTRADD: return "pointer index";
            case PcodeOp.PTRSUB: return "field offset";
            case PcodeOp.MULTIEQUAL: return "merge";
            case PcodeOp.INDIRECT: return "side effect";
            case PcodeOp.CBRANCH: return "if";
            case PcodeOp.BRANCHIND: return "switch";
            case PcodeOp.RETURN: return "return";
            default: return PcodeOp.getMnemonic(opc).toLowerCase(Locale.ROOT);
        }
    }

    // ------------------------------------------------------------------ tooltip

    private static final String DIM = "#808080";

    /**
     * Compact Swing-HTML (3.2: tables and font tags only) tooltip for a result, or
     * null when there is nothing worth showing.
     */
    public static String toHtml(Result r, int maxItems) {
        if (r == null || r.isEmpty()) return null;
        Seed seed = r.seed;
        StringBuilder sb = new StringBuilder("<html>");
        sb.append("<b>").append(esc(seed.label)).append("</b>");
        List<String> facts = new ArrayList<>();
        if (seed.kind == SeedKind.CALL) facts.add("call");
        if (seed.kind == SeedKind.OPERATOR) facts.add("expression");
        if (seed.kind == SeedKind.FIELD) facts.add("field");
        if (seed.dataType != null) facts.add(seed.dataType);
        if (seed.variableKind != null && seed.kind == SeedKind.VARIABLE) facts.add(seed.variableKind);
        if (seed.access != null) facts.add(seed.access);
        if (!facts.isEmpty()) {
            sb.append(" <font color=\"").append(DIM).append("\">").append(esc(String.join(", ", facts))).append("</font>");
        }
        if (seed.signature != null) {
            sb.append("<br><font color=\"").append(DIM).append("\">").append(esc(seed.signature)).append("</font>");
        }
        sb.append("<table cellspacing=\"0\" cellpadding=\"1\">");
        section(sb, "Affected by", r.affectedBy, r.backwardTruncated, maxItems);
        if (!r.mayBeModifiedBy.isEmpty()) {
            List<String> shown = r.mayBeModifiedBy.subList(0, Math.min(maxItems, r.mayBeModifiedBy.size()));
            String more = r.mayBeModifiedBy.size() > shown.size() ? ", +" + (r.mayBeModifiedBy.size() - shown.size()) + " more" : "";
            sb.append("<tr><td><font color=\"").append(DIM).append("\">may be modified by:</font></td><td>")
                .append(esc(String.join(", ", shown) + more)).append("</td></tr>");
        }
        section(sb, "Affects", r.affects, r.forwardTruncated, maxItems);
        return sb.append("</table></html>").toString();
    }

    private static void section(StringBuilder sb, String title, List<Item> items, boolean truncated, int maxItems) {
        sb.append("<tr><td colspan=\"2\"><b>").append(title).append("</b> (").append(items.size())
            .append(truncated ? "+" : "").append(")</td></tr>");
        if (items.isEmpty()) {
            sb.append("<tr><td></td><td><font color=\"").append(DIM).append("\">(none)</font></td></tr>");
        }
        int shown = 0;
        for (Item item : items) {
            if (shown++ >= maxItems) break;
            sb.append("<tr><td><font color=\"").append(DIM).append("\">&nbsp;&nbsp;").append(esc(item.kind))
                .append("</font></td><td>").append(esc(item.text));
            if (item.detail != null) {
                sb.append(" <font color=\"").append(DIM).append("\">").append(esc(item.detail)).append("</font>");
            }
            sb.append("</td></tr>");
        }
        if (items.size() > maxItems) {
            sb.append("<tr><td></td><td><font color=\"").append(DIM).append("\">+").append(items.size() - maxItems)
                .append(" more</font></td></tr>");
        }
        if (truncated) {
            sb.append("<tr><td></td><td><font color=\"").append(DIM)
                .append("\">search stopped at the depth/size limit</font></td></tr>");
        }
    }

    private static String esc(String s) {
        return HTMLUtilities.escapeHTML(s == null ? "" : s);
    }
}
