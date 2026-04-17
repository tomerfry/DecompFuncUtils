package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.DecompInterfacePool;
import decompfuncutils.mcp.McpTool;
import decompfuncutils.mcp.McpUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.*;

/**
 * Closed-form branch-flip suggester. Given a conditional-branch address, matches
 * the condition against a small set of common shapes (comparisons against a
 * constant, optionally with a bitmask) and proposes concrete values for the
 * single named input that would flip the branch either way.
 *
 * Intentionally conservative: returns 'unsupported' for multi-variable or
 * complex expressions — a wrong suggestion is worse than no suggestion.
 */
public class SuggestBranchFlipTool implements McpTool {

    private static final int DEFAULT_EXPR_DEPTH = 8;

    private final DecompInterfacePool pool;

    public SuggestBranchFlipTool(DecompInterfacePool pool) {
        this.pool = pool;
    }

    @Override public String name() { return "ghidra_suggest_branch_flip"; }

    @Override
    public String description() {
        return "Given a conditional-branch address, propose concrete values that would make the " +
               "branch go either direction. Handles shapes like x == c, x != c, x < c (signed/unsigned), " +
               "x <= c, and (x & mask) == c. Returns 'unsupported' with the symbolic form when the " +
               "condition involves multiple variables or shapes outside the supported set — callers " +
               "should treat that as a hint to fall back to manual reasoning, not a solver failure.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("branchAddress", Map.of("type", "string",
            "description", "Address (hex) of the conditional-branch instruction"));
        props.put("maxExpressionDepth", Map.of("type", "integer",
            "description", "Max recursion depth for symbolic rendering (default 8)"));
        schema.put("properties", props);
        schema.put("required", List.of("branchAddress"));
        return schema;
    }

    @Override public boolean requiresEdt() { return false; }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (program == null) throw new IllegalStateException("No program is open");

        Address branchAddr = McpUtil.parseAddress((String) arguments.get("branchAddress"), program);
        int maxDepth = ((Number) arguments.getOrDefault("maxExpressionDepth", DEFAULT_EXPR_DEPTH)).intValue();

        Function func = program.getFunctionManager().getFunctionContaining(branchAddr);
        if (func == null) throw new IllegalArgumentException("No function contains " + branchAddr);

        DecompInterface decomp = pool.acquire(program);
        try {
            DecompileResults res = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
            if (res == null || !res.decompileCompleted()) {
                throw new RuntimeException("Decompilation failed: "
                    + (res != null ? res.getErrorMessage() : "null"));
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) throw new RuntimeException("No HighFunction");

            PcodeOp cbranch = findCBranchAt(hf, branchAddr);
            if (cbranch == null) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("branchAddress", branchAddr.toString());
                out.put("supported", false);
                out.put("reason", "No CBRANCH found at this address in the decompiled function.");
                return out;
            }

            Varnode condition = cbranch.getInput(1);
            PcodeExpressionRenderer renderer = new PcodeExpressionRenderer(program, maxDepth);
            String symbolic = renderer.render(condition);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("branchAddress", branchAddr.toString());
            result.put("function", func.getName());
            result.put("symbolic", symbolic);

            Analysis a = analyze(condition, program);
            if (a == null) {
                result.put("supported", false);
                result.put("reason", "Condition shape is not in the supported set (multi-variable, " +
                    "non-comparison, or unnamable leaf).");
                return result;
            }

            result.put("supported", true);
            result.put("shape", a.shape);
            result.put("variable", a.leafName);
            result.put("variableSizeBytes", a.leafSize);
            if (a.mask != null) result.put("mask", "0x" + a.mask.toString(16));
            result.put("constant", "0x" + a.constant.toString(16));
            result.put("signed", a.signed);
            if (a.isMemLoad) {
                result.put("basePointer", a.basePointer);
                result.put("offset", a.memOffset);
                if (a.fieldName != null) result.put("fieldName", a.fieldName);
                result.put("hint", "Write the suggested value at [" + a.basePointer
                    + " + 0x" + Long.toHexString(a.memOffset) + "] "
                    + "(" + a.leafSize + " byte" + (a.leafSize == 1 ? "" : "s") + ") to flip the branch.");
            }
            result.put("valuesMakingTrue", hexList(a.valuesForTrue()));
            result.put("valuesMakingFalse", hexList(a.valuesForFalse()));
            result.put("note",
                "Branch taken when condition is non-zero (TRUE). Values are suggestions for the named " +
                "input variable; write them into the corresponding register/memory before re-emulating.");
            return result;
        } finally {
            pool.release(program, decomp);
        }
    }

    // ------------------------------------------------------------------
    // Condition analysis
    // ------------------------------------------------------------------

    private static PcodeOp findCBranchAt(HighFunction hf, Address addr) {
        for (PcodeBlockBasic b : hf.getBasicBlocks()) {
            PcodeOp last = b.getLastOp();
            if (last != null && last.getOpcode() == PcodeOp.CBRANCH) {
                Address target = last.getSeqnum() != null ? last.getSeqnum().getTarget() : null;
                if (target != null && target.equals(addr)) return last;
            }
        }
        return null;
    }

    private enum Cmp { EQ, NEQ, ULT, ULE, UGT, UGE, SLT, SLE, SGT, SGE }

    private static class Analysis {
        String shape;     // e.g. "EQ", "AND_MASK_EQ", "MEM_EQ"
        String leafName;
        int leafSize;     // bytes
        Cmp cmp;
        boolean signed;
        BigInteger constant;
        BigInteger mask;  // null if no mask
        boolean negated;  // BOOL_NEGATE wrapping
        // Memory-load shape: condition compares *(base + memOffset) against constant.
        boolean isMemLoad;
        String basePointer;
        Long memOffset;   // byte offset from basePointer
        String fieldName; // struct field name when resolvable, otherwise null

        BigInteger modulus() { return BigInteger.ONE.shiftLeft(leafSize * 8); }
        BigInteger maxU() { return modulus().subtract(BigInteger.ONE); }
        BigInteger minS() { return BigInteger.ONE.shiftLeft(leafSize * 8 - 1).negate(); }
        BigInteger maxS() { return BigInteger.ONE.shiftLeft(leafSize * 8 - 1).subtract(BigInteger.ONE); }
        BigInteger addMod(BigInteger a, long delta) {
            return a.add(BigInteger.valueOf(delta)).mod(modulus());
        }

        List<BigInteger> valuesForTrue() {
            return negated ? falseValues() : trueValues();
        }
        List<BigInteger> valuesForFalse() {
            return negated ? trueValues() : falseValues();
        }

        private List<BigInteger> trueValues() {
            if (mask != null) {
                // (x & mask) == constant
                if (cmp == Cmp.EQ) return List.of(constant.and(mask));
                if (cmp == Cmp.NEQ) return List.of(constant.and(mask).xor(mask));
                return Collections.emptyList();
            }
            switch (cmp) {
                case EQ:  return List.of(constant);
                case NEQ: return List.of(addMod(constant, 1));
                case ULT: return List.of(BigInteger.ZERO);
                case ULE: return List.of(BigInteger.ZERO);
                case UGT: return List.of(maxU());
                case UGE: return List.of(maxU());
                case SLT: return List.of(minS());
                case SLE: return List.of(minS());
                case SGT: return List.of(maxS());
                case SGE: return List.of(maxS());
            }
            return Collections.emptyList();
        }

        private List<BigInteger> falseValues() {
            if (mask != null) {
                if (cmp == Cmp.EQ) return List.of(constant.and(mask).xor(mask));
                if (cmp == Cmp.NEQ) return List.of(constant.and(mask));
                return Collections.emptyList();
            }
            switch (cmp) {
                case EQ:  return List.of(addMod(constant, 1));
                case NEQ: return List.of(constant);
                case ULT: return List.of(constant);
                case ULE: return List.of(addMod(constant, 1));
                case UGT: return List.of(constant);
                case UGE: return List.of(addMod(constant, -1));
                case SLT: return List.of(constant);
                case SLE: return List.of(addMod(constant, 1));
                case SGT: return List.of(constant);
                case SGE: return List.of(addMod(constant, -1));
            }
            return Collections.emptyList();
        }
    }

    private Analysis analyze(Varnode cond, Program program) {
        Analysis a = new Analysis();

        // Peel BOOL_NEGATE
        Varnode c = cond;
        PcodeOp def = c.getDef();
        while (def != null && def.getOpcode() == PcodeOp.BOOL_NEGATE) {
            a.negated = !a.negated;
            c = def.getInput(0);
            def = c.getDef();
        }
        if (def == null) return null;

        Cmp cmp = opToCmp(def.getOpcode());
        if (cmp == null) return null;
        a.cmp = cmp;
        a.signed = isSigned(def.getOpcode());

        Varnode left = def.getInput(0);
        Varnode right = def.getInput(1);
        Varnode constVn, exprVn;
        if (right.isConstant()) { constVn = right; exprVn = left; }
        else if (left.isConstant()) {
            constVn = left; exprVn = right;
            a.cmp = swap(cmp);
        } else return null;

        a.constant = BigInteger.valueOf(constVn.getOffset())
            .and(BigInteger.ONE.shiftLeft(constVn.getSize() * 8).subtract(BigInteger.ONE));

        // Maybe peel INT_AND (mask) on exprVn
        PcodeOp eDef = exprVn.getDef();
        if (eDef != null && eDef.getOpcode() == PcodeOp.INT_AND) {
            Varnode la = eDef.getInput(0);
            Varnode lb = eDef.getInput(1);
            if (lb.isConstant()) {
                a.mask = BigInteger.valueOf(lb.getOffset())
                    .and(BigInteger.ONE.shiftLeft(lb.getSize() * 8).subtract(BigInteger.ONE));
                exprVn = la;
            } else if (la.isConstant()) {
                a.mask = BigInteger.valueOf(la.getOffset())
                    .and(BigInteger.ONE.shiftLeft(la.getSize() * 8).subtract(BigInteger.ONE));
                exprVn = lb;
            }
        }

        // Peel transparent ops (COPY/CAST/ZEXT/SEXT) to find the named leaf
        Varnode leaf = peelTransparent(exprVn);

        // Memory-load leaf: comparison like `*(base + offset) == c` — common for
        // struct-field dispatch (`r->magic == 'P'`, `buf[0] == 0xff`, etc.).
        PcodeOp leafDef = leaf.getDef();
        if (leafDef != null && leafDef.getOpcode() == PcodeOp.LOAD) {
            Varnode loadPtr = leafDef.getInput(1);
            BaseOffset bo = baseOffsetOf(loadPtr);
            if (bo != null) {
                String baseName = leafName(bo.base, program);
                if (baseName != null) {
                    a.isMemLoad = true;
                    a.basePointer = baseName;
                    a.memOffset = bo.offset;
                    a.fieldName = lookupFieldName(bo.base, bo.offset);
                    a.leafName = a.fieldName != null
                        ? baseName + "->" + a.fieldName
                        : "*(" + baseName + " + 0x" + Long.toHexString(bo.offset) + ")";
                    a.leafSize = Math.max(1, leaf.getSize());
                    a.shape = (a.mask != null ? "AND_MASK_" : "") + "MEM_" + a.cmp.name();
                    return a;
                }
            }
        }

        // Leaf must be namable — param/local/global or a register.
        String name = leafName(leaf, program);
        if (name == null) return null;

        a.leafName = name;
        a.leafSize = Math.max(1, leaf.getSize());
        a.shape = (a.mask != null ? "AND_MASK_" : "") + a.cmp.name();
        return a;
    }

    /**
     * Resolve `base + constOffset` through PTRSUB/PTRADD/INT_ADD/COPY/CAST.
     * Returns null if the varnode isn't an offset-from-a-base expression.
     */
    private static BaseOffset baseOffsetOf(Varnode vn) {
        if (vn == null) return null;
        PcodeOp def = vn.getDef();
        if (def == null) return new BaseOffset(vn, 0L);
        int op = def.getOpcode();
        if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
            return baseOffsetOf(def.getInput(0));
        }
        if (op == PcodeOp.PTRSUB || op == PcodeOp.PTRADD || op == PcodeOp.INT_ADD) {
            Varnode aIn = def.getInput(0);
            Varnode bIn = def.getInput(1);
            if (aIn != null && bIn != null && bIn.isConstant()) {
                long mult = (op == PcodeOp.PTRADD && def.getNumInputs() >= 3
                    && def.getInput(2) != null && def.getInput(2).isConstant())
                    ? def.getInput(2).getOffset() : 1L;
                return new BaseOffset(aIn, bIn.getOffset() * mult);
            }
            if (aIn != null && bIn != null && aIn.isConstant()) {
                return new BaseOffset(bIn, aIn.getOffset());
            }
        }
        return new BaseOffset(vn, 0L);
    }

    private static String lookupFieldName(Varnode base, long offset) {
        if (base == null) return null;
        HighVariable hv = base.getHigh();
        if (hv == null) return null;
        ghidra.program.model.data.DataType dt = hv.getDataType();
        ghidra.program.model.data.Structure s = null;
        if (dt instanceof ghidra.program.model.data.Pointer p
                && p.getDataType() instanceof ghidra.program.model.data.Structure sp) {
            s = sp;
        } else if (dt instanceof ghidra.program.model.data.Structure sd) {
            s = sd;
        }
        if (s == null) return null;
        if (offset < 0 || offset >= s.getLength()) return null;
        ghidra.program.model.data.DataTypeComponent comp = s.getComponentContaining((int) offset);
        if (comp == null || comp.getOffset() != (int) offset) return null;
        String n = comp.getFieldName();
        return (n == null || n.isEmpty()) ? null : n;
    }

    private static final class BaseOffset {
        final Varnode base;
        final long offset;
        BaseOffset(Varnode base, long offset) { this.base = base; this.offset = offset; }
    }

    private static Varnode peelTransparent(Varnode vn) {
        while (vn.getDef() != null) {
            int op = vn.getDef().getOpcode();
            if (op == PcodeOp.COPY || op == PcodeOp.CAST
                    || op == PcodeOp.INT_ZEXT || op == PcodeOp.INT_SEXT) {
                vn = vn.getDef().getInput(0);
            } else break;
        }
        return vn;
    }

    private static String leafName(Varnode vn, Program program) {
        HighVariable hv = vn.getHigh();
        if (hv != null) {
            HighSymbol sym = hv.getSymbol();
            if (sym != null && isUseful(sym.getName())) return sym.getName();
            if (isUseful(hv.getName())) return hv.getName();
        }
        if (vn.isRegister()) {
            try {
                Register r = program.getRegister(vn.getAddress(), vn.getSize());
                if (r != null) return r.getName();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static boolean isUseful(String n) {
        return n != null && !n.isEmpty() && !n.equals("UNNAMED");
    }

    private static Cmp opToCmp(int opcode) {
        switch (opcode) {
            case PcodeOp.INT_EQUAL:       return Cmp.EQ;
            case PcodeOp.INT_NOTEQUAL:    return Cmp.NEQ;
            case PcodeOp.INT_LESS:        return Cmp.ULT;
            case PcodeOp.INT_LESSEQUAL:   return Cmp.ULE;
            case PcodeOp.INT_SLESS:       return Cmp.SLT;
            case PcodeOp.INT_SLESSEQUAL:  return Cmp.SLE;
            default: return null;
        }
    }

    private static boolean isSigned(int opcode) {
        return opcode == PcodeOp.INT_SLESS || opcode == PcodeOp.INT_SLESSEQUAL;
    }

    // When operand order is swapped (const on left), comparisons flip direction.
    private static Cmp swap(Cmp c) {
        switch (c) {
            case ULT: return Cmp.UGT;
            case ULE: return Cmp.UGE;
            case UGT: return Cmp.ULT;
            case UGE: return Cmp.ULE;
            case SLT: return Cmp.SGT;
            case SLE: return Cmp.SGE;
            case SGT: return Cmp.SLT;
            case SGE: return Cmp.SLE;
            default:  return c; // EQ / NEQ symmetric
        }
    }

    private static List<String> hexList(List<BigInteger> xs) {
        List<String> out = new ArrayList<>(xs.size());
        for (BigInteger x : xs) out.add("0x" + x.toString(16));
        return out;
    }
}
