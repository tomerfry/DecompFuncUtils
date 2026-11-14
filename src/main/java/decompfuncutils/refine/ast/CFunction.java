package decompfuncutils.refine.ast;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One decompiled function as the refinement engine sees it. */
public final class CFunction {
    /** A parameter or local declaration. {@code text} is the declaration as the decompiler printed it. */
    public static final class Var {
        public String name;
        public CType type;
        public String text;
        public HighSymbol symbol;
        public boolean param;
        /** Set by a pass that made the variable unnecessary; the printer then drops its declaration. */
        public boolean dropped;

        public Var(String name, CType type, String text, HighSymbol symbol, boolean param) {
            this.name = name; this.type = type; this.text = text; this.symbol = symbol; this.param = param;
        }
    }

    public Program program;
    public Function function;
    public HighFunction high;
    public String name;
    /** Prototype line as printed, without the opening brace. */
    public String prototype;
    public CType returnType = CType.UNKNOWN;
    public final List<Var> params = new ArrayList<>();
    public final List<Var> locals = new ArrayList<>();
    public final Map<String, Var> vars = new LinkedHashMap<>();
    /** Comments the decompiler printed ahead of the prototype (warnings, mostly). */
    public final List<String> header = new ArrayList<>();
    public Stmt.Block body = new Stmt.Block();
    public int pointerBits = 64;
    public boolean bigEndian;
    /** Number of statements the parser had to keep as raw text. */
    public int rawStatements;
    /** The body has gotos, labels or unparsed text, so the order of statements is not the order of execution. */
    public boolean unstructured;
    /**
     * The address of something in the stack frame is taken somewhere in the function. From then
     * on a store to any stack variable may be read through a pointer: the decompiler routinely
     * shows a struct that is passed by address as a handful of unrelated-looking locals.
     */
    public boolean frameEscapes;

    /**
     * May an assignment to this variable be deleted, or folded away, when its value is not read
     * again? True for variables that live in registers; for stack variables only while no stack
     * address escapes. Unknown storage counts as not removable.
     */
    public boolean removable(String name) {
        Var v = vars.get(name);
        if (v == null || v.symbol == null || v.type.isAggregate()) return false;
        ghidra.program.model.listing.VariableStorage st = v.symbol.getStorage();
        if (st == null || st.isBadStorage()) return false;
        if (st.isRegisterStorage() || st.isUniqueStorage() || st.isHashStorage()) return true;
        return st.isStackStorage() && !frameEscapes;
    }

    public CType typeOf(String name) {
        Var v = vars.get(name);
        return v == null ? null : v.type;
    }

    /** Declare a new local for a pass that needs a temporary. */
    public Var declare(String base, CType type) {
        String name = base;
        for (int i = 1; vars.containsKey(name); i++) name = base + i;
        Var v = new Var(name, type, type.name + " " + name, null, false);
        locals.add(v);
        vars.put(name, v);
        return v;
    }
}
