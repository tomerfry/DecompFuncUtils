package decompfuncutils.refine.ast;

import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.List;

/** Statement nodes of the refinement AST. */
public abstract class Stmt {
    /** Lowest and highest machine address the decompiler attributed to this statement. */
    public Address addr, maxAddr;
    /** Set when a pass produced or changed this statement. */
    public Object note;

    /** Expressions held directly by this statement (not those of nested statements). */
    public List<Expr> exprs() { return List.of(); }
    public void expr(int i, Expr e) { throw new IndexOutOfBoundsException(); }
    /** Nested blocks. */
    public List<Block> blocks() { return List.of(); }
    public abstract Stmt copy();

    protected <T extends Stmt> T from(T src) {
        addr = src.addr;
        maxAddr = src.maxAddr;
        note = src.note;
        @SuppressWarnings("unchecked") T self = (T) this;
        return self;
    }

    public Stmt span(Address lo, Address hi) {
        if (lo != null && (addr == null || lo.compareTo(addr) < 0)) addr = lo;
        if (hi != null && (maxAddr == null || hi.compareTo(maxAddr) > 0)) maxAddr = hi;
        return this;
    }

    public static final class Block extends Stmt {
        public final List<Stmt> body = new ArrayList<>();

        public Block() {}
        public Block(List<Stmt> body) { this.body.addAll(body); }
        @Override public Block copy() {
            Block b = new Block().from(this);
            for (Stmt s : body) b.body.add(s.copy());
            return b;
        }
    }

    public static final class ExprStmt extends Stmt {
        public Expr e;

        public ExprStmt(Expr e) { this.e = e; }
        @Override public List<Expr> exprs() { return List.of(e); }
        @Override public void expr(int i, Expr x) { e = x; }
        @Override public Stmt copy() { return new ExprStmt(e.copy()).from(this); }
    }

    public static final class If extends Stmt {
        public Expr cond;
        public Block then;
        /** Null when there is no else. */
        public Block otherwise;

        public If(Expr cond, Block then, Block otherwise) { this.cond = cond; this.then = then; this.otherwise = otherwise; }
        @Override public List<Expr> exprs() { return List.of(cond); }
        @Override public void expr(int i, Expr x) { cond = x; }
        @Override public List<Block> blocks() { return otherwise == null ? List.of(then) : List.of(then, otherwise); }
        @Override public Stmt copy() {
            return new If(cond.copy(), then.copy(), otherwise == null ? null : otherwise.copy()).from(this);
        }
    }

    public static final class While extends Stmt {
        public Expr cond;
        public Block body;

        public While(Expr cond, Block body) { this.cond = cond; this.body = body; }
        @Override public List<Expr> exprs() { return List.of(cond); }
        @Override public void expr(int i, Expr x) { cond = x; }
        @Override public List<Block> blocks() { return List.of(body); }
        @Override public Stmt copy() { return new While(cond.copy(), body.copy()).from(this); }
    }

    public static final class DoWhile extends Stmt {
        public Block body;
        public Expr cond;

        public DoWhile(Block body, Expr cond) { this.body = body; this.cond = cond; }
        @Override public List<Expr> exprs() { return List.of(cond); }
        @Override public void expr(int i, Expr x) { cond = x; }
        @Override public List<Block> blocks() { return List.of(body); }
        @Override public Stmt copy() { return new DoWhile(body.copy(), cond.copy()).from(this); }
    }

    /** for (init; cond; step) body -- any of the three headers may be null. */
    public static final class For extends Stmt {
        public Expr init, cond, step;
        public Block body;

        public For(Expr init, Expr cond, Expr step, Block body) {
            this.init = init; this.cond = cond; this.step = step; this.body = body;
        }
        @Override public List<Expr> exprs() {
            List<Expr> out = new ArrayList<>(3);
            if (init != null) out.add(init);
            if (cond != null) out.add(cond);
            if (step != null) out.add(step);
            return out;
        }
        @Override public void expr(int i, Expr x) {
            int k = 0;
            if (init != null && k++ == i) { init = x; return; }
            if (cond != null && k++ == i) { cond = x; return; }
            if (step != null && k == i) { step = x; return; }
            throw new IndexOutOfBoundsException();
        }
        @Override public List<Block> blocks() { return List.of(body); }
        @Override public Stmt copy() {
            return new For(init == null ? null : init.copy(), cond == null ? null : cond.copy(),
                step == null ? null : step.copy(), body.copy()).from(this);
        }
    }

    /** switch (e) { ... } with {@link CaseLabel} statements inside the body, as in C. */
    public static final class Switch extends Stmt {
        public Expr e;
        public Block body;

        public Switch(Expr e, Block body) { this.e = e; this.body = body; }
        @Override public List<Expr> exprs() { return List.of(e); }
        @Override public void expr(int i, Expr x) { e = x; }
        @Override public List<Block> blocks() { return List.of(body); }
        @Override public Stmt copy() { return new Switch(e.copy(), body.copy()).from(this); }
    }

    /** case value: or, with a null value, default: */
    public static final class CaseLabel extends Stmt {
        public Expr value;

        public CaseLabel(Expr value) { this.value = value; }
        @Override public List<Expr> exprs() { return value == null ? List.of() : List.of(value); }
        @Override public void expr(int i, Expr x) { value = x; }
        @Override public Stmt copy() { return new CaseLabel(value == null ? null : value.copy()).from(this); }
    }

    public static final class Return extends Stmt {
        /** Null for a bare return. */
        public Expr e;

        public Return(Expr e) { this.e = e; }
        @Override public List<Expr> exprs() { return e == null ? List.of() : List.of(e); }
        @Override public void expr(int i, Expr x) { e = x; }
        @Override public Stmt copy() { return new Return(e == null ? null : e.copy()).from(this); }
    }

    public static final class Break extends Stmt {
        @Override public Stmt copy() { return new Break().from(this); }
    }

    public static final class Continue extends Stmt {
        @Override public Stmt copy() { return new Continue().from(this); }
    }

    public static final class Goto extends Stmt {
        public String label;

        public Goto(String label) { this.label = label; }
        @Override public Stmt copy() { return new Goto(label).from(this); }
    }

    public static final class Label extends Stmt {
        public String name;

        public Label(String name) { this.name = name; }
        @Override public Stmt copy() { return new Label(name).from(this); }
    }

    public static final class Comment extends Stmt {
        public String text;

        public Comment(String text) { this.text = text; }
        @Override public Stmt copy() { return new Comment(text).from(this); }
    }

    /** Source text the parser could not structure; printed back verbatim, one entry per line. */
    public static final class Raw extends Stmt {
        public final List<String> lines = new ArrayList<>();
        /** Why the parser gave up on this statement. */
        public String reason;

        public Raw(List<String> lines) { this.lines.addAll(lines); }
        @Override public Stmt copy() { return new Raw(lines).from(this); }
    }
}
