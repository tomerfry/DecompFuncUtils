package decompfuncutils.refine.ast;

import decompfuncutils.refine.ast.Expr.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/** Traversal, comparison and simple data-flow questions over the refinement AST. */
public final class AstUtil {
    private AstUtil() {}

    // ------------------------------------------------------------------ traversal

    public static void walk(Expr e, Consumer<Expr> visit) {
        visit.accept(e);
        for (int i = 0; i < e.kids(); i++) walk(e.kid(i), visit);
    }

    /** Visit a statement and everything nested in it, outermost first. */
    public static void walk(Stmt s, Consumer<Stmt> visit) {
        visit.accept(s);
        if (s instanceof Stmt.Block b) for (Stmt c : new ArrayList<>(b.body)) walk(c, visit);
        for (Stmt.Block b : s.blocks()) walk(b, visit);
    }

    /** Visit every expression root held anywhere under {@code s}. */
    public static void exprs(Stmt s, Consumer<Expr> visit) {
        walk(s, st -> { for (Expr e : st.exprs()) visit.accept(e); });
    }

    public static boolean any(Expr e, Predicate<Expr> test) {
        if (test.test(e)) return true;
        for (int i = 0; i < e.kids(); i++) if (any(e.kid(i), test)) return true;
        return false;
    }

    public static boolean any(Stmt s, Predicate<Expr> test) {
        boolean[] hit = new boolean[1];
        exprs(s, e -> { if (!hit[0] && any(e, test)) hit[0] = true; });
        return hit[0];
    }

    public static int size(Expr e) {
        int n = 1;
        for (int i = 0; i < e.kids(); i++) n += size(e.kid(i));
        return n;
    }

    /** Rewrite bottom-up: children first, then the node itself. Returns the (possibly new) root. */
    public static Expr rewrite(Expr e, Function<Expr, Expr> f) {
        for (int i = 0; i < e.kids(); i++) {
            Expr k = e.kid(i);
            Expr r = rewrite(k, f);
            if (r != k) e.kid(i, r);
        }
        Expr out = f.apply(e);
        return out == null ? e : out;
    }

    /** Rewrite every expression under {@code s} bottom-up. Returns true if anything changed. */
    public static boolean rewriteAll(Stmt s, Function<Expr, Expr> f) {
        boolean[] changed = new boolean[1];
        walk(s, st -> {
            List<Expr> es = st.exprs();
            for (int i = 0; i < es.size(); i++) {
                Expr before = es.get(i);
                Expr after = rewrite(before, x -> {
                    Expr r = f.apply(x);
                    if (r != null && r != x) changed[0] = true;
                    return r;
                });
                if (after != before) st.expr(i, after);
            }
        });
        return changed[0];
    }

    // ------------------------------------------------------------------ comparison

    /** Structural equality: same shape, names, values and widths. Provenance is ignored. */
    public static boolean same(Expr a, Expr b) {
        if (a == b) return true;
        if (a == null || b == null || a.getClass() != b.getClass() || a.kids() != b.kids()) return false;
        switch (a) {
            case Id x -> { if (!x.name.equals(((Id) b).name)) return false; }
            case Lit x -> {
                Lit y = (Lit) b;
                if (x.value == null || y.value == null) return x.value == y.value && String.valueOf(x.text).equals(String.valueOf(y.text));
                if (!x.value.equals(y.value) || x.type.bits != y.type.bits) return false;
            }
            case Un x -> { if (!x.o.equals(((Un) b).o) || x.postfix != ((Un) b).postfix) return false; }
            case Bin x -> { if (!x.o.equals(((Bin) b).o) || x.sgn != ((Bin) b).sgn || x.scale != ((Bin) b).scale) return false; }
            case Assign x -> { if (!x.o.equals(((Assign) b).o)) return false; }
            case Cast x -> { if (x.type.bits != b.type.bits || x.type.signed != b.type.signed || x.type.kind != b.type.kind) return false; }
            case Member x -> { if (!x.field.equals(((Member) b).field) || x.arrow != ((Member) b).arrow) return false; }
            case Expr.Raw x -> { if (!x.text.equals(((Expr.Raw) b).text)) return false; }
            default -> { }
        }
        for (int i = 0; i < a.kids(); i++) if (!same(a.kid(i), b.kid(i))) return false;
        return true;
    }

    // ------------------------------------------------------------------ effects

    /** No assignment, no increment, no call other than to a known pure function. */
    public static boolean isPure(Expr e) {
        return !any(e, x -> x instanceof Assign || x instanceof Expr.Raw
            || (x instanceof Un u && (u.o.equals("++") || u.o.equals("--")))
            || (x instanceof Call c && !pureCall(c)));
    }

    private static boolean pureCall(Call c) {
        if (c.pure) return true;
        String n = c.name();
        return n != null && c.fn instanceof Id id && id.function == null && decompfuncutils.refine.sem.Builtins.isSideEffectFree(n);
    }

    /** Whether the value depends on memory contents (dereference, subscript, field, global). */
    public static boolean readsMemory(Expr e) {
        return any(e, x -> (x instanceof Un u && u.o.equals("*")) || x instanceof Index
            || (x instanceof Member m && (m.arrow || readsMemory(m.base)))
            || (x instanceof Id id && id.kind == Id.Kind.GLOBAL)
            || (x instanceof Call c && !(c.fn instanceof Id id && id.function == null && !c.pure
                && decompfuncutils.refine.sem.Builtins.isPure(c.name()))));
    }

    public static boolean mentions(Expr e, String name) {
        return any(e, x -> x instanceof Id id && id.name.equals(name) && id.kind != Id.Kind.FUNC);
    }

    public static boolean mentions(Stmt s, String name) {
        if (s instanceof Stmt.Raw raw) {
            for (String line : raw.lines) for (String w : line.split("[^A-Za-z0-9_]+")) if (w.equals(name)) return true;
        }
        boolean[] hit = new boolean[1];
        walk(s, st -> {
            if (st instanceof Stmt.Raw raw && st != s) {
                for (String line : raw.lines) for (String w : line.split("[^A-Za-z0-9_]+")) if (w.equals(name)) hit[0] = true;
            }
        });
        return hit[0] || any(s, x -> x instanceof Id id && id.name.equals(name) && id.kind != Id.Kind.FUNC);
    }

    /** Names of variables read or written anywhere in the expression. */
    public static Set<String> names(Expr e) {
        Set<String> out = new HashSet<>();
        walk(e, x -> { if (x instanceof Id id && id.kind != Id.Kind.FUNC) out.add(id.name); });
        return out;
    }

    /** Variables a statement (and what it contains) assigns directly. */
    public static Set<String> assigned(Stmt s) {
        Set<String> out = new HashSet<>();
        exprs(s, root -> walk(root, x -> {
            if (x instanceof Assign a && a.l instanceof Id id) out.add(id.name);
            if (x instanceof Un u && (u.o.equals("++") || u.o.equals("--")) && u.e instanceof Id id) out.add(id.name);
        }));
        return out;
    }

    /** Whether anything under {@code s} writes memory or calls something that might. */
    public static boolean writesMemory(Stmt s) {
        return any(s, x -> (x instanceof Assign a && !(a.l instanceof Id))
            || (x instanceof Un u && (u.o.equals("++") || u.o.equals("--")) && !(u.e instanceof Id))
            || (x instanceof Call c && !pureCall(c)));
    }

    public static boolean hasCalls(Stmt s) { return any(s, x -> x instanceof Call c && !pureCall(c)); }

    /** Whether control can leave {@code s} other than by falling off its end. */
    public static boolean hasJumps(Stmt s) {
        boolean[] hit = new boolean[1];
        walk(s, st -> {
            if (st instanceof Stmt.Return || st instanceof Stmt.Goto || st instanceof Stmt.Label || st instanceof Stmt.Raw
                    || st instanceof Stmt.Break || st instanceof Stmt.Continue) hit[0] = true;
        });
        return hit[0];
    }

    // ------------------------------------------------------------------ position and liveness

    /** Chain of statements from {@code root} down to {@code target} (both included), or null. */
    public static List<Stmt> path(Stmt root, Stmt target) {
        if (root == target) {
            List<Stmt> p = new ArrayList<>();
            p.add(root);
            return p;
        }
        List<Stmt> children = new ArrayList<>();
        if (root instanceof Stmt.Block b) children.addAll(b.body);
        children.addAll(root.blocks());
        for (Stmt c : children) {
            List<Stmt> p = path(c, target);
            if (p != null) {
                p.add(0, root);
                return p;
            }
        }
        return null;
    }

    /** The block that directly contains {@code target}, or null. */
    public static Stmt.Block parentBlock(Stmt root, Stmt target) {
        List<Stmt> p = path(root, target);
        if (p == null || p.size() < 2) return null;
        return p.get(p.size() - 2) instanceof Stmt.Block b ? b : null;
    }

    /**
     * May the value {@code name} holds after statement {@code s} still be read? This errs toward
     * "yes": any later mention counts unless a plain reassignment comes first in the same block,
     * and inside a loop every mention in the loop counts because the back edge reaches it.
     */
    public static boolean liveAfter(CFunction f, Stmt s, String name) {
        List<Stmt> p = path(f.body, s);
        if (p == null) return true;
        if (f.unstructured) {
            // With gotos, text order says nothing about what runs next: any other mention counts.
            boolean[] hit = new boolean[1];
            walk(f.body, st -> {
                if (hit[0] || st == s || path(s, st) != null) return;
                for (Expr e : st.exprs()) if (mentions(e, name)) hit[0] = true;
                if (st instanceof Stmt.Raw && mentions(st, name)) hit[0] = true;
            });
            return hit[0];
        }
        for (int level = p.size() - 1; level >= 1; level--) {
            Stmt child = p.get(level), parent = p.get(level - 1);
            if (parent instanceof Stmt.Block b) {
                int at = b.body.indexOf(child);
                for (int i = at + 1; i < b.body.size(); i++) {
                    Stmt later = b.body.get(i);
                    if (later instanceof Stmt.ExprStmt es && es.e instanceof Assign a && a.o.equals("=")
                            && a.l instanceof Id id && id.name.equals(name) && !mentions(a.r, name)) {
                        if (!insideLoop(p, level - 1)) return false;
                        break;
                    }
                    if (mentions(later, name)) return true;
                }
            } else if (parent instanceof Stmt.While || parent instanceof Stmt.DoWhile || parent instanceof Stmt.For) {
                // The back edge: anything in the loop outside s can run after s.
                for (Expr e : parent.exprs()) if (mentions(e, name)) return true;
                for (Stmt.Block body : parent.blocks()) {
                    boolean[] hit = new boolean[1];
                    walk(body, st -> {
                        if (st == s || hit[0]) return;
                        if (path(s, st) != null) return;
                        for (Expr e : st.exprs()) if (mentions(e, name)) hit[0] = true;
                        if (st instanceof Stmt.Raw && mentions(st, name)) hit[0] = true;
                    });
                    if (hit[0]) return true;
                }
            } else {
                for (Expr e : parent.exprs()) {
                    // A condition or header of an enclosing if/switch was evaluated before s.
                    if (parent instanceof Stmt.If || parent instanceof Stmt.Switch) continue;
                    if (mentions(e, name)) return true;
                }
            }
        }
        return false;
    }

    private static boolean insideLoop(List<Stmt> path, int upTo) {
        for (int i = 0; i <= upTo && i < path.size(); i++) {
            Stmt s = path.get(i);
            if (s instanceof Stmt.While || s instanceof Stmt.DoWhile || s instanceof Stmt.For) return true;
        }
        return false;
    }

    /** Count how many times {@code name} appears as a value or target anywhere in the function. */
    public static int mentionCount(Stmt root, String name) {
        int[] n = new int[1];
        exprs(root, e -> walk(e, x -> { if (x instanceof Id id && id.name.equals(name) && id.kind != Id.Kind.FUNC) n[0]++; }));
        walk(root, st -> { if (st instanceof Stmt.Raw && mentions(st, name)) n[0] += 2; });
        return n[0];
    }
}
