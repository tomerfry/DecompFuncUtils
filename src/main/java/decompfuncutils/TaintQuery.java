/*
 * TaintQuery - Query language AST and parser for semantic code pattern matching
 * 
 * Syntax:
 *   PATTERN name {
 *       // C-like pattern with $variables
 *   } WHERE constraints
 * 
 * Constraints:
 *   - tainted($var)              : variable is tainted by any source
 *   - tainted($var, "funcname")  : variable is tainted by specific source
 *   - flows_to($src, $dst)       : data flows from src to dst
 *   - is_constant($var)          : variable is a constant
 *   - is_param($var)             : variable is a function parameter  
 *   - is_local($var)             : variable is a local variable
 *   - tainted_ext($var)          : tainted by a real input source (parameters do not count)
 *   - unchecked($var)            : value never reaches a comparison feeding a branch
 *   - bounded($var)              : value reaches an ordered (<, <=, ...) comparison feeding a branch
 *   - nonneg_checked($var)       : a branch rejects negative values of the variable
 *   - overflow_checked($a[, $b]) : operands of a size computation are range- or division-checked
 *   - signed($var)               : value is a signed integer (sign-extended or signed type)
 *   - same($a, $b)               : both bind the same value (casts / extensions ignored)
 *   - related($a, $b)            : one derives from the other, or the two are compared
 *   - const_eq/ne/lt/le/gt/ge($a, $b|N) : compare constant bindings
 *   - in_loop($var) / in_loop()  : binding site (or the last matched element) is inside a loop
 *   - function_is($f, "name") / function_in($f, "a", "b", ...)
 *   - returned_by($var, "f", ...) : value is the return value of one of the named calls
 *   - NOT constraint             : negation
 *   - c1 AND c2                  : conjunction
 *   - c1 OR c2                   : disjunction
 */
package decompfuncutils;

import java.util.*;
import java.util.regex.*;

public class TaintQuery {
    
    private String name;
    private String rawPattern;
    private List<PatternElement> patternElements;
    private Constraint constraint;
    private Set<String> boundVariables;
    
    // Pattern elements
    public static abstract class PatternElement {
        public abstract boolean matches(TokenContext ctx, Map<String, Object> bindings);
    }
    
    public static class VariableDecl extends PatternElement {
        public String varName;      // e.g., "$buf"
        public String typeName;     // e.g., "char", null for any
        public boolean isArray;
        public String arraySize;    // "_" for any, number for specific, null for not array
        public boolean isPointer;
        /** {@code $n} in {@code char $buf[$n]}: bound to the array length in bytes (a Long). */
        public String sizeVar;

        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            if (!ctx.isVariableDeclaration()) return false;
            if (typeName != null && !ctx.getTypeName().contains(typeName)) return false;
            if (isArray && !ctx.isArray()) return false;
            if (isPointer && !ctx.isPointer()) return false;
            
            // Bind the variable
            bindings.put(varName, ctx.getVarnode());
            return true;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            if (typeName != null) sb.append(typeName).append(" ");
            if (isPointer) sb.append("*");
            sb.append(varName);
            if (isArray) sb.append("[").append(arraySize != null ? arraySize : "_").append("]");
            return sb.toString();
        }
    }
    
    public static class FunctionCall extends PatternElement {
        public String funcName;     // literal name or "$var" for any
        public List<String> args;   // "$arg1", "$arg2", "..." for varargs
        /** Parsed argument patterns (same order as {@link #args}); set by the parser. */
        public List<Expr> argExprs;

        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            if (!ctx.isFunctionCall()) return false;
            
            // Check function name
            if (funcName.startsWith("$")) {
                bindings.put(funcName, ctx.getCalledFunctionName());
            } else {
                if (!ctx.getCalledFunctionName().equals(funcName) && 
                    !ctx.getCalledFunctionName().contains(funcName)) {
                    return false;
                }
            }
            
            // Bind arguments
            List<Object> callArgs = ctx.getCallArguments();
            int argIdx = 0;
            for (String argPattern : args) {
                if (argPattern.equals("...")) {
                    // Varargs - match remaining
                    break;
                }
                if (argIdx >= callArgs.size()) return false;
                
                if (argPattern.startsWith("$")) {
                    bindings.put(argPattern, callArgs.get(argIdx));
                }
                argIdx++;
            }
            
            return true;
        }
        
        @Override
        public String toString() {
            return funcName + "(" + String.join(", ", args) + ")";
        }
    }
    
    public static class Assignment extends PatternElement {
        public String lhs;  // "$var" or pattern
        public String rhs;  // "$var", expression pattern, or "_" for any
        /** Parsed right-hand side; null for the legacy cast form {@code (type)$var}. */
        public Expr rhsExpr;

        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            if (!ctx.isAssignment()) return false;
            
            if (lhs.startsWith("$")) {
                bindings.put(lhs, ctx.getAssignmentTarget());
            }
            if (rhs.startsWith("$")) {
                bindings.put(rhs, ctx.getAssignmentSource());
            }
            
            return true;
        }
        
        @Override
        public String toString() {
            return lhs + " = " + rhs;
        }
    }
    
    public static class Dereference extends PatternElement {
        public String ptrVar;
        
        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            if (!ctx.isDereference()) return false;
            
            if (ptrVar.startsWith("$")) {
                Object bound = bindings.get(ptrVar);
                if (bound != null) {
                    // Check if same variable
                    return ctx.getDereferencedVar().equals(bound);
                }
                bindings.put(ptrVar, ctx.getDereferencedVar());
            }
            return true;
        }
        
        @Override
        public String toString() {
            return "*" + ptrVar;
        }
    }
    
    // ------------------------------------------------------------------
    // Expression patterns (call arguments, assignment right-hand sides,
    // operands of conditions). Produced by TaintQueryParser.
    // ------------------------------------------------------------------
    public static abstract class Expr {
        /** Collect $variables referenced by this expression. */
        public void collectVariables(Set<String> out) {}
        /** Collect literal (non-$) function names called inside this expression. */
        public void collectCallNames(Set<String> out) {}
    }

    /** {@code $name} - binds to (or must equal) a value. */
    public static class VarExpr extends Expr {
        public final String name;
        public VarExpr(String name) { this.name = name; }
        @Override public void collectVariables(Set<String> out) { out.add(name); }
        @Override public String toString() { return name; }
    }

    /** {@code _} - any single value. */
    public static class AnyExpr extends Expr {
        @Override public String toString() { return "_"; }
    }

    /** {@code ...} - any remaining arguments (only valid as a call argument). */
    public static class RestExpr extends Expr {
        @Override public String toString() { return "..."; }
    }

    /** Integer literal. */
    public static class LiteralExpr extends Expr {
        public final long value;
        public LiteralExpr(long value) { this.value = value; }
        @Override public String toString() {
            return value >= 0 && value < 10 ? Long.toString(value) : "0x" + Long.toHexString(value);
        }
    }

    /** {@code left op right} with op one of + - * / % << >> & | ^. */
    public static class BinaryExpr extends Expr {
        public final String op;
        public final Expr left, right;
        public BinaryExpr(String op, Expr left, Expr right) { this.op = op; this.left = left; this.right = right; }
        @Override public void collectVariables(Set<String> out) { left.collectVariables(out); right.collectVariables(out); }
        @Override public void collectCallNames(Set<String> out) { left.collectCallNames(out); right.collectCallNames(out); }
        @Override public String toString() { return left + " " + op + " " + right; }
    }

    /** {@code name(args)} used as a value, e.g. {@code malloc(strlen($s))}. */
    public static class CallExpr extends Expr {
        public final String funcName;
        public final List<Expr> args;
        public CallExpr(String funcName, List<Expr> args) { this.funcName = funcName; this.args = args; }
        @Override public void collectVariables(Set<String> out) {
            if (funcName.startsWith("$")) out.add(funcName);
            for (Expr a : args) a.collectVariables(out);
        }
        @Override public void collectCallNames(Set<String> out) {
            if (!funcName.startsWith("$")) out.add(funcName);
            for (Expr a : args) a.collectCallNames(out);
        }
        @Override public String toString() {
            StringBuilder sb = new StringBuilder(funcName).append("(");
            for (int i = 0; i < args.size(); i++) { if (i > 0) sb.append(", "); sb.append(args.get(i)); }
            return sb.append(")").toString();
        }
    }

    /** {@code *expr} used as a value: a load through the pointer. */
    public static class DerefExpr extends Expr {
        public final Expr pointer;
        public DerefExpr(Expr pointer) { this.pointer = pointer; }
        @Override public void collectVariables(Set<String> out) { pointer.collectVariables(out); }
        @Override public void collectCallNames(Set<String> out) { pointer.collectCallNames(out); }
        @Override public String toString() { return "*" + pointer; }
    }

    /**
     * A comparison that decides a branch: {@code $p == 0}, {@code $n < $max}.
     * == and != are interchangeable (the decompiler normalises freely), as are
     * the ordered operators and the operand order.
     */
    public static class Condition extends PatternElement {
        public Expr left;
        public String op;
        public Expr right;

        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) { return false; }

        @Override
        public String toString() { return left + " " + op + " " + right; }
    }

    public static class Wildcard extends PatternElement {
        // Matches any single statement or "_" for anything
        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            return true;
        }
        
        @Override
        public String toString() {
            return "_";
        }
    }
    
    public static class WildcardMulti extends PatternElement {
        // Matches zero or more statements "..."
        public List<NegativePattern> negatives = new ArrayList<>();  // not: patterns
        
        // Distance constraint: ...{min,max} limits how many statements the gap can span
        // -1 means unbounded (default behavior)
        public int minDistance = 0;   // minimum number of statements in the gap
        public int maxDistance = -1;  // maximum number of statements (-1 = unlimited)
        
        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            return true;
        }
        
        /**
         * Check if a given gap size satisfies the distance constraint
         */
        public boolean isDistanceSatisfied(int gapSize) {
            if (gapSize < minDistance) return false;
            if (maxDistance >= 0 && gapSize > maxDistance) return false;
            return true;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("...");
            if (maxDistance >= 0 || minDistance > 0) {
                sb.append("{").append(minDistance).append(",");
                sb.append(maxDistance >= 0 ? maxDistance : "").append("}");
            }
            for (NegativePattern neg : negatives) {
                if (neg.guardVarName != null) {
                    // Guard/conditional patterns already include their prefix in toString()
                    sb.append(" ").append(neg);
                } else {
                    sb.append(" not:").append(neg);
                }
            }
            return sb.toString();
        }
    }
    
    public static class NegativePattern {
        public String varName;      // Variable that must NOT be assigned
        public String pattern;      // Full pattern that must NOT appear
        /** Parsed form of {@link #pattern}: a call that must not execute in the gap. */
        public FunctionCall call;

        // Conditional branch barrier: not:($var == 0xffffffff) or not:($var cmp const)
        // If set, the gap must NOT contain a conditional branch that compares
        // the bound variable against the given constant - meaning such a check
        // IS required (double negation: "not having a check" = "check is absent" = bug)
        // When used as: ...{0,5} guard:($a == 0xffffffff), it means the gap must 
        // CONTAIN a branch comparing $a to the constant (sanitizer/guard check)
        public String guardVarName;     // Variable being compared (e.g., "$a")
        public Long guardConstant;      // Constant being compared against (e.g., 0xffffffff for npos)
        public boolean isGuardCheck;    // true = require guard (gap must contain check)
                                        // false = forbid guard (default not: behavior)
        
        @Override
        public String toString() {
            if (guardVarName != null) {
                String prefix = isGuardCheck ? "guard:" : "not:";
                String constStr = guardConstant != null ? 
                    "0x" + Long.toHexString(guardConstant) : "_";
                return prefix + "(" + guardVarName + " == " + constStr + ")";
            }
            if (varName != null) return varName + "=_";
            return pattern;
        }
    }
    
    // Constraints
    public static abstract class Constraint {
        public abstract boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx);
    }
    
    public static class TaintedConstraint extends Constraint {
        public String varName;
        public String sourceName;  // null for any source
        /** tainted_ext(): only real input sources count, parameters do not. */
        public boolean externalOnly;

        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object var = bindings.get(varName);
            if (var == null) return false;

            // Buffer contents are judged where the variable was last matched
            // (e.g. at the sink), not at the first pattern element.
            taintCtx.setUseSite(bindings.get(SITE_PREFIX + varName));
            if (externalOnly) {
                return taintCtx.isTaintedExternal(var);
            }
            if (sourceName != null) {
                return taintCtx.isTaintedBySource(var, sourceName);
            }
            return taintCtx.isTainted(var);
        }

        @Override
        public String toString() {
            if (externalOnly) {
                return "tainted_ext(" + varName + ")";
            }
            if (sourceName != null) {
                return "tainted(" + varName + ", \"" + sourceName + "\")";
            }
            return "tainted(" + varName + ")";
        }
    }

    /**
     * Value/site predicates that need p-code analysis. {@code kind} is the
     * constraint name; {@code vars} are $variables, {@code names} are quoted
     * strings and {@code number} an optional integer literal operand.
     */
    public static class CheckConstraint extends Constraint {
        public String kind;
        public List<String> vars = new ArrayList<>();
        public List<String> names = new ArrayList<>();
        public Long number;

        private Object bound(Map<String, Object> bindings, int i) {
            return i < vars.size() ? bindings.get(vars.get(i)) : null;
        }

        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext ctx) {
            Object a = bound(bindings, 0);
            Object b = bound(bindings, 1);
            switch (kind) {
                case "unchecked":      return a != null && ctx.isUnchecked(a);
                case "bounded":        return a != null && ctx.isBounded(a);
                case "nonneg_checked": return a != null && ctx.isNonNegativeChecked(a);
                case "signed":         return a != null && ctx.isSigned(a);
                case "overflow_checked":
                    if (a == null) return false;
                    return ctx.isOverflowChecked(a, vars.size() > 1 ? b : null);
                case "same":           return a != null && b != null && ctx.isSame(a, b);
                case "related":        return a != null && b != null && ctx.isRelated(a, b);
                case "returned_by":    return a != null && ctx.isReturnedBy(a, names);
                case "function_in": {
                    if (!(a instanceof String called)) return false;
                    for (String n : names) {
                        if (functionNameMatches(called, n)) return true;
                    }
                    return false;
                }
                case "in_loop": {
                    Object site = vars.isEmpty() ? bindings.get(LAST_SITE)
                        : bindings.get(SITE_PREFIX + vars.get(0));
                    return ctx.isInLoop(vars.isEmpty() ? null : a, site);
                }
                case "const_eq": case "const_ne": case "const_lt":
                case "const_le": case "const_gt": case "const_ge": {
                    Long x = a == null ? null : ctx.constantValue(a);
                    Long y = vars.size() > 1 ? (b == null ? null : ctx.constantValue(b)) : number;
                    if (x == null || y == null) return false;
                    int c = Long.compareUnsigned(x, y);
                    switch (kind) {
                        case "const_eq": return c == 0;
                        case "const_ne": return c != 0;
                        case "const_lt": return c < 0;
                        case "const_le": return c <= 0;
                        case "const_gt": return c > 0;
                        default:         return c >= 0;
                    }
                }
                default:
                    return false;
            }
        }

        @Override
        public String toString() {
            List<String> parts = new ArrayList<>(vars);
            for (String n : names) parts.add("\"" + n + "\"");
            if (number != null) parts.add(Long.toString(number));
            return kind + "(" + String.join(", ", parts) + ")";
        }
    }
    
    /** Restricts a captured call name to an explicitly modeled API. */
    public static class FunctionIsConstraint extends Constraint {
        public String varName;
        public String functionName;

        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object value = bindings.get(varName);
            return value instanceof String name && functionNameMatches(name, functionName);
        }

        @Override
        public String toString() {
            return "function_is(" + varName + ", \"" + functionName + "\")";
        }
    }

    public static class FlowsToConstraint extends Constraint {
        public String srcVar;
        public String dstVar;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object src = bindings.get(srcVar);
            Object dst = bindings.get(dstVar);
            if (src == null || dst == null) return false;
            return taintCtx.flowsTo(src, dst);
        }
        
        @Override
        public String toString() {
            return "flows_to(" + srcVar + ", " + dstVar + ")";
        }
    }
    
    public static class IsConstantConstraint extends Constraint {
        public String varName;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object var = bindings.get(varName);
            if (var == null) return false;
            return taintCtx.isConstant(var);
        }
        
        @Override
        public String toString() {
            return "is_constant(" + varName + ")";
        }
    }
    
    public static class IsParamConstraint extends Constraint {
        public String varName;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object var = bindings.get(varName);
            if (var == null) return false;
            return taintCtx.isParameter(var);
        }
        
        @Override
        public String toString() {
            return "is_param(" + varName + ")";
        }
    }
    
    public static class IsLocalConstraint extends Constraint {
        public String varName;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object var = bindings.get(varName);
            if (var == null) return false;
            return taintCtx.isLocal(var);
        }
        
        @Override
        public String toString() {
            return "is_local(" + varName + ")";
        }
    }
    
    public static class NotConstraint extends Constraint {
        public Constraint inner;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            return !inner.evaluate(bindings, taintCtx);
        }
        
        @Override
        public String toString() {
            return "NOT " + inner;
        }
    }
    
    public static class AndConstraint extends Constraint {
        public Constraint left;
        public Constraint right;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            return left.evaluate(bindings, taintCtx) && right.evaluate(bindings, taintCtx);
        }
        
        @Override
        public String toString() {
            return "(" + left + " AND " + right + ")";
        }
    }
    
    public static class OrConstraint extends Constraint {
        public Constraint left;
        public Constraint right;
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            return left.evaluate(bindings, taintCtx) || right.evaluate(bindings, taintCtx);
        }
        
        @Override
        public String toString() {
            return "(" + left + " OR " + right + ")";
        }
    }
    
    public static class TrueConstraint extends Constraint {
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            return true;
        }
        
        @Override
        public String toString() {
            return "true";
        }
    }
    
    // Interfaces for context during matching
    public interface TokenContext {
        boolean isVariableDeclaration();
        boolean isFunctionCall();
        boolean isAssignment();
        boolean isDereference();
        boolean isArray();
        boolean isPointer();
        String getTypeName();
        String getCalledFunctionName();
        List<Object> getCallArguments();
        Object getVarnode();
        Object getAssignmentTarget();
        Object getAssignmentSource();
        Object getDereferencedVar();
    }
    
    public interface TaintContext {
        boolean isTainted(Object var);
        boolean isTaintedBySource(Object var, String sourceName);
        boolean flowsTo(Object src, Object dst);
        boolean isConstant(Object var);
        boolean isParameter(Object var);
        boolean isLocal(Object var);

        // Analysis hooks added with the newer constraints. Defaults keep other
        // TaintContext implementations source compatible.

        /** Where the variable about to be tested was last matched (a PcodeOp), or null. */
        default void setUseSite(Object site) {}
        /** Tainted by a real input source; parameters are not sources. */
        default boolean isTaintedExternal(Object var) { return isTainted(var); }
        /** The value never reaches a comparison that decides a branch. */
        default boolean isUnchecked(Object var) { return false; }
        /** The value reaches an ordered comparison that decides a branch. */
        default boolean isBounded(Object var) { return false; }
        /** A branch rejects negative values (signed compare with 0/1/-1, or any unsigned compare). */
        default boolean isNonNegativeChecked(Object var) { return false; }
        /** Operands of a size computation are bounded, or a division-style check exists. */
        default boolean isOverflowChecked(Object a, Object b) { return false; }
        default boolean isSigned(Object var) { return false; }
        default boolean isSame(Object a, Object b) { return a != null && a.equals(b); }
        default boolean isRelated(Object a, Object b) { return isSame(a, b) || flowsTo(a, b) || flowsTo(b, a); }
        default boolean isReturnedBy(Object var, List<String> functionNames) { return false; }
        default boolean isInLoop(Object var, Object site) { return false; }
        /** Constant value of a binding (unsigned), or null when it is not a constant. */
        default Long constantValue(Object var) { return var instanceof Long l ? l : null; }
    }

    /**
     * Does a called function's name denote {@code target}? Wrapper prefixes and
     * suffixes (__x, __x_chk, x@plt, __imp_x, ...) are ignored, and a C++
     * qualified name matches on its last component.
     */
    public static boolean functionNameMatches(String called, String target) {
        if (called == null || target == null) return false;
        if (TaintMatrixConverter.nameMatches(called, target)) return true;
        int scope = called.lastIndexOf("::");
        return scope >= 0 && TaintMatrixConverter.nameMatches(called.substring(scope + 2), target);
    }

    /** Bindings whose key starts with this character are engine bookkeeping, not user variables. */
    public static final String INTERNAL_PREFIX = "#";
    /** {@code "#site:$var"} maps a variable to the PcodeOp where it was last matched. */
    public static final String SITE_PREFIX = "#site:";
    /** PcodeOp of the most recently matched pattern element (the sink once a match completes). */
    public static final String LAST_SITE = "#last";
    
    // Getters
    public String getName() { return name; }
    public String getRawPattern() { return rawPattern; }
    public List<PatternElement> getPatternElements() { return patternElements; }
    public Constraint getConstraint() { return constraint; }
    public Set<String> getBoundVariables() { return boundVariables; }
    
    // Builder
    public static class Builder {
        private TaintQuery query = new TaintQuery();
        
        public Builder name(String name) {
            query.name = name;
            return this;
        }
        
        public Builder rawPattern(String pattern) {
            query.rawPattern = pattern;
            return this;
        }
        
        public Builder elements(List<PatternElement> elements) {
            query.patternElements = elements;
            return this;
        }
        
        public Builder constraint(Constraint constraint) {
            query.constraint = constraint;
            return this;
        }
        
        public Builder variables(Set<String> vars) {
            query.boundVariables = vars;
            return this;
        }
        
        public TaintQuery build() {
            if (query.constraint == null) {
                query.constraint = new TrueConstraint();
            }
            if (query.boundVariables == null) {
                query.boundVariables = new HashSet<>();
            }
            if (query.patternElements == null) {
                query.patternElements = new ArrayList<>();
            }
            return query;
        }
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PATTERN ").append(name).append(" {\n");
        for (PatternElement elem : patternElements) {
            sb.append("    ").append(elem).append(";\n");
        }
        sb.append("}");
        if (!(constraint instanceof TrueConstraint)) {
            sb.append(" WHERE ").append(constraint);
        }
        return sb.toString();
    }
}
