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
 *   - calls($func)               : pattern contains call to func
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
        @Override
        public boolean matches(TokenContext ctx, Map<String, Object> bindings) {
            return true;
        }
        
        @Override
        public String toString() {
            return "...";
        }
    }
    
    // Constraints
    public static abstract class Constraint {
        public abstract boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx);
    }
    
    public static class TaintedConstraint extends Constraint {
        public String varName;
        public String sourceName;  // null for any source
        
        @Override
        public boolean evaluate(Map<String, Object> bindings, TaintContext taintCtx) {
            Object var = bindings.get(varName);
            if (var == null) return false;
            
            if (sourceName != null) {
                return taintCtx.isTaintedBySource(var, sourceName);
            }
            return taintCtx.isTainted(var);
        }
        
        @Override
        public String toString() {
            if (sourceName != null) {
                return "tainted(" + varName + ", \"" + sourceName + "\")";
            }
            return "tainted(" + varName + ")";
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
    }
    
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
