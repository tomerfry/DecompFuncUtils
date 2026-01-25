/*
 * TaintQueryMatcher - Matches TaintQuery patterns against decompiled code
 * 
 * Uses ClangTokens for structural matching and the taint matrix for constraint verification.
 */
package decompfuncutils;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;

import java.util.*;

public class TaintQueryMatcher {
    
    private final Program program;
    private final TaintLogPanel logPanel;
    private final TaintMatrixConverter converter;
    private final GpuTaintEngine engine;
    
    // Results
    private List<QueryMatch> matches = new ArrayList<>();
    
    public static class QueryMatch {
        public Function function;
        public Address address;
        public String matchedCode;
        public Map<String, Object> bindings;
        public List<ClangToken> matchedTokens;
        public float confidence;
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(function.getName()).append(" @ ").append(address);
            sb.append("\n  Code: ").append(matchedCode);
            sb.append("\n  Bindings: ");
            for (Map.Entry<String, Object> e : bindings.entrySet()) {
                sb.append(e.getKey()).append("=").append(e.getValue()).append(", ");
            }
            return sb.toString();
        }
    }
    
    public TaintQueryMatcher(Program program, TaintLogPanel logPanel) {
        this.program = program;
        this.logPanel = logPanel;
        this.converter = new TaintMatrixConverter();
        this.engine = new GpuTaintEngine();
    }
    
    /**
     * Search for pattern matches in a single function
     */
    public List<QueryMatch> matchInFunction(TaintQuery query, HighFunction highFunc) {
        matches.clear();
        
        if (highFunc == null) return matches;
        
        Function func = highFunc.getFunction();
        logPanel.logInfo("Searching in " + func.getName() + "...");
        
        // Build taint matrix for constraint evaluation
        TaintMatrixConverter.CsrData taintData = converter.convert(highFunc);
        
        // Create taint context
        TaintContextImpl taintCtx = new TaintContextImpl(taintData, highFunc, engine);
        
        // Get the C code markup - need to decompile to get it
        ClangTokenGroup root = decompileAndGetMarkup(func);
        if (root == null) {
            logPanel.logWarning("Could not get C code markup for " + func.getName());
            return matches;
        }
        
        // Search for pattern matches
        searchInTokens(query, root, highFunc, taintCtx, new ArrayList<>());
        
        logPanel.logInfo("Found " + matches.size() + " match(es) in " + func.getName());
        
        return matches;
    }
    
    /**
     * Search for pattern matches across all functions
     */
    public List<QueryMatch> matchInAllFunctions(TaintQuery query, DecompInterface decompiler,
                                                 ghidra.util.task.TaskMonitor monitor) {
        matches.clear();
        
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        
        int funcCount = 0;
        int matchCount = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            funcCount++;
            
            if (funcCount % 100 == 0) {
                monitor.setMessage("Searching... " + funcCount + " functions, " + matchCount + " matches");
            }
            
            // Decompile
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results == null || !results.decompileCompleted()) continue;
            
            HighFunction hf = results.getHighFunction();
            if (hf == null) continue;
            
            ClangTokenGroup root = results.getCCodeMarkup();
            if (root == null) continue;
            
            int before = matches.size();
            matchInFunctionWithMarkup(query, hf, root);
            matchCount += (matches.size() - before);
        }
        
        logPanel.logInfo("Searched " + funcCount + " functions, found " + matchCount + " total matches");
        
        return matches;
    }
    
    /**
     * Search for pattern matches in a single function with pre-provided markup
     */
    public List<QueryMatch> matchInFunctionWithMarkup(TaintQuery query, HighFunction highFunc, ClangTokenGroup root) {
        if (highFunc == null || root == null) return matches;
        
        Function func = highFunc.getFunction();
        logPanel.logInfo("Searching in " + func.getName() + "...");
        
        // Build taint matrix for constraint evaluation
        TaintMatrixConverter.CsrData taintData = converter.convert(highFunc);
        
        // Create taint context
        TaintContextImpl taintCtx = new TaintContextImpl(taintData, highFunc, engine);
        
        // Search for pattern matches
        searchInTokens(query, root, highFunc, taintCtx, new ArrayList<>());
        
        return matches;
    }
    
    /**
     * Recursively search for pattern matches in token tree
     */
    private void searchInTokens(TaintQuery query, ClangNode node, HighFunction highFunc,
                                TaintContextImpl taintCtx, List<ClangToken> context) {
        
        // Check if this subtree could match the pattern
        if (node instanceof ClangStatement stmt) {
            // Check statement-level patterns
            checkStatementMatch(query, stmt, highFunc, taintCtx);
        }
        
        // For function calls, check call-level patterns
        if (node instanceof ClangFuncNameToken funcToken) {
            checkFunctionCallMatch(query, funcToken, highFunc, taintCtx);
        }
        
        // Recurse into children
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                searchInTokens(query, group.Child(i), highFunc, taintCtx, context);
            }
        }
    }
    
    /**
     * Check if a statement matches the pattern
     */
    private void checkStatementMatch(TaintQuery query, ClangStatement stmt, 
                                     HighFunction highFunc, TaintContextImpl taintCtx) {
        
        // Extract information from the statement
        TokenContextImpl ctx = new TokenContextImpl(stmt, highFunc);
        Map<String, Object> bindings = new HashMap<>();
        
        // Try to match pattern elements
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        if (elements.isEmpty()) return;
        
        // For simple patterns (single function call), check directly
        if (elements.size() == 1 && elements.get(0) instanceof TaintQuery.FunctionCall fc) {
            if (matchFunctionCall(fc, stmt, highFunc, bindings)) {
                // Check constraints
                if (query.getConstraint().evaluate(bindings, taintCtx)) {
                    addMatch(query, stmt, highFunc, bindings);
                }
            }
        }
        
        // For assignment patterns
        if (elements.size() == 1 && elements.get(0) instanceof TaintQuery.Assignment assign) {
            if (ctx.isAssignment() && matchAssignment(assign, stmt, highFunc, bindings)) {
                if (query.getConstraint().evaluate(bindings, taintCtx)) {
                    addMatch(query, stmt, highFunc, bindings);
                }
            }
        }
        
        // For multi-element patterns (like UAF, double-free)
        // Check if this statement could be the START of a multi-element pattern
        if (elements.size() >= 2) {
            TaintQuery.PatternElement firstElem = elements.get(0);
            if (firstElem instanceof TaintQuery.FunctionCall fc) {
                if (matchFunctionCall(fc, stmt, highFunc, bindings)) {
                    // This matches the first element - search for rest of pattern
                    searchMultiElementPattern(query, stmt, highFunc, taintCtx, bindings, 1);
                }
            }
        }
    }
    
    /**
     * Search for remaining elements of a multi-element pattern
     */
    private void searchMultiElementPattern(TaintQuery query, ClangStatement startStmt,
                                           HighFunction highFunc, TaintContextImpl taintCtx,
                                           Map<String, Object> bindings, int elementIdx) {
        
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        if (elementIdx >= elements.size()) {
            // All elements matched!
            if (query.getConstraint().evaluate(bindings, taintCtx)) {
                addMatch(query, startStmt, highFunc, bindings);
            }
            return;
        }
        
        TaintQuery.PatternElement currentElem = elements.get(elementIdx);
        
        // Handle WildcardMulti with negative patterns
        if (currentElem instanceof TaintQuery.WildcardMulti wm) {
            // Need to find the NEXT pattern element after the wildcard
            if (elementIdx + 1 >= elements.size()) {
                // Wildcard at end - match complete
                if (query.getConstraint().evaluate(bindings, taintCtx)) {
                    addMatch(query, startStmt, highFunc, bindings);
                }
                return;
            }
            
            TaintQuery.PatternElement nextElem = elements.get(elementIdx + 1);
            
            // Search through remaining statements for next element
            List<ClangStatement> remainingStmts = getStatementsAfter(startStmt, highFunc);
            
            for (int i = 0; i < remainingStmts.size(); i++) {
                ClangStatement candidateStmt = remainingStmts.get(i);
                Map<String, Object> newBindings = new HashMap<>(bindings);
                
                // Check if this statement matches the next element
                boolean matches = false;
                if (nextElem instanceof TaintQuery.FunctionCall fc) {
                    matches = matchFunctionCall(fc, candidateStmt, highFunc, newBindings);
                } else if (nextElem instanceof TaintQuery.Dereference deref) {
                    matches = matchDereference(deref, candidateStmt, highFunc, newBindings);
                }
                
                if (matches) {
                    // Check negative patterns on statements between start and candidate
                    List<ClangStatement> between = remainingStmts.subList(0, i);
                    if (checkNegativePatterns(wm.negatives, between, newBindings, highFunc)) {
                        // Negative patterns satisfied - continue matching
                        searchMultiElementPattern(query, startStmt, highFunc, taintCtx, 
                                                 newBindings, elementIdx + 2);
                    }
                }
            }
        }
        // Handle regular elements
        else if (currentElem instanceof TaintQuery.FunctionCall fc) {
            List<ClangStatement> remaining = getStatementsAfter(startStmt, highFunc);
            for (ClangStatement stmt : remaining) {
                Map<String, Object> newBindings = new HashMap<>(bindings);
                if (matchFunctionCall(fc, stmt, highFunc, newBindings)) {
                    searchMultiElementPattern(query, startStmt, highFunc, taintCtx,
                                             newBindings, elementIdx + 1);
                }
            }
        }
    }
    
    /**
     * Check that negative patterns are NOT present in the given statements
     */
    private boolean checkNegativePatterns(List<TaintQuery.NegativePattern> negatives,
                                          List<ClangStatement> statements,
                                          Map<String, Object> bindings,
                                          HighFunction highFunc) {
        if (negatives.isEmpty()) return true;
        
        for (TaintQuery.NegativePattern neg : negatives) {
            for (ClangStatement stmt : statements) {
                String stmtText = extractCodeText(stmt);
                
                // Check for variable assignment: not:$ptr=_
                if (neg.varName != null) {
                    Object boundVar = bindings.get(neg.varName);
                    if (boundVar != null) {
                        // Check if this statement assigns to the bound variable
                        if (isAssignmentTo(stmt, boundVar, highFunc)) {
                            return false;  // Found forbidden assignment
                        }
                    }
                }
                
                // Check for pattern match: not:free($ptr)
                if (neg.pattern != null) {
                    // Simple text-based check for now
                    if (stmtText.contains(neg.pattern.split("\\(")[0])) {
                        return false;  // Found forbidden pattern
                    }
                }
            }
        }
        
        return true;  // No negative patterns found - OK
    }
    
    /**
     * Check if a statement assigns to the given variable
     */
    private boolean isAssignmentTo(ClangStatement stmt, Object targetVar, HighFunction highFunc) {
        if (!(targetVar instanceof Varnode targetVn)) return false;
        
        // Look for COPY/STORE operations that write to targetVn
        Address stmtAddr = stmt.getMinAddress();
        if (stmtAddr == null) return false;
        
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            
            if (opcode == PcodeOp.COPY || opcode == PcodeOp.STORE || 
                opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                Varnode output = op.getOutput();
                if (output != null && varnodeMatches(output, targetVn)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if two varnodes refer to the same variable
     */
    private boolean varnodeMatches(Varnode a, Varnode b) {
        if (a.equals(b)) return true;
        
        // Check high variables
        HighVariable hvA = a.getHigh();
        HighVariable hvB = b.getHigh();
        if (hvA != null && hvB != null && hvA.equals(hvB)) return true;
        
        // Check by name
        if (hvA != null && hvB != null) {
            String nameA = hvA.getName();
            String nameB = hvB.getName();
            if (nameA != null && nameA.equals(nameB)) return true;
        }
        
        return false;
    }
    
    /**
     * Get all statements after a given statement in the function
     */
    private List<ClangStatement> getStatementsAfter(ClangStatement start, HighFunction highFunc) {
        List<ClangStatement> result = new ArrayList<>();
        
        // Get all statements in the function
        ClangNode parentNode = start.Parent();
        if (!(parentNode instanceof ClangTokenGroup parent)) return result;
        
        boolean found = false;
        collectStatementsRecursive(parent, start, result, new boolean[]{false});
        
        return result;
    }
    
    private void collectStatementsRecursive(ClangNode node, ClangStatement after,
                                            List<ClangStatement> result, boolean[] foundStart) {
        if (node instanceof ClangStatement stmt) {
            if (foundStart[0]) {
                result.add(stmt);
            } else if (stmt == after) {
                foundStart[0] = true;
            }
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                collectStatementsRecursive(group.Child(i), after, result, foundStart);
            }
        }
    }
    
    /**
     * Match a dereference pattern
     */
    private boolean matchDereference(TaintQuery.Dereference deref, ClangStatement stmt,
                                     HighFunction highFunc, Map<String, Object> bindings) {
        String stmtText = extractCodeText(stmt);
        if (!stmtText.contains("*")) return false;
        
        // Check if dereferencing the bound variable
        Object boundVar = bindings.get(deref.ptrVar);
        if (boundVar == null) return true;  // Not yet bound, will bind later
        
        if (boundVar instanceof Varnode targetVn) {
            // Check P-Code for LOAD operations on this varnode
            Address stmtAddr = stmt.getMinAddress();
            if (stmtAddr == null) return false;
            
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() == PcodeOp.LOAD) {
                    Varnode ptr = op.getInput(1);
                    if (ptr != null && varnodeMatches(ptr, targetVn)) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if a function call token matches the pattern
     */
    private void checkFunctionCallMatch(TaintQuery query, ClangFuncNameToken funcToken,
                                        HighFunction highFunc, TaintContextImpl taintCtx) {
        
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        
        for (TaintQuery.PatternElement elem : elements) {
            if (elem instanceof TaintQuery.FunctionCall fc) {
                Map<String, Object> bindings = new HashMap<>();
                
                String calledName = funcToken.getText();
                
                // Check function name match
                if (fc.funcName.startsWith("$")) {
                    bindings.put(fc.funcName, calledName);
                } else if (!calledName.equals(fc.funcName) && !calledName.contains(fc.funcName)) {
                    continue;
                }
                
                // Try to get arguments from P-Code
                PcodeOp callOp = findCallPcodeOp(funcToken, highFunc);
                if (callOp != null) {
                    Varnode[] inputs = callOp.getInputs();
                    
                    // Bind arguments
                    for (int i = 0; i < fc.args.size() && i + 1 < inputs.length; i++) {
                        String argPattern = fc.args.get(i);
                        if (argPattern.equals("...")) break;
                        
                        if (argPattern.startsWith("$")) {
                            bindings.put(argPattern, inputs[i + 1]);  // +1 because input[0] is target
                        }
                    }
                    
                    // Check constraints
                    if (query.getConstraint().evaluate(bindings, taintCtx)) {
                        addMatch(query, funcToken, highFunc, bindings, callOp);
                    }
                }
            }
        }
    }
    
    /**
     * Match a function call pattern against a statement
     */
    private boolean matchFunctionCall(TaintQuery.FunctionCall fc, ClangStatement stmt,
                                      HighFunction highFunc, Map<String, Object> bindings) {
        // Find function name token in statement
        ClangFuncNameToken funcToken = findFuncNameToken(stmt);
        if (funcToken == null) return false;
        
        String calledName = funcToken.getText();
        
        // Check function name
        if (fc.funcName.startsWith("$")) {
            bindings.put(fc.funcName, calledName);
        } else if (!calledName.equals(fc.funcName) && !calledName.contains(fc.funcName)) {
            return false;
        }
        
        // Find and bind arguments
        PcodeOp callOp = findCallPcodeOp(funcToken, highFunc);
        if (callOp != null) {
            Varnode[] inputs = callOp.getInputs();
            for (int i = 0; i < fc.args.size() && i + 1 < inputs.length; i++) {
                String argPattern = fc.args.get(i);
                if (argPattern.equals("...")) break;
                
                if (argPattern.startsWith("$")) {
                    bindings.put(argPattern, inputs[i + 1]);
                }
            }
        }
        
        return true;
    }
    
    /**
     * Match assignment pattern
     */
    private boolean matchAssignment(TaintQuery.Assignment assign, ClangStatement stmt,
                                   HighFunction highFunc, Map<String, Object> bindings) {
        // Look for assignment in P-Code
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() == PcodeOp.COPY || op.getOpcode() == PcodeOp.CAST) {
                Varnode output = op.getOutput();
                Varnode input = op.getInput(0);
                
                if (output != null && input != null) {
                    if (assign.lhs.startsWith("$")) {
                        bindings.put(assign.lhs, output);
                    }
                    if (assign.rhs.startsWith("$")) {
                        bindings.put(assign.rhs, input);
                    }
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Find function name token in a statement
     */
    private ClangFuncNameToken findFuncNameToken(ClangNode node) {
        if (node instanceof ClangFuncNameToken ft) {
            return ft;
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                ClangFuncNameToken found = findFuncNameToken(group.Child(i));
                if (found != null) return found;
            }
        }
        return null;
    }
    
    /**
     * Find the CALL PcodeOp associated with a function token
     */
    private PcodeOp findCallPcodeOp(ClangFuncNameToken funcToken, HighFunction highFunc) {
        Address addr = funcToken.getMinAddress();
        if (addr == null) return null;
        
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(addr);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                return op;
            }
        }
        return null;
    }
    
    /**
     * Add a match to results
     */
    private void addMatch(TaintQuery query, ClangNode node, HighFunction highFunc,
                         Map<String, Object> bindings) {
        QueryMatch match = new QueryMatch();
        match.function = highFunc.getFunction();
        match.address = node.getMinAddress();
        match.matchedCode = extractCodeText(node);
        match.bindings = new HashMap<>(bindings);
        match.matchedTokens = collectTokens(node);
        match.confidence = 1.0f;
        
        matches.add(match);
        
        logPanel.logSuccess("Match: " + match.function.getName() + " @ " + match.address);
        logPanel.logInfo("  Code: " + match.matchedCode);
        for (Map.Entry<String, Object> e : bindings.entrySet()) {
            logPanel.logInfo("  " + e.getKey() + " = " + formatBinding(e.getValue(), highFunc));
        }
    }
    
    private void addMatch(TaintQuery query, ClangFuncNameToken funcToken, HighFunction highFunc,
                         Map<String, Object> bindings, PcodeOp callOp) {
        QueryMatch match = new QueryMatch();
        match.function = highFunc.getFunction();
        match.address = funcToken.getMinAddress();
        match.matchedCode = funcToken.getText() + "(...)";
        match.bindings = new HashMap<>(bindings);
        match.matchedTokens = new ArrayList<>();
        match.matchedTokens.add(funcToken);
        match.confidence = 1.0f;
        
        matches.add(match);
        
        logPanel.logSuccess("Match: " + match.function.getName() + " @ " + match.address);
        logPanel.logInfo("  Call: " + funcToken.getText());
        for (Map.Entry<String, Object> e : bindings.entrySet()) {
            logPanel.logInfo("  " + e.getKey() + " = " + formatBinding(e.getValue(), highFunc));
        }
    }
    
    /**
     * Extract text representation of a node
     */
    private String extractCodeText(ClangNode node) {
        StringBuilder sb = new StringBuilder();
        extractTextRecursive(node, sb);
        return sb.toString().trim();
    }
    
    private void extractTextRecursive(ClangNode node, StringBuilder sb) {
        if (node instanceof ClangToken token) {
            sb.append(token.getText()).append(" ");
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                extractTextRecursive(group.Child(i), sb);
            }
        }
    }
    
    /**
     * Collect all tokens from a node
     */
    private List<ClangToken> collectTokens(ClangNode node) {
        List<ClangToken> tokens = new ArrayList<>();
        collectTokensRecursive(node, tokens);
        return tokens;
    }
    
    private void collectTokensRecursive(ClangNode node, List<ClangToken> tokens) {
        if (node instanceof ClangToken token) {
            tokens.add(token);
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                collectTokensRecursive(group.Child(i), tokens);
            }
        }
    }
    
    /**
     * Format a binding value for display
     */
    private String formatBinding(Object value, HighFunction highFunc) {
        if (value instanceof Varnode vn) {
            HighVariable hv = vn.getHigh();
            if (hv != null && hv.getName() != null) {
                return hv.getName();
            }
            if (vn.isConstant()) {
                return "0x" + Long.toHexString(vn.getOffset());
            }
            return vn.toString();
        }
        return String.valueOf(value);
    }
    
    /**
     * Decompile a function and get its C code markup
     */
    private ClangTokenGroup decompileAndGetMarkup(Function func) {
        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.openProgram(program);
            
            DecompileResults results = decompiler.decompileFunction(func, 30, null);
            if (results != null && results.decompileCompleted()) {
                return results.getCCodeMarkup();
            }
        } finally {
            decompiler.dispose();
        }
        return null;
    }
    
    // ============ Context Implementations ============
    
    private class TokenContextImpl implements TaintQuery.TokenContext {
        private ClangStatement stmt;
        private HighFunction highFunc;
        
        public TokenContextImpl(ClangStatement stmt, HighFunction highFunc) {
            this.stmt = stmt;
            this.highFunc = highFunc;
        }
        
        @Override
        public boolean isVariableDeclaration() {
            // Check if statement contains a type token followed by variable
            return false;  // Simplified
        }
        
        @Override
        public boolean isFunctionCall() {
            return findFuncNameToken(stmt) != null;
        }
        
        @Override
        public boolean isAssignment() {
            // Look for "=" in the statement
            return extractCodeText(stmt).contains("=") && !extractCodeText(stmt).contains("==");
        }
        
        @Override
        public boolean isDereference() {
            return extractCodeText(stmt).contains("*");
        }
        
        @Override
        public boolean isArray() { return false; }
        
        @Override
        public boolean isPointer() { return false; }
        
        @Override
        public String getTypeName() { return ""; }
        
        @Override
        public String getCalledFunctionName() {
            ClangFuncNameToken ft = findFuncNameToken(stmt);
            return ft != null ? ft.getText() : "";
        }
        
        @Override
        public List<Object> getCallArguments() {
            return new ArrayList<>();
        }
        
        @Override
        public Object getVarnode() { return null; }
        
        @Override
        public Object getAssignmentTarget() { return null; }
        
        @Override
        public Object getAssignmentSource() { return null; }
        
        @Override
        public Object getDereferencedVar() { return null; }
    }
    
    private class TaintContextImpl implements TaintQuery.TaintContext {
        private TaintMatrixConverter.CsrData data;
        private HighFunction highFunc;
        private GpuTaintEngine engine;
        private Map<Object, float[]> taintCache = new HashMap<>();
        
        public TaintContextImpl(TaintMatrixConverter.CsrData data, HighFunction highFunc, 
                               GpuTaintEngine engine) {
            this.data = data;
            this.highFunc = highFunc;
            this.engine = engine;
        }
        
        @Override
        public boolean isTainted(Object var) {
            if (!(var instanceof Varnode vn)) return false;
            
            // Check if this varnode is reachable from any source
            Set<Integer> sources = converter.findSources(data);
            
            for (int srcId : sources) {
                float[] taintVector = getTaintFromSource(srcId);
                Integer varId = data.varnodeToId.get(vn);
                if (varId != null && taintVector[varId] > 0.1f) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public boolean isTaintedBySource(Object var, String sourceName) {
            // For specific source checking - would need more sophisticated tracking
            return isTainted(var);
        }
        
        @Override
        public boolean flowsTo(Object src, Object dst) {
            if (!(src instanceof Varnode srcVn) || !(dst instanceof Varnode dstVn)) {
                return false;
            }
            
            Integer srcId = data.varnodeToId.get(srcVn);
            Integer dstId = data.varnodeToId.get(dstVn);
            
            if (srcId == null || dstId == null) return false;
            
            float[] taintVector = getTaintFromSource(srcId);
            return taintVector[dstId] > 0.1f;
        }
        
        @Override
        public boolean isConstant(Object var) {
            if (var instanceof Varnode vn) {
                return vn.isConstant();
            }
            return false;
        }
        
        @Override
        public boolean isParameter(Object var) {
            if (!(var instanceof Varnode vn)) return false;
            
            LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
            if (lsm == null) return false;
            
            for (int i = 0; i < lsm.getNumParams(); i++) {
                HighVariable param = lsm.getParam(i);
                if (param != null && param.getRepresentative() != null) {
                    if (param.getRepresentative().equals(vn)) {
                        return true;
                    }
                }
            }
            return false;
        }
        
        @Override
        public boolean isLocal(Object var) {
            if (!(var instanceof Varnode vn)) return false;
            return !isParameter(var) && !vn.isConstant();
        }
        
        private float[] getTaintFromSource(int sourceId) {
            if (taintCache.containsKey(sourceId)) {
                return taintCache.get(sourceId);
            }
            
            float[] taintVector = new float[data.numNodes];
            taintVector[sourceId] = 1.0f;
            
            engine.runTaintPropagation(data.numNodes, data.numEdges,
                data.rowPtr, data.colInd, data.values, taintVector, 30);
            
            taintCache.put(sourceId, taintVector);
            return taintVector;
        }
    }
    
    public List<QueryMatch> getMatches() {
        return matches;
    }
}
