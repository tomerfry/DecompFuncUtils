/*
 * TaintQueryMatcher - Matches TaintQuery patterns against decompiled code
 * 
 * Uses ClangTokens for structural matching and the taint matrix for constraint verification.
 */
package decompfuncutils;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.util.*;

public class TaintQueryMatcher {
    
    private final Program program;
    private final TaintLogPanel logPanel;
    private final TaintMatrixConverter converter;
    private final GpuTaintEngine engine;
    
    // Alias tracking for current function being analyzed
    private AliasTracker aliasTracker;
    
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
        
        // Build alias tracker for this function
        aliasTracker = new AliasTracker(highFunc);
        logPanel.logInfo("  " + aliasTracker.getStats());
        
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
     * Search for pattern matches across all functions (OPTIMIZED)
     * 
     * Uses xref-based filtering with fallback to reference scanning.
     */
    public List<QueryMatch> matchInAllFunctions(TaintQuery query, DecompInterface decompiler,
                                                ghidra.util.task.TaskMonitor monitor) {
        matches.clear();
        
        FunctionManager fm = program.getFunctionManager();
        
        // Optimization: Extract concrete function names and filter by xrefs
        Set<String> concreteFuncs = extractConcreteFunctionNames(query);
        Set<Function> candidateFunctions;
        
        if (!concreteFuncs.isEmpty()) {
            logPanel.logInfo("Pattern references concrete functions: " + concreteFuncs);
            
            // Try xref-based lookup first
            candidateFunctions = getFunctionsWithXrefsTo(concreteFuncs);
            
            // If no results, try the fallback approach
            if (candidateFunctions.isEmpty()) {
                logPanel.logInfo("Xref lookup found no results, trying reference scan...");
                candidateFunctions = getFunctionsCallingByName(concreteFuncs, decompiler, monitor);
            }
            
            logPanel.logInfo("Optimization: Analyzing " + candidateFunctions.size() + 
                            " functions (filtered by calls to " + concreteFuncs + ")");
            
            if (candidateFunctions.isEmpty()) {
                logPanel.logWarning("No functions found that call " + concreteFuncs);
                // Fall back to analyzing all functions
                logPanel.logInfo("Falling back to full analysis...");
                FunctionIterator allFuncs = fm.getFunctions(true);
                candidateFunctions = new HashSet<>();
                while (allFuncs.hasNext()) {
                    candidateFunctions.add(allFuncs.next());
                }
            }
        } else {
            // No concrete functions in pattern - must analyze all functions
            logPanel.logInfo("Pattern uses only variable function names - analyzing all functions");
            candidateFunctions = new HashSet<>();
            FunctionIterator allFuncs = fm.getFunctions(true);
            while (allFuncs.hasNext()) {
                candidateFunctions.add(allFuncs.next());
            }
        }
        
        int funcCount = 0;
        int totalFuncs = candidateFunctions.size();
        int matchCount = 0;
        
        for (Function func : candidateFunctions) {
            if (monitor.isCancelled()) break;
            
            funcCount++;
            
            if (funcCount % 50 == 0 || funcCount == totalFuncs) {
                monitor.setMessage("Searching... " + funcCount + "/" + totalFuncs + 
                                " functions, " + matchCount + " matches");
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
     * Get statistics about how effective the xref filtering would be for a query.
     * Useful for debugging/logging.
     */
    public String getOptimizationStats(TaintQuery query) {
        Set<String> concreteFuncs = extractConcreteFunctionNames(query);
        
        if (concreteFuncs.isEmpty()) {
            return "No optimization possible - pattern uses only variable function names";
        }
        
        Set<Function> candidates = getFunctionsWithXrefsTo(concreteFuncs);
        int totalFuncs = program.getFunctionManager().getFunctionCount();
        
        double reduction = totalFuncs > 0 ? 
            (1.0 - ((double) candidates.size() / totalFuncs)) * 100 : 0;
        
        return String.format(
            "Pattern references %s: %d/%d functions to analyze (%.1f%% reduction)",
            concreteFuncs, candidates.size(), totalFuncs, reduction
        );
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
        
        // Build alias tracker for this function
        aliasTracker = new AliasTracker(highFunc);
        
        // Create taint context
        TaintContextImpl taintCtx = new TaintContextImpl(taintData, highFunc, engine);
        
        // Search for pattern matches
        searchInTokens(query, root, highFunc, taintCtx, new ArrayList<>());
        
        return matches;
    }
    
    /**
     * Extract concrete (non-variable) function names from a query pattern.
     * 
     * For example, from pattern:
     *   PATTERN uaf {
     *       free($ptr);
     *       ...;
     *       *$ptr;
     *   }
     * 
     * This extracts: ["free"]
     * 
     * Variable function names like "$func" are ignored since they match anything.
     */
    private Set<String> extractConcreteFunctionNames(TaintQuery query) {
        Set<String> concreteNames = new HashSet<>();
        
        for (TaintQuery.PatternElement elem : query.getPatternElements()) {
            if (elem instanceof TaintQuery.FunctionCall fc) {
                // Only add non-variable function names
                if (!fc.funcName.startsWith("$")) {
                    concreteNames.add(fc.funcName);
                }
            }
            else if (elem instanceof TaintQuery.Assignment assign) {
                // Check RHS for function calls like "$ptr = malloc($size)"
                String rhs = assign.rhs;
                if (rhs != null && rhs.contains("(") && !rhs.startsWith("$")) {
                    // Extract function name from "funcname(...)"
                    int parenIdx = rhs.indexOf('(');
                    if (parenIdx > 0) {
                        String funcName = rhs.substring(0, parenIdx).trim();
                        if (!funcName.startsWith("$")) {
                            concreteNames.add(funcName);
                        }
                    }
                }
            }
        }
        
        return concreteNames;
    }

    /**
     * Match a function call argument against a pattern.
     * 
     * Handles:
     * - Simple variables: "$x" matches any argument
     * - Binary expressions: "$a * $b" requires INT_MULT operation
     * - Constants: literal values must match
     */
    private boolean matchArgument(String argPattern, Varnode actualArg, 
                                HighFunction highFunc, Map<String, Object> bindings) {
        argPattern = argPattern.trim();
        
        // Check for binary operation patterns: $a * $b, $a + $b, etc.
        java.util.regex.Pattern binOpPattern = java.util.regex.Pattern.compile(
            "^(\\$\\w+)\\s*([+\\-*/%])\\s*(\\$\\w+)$");
        java.util.regex.Matcher binOpMatcher = binOpPattern.matcher(argPattern);
        
        if (binOpMatcher.matches()) {
            String leftVar = binOpMatcher.group(1);
            String operator = binOpMatcher.group(2);
            String rightVar = binOpMatcher.group(3);
            
            // The actual argument must be the result of the matching operation
            PcodeOp defOp = actualArg.getDef();
            if (defOp == null) {
                return false;  // Argument isn't defined by an operation
            }
            
            int expectedOpcode = getOpcodeForOperator(operator);
            if (defOp.getOpcode() != expectedOpcode) {
                return false;  // Wrong operation type
            }
            
            // Bind the operands
            Varnode input0 = defOp.getInput(0);
            Varnode input1 = defOp.getInput(1);
            
            if (input0 == null || input1 == null) {
                return false;
            }
            
            bindings.put(leftVar, input0);
            bindings.put(rightVar, input1);
            return true;
        }
        
        // Simple variable pattern: $x
        if (argPattern.startsWith("$")) {
            Object existing = bindings.get(argPattern);
            if (existing != null) {
                // Already bound - verify it matches (exact or alias)
                if (existing instanceof Varnode existingVn) {
                    if (varnodeMatchesExact(actualArg, existingVn, highFunc)) {
                        return true;
                    }
                    // Also check aliases - free(ptr) followed by free(alias) 
                    // where alias == ptr should still match
                    if (aliasTracker != null && aliasTracker.areAliases(actualArg, existingVn)) {
                        return true;
                    }
                }
                return false;
            }
            bindings.put(argPattern, actualArg);
            return true;
        }
        
        // Wildcard
        if (argPattern.equals("_")) {
            return true;
        }
        
        // Literal/constant - would need value comparison
        return true;  // For now, accept
    }

    /**
     * Find all functions that have xrefs (calls) to any of the target functions.
     * 
     * This improved version handles:
     * - Multiple symbols with the same name
     * - Thunk functions
     * - PLT/external entries
     * - Function name variants
     * 
     * @param targetFuncNames Set of function names to look for (e.g., {"malloc", "free"})
     * @return Set of functions that call at least one of the target functions
     */
    private Set<Function> getFunctionsWithXrefsTo(Set<String> targetFuncNames) {
        Set<Function> callingFunctions = new HashSet<>();
        
        if (targetFuncNames.isEmpty()) {
            return callingFunctions;
        }
        
        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refMgr = program.getReferenceManager();
        ExternalManager extMgr = program.getExternalManager();
        
        // Collect all addresses that represent the target functions
        Set<Address> targetAddresses = new HashSet<>();
        
        for (String targetName : targetFuncNames) {
            // Get all variants of the function name
            List<String> variants = getFunctionNameVariants(targetName);
            
            for (String name : variants) {
                // 1. Find all symbols with this name (functions, labels, etc.)
                SymbolIterator symbols = symbolTable.getSymbols(name);
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    targetAddresses.add(sym.getAddress());
                    logPanel.logInfo("  Found symbol '" + name + "' at " + sym.getAddress() + 
                                " (type: " + sym.getSymbolType() + ")");
                }
                
                // 2. Find external functions with this name
                // These might not have regular symbols but are called via PLT/GOT
                ExternalLocationIterator extLocIter = extMgr.getExternalLocations(name);
                while (extLocIter.hasNext()) {
                    ExternalLocation extLoc = extLocIter.next();
                    Address extAddr = extLoc.getAddress();
                    if (extAddr != null) {
                        targetAddresses.add(extAddr);
                        logPanel.logInfo("  Found external '" + name + "' at " + extAddr);
                    }
                    // Also get the thunk address if there is one
                    Function extFunc = extLoc.getFunction();
                    if (extFunc != null) {
                        // Get all thunks pointing to this external
                        Address[] thunkAddrs = extFunc.getFunctionThunkAddresses(true);
                        if (thunkAddrs != null) {
                            for (Address thunkAddr : thunkAddrs) {
                                targetAddresses.add(thunkAddr);
                                logPanel.logInfo("  Found thunk for '" + name + "' at " + thunkAddr);
                            }
                        }
                    }
                }
                
                // 3. Find functions by name directly (catches named functions)
                FunctionIterator funcIter = funcMgr.getFunctions(true);
                while (funcIter.hasNext()) {
                    Function func = funcIter.next();
                    if (func.getName().equals(name) || 
                        func.getName().equals(name + "@PLT") ||
                        func.getName().startsWith(name + "@")) {
                        targetAddresses.add(func.getEntryPoint());
                        logPanel.logInfo("  Found function '" + func.getName() + "' at " + 
                                    func.getEntryPoint());
                    }
                }
            }
        }
        
        logPanel.logInfo("Total target addresses to check for xrefs: " + targetAddresses.size());
        
        // Now find all functions that reference any of these addresses
        for (Address targetAddr : targetAddresses) {
            ReferenceIterator refs = refMgr.getReferencesTo(targetAddr);
            
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddr = ref.getFromAddress();
                
                // Find the function containing this reference
                Function callingFunc = funcMgr.getFunctionContaining(fromAddr);
                if (callingFunc != null) {
                    // Don't include the target function itself (avoid self-reference from thunks)
                    if (!targetAddresses.contains(callingFunc.getEntryPoint())) {
                        callingFunctions.add(callingFunc);
                    }
                }
            }
        }
        
        return callingFunctions;
    }

    /**
     * Get common variants of a function name that should also be matched.
     * This corresponds to the matchFunctionName() logic.
     */
    private List<String> getFunctionNameVariants(String baseName) {
        List<String> variants = new ArrayList<>();
        variants.add(baseName);
        variants.add("__wrap_" + baseName);   // Linker wrapper
        variants.add(baseName + "_s");         // Safe variant (e.g., strcpy_s)
        variants.add("__" + baseName);         // Internal variant
        variants.add("_" + baseName);          // Single underscore prefix
        variants.add(baseName + "@PLT");       // PLT entry (ELF)
        variants.add("__imp_" + baseName);     // Import entry (PE/Windows)
        variants.add(baseName + "_impl");      // Implementation variant
        return variants;
    }


    /**
     * Alternative implementation: Instead of relying on xrefs, scan all functions
     * and check if they contain calls to functions with matching names.
     * 
     * This is slower but more reliable as it doesn't depend on xref accuracy.
     */
    private Set<Function> getFunctionsCallingByName(Set<String> targetFuncNames, 
                                                    DecompInterface decompiler,
                                                    ghidra.util.task.TaskMonitor monitor) {
        Set<Function> callingFunctions = new HashSet<>();
        Set<String> allVariants = new HashSet<>();
        
        // Build complete set of name variants to look for
        for (String name : targetFuncNames) {
            allVariants.addAll(getFunctionNameVariants(name));
        }
        
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        int count = 0;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            count++;
            
            if (count % 500 == 0) {
                monitor.setMessage("Pre-filtering functions... " + count);
            }
            
            // Quick check: does this function have any CALL references to our targets?
            // This uses the reference manager but checks FROM this function
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();
            
            ReferenceIterator refs = program.getReferenceManager().getReferenceIterator(start);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getFromAddress().compareTo(end) > 0) break;
                
                if (ref.getReferenceType().isCall()) {
                    // Get the target of this call
                    Address toAddr = ref.getToAddress();
                    Function targetFunc = funcMgr.getFunctionAt(toAddr);
                    
                    if (targetFunc != null) {
                        String targetName = targetFunc.getName();
                        // Check if target name matches any of our variants
                        for (String variant : allVariants) {
                            if (targetName.equals(variant) || 
                                targetName.contains(variant) ||
                                variant.contains(targetName)) {
                                callingFunctions.add(func);
                                break;
                            }
                        }
                    }
                    
                    // Also check symbol at target address
                    Symbol sym = program.getSymbolTable().getPrimarySymbol(toAddr);
                    if (sym != null) {
                        String symName = sym.getName();
                        for (String variant : allVariants) {
                            if (symName.equals(variant) || 
                                symName.startsWith(variant + "@")) {
                                callingFunctions.add(func);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        return callingFunctions;
    }

    /**
     * Recursively search for pattern matches in token tree
     * 
     * NOTE: For multi-element patterns, we only use checkStatementMatch which properly
     * validates the full pattern sequence. checkFunctionCallMatch is only used for
     * single-element function call patterns.
     */
    private void searchInTokens(TaintQuery query, ClangNode node, HighFunction highFunc,
                                TaintContextImpl taintCtx, List<ClangToken> context) {
        
        // Check statement-level patterns (handles both single and multi-element patterns)
        if (node instanceof ClangStatement stmt) {
            checkStatementMatch(query, stmt, highFunc, taintCtx);
        }
        
        // For single-element function call patterns only, also check at token level
        // This prevents multi-element patterns from matching individual function calls
        if (node instanceof ClangFuncNameToken funcToken && isSingleFunctionCallPattern(query)) {
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
     * Check if the query is a single function call pattern (no other elements)
     */
    private boolean isSingleFunctionCallPattern(TaintQuery query) {
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        return elements.size() == 1 && 
            elements.get(0) instanceof TaintQuery.FunctionCall;
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
        
        // For multi-element patterns (like UAF, double-free, int-overflow-malloc)
        // Check if this statement could be the START of a multi-element pattern
        if (elements.size() >= 2) {
            TaintQuery.PatternElement firstElem = elements.get(0);
            
            // Handle patterns starting with FunctionCall (e.g., free($ptr); ...; free($ptr))
            if (firstElem instanceof TaintQuery.FunctionCall fc) {
                if (matchFunctionCall(fc, stmt, highFunc, bindings)) {
                    // This matches the first element - search for rest of pattern
                    searchMultiElementPattern(query, stmt, highFunc, taintCtx, bindings, 1);
                }
            }
            
            // Handle patterns starting with Assignment (e.g., $size = $a * $b; malloc($size))
            else if (firstElem instanceof TaintQuery.Assignment assign) {
                if (matchAssignmentWithExpression(assign, stmt, highFunc, bindings)) {
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

        logPanel.logInfo("Pattern has " + elements.size() + " elements:");
        for (int i = 0; i < elements.size(); i++) {
            logPanel.logInfo("  [" + i + "] " + elements.get(i).getClass().getSimpleName() + ": " + elements.get(i));
        }

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
                } else if (nextElem instanceof TaintQuery.Assignment assign) {
                    matches = matchAssignmentWithExpression(assign, candidateStmt, highFunc, newBindings);
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
        // Handle regular FunctionCall elements
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
        // Handle Assignment elements in multi-element patterns
        else if (currentElem instanceof TaintQuery.Assignment assign) {
            List<ClangStatement> remaining = getStatementsAfter(startStmt, highFunc);
            for (ClangStatement stmt : remaining) {
                Map<String, Object> newBindings = new HashMap<>(bindings);
                if (matchAssignmentWithExpression(assign, stmt, highFunc, newBindings)) {
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
    /**
     * Check if a statement assigns to the given variable (or any of its aliases)
     * 
     * FIXED: Previously only checked COPY/STORE/CALL/CALLIND opcodes, missing
     * LOAD (ptr reassignment from memory), MULTIEQUAL (PHI nodes in loops),
     * and other operations that produce a new value for the variable.
     * Now checks ANY operation whose output matches the target varnode.
     */
    private boolean isAssignmentTo(ClangStatement stmt, Object targetVar, HighFunction highFunc) {
        if (!(targetVar instanceof Varnode targetVn)) return false;
        
        Address stmtAddr = stmt.getMinAddress();
        if (stmtAddr == null) return false;
        
        // Get alias set - check assignment to the target OR any of its aliases
        Set<Varnode> aliasSet = (aliasTracker != null) 
            ? aliasTracker.getAliases(targetVn) 
            : Collections.singleton(targetVn);
        
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            Varnode output = op.getOutput();
            
            // Check ANY operation that produces output matching our target or aliases
            if (output != null) {
                for (Varnode alias : aliasSet) {
                    if (varnodeMatches(output, alias)) {
                        return true;
                    }
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
     * 
     * This checks if the statement dereferences the EXACT pointer that was bound,
     * OR any alias of that pointer (to catch UAF through aliased variables).
     * 
     * For UAF detection: free(ptr); ... *alias; where alias == ptr
     */
    private boolean matchDereference(TaintQuery.Dereference deref, ClangStatement stmt,
                                     HighFunction highFunc, Map<String, Object> bindings) {
        // Check if dereferencing the bound variable
        Object boundVar = bindings.get(deref.ptrVar);
        if (boundVar == null) return false;  // Must have a bound variable to match
        
        if (!(boundVar instanceof Varnode targetVn)) return false;
        
        // Get alias set for the bound pointer
        Set<Varnode> aliasSet = (aliasTracker != null)
            ? aliasTracker.getAliases(targetVn)
            : Collections.singleton(targetVn);
        
        Address stmtAddr = stmt.getMinAddress();
        if (stmtAddr == null) return false;
        
        // Check P-Code for LOAD or STORE operations that use the pointer or any alias
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            
            // LOAD: reading through a pointer (*ptr on right side)
            if (opcode == PcodeOp.LOAD) {
                Varnode ptr = op.getInput(1);
                if (ptr != null) {
                    for (Varnode alias : aliasSet) {
                        if (varnodeMatchesExact(ptr, alias, highFunc)) {
                            return true;
                        }
                    }
                }
            }
            
            // STORE: writing through a pointer (*ptr on left side, or ptr->field = x)
            if (opcode == PcodeOp.STORE) {
                Varnode ptr = op.getInput(1);
                if (ptr != null) {
                    for (Varnode alias : aliasSet) {
                        if (varnodeMatchesExact(ptr, alias, highFunc)) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Strict varnode matching for UAF/double-free detection.
     * 
     * This is more strict than varnodeMatches() - it checks that the pointers
     * are semantically equivalent, not just that they share a high variable.
     * 
     * For example: local_10->obj and local_10 should NOT match, even though
     * they're related. The freed pointer was local_10->obj (a field load),
     * and accessing local_10->field is accessing a different memory location.
     */
    private boolean varnodeMatchesExact(Varnode a, Varnode b, HighFunction highFunc) {
        // Direct equality
        if (a.equals(b)) return true;
        
        // Check if they resolve to the same high variable AND same offset
        HighVariable hvA = a.getHigh();
        HighVariable hvB = b.getHigh();
        
        if (hvA != null && hvB != null) {
            // Must be the exact same high variable
            if (!hvA.equals(hvB)) return false;
            
            // Check if both varnodes are the representative (main) varnode
            // or if they have the same defining operation
            Varnode repA = hvA.getRepresentative();
            Varnode repB = hvB.getRepresentative();
            
            if (repA != null && repB != null && repA.equals(repB)) {
                return true;
            }
        }
        
        // Check by tracing definitions - if both come from the same computation
        PcodeOp defA = a.getDef();
        PcodeOp defB = b.getDef();
        
        if (defA != null && defB != null) {
            // If both are defined by the same operation, they're the same value
            if (defA.equals(defB)) return true;
            
            // If one is a field load (LOAD) and the other is the base pointer, they're DIFFERENT
            // This handles the case: free(ptr->obj) followed by ptr->field = x
            // ptr->obj and ptr are different even though ptr is involved in both
            if (defA.getOpcode() == PcodeOp.LOAD || defB.getOpcode() == PcodeOp.LOAD) {
                // One is loaded from memory, need exact match
                return false;
            }
        }
        
        return false;
    }

    /**
     * Check if a function call token matches the pattern.
     * 
     * IMPORTANT: This method is now ONLY called for single-element function call patterns.
     * Multi-element patterns are handled entirely through checkStatementMatch and
     * searchMultiElementPattern to ensure proper pattern sequence validation.
     */
    private void checkFunctionCallMatch(TaintQuery query, ClangFuncNameToken funcToken,
                                        HighFunction highFunc, TaintContextImpl taintCtx) {
        
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        
        // Only process single-element function call patterns here
        // Multi-element patterns are handled in checkStatementMatch
        if (elements.size() != 1 || !(elements.get(0) instanceof TaintQuery.FunctionCall fc)) {
            return;
        }
        
        Map<String, Object> bindings = new HashMap<>();
        String calledName = funcToken.getText();
        
        // Check function name match - use strict matching
        if (!matchFunctionName(calledName, fc.funcName, bindings)) {
            return;
        }
        
        // Try to get arguments from P-Code
        PcodeOp callOp = findCallPcodeOp(funcToken, highFunc);
        if (callOp != null) {
            Varnode[] inputs = callOp.getInputs();
            
            boolean argsMatch = true;
            for (int i = 0; i < fc.args.size() && i + 1 < inputs.length; i++) {
                String argPattern = fc.args.get(i);
                if (argPattern.equals("...")) break;
                
                Varnode currentArg = inputs[i + 1];
                
                if (!matchArgument(argPattern, currentArg, highFunc, bindings)) {
                    argsMatch = false;
                    break;  // Stop checking arguments
                }
            }

            if (!argsMatch) {
                return;  // Exit the void method, no match
            }

            // Continue with constraint checking...
            if (query.getConstraint().evaluate(bindings, taintCtx)) {
                addMatch(query, funcToken, highFunc, bindings, callOp);
            }
        }
    }

    /**
     * Match function name with strict rules.
     * 
     * Matching rules:
     * - If pattern is a variable ($func), bind to any function name
     * - If pattern is a literal, require exact match OR common wrapper patterns:
     *   - __wrap_X matches X (linker wrapper)
     *   - X_s matches X (safe variant like strcpy_s)
     *   - __X matches X (internal variant)
     * 
     * This prevents false positives like av_mallocz matching malloc.
     */
    private boolean matchFunctionName(String calledName, String patternName, Map<String, Object> bindings) {
        // Variable function name - bind to anything
        if (patternName.startsWith("$")) {
            Object boundFunc = bindings.get(patternName);
            if (boundFunc != null) {
                return calledName.equals(boundFunc);
            }
            bindings.put(patternName, calledName);
            return true;
        }
        
        // Exact match
        if (calledName.equals(patternName)) {
            return true;
        }
        
        // Common wrapper patterns (strict)
        // __wrap_malloc -> matches malloc
        if (calledName.equals("__wrap_" + patternName)) {
            return true;
        }
        
        // malloc_s -> matches malloc (safe variants)
        if (calledName.equals(patternName + "_s")) {
            return true;
        }
        
        // __malloc -> matches malloc (internal variants)
        if (calledName.equals("__" + patternName)) {
            return true;
        }
        
        // No match - reject things like av_mallocz for malloc
        return false;
    }

    /**
     * Match a function call pattern against a statement
     * 
     * When a variable like $ptr is already bound (from a previous pattern element),
     * this method verifies that the argument in this call matches the bound value.
     * This is critical for double-free detection: free($ptr) ... free($ptr)
     * must verify both calls free the SAME pointer.
     */
    private boolean matchFunctionCall(TaintQuery.FunctionCall fc, ClangStatement stmt,
                                    HighFunction highFunc, Map<String, Object> bindings) {
        // Find function name token in statement
        ClangFuncNameToken funcToken = findFuncNameToken(stmt);
        if (funcToken == null) return false;
        
        String calledName = funcToken.getText();
        
        // Check function name with strict matching
        if (!matchFunctionName(calledName, fc.funcName, bindings)) {
            return false;
        }
        
        // Find and bind/verify arguments
        PcodeOp callOp = findCallPcodeOp(funcToken, highFunc);
        if (callOp != null) {
            Varnode[] inputs = callOp.getInputs();
            for (int i = 0; i < fc.args.size() && i + 1 < inputs.length; i++) {
                String argPattern = fc.args.get(i);
                if (argPattern.equals("...")) break;
                
                Varnode currentArg = inputs[i + 1];
                
                if (!matchArgument(argPattern, currentArg, highFunc, bindings)) {
                    return false;  // Argument doesn't match pattern
                }
            }
        }
        
        return true;
    }

    /**
     * Match assignment pattern with expression analysis.
     * 
     * This enhanced version handles patterns like "$size = $a * $b" by:
     * 1. Finding the P-Code operation that defines the LHS variable
     * 2. Checking if the RHS expression matches the expected pattern (e.g., multiplication)
     * 3. Binding operands to pattern variables
     */
    private boolean matchAssignmentWithExpression(TaintQuery.Assignment assign, ClangStatement stmt,
                                                HighFunction highFunc, Map<String, Object> bindings) {
        Address stmtAddr = stmt.getMinAddress();
        if (stmtAddr == null) return false;
        
        // Parse the RHS to determine what operation we're looking for
        String rhs = assign.rhs;
        
        // Check for binary operation patterns like "$a * $b", "$a + $b", etc.
        java.util.regex.Pattern binOpPattern = java.util.regex.Pattern.compile(
            "^(\\$\\w+)\\s*([+\\-*/%&|^]|<<|>>)\\s*(\\$\\w+)$");
        java.util.regex.Matcher binOpMatcher = binOpPattern.matcher(rhs);
        
        if (binOpMatcher.matches()) {
            String leftVar = binOpMatcher.group(1);
            String operator = binOpMatcher.group(2);
            String rightVar = binOpMatcher.group(3);
            
            // Map operator to P-Code opcode
            int targetOpcode = getOpcodeForOperator(operator);
            if (targetOpcode == -1) return false;
            
            // Search for matching P-Code operation at this statement
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() == targetOpcode) {
                    Varnode output = op.getOutput();
                    Varnode input0 = op.getInput(0);
                    Varnode input1 = op.getInput(1);
                    
                    if (output != null && input0 != null && input1 != null) {
                        // Bind LHS
                        if (assign.lhs.startsWith("$")) {
                            bindings.put(assign.lhs, output);
                        }
                        // Bind operands
                        bindings.put(leftVar, input0);
                        bindings.put(rightVar, input1);
                        return true;
                    }
                }
            }
            return false;
        }
        
        // Check for function call on RHS like "$ptr = malloc($size)"
        java.util.regex.Pattern callPattern = java.util.regex.Pattern.compile(
            "^(\\$?\\w+)\\s*\\((.*)\\)$");
        java.util.regex.Matcher callMatcher = callPattern.matcher(rhs);
        
        if (callMatcher.matches()) {
            String funcName = callMatcher.group(1);
            String argsStr = callMatcher.group(2);
            
            // Find CALL operation and verify function name
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(stmtAddr);
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                    Varnode output = op.getOutput();
                    Varnode target = op.getInput(0);
                    
                    // Get called function name
                    String calledName = getCalledFunctionName(target, highFunc);
                    if (calledName != null && matchFunctionName(calledName, funcName, bindings)) {
                        // Bind LHS
                        if (assign.lhs.startsWith("$") && output != null) {
                            bindings.put(assign.lhs, output);
                        }
                        
                        // Bind arguments
                        List<String> args = parseArgumentList(argsStr);
                        Varnode[] inputs = op.getInputs();
                        for (int i = 0; i < args.size() && i + 1 < inputs.length; i++) {
                            String argPattern = args.get(i);
                            if (argPattern.startsWith("$")) {
                                bindings.put(argPattern, inputs[i + 1]);
                            }
                        }
                        return true;
                    }
                }
            }
            return false;
        }
        
        // Fall back to simple assignment matching
        return matchAssignment(assign, stmt, highFunc, bindings);
    }

    /**
     * Map operator string to P-Code opcode
     */
    private int getOpcodeForOperator(String op) {
        return switch (op) {
            case "*" -> PcodeOp.INT_MULT;
            case "+" -> PcodeOp.INT_ADD;
            case "-" -> PcodeOp.INT_SUB;
            case "/" -> PcodeOp.INT_DIV;
            case "%" -> PcodeOp.INT_REM;
            case "&" -> PcodeOp.INT_AND;
            case "|" -> PcodeOp.INT_OR;
            case "^" -> PcodeOp.INT_XOR;
            case "<<" -> PcodeOp.INT_LEFT;
            case ">>" -> PcodeOp.INT_RIGHT;
            default -> -1;
        };
    }

    /**
     * Get the name of a called function from its target varnode
     */
    private String getCalledFunctionName(Varnode target, HighFunction highFunc) {
        if (target == null) return null;
        
        if (target.isAddress()) {
            Function func = program.getFunctionManager().getFunctionAt(target.getAddress());
            if (func != null) {
                return func.getName();
            }
        }
        
        // Try to resolve from high variable
        HighVariable hv = target.getHigh();
        if (hv != null && hv.getSymbol() != null) {
            return hv.getSymbol().getName();
        }
        
        return null;
    }

    // ============================================================================
    // METHOD 11: parseArgumentList (NEW METHOD)
    // ============================================================================

    /**
     * Parse a comma-separated argument list
     */
    private List<String> parseArgumentList(String argsStr) {
        List<String> args = new ArrayList<>();
        if (argsStr == null || argsStr.trim().isEmpty()) return args;
        
        for (String arg : argsStr.split(",")) {
            args.add(arg.trim());
        }
        return args;
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
            if (!(var instanceof Varnode vn)) {
                return false;
            }
            
            // Case 1: Direct constant value (like 0xb in strncmp(buf, str, 0xb))
            if (vn.isConstant()) {
                return true;
            }
            
            // Case 2: Address-type varnode pointing to constant data
            if (vn.isAddress()) {
                Address addr = vn.getAddress();
                return isAddressInConstantMemory(addr);
            }
            
            // Case 3: Check the defining PcodeOp to see if value comes from constant
            PcodeOp def = vn.getDef();
            if (def != null) {
                int opcode = def.getOpcode();
                
                // COPY or PTRSUB from a constant address
                if (opcode == PcodeOp.COPY || opcode == PcodeOp.PTRSUB) {
                    Varnode input = def.getInput(0);
                    if (input != null) {
                        // Recursively check if input is constant
                        if (input.isConstant()) {
                            // The constant might be an address - check it
                            long offset = input.getOffset();
                            Address addr = highFunc.getFunction().getProgram()
                                .getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                            if (isAddressInConstantMemory(addr)) {
                                return true;
                            }
                        }
                        // Also check if input is itself pointing to constant memory
                        if (isConstant(input)) {
                            return true;
                        }
                    }
                }
                
                // LOAD from constant address (reading string pointer from GOT, etc.)
                if (opcode == PcodeOp.LOAD) {
                    Varnode addrInput = def.getInput(1);
                    if (addrInput != null && addrInput.isConstant()) {
                        long offset = addrInput.getOffset();
                        Address addr = highFunc.getFunction().getProgram()
                            .getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                        if (isAddressInConstantMemory(addr)) {
                            return true;
                        }
                    }
                }
            }
            
            // Case 4: Check HighVariable for additional info
            HighVariable hv = vn.getHigh();
            if (hv != null) {
                // Check if it's a global constant
                if (hv instanceof HighGlobal hg) {
                    HighSymbol highSym = hg.getSymbol();
                    if (highSym != null) {
                        Address symAddr = highSym.getStorage().getMinAddress();
                        if (symAddr != null && isAddressInConstantMemory(symAddr)) {
                            return true;
                        }
                    }
                }
            }
            
            return false;
        }
        
        /**
         * Check if an address points to constant/read-only memory
         * (e.g., .rodata, .text, or defined string data)
         */
        private boolean isAddressInConstantMemory(Address addr) {
            if (addr == null) return false;
            
            Program prog = highFunc.getFunction().getProgram();
            Memory memory = prog.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            
            if (block != null) {
                // Check if block is read-only (not writable)
                if (!block.isWrite()) {
                    return true;
                }
                
                // Check common constant section names
                String name = block.getName().toLowerCase();
                if (name.contains("rodata") || name.contains("const") || 
                    name.equals(".text") || name.contains("string") ||
                    name.equals(".rdata")) {
                    return true;
                }
            }
            
            // Check if there's defined data at this address
            Listing listing = prog.getListing();
            Data data = listing.getDataAt(addr);
            if (data != null) {
                DataType dt = data.getDataType();
                // String types are constants
                if (dt instanceof StringDataType || 
                    dt instanceof TerminatedStringDataType ||
                    dt instanceof AbstractStringDataType) {
                    return true;
                }
            }
            
            // Check for defined strings that might not have exact Data at addr
            Data containingData = listing.getDataContaining(addr);
            if (containingData != null) {
                DataType dt = containingData.getDataType();
                if (dt instanceof StringDataType || 
                    dt instanceof TerminatedStringDataType ||
                    dt instanceof AbstractStringDataType) {
                    return true;
                }
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