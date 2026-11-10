/*
 * TaintQueryMatcher - Matches TaintQuery patterns against decompiled code
 *
 * Matching is driven by the HighFunction p-code: every pattern element is
 * matched to an "anchor" PcodeOp (a CALL, a LOAD/STORE, the op defining an
 * assigned value, a comparison feeding a branch). Order between elements is
 * decided on the control-flow graph, so a statement that the decompiler
 * prints later but that cannot execute later does not match. The C markup is
 * used for function-name tokens, for reporting, and for statement distances.
 */
package decompfuncutils;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TypeDef;
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
    private final TaintLog logPanel;
    private final TaintMatrixConverter converter;

    // Per-function state (rebuilt for each function searched)
    private AliasTracker aliasTracker;
    private FunctionModel model;
    /** $fn -> allowed names, taken from top-level function_in()/function_is() constraints. */
    private Map<String, List<String>> nameRestrictions = Collections.emptyMap();
    private int budget;
    private int functionMatchStart;
    private final Map<Varnode, List<PcodeOp>> assignmentCache = new HashMap<>();
    private int searchErrors;
    private String lastSearchError;

    /** Candidate evaluations allowed per function before the search gives up. */
    private static final int SEARCH_BUDGET = 400_000;
    private static final int MAX_MATCHES_PER_FUNCTION = 200;

    // Results
    private List<QueryMatch> matches = new ArrayList<>();

    public static class QueryMatch {
        public Function function;
        /** Location of the first matched pattern element. */
        public Address address;
        public String matchedCode;
        public Map<String, Object> bindings;
        public List<ClangToken> matchedTokens;
        public float confidence;
        /** Location and text of the last matched element (the sink). Equal to
         *  {@link #address} for single-element patterns. */
        public Address sinkAddress;
        public String sinkCode;
        /** One "address: code" line per matched element, in pattern order. */
        public List<String> trace = new ArrayList<>();

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(function.getName()).append(" @ ").append(address);
            sb.append("\n  Code: ").append(matchedCode);
            if (sinkAddress != null && !sinkAddress.equals(address)) {
                sb.append("\n  Sink: ").append(sinkAddress).append(" ").append(sinkCode);
            }
            sb.append("\n  Bindings: ");
            for (Map.Entry<String, Object> e : bindings.entrySet()) {
                sb.append(e.getKey()).append("=").append(e.getValue()).append(", ");
            }
            return sb.toString();
        }
    }

    public TaintQueryMatcher(Program program, TaintLog logPanel) {
        this.program = program;
        this.logPanel = logPanel;
        this.converter = new TaintMatrixConverter();
    }

    /**
     * Search for pattern matches in a single function
     */
    public List<QueryMatch> matchInFunction(TaintQuery query, HighFunction highFunc) {
        matches.clear();

        if (highFunc == null) return matches;

        Function func = highFunc.getFunction();
        logPanel.logInfo("Searching in " + func.getName() + "...");

        // Log pattern structure once
        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        logPanel.logInfo("Pattern has " + elements.size() + " elements:");
        for (int i = 0; i < elements.size(); i++) {
            logPanel.logInfo("  [" + i + "] " + elements.get(i).getClass().getSimpleName() + ": " + elements.get(i));
        }

        // The markup and the p-code must come from the same decompilation:
        // tokens are tied to the PcodeOps of their own HighFunction.
        DecompileResults results = decompile(func);
        if (results == null || results.getCCodeMarkup() == null || results.getHighFunction() == null) {
            logPanel.logWarning("Could not get C code markup for " + func.getName());
            return matches;
        }

        runSearch(query, results.getHighFunction(), results.getCCodeMarkup());
        logPanel.logInfo("  " + aliasTracker.getStats());
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
     * Search for pattern matches in a single function with pre-provided markup.
     * Accumulates into the shared {@code matches} list (used by whole-program scans).
     */
    public List<QueryMatch> matchInFunctionWithMarkup(TaintQuery query, HighFunction highFunc, ClangTokenGroup root) {
        return matchInFunctionWithMarkup(query, highFunc, root, false);
    }

    /**
     * Search for pattern matches in a single function with pre-provided markup.
     *
     * @param clearFirst when true, reset the match list before searching so the
     *        returned list contains only this function's matches. Per-function
     *        callers (e.g. the MCP taint-query tool) pass true; the whole-program
     *        scanner passes false because it clears once and accumulates.
     */
    public List<QueryMatch> matchInFunctionWithMarkup(TaintQuery query, HighFunction highFunc,
                                                      ClangTokenGroup root, boolean clearFirst) {
        if (clearFirst) matches.clear();
        if (highFunc == null || root == null) return matches;

        Function func = highFunc.getFunction();
        logPanel.logInfo("Searching in " + func.getName() + "...");

        runSearch(query, highFunc, root);

        return matches;
    }

    /**
     * Number of functions whose search was abandoned because of an internal
     * error since this matcher was created. A failed function contributes no
     * matches, so callers that report coverage should surface this.
     */
    public int getSearchErrorCount() {
        return searchErrors;
    }

    /** Description of the most recent internal search error, or null. */
    public String getLastSearchError() {
        return lastSearchError;
    }

    private void runSearch(TaintQuery query, HighFunction highFunc, ClangNode root) {
        try {
            runSearchUnchecked(query, highFunc, root);
        } catch (RuntimeException e) {
            // One odd function must not abort a whole-program scan, but the
            // failure is counted and logged rather than hidden.
            searchErrors++;
            lastSearchError = highFunc.getFunction().getName() + ": " + e;
            logPanel.logWarning("Query failed in " + lastSearchError);
        }
    }

    private void runSearchUnchecked(TaintQuery query, HighFunction highFunc, ClangNode root) {
        assignmentCache.clear();
        aliasTracker = new AliasTracker(highFunc);
        model = new FunctionModel(highFunc, root);
        TaintContextImpl taintCtx = new TaintContextImpl(converter.convert(highFunc), model);
        nameRestrictions = new HashMap<>();
        collectNameRestrictions(query.getConstraint(), nameRestrictions);
        budget = SEARCH_BUDGET;
        functionMatchStart = matches.size();

        List<TaintQuery.PatternElement> elements = query.getPatternElements();
        if (elements.isEmpty()) return;
        search(query, elements, 0, null, new ArrayList<>(), new HashMap<>(), taintCtx);
        if (budget <= 0) {
            logPanel.logWarning("Search budget exhausted in " + highFunc.getFunction().getName()
                + "; results for this function may be incomplete. Narrow the pattern.");
        }
    }

    /**
     * Function names a matching function must call (at least one of them).
     * Literal call names count, and so do $fn names restricted by a top-level
     * function_in()/function_is() constraint. Used only to pre-filter the
     * functions a whole-program scan decompiles.
     */
    private Set<String> extractConcreteFunctionNames(TaintQuery query) {
        Set<String> concreteNames = new HashSet<>();
        Map<String, List<String>> restrictions = new HashMap<>();
        collectNameRestrictions(query.getConstraint(), restrictions);

        for (TaintQuery.PatternElement elem : query.getPatternElements()) {
            String callName = null;
            if (elem instanceof TaintQuery.FunctionCall fc) {
                callName = fc.funcName;
            } else if (elem instanceof TaintQuery.Assignment assign
                    && assign.rhsExpr instanceof TaintQuery.CallExpr call) {
                callName = call.funcName;
            }
            if (callName == null) continue;
            if (!callName.startsWith("$")) {
                concreteNames.add(callName);
            } else if (restrictions.containsKey(callName)) {
                concreteNames.addAll(restrictions.get(callName));
            }
        }

        return concreteNames;
    }

    /** Conjuncts of the WHERE clause that pin a $fn variable to a set of names. */
    private static void collectNameRestrictions(TaintQuery.Constraint c, Map<String, List<String>> out) {
        if (c instanceof TaintQuery.AndConstraint and) {
            collectNameRestrictions(and.left, out);
            collectNameRestrictions(and.right, out);
        } else if (c instanceof TaintQuery.FunctionIsConstraint is) {
            out.putIfAbsent(is.varName, List.of(is.functionName));
        } else if (c instanceof TaintQuery.CheckConstraint check && check.kind.equals("function_in")
                && !check.vars.isEmpty()) {
            out.putIfAbsent(check.vars.get(0), check.names);
        }
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
        // _FORTIFY_SOURCE — e.g. memcpy → __memcpy_chk, printf → __printf_chk
        variants.add("__" + baseName + "_chk");
        variants.add(baseName + "_chk");
        // isoc99 scanf family
        variants.add("__isoc99_" + baseName);
        variants.add("__isoc23_" + baseName);
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

    // ====================================================================
    // Search
    // ====================================================================

    /** One matched pattern element: the bindings after it and its anchor op (null for declarations). */
    private static final class Hit {
        final Map<String, Object> bindings;
        final PcodeOp anchor;
        Hit(Map<String, Object> bindings, PcodeOp anchor) {
            this.bindings = bindings;
            this.anchor = anchor;
        }
    }

    /** A local stack variable bound by a declaration pattern such as {@code char $buf[_]}. */
    private static final class StackVarRef {
        final String name;
        final long offset;
        final long size;
        StackVarRef(String name, long offset, long size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }
        boolean contains(long stackOffset) {
            return stackOffset >= offset && stackOffset < offset + Math.max(size, 1);
        }
        @Override public String toString() { return name; }
    }

    /**
     * Match elements[idx..] after {@code prev}. Elements are ordered by control
     * flow: each anchor must be able to execute after the previous one, with or
     * without a "..." gap between them. A gap additionally carries a statement
     * distance and negative/guard clauses that are checked along CFG paths.
     */
    private void search(TaintQuery query, List<TaintQuery.PatternElement> elements, int idx,
                        PcodeOp prev, List<PcodeOp> anchors, Map<String, Object> bindings,
                        TaintContextImpl taintCtx) {
        if (budget <= 0 || matches.size() - functionMatchStart >= MAX_MATCHES_PER_FUNCTION) return;

        // Fold gap elements that precede the next real element.
        TaintQuery.WildcardMulti gap = null;
        while (idx < elements.size()) {
            TaintQuery.PatternElement e = elements.get(idx);
            if (e instanceof TaintQuery.WildcardMulti wm) {
                gap = mergeGaps(gap, wm);
            } else if (e instanceof TaintQuery.Wildcard) {
                TaintQuery.WildcardMulti one = new TaintQuery.WildcardMulti();
                one.minDistance = 1;
                one.maxDistance = 1;
                gap = mergeGaps(gap, one);
            } else {
                break;
            }
            idx++;
        }

        if (idx >= elements.size()) {
            // All elements matched (a trailing gap matches anything).
            if (!anchors.isEmpty() && query.getConstraint().evaluate(bindings, taintCtx)) {
                addMatch(query, anchors, bindings);
            }
            return;
        }

        TaintQuery.PatternElement element = elements.get(idx);
        Set<String> reused = variablesOf(element);
        reused.retainAll(bindings.keySet());
        for (Hit hit : candidates(element, bindings)) {
            if (--budget <= 0) return;
            PcodeOp anchor = hit.anchor;
            if (prev != null && anchor != null) {
                if (sameOp(prev, anchor)) continue;
                if (!model.canExecuteAfter(prev, anchor)) continue;
                if (!sameInstances(reused, bindings, anchor)) continue;
                if (gap != null) {
                    if (!distanceSatisfied(gap, prev, anchor)) continue;
                    if (!checkGap(gap.negatives, prev, anchor, hit.bindings)) continue;
                }
            }
            List<PcodeOp> nextAnchors = anchors;
            if (anchor != null) {
                nextAnchors = new ArrayList<>(anchors);
                nextAnchors.add(anchor);
                hit.bindings.put(TaintQuery.LAST_SITE, anchor);
            }
            search(query, elements, idx + 1, anchor != null ? anchor : prev, nextAnchors,
                   hit.bindings, taintCtx);
        }
    }

    /** $variables an element mentions. */
    private static Set<String> variablesOf(TaintQuery.PatternElement element) {
        Set<String> vars = new HashSet<>();
        if (element instanceof TaintQuery.FunctionCall fc) {
            for (TaintQuery.Expr arg : argExprs(fc)) arg.collectVariables(vars);
        } else if (element instanceof TaintQuery.Assignment assign) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\$\\w+").matcher(assign.lhs + " " + assign.rhs);
            while (m.find()) vars.add(m.group());
        } else if (element instanceof TaintQuery.Dereference deref) {
            vars.add(deref.ptrVar);
        } else if (element instanceof TaintQuery.Condition cond) {
            cond.left.collectVariables(vars);
            cond.right.collectVariables(vars);
        }
        return vars;
    }

    /**
     * A variable matched again at {@code anchor} must still hold the value it
     * was bound to. In SSA the same varnode names a new value each time its
     * definition executes again, which happens around a loop: after
     * {@code free(p)} in a list-freeing loop, the {@code p->next} of the next
     * iteration reads a different p. Such a match is only valid if some path
     * from the variable's last site to the anchor does not redefine it.
     */
    private boolean sameInstances(Set<String> variables, Map<String, Object> before, PcodeOp anchor) {
        for (String name : variables) {
            if (!(before.get(name) instanceof Varnode value)) continue;
            if (!(before.get(TaintQuery.SITE_PREFIX + name) instanceof PcodeOp from)) continue;
            if (sameOp(from, anchor)) continue;
            PcodeOp def = value.getDef();
            if (def == null || def.getOpcode() == PcodeOp.INDIRECT) continue;
            if (def.getOpcode() == PcodeOp.MULTIEQUAL && !mergesLoopValue(def)) continue;
            if (!model.canExecuteAfter(from, def) || !model.canExecuteAfter(def, anchor)) continue;
            if (!model.pathAvoiding(from, anchor, List.of(def))) return false;
        }
        return true;
    }

    private static TaintQuery.WildcardMulti mergeGaps(TaintQuery.WildcardMulti a, TaintQuery.WildcardMulti b) {
        if (a == null) return b;
        TaintQuery.WildcardMulti merged = new TaintQuery.WildcardMulti();
        merged.negatives.addAll(a.negatives);
        merged.negatives.addAll(b.negatives);
        merged.minDistance = a.minDistance + b.minDistance;
        merged.maxDistance = (a.maxDistance < 0 || b.maxDistance < 0) ? -1 : a.maxDistance + b.maxDistance;
        return merged;
    }

    private static boolean sameOp(PcodeOp a, PcodeOp b) {
        return a == b || a.getSeqnum().equals(b.getSeqnum());
    }

    /** Number of printed statements between two anchors, for "...{min,max}". */
    private boolean distanceSatisfied(TaintQuery.WildcardMulti gap, PcodeOp from, PcodeOp to) {
        if (gap.minDistance <= 0 && gap.maxDistance < 0) return true;
        Integer a = model.statementIndex(from);
        Integer b = model.statementIndex(to);
        if (a == null || b == null) return true;
        int between = Math.max(0, Math.abs(b - a) - 1);
        return gap.isDistanceSatisfied(between);
    }

    /** All ways {@code element} can match given the current bindings. */
    private List<Hit> candidates(TaintQuery.PatternElement element, Map<String, Object> bindings) {
        List<Hit> hits = new ArrayList<>();
        if (element instanceof TaintQuery.FunctionCall fc) {
            for (CallSite call : model.calls) {
                Map<String, Object> b = new HashMap<>(bindings);
                if (matchCallSite(fc.funcName, argExprs(fc), call, b)) hits.add(new Hit(b, call.op));
            }
        } else if (element instanceof TaintQuery.Assignment assign) {
            matchAssignment(assign, bindings, hits);
        } else if (element instanceof TaintQuery.Dereference deref) {
            for (PcodeOpAST op : model.ops) {
                int opcode = op.getOpcode();
                if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) continue;
                Map<String, Object> b = new HashMap<>(bindings);
                if (matchPointer(deref.ptrVar, op.getInput(1), b, op)) hits.add(new Hit(b, op));
            }
        } else if (element instanceof TaintQuery.Condition cond) {
            boolean equality = cond.op.equals("==") || cond.op.equals("!=");
            for (PcodeOpAST op : model.ops) {
                if (!isComparisonOpcode(op.getOpcode()) || !model.feedsBranch(op)) continue;
                boolean opEquality = op.getOpcode() == PcodeOp.INT_EQUAL || op.getOpcode() == PcodeOp.INT_NOTEQUAL;
                if (equality != opEquality) continue;
                Map<String, Object> b = new HashMap<>(bindings);
                if (matchExpr(cond.left, op.getInput(0), b, op) && matchExpr(cond.right, op.getInput(1), b, op)) {
                    hits.add(new Hit(b, op));
                    continue;
                }
                b = new HashMap<>(bindings);
                if (matchExpr(cond.left, op.getInput(1), b, op) && matchExpr(cond.right, op.getInput(0), b, op)) {
                    hits.add(new Hit(b, op));
                }
            }
        } else if (element instanceof TaintQuery.VariableDecl decl) {
            matchDeclaration(decl, bindings, hits);
        }
        return hits;
    }

    private static List<TaintQuery.Expr> argExprs(TaintQuery.FunctionCall fc) {
        if (fc.argExprs != null) return fc.argExprs;
        // Hand-built FunctionCall (not from the parser): derive patterns from the strings.
        List<TaintQuery.Expr> exprs = new ArrayList<>();
        for (String arg : fc.args) {
            String a = arg.trim();
            if (a.equals("...")) exprs.add(new TaintQuery.RestExpr());
            else if (a.equals("_")) exprs.add(new TaintQuery.AnyExpr());
            else if (a.startsWith("$")) exprs.add(new TaintQuery.VarExpr(a));
            else {
                try {
                    exprs.add(new TaintQuery.LiteralExpr(Long.decode(a)));
                } catch (NumberFormatException e) {
                    exprs.add(new TaintQuery.AnyExpr());
                }
            }
        }
        return exprs;
    }

    /** {@code char $buf[$n]}: bind to a stack variable of the declared shape. */
    private void matchDeclaration(TaintQuery.VariableDecl decl, Map<String, Object> bindings, List<Hit> hits) {
        for (StackSymbol symbol : model.stackSymbols) {
            DataType type = symbol.type;
            long length = symbol.size;
            String typeName = type == null ? "" : type.getName();
            if (decl.isArray) {
                if (!(type instanceof Array array)) continue;
                typeName = array.getDataType().getName();
                if (decl.arraySize != null && !decl.arraySize.equals("_")
                        && array.getNumElements() != Long.parseLong(decl.arraySize)) continue;
            } else if (type instanceof Array) {
                continue;
            }
            if (decl.isPointer && !(baseType(type) instanceof Pointer)) continue;
            if (decl.typeName != null && !typeName.toLowerCase().contains(decl.typeName.toLowerCase())) continue;

            Map<String, Object> b = new HashMap<>(bindings);
            Object existing = b.get(decl.varName);
            if (existing instanceof Varnode vn) {
                Long offset = model.stackOffset(vn);
                if (offset == null || !symbol.ref.contains(offset)) continue;
            } else if (existing != null) {
                if (existing != symbol.ref) continue;
            } else {
                b.put(decl.varName, symbol.ref);
            }
            if (decl.sizeVar != null) {
                Object bound = b.get(decl.sizeVar);
                if (bound == null) b.put(decl.sizeVar, Long.valueOf(length));
                else if (!Long.valueOf(length).equals(bound)) continue;
            }
            hits.add(new Hit(b, null));
        }
    }

    // ====================================================================
    // Element matching
    // ====================================================================

    /** Match a call pattern against one call site, binding or verifying its arguments. */
    private boolean matchCallSite(String namePattern, List<TaintQuery.Expr> argPatterns, CallSite call,
                                  Map<String, Object> bindings) {
        String calledName = call.name;
        if (namePattern.startsWith("$")) {
            List<String> allowed = nameRestrictions.get(namePattern);
            if (allowed != null && !nameInList(call, allowed)) return false;
        }
        if (!matchFunctionName(calledName, namePattern, bindings)
                && !(call.resolvedName != null && !call.resolvedName.equals(calledName)
                     && matchFunctionName(call.resolvedName, namePattern, bindings))) {
            return false;
        }
        if (namePattern.startsWith("$")) {
            bindings.put(TaintQuery.SITE_PREFIX + namePattern, call.op);
        }
        // FORTIFY wrappers (__printf_chk, __sprintf_chk, ...) insert arguments;
        // present the call with the argument layout of the plain function.
        String base = namePattern.startsWith("$") ? stripWrapperPrefixes(calledName) : namePattern;
        List<Varnode> actual = logicalArguments(call.op, calledName, base);
        return matchArguments(argPatterns, 0, actual, 0, bindings, call.op, containsRest(argPatterns));
    }

    private static boolean nameInList(CallSite call, List<String> names) {
        for (String n : names) {
            if (TaintQuery.functionNameMatches(call.name, n)
                    || (call.resolvedName != null && TaintQuery.functionNameMatches(call.resolvedName, n))) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsRest(List<TaintQuery.Expr> patterns) {
        for (TaintQuery.Expr e : patterns) {
            if (e instanceof TaintQuery.RestExpr) return true;
        }
        return false;
    }

    /** Arguments of a call in the order of the un-fortified function's parameters. */
    private static List<Varnode> logicalArguments(PcodeOp callOp, String calledName, String baseName) {
        Varnode[] inputs = callOp.getInputs();
        int[] map = getFortifyArgMapping(calledName, baseName);
        List<Varnode> args = new ArrayList<>();
        if (map == null || map.length == 0) {
            for (int i = 1; i < inputs.length; i++) args.add(inputs[i]);
            return args;
        }
        for (int m : map) {
            if (1 + m < inputs.length) args.add(inputs[1 + m]);
        }
        for (int i = 2 + map[map.length - 1]; i < inputs.length; i++) args.add(inputs[i]);
        return args;
    }

    /**
     * Positional match with "..." standing for any run of arguments. Without
     * any "..." the pattern is a prefix: extra actual arguments are allowed
     * (the long-standing behaviour presets rely on). With one, the pattern
     * must account for every argument.
     */
    private boolean matchArguments(List<TaintQuery.Expr> patterns, int pi, List<Varnode> actual, int ai,
                                   Map<String, Object> bindings, PcodeOp site, boolean anchored) {
        if (pi == patterns.size()) {
            return !anchored || ai == actual.size();
        }
        TaintQuery.Expr pattern = patterns.get(pi);
        if (pattern instanceof TaintQuery.RestExpr) {
            if (pi == patterns.size() - 1) return true;
            for (int skip = ai; skip <= actual.size(); skip++) {
                Map<String, Object> trial = new HashMap<>(bindings);
                if (matchArguments(patterns, pi + 1, actual, skip, trial, site, anchored)) {
                    bindings.putAll(trial);
                    return true;
                }
            }
            return false;
        }
        if (ai >= actual.size()) return false;
        if (!matchExpr(pattern, actual.get(ai), bindings, site)) return false;
        return matchArguments(patterns, pi + 1, actual, ai + 1, bindings, site, anchored);
    }

    /**
     * Match a value pattern against a varnode. Structure ($a * $b, f($x), *$p)
     * is matched on the defining p-code, looking through copies, casts and
     * integer extensions, so it also matches when the decompiler names the
     * intermediate value in a separate statement.
     */
    private boolean matchExpr(TaintQuery.Expr pattern, Varnode actual, Map<String, Object> bindings, PcodeOp site) {
        if (actual == null) return false;
        if (pattern instanceof TaintQuery.AnyExpr || pattern instanceof TaintQuery.RestExpr) {
            return true;
        }
        if (pattern instanceof TaintQuery.VarExpr var) {
            return bindVariable(var.name, actual, bindings, site);
        }
        if (pattern instanceof TaintQuery.LiteralExpr literal) {
            Varnode value = stripCopies(actual);
            return value.isConstant() && constantEquals(value, literal.value);
        }
        if (pattern instanceof TaintQuery.CallExpr callPattern) {
            Varnode value = stripExtensions(actual);
            PcodeOp def = value.getDef();
            if (def == null) return false;
            CallSite call = model.callBySeq.get(def.getSeqnum());
            if (call == null) return false;
            Map<String, Object> trial = new HashMap<>(bindings);
            if (!matchCallSite(callPattern.funcName, callPattern.args, call, trial)) return false;
            bindings.putAll(trial);
            return true;
        }
        if (pattern instanceof TaintQuery.DerefExpr deref) {
            Varnode value = stripExtensions(actual);
            PcodeOp def = value.getDef();
            if (def == null || def.getOpcode() != PcodeOp.LOAD) return false;
            if (deref.pointer instanceof TaintQuery.VarExpr ptr) {
                return matchPointer(ptr.name, def.getInput(1), bindings, site);
            }
            return matchExpr(deref.pointer, def.getInput(1), bindings, site);
        }
        if (pattern instanceof TaintQuery.BinaryExpr binary) {
            Varnode value = stripExtensions(actual);
            PcodeOp def = value.getDef();
            if (def == null || def.getNumInputs() < 2) return false;
            Varnode[] operands = binaryOperands(binary.op, def);
            if (operands == null) return false;
            Map<String, Object> trial = new HashMap<>(bindings);
            if (matchExpr(binary.left, operands[0], trial, site) && matchExpr(binary.right, operands[1], trial, site)) {
                bindings.putAll(trial);
                return true;
            }
            if (isCommutative(binary.op)) {
                trial = new HashMap<>(bindings);
                if (matchExpr(binary.left, operands[1], trial, site) && matchExpr(binary.right, operands[0], trial, site)) {
                    bindings.putAll(trial);
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    private static boolean isCommutative(String op) {
        return op.equals("+") || op.equals("*") || op.equals("&") || op.equals("|") || op.equals("^");
    }

    /** Operands of {@code def} when it computes the binary operator {@code op}; null otherwise. */
    private Varnode[] binaryOperands(String op, PcodeOp def) {
        int opcode = def.getOpcode();
        Varnode a = def.getInput(0), b = def.getInput(1);
        if (a == null || b == null) return null;
        switch (op) {
            case "+":
                if (opcode == PcodeOp.INT_ADD) return new Varnode[]{a, b};
                if (opcode == PcodeOp.PTRSUB && !model.isStackPointer(a)) return new Varnode[]{a, b};
                if (opcode == PcodeOp.PTRADD && def.getNumInputs() > 2 && def.getInput(2).isConstant()
                        && def.getInput(2).getOffset() == 1) return new Varnode[]{a, b};
                return null;
            case "-":
                if (opcode == PcodeOp.INT_SUB) return new Varnode[]{a, b};
                if (opcode == PcodeOp.INT_ADD && b.isConstant() && signedValue(b) < 0) {
                    return new Varnode[]{a, model.constant(-signedValue(b), b.getSize())};
                }
                return null;
            case "*":
                if (opcode == PcodeOp.INT_MULT) return new Varnode[]{a, b};
                // x << k is how compilers multiply by 2^k
                if (opcode == PcodeOp.INT_LEFT && b.isConstant() && b.getOffset() < 63) {
                    return new Varnode[]{a, model.constant(1L << b.getOffset(), a.getSize())};
                }
                return null;
            case "/":
                return opcode == PcodeOp.INT_DIV || opcode == PcodeOp.INT_SDIV ? new Varnode[]{a, b} : null;
            case "%":
                return opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM ? new Varnode[]{a, b} : null;
            case "&":
                return opcode == PcodeOp.INT_AND ? new Varnode[]{a, b} : null;
            case "|":
                return opcode == PcodeOp.INT_OR ? new Varnode[]{a, b} : null;
            case "^":
                return opcode == PcodeOp.INT_XOR ? new Varnode[]{a, b} : null;
            case "<<":
                return opcode == PcodeOp.INT_LEFT ? new Varnode[]{a, b} : null;
            case ">>":
                return opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT ? new Varnode[]{a, b} : null;
            default:
                return null;
        }
    }

    /** Bind {@code $name} to a value, or check that it already names the same value. */
    private boolean bindVariable(String name, Varnode actual, Map<String, Object> bindings, PcodeOp site) {
        Object existing = bindings.get(name);
        if (existing == null) {
            bindings.put(name, actual);
        } else if (existing instanceof StackVarRef ref) {
            Long offset = model.stackOffset(actual);
            if (offset == null || !ref.contains(offset)) return false;
            // From here on the variable is the pointer value itself, so that
            // constraints can analyse it.
            bindings.put(name, actual);
        } else if (existing instanceof Varnode bound) {
            if (!sameValue(actual, bound)) return false;
        } else {
            return false;
        }
        if (site != null) bindings.put(TaintQuery.SITE_PREFIX + name, site);
        return true;
    }

    /** Same value: same SSA value / variable, an alias, or the same address expression. */
    private boolean sameValue(Varnode actual, Varnode bound) {
        if (varnodeMatchesExact(actual, bound)) return true;
        if (aliasTracker != null && aliasTracker.areAliases(actual, bound)) return true;
        return model.sameAddress(actual, bound, 0, true);
    }

    /**
     * {@code *$p}: the accessed address is the pointer itself or the pointer
     * plus an offset (p->field, p[i]). An unbound variable binds to the base.
     */
    private boolean matchPointer(String name, Varnode address, Map<String, Object> bindings, PcodeOp site) {
        if (address == null) return false;
        Varnode base = model.pointerBase(address);
        Object existing = bindings.get(name);
        if (existing == null) {
            if (base.isConstant()) return false;
            bindings.put(name, base);
        } else if (existing instanceof Varnode bound) {
            if (!sameValue(address, bound) && (base == address || !sameValue(base, bound))) return false;
        } else if (existing instanceof StackVarRef ref) {
            Long offset = model.stackOffset(address);
            if (offset == null || !ref.contains(offset)) return false;
            bindings.put(name, address);
        } else {
            return false;
        }
        bindings.put(TaintQuery.SITE_PREFIX + name, site);
        return true;
    }

    /**
     * Assignment patterns. The anchor is the op that produces the assigned
     * value: the CALL for {@code $p = f(...)}, the arithmetic op for
     * {@code $s = $a * $b}, the STORE for {@code *$p = $v}.
     */
    private void matchAssignment(TaintQuery.Assignment assign, Map<String, Object> bindings, List<Hit> hits) {
        // *$p = value
        if (assign.lhs.startsWith("*")) {
            String pointerVar = assign.lhs.substring(1).trim();
            for (PcodeOpAST op : model.ops) {
                if (op.getOpcode() != PcodeOp.STORE) continue;
                Map<String, Object> b = new HashMap<>(bindings);
                if (!matchPointer(pointerVar, op.getInput(1), b, op)) continue;
                if (assign.rhsExpr != null && !matchExpr(assign.rhsExpr, op.getInput(2), b, op)) continue;
                hits.add(new Hit(b, op));
            }
            return;
        }

        // $small = (int)$big  -- narrowing cast, matched per printed statement
        if (assign.rhsExpr == null) {
            for (ClangStatement stmt : model.statements) {
                Map<String, Object> b = new HashMap<>(bindings);
                PcodeOp op = matchTruncCast(assign.lhs, assign.rhs, stmt, b);
                if (op != null) hits.add(new Hit(b, op));
            }
            return;
        }

        TaintQuery.Expr rhs = assign.rhsExpr;

        // $p = f(args)
        if (rhs instanceof TaintQuery.CallExpr callPattern) {
            for (CallSite call : model.calls) {
                Varnode output = call.op.getOutput();
                if (output == null && assign.lhs.startsWith("$")) continue;
                Map<String, Object> b = new HashMap<>(bindings);
                if (!matchCallSite(callPattern.funcName, callPattern.args, call, b)) continue;
                if (!bindAssigned(assign.lhs, output, b, call.op)) continue;
                hits.add(new Hit(b, call.op));
            }
            return;
        }

        boolean plainCopy = rhs instanceof TaintQuery.VarExpr || rhs instanceof TaintQuery.AnyExpr
            || rhs instanceof TaintQuery.LiteralExpr;
        for (PcodeOpAST op : model.ops) {
            Varnode output = op.getOutput();
            if (output == null) continue;
            int opcode = op.getOpcode();
            Map<String, Object> b = new HashMap<>(bindings);
            if (plainCopy) {
                // $x = $y, $x = _, $x = 5: a printed copy
                if (opcode != PcodeOp.COPY && opcode != PcodeOp.CAST) continue;
                if (model.statementFor(op) == null) continue;
                if (!matchExpr(rhs, op.getInput(0), b, op)) continue;
            } else {
                // Structured right-hand side: this op must compute it.
                if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INT_ZEXT
                        || opcode == PcodeOp.INT_SEXT || opcode == PcodeOp.MULTIEQUAL
                        || opcode == PcodeOp.INDIRECT) continue;
                if (!matchExpr(rhs, output, b, op)) continue;
            }
            if (!bindAssigned(assign.lhs, output, b, op)) continue;
            hits.add(new Hit(b, op));
        }
    }

    /**
     * Bind the assigned variable to the produced value. If the variable is
     * already bound (by an earlier element, or by this element's own operands
     * as in {@code $p = realloc($p, $n)}) the target must be the same variable;
     * it then names the new value.
     */
    private boolean bindAssigned(String lhs, Varnode output, Map<String, Object> bindings, PcodeOp site) {
        if (!lhs.startsWith("$")) return true;
        if (output == null) return false;
        Object existing = bindings.get(lhs);
        if (existing instanceof Varnode bound) {
            if (!sameVariable(output, bound)) return false;
        } else if (existing != null) {
            return false;
        }
        bindings.put(lhs, output);
        bindings.put(TaintQuery.SITE_PREFIX + lhs, site);
        return true;
    }

    /** Both varnodes are versions of one decompiler variable (or the very same value). */
    private boolean sameVariable(Varnode a, Varnode b) {
        if (a.equals(b)) return true;
        HighVariable ha = a.getHigh(), hb = b.getHigh();
        if (ha != null && ha.equals(hb)) return true;
        return aliasTracker != null && aliasTracker.areAliases(a, b);
    }

    // ====================================================================
    // Gap clauses: not:$v=_, not:f(args), not:($v == c), guard:($v == c)
    // ====================================================================

    /**
     * A gap is satisfied when some control-flow path from {@code from} to
     * {@code to} avoids every forbidden op (reassignments, forbidden calls,
     * guarding comparisons), and every required guard lies between them.
     */
    private boolean checkGap(List<TaintQuery.NegativePattern> negatives, PcodeOp from, PcodeOp to,
                             Map<String, Object> bindings) {
        if (negatives.isEmpty()) return true;
        List<PcodeOp> forbidden = new ArrayList<>();

        for (TaintQuery.NegativePattern neg : negatives) {
            if (neg.guardVarName != null) {
                Object bound = bindings.get(neg.guardVarName);
                if (!(bound instanceof Varnode value)) {
                    if (neg.isGuardCheck) return false;
                    continue;
                }
                List<PcodeOp> guards = model.comparisons(model.family(value, false), neg.guardConstant);
                if (neg.isGuardCheck) {
                    boolean found = false;
                    for (PcodeOp guard : guards) {
                        if (model.canExecuteAfter(from, guard) && model.canExecuteAfter(guard, to)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) return false;
                } else {
                    forbidden.addAll(guards);
                }
            } else if (neg.varName != null) {
                Object bound = bindings.get(neg.varName);
                if (bound instanceof Varnode value) forbidden.addAll(assignmentsTo(value));
            } else if (neg.call != null) {
                for (CallSite call : model.calls) {
                    // Bindings made while testing a forbidden call are discarded.
                    if (matchCallSite(neg.call.funcName, argExprs(neg.call), call, new HashMap<>(bindings))) {
                        forbidden.add(call.op);
                    }
                }
            } else if (neg.pattern != null) {
                // Hand-built negative without a parsed call: match by name.
                String name = neg.pattern.split("\\(")[0].trim();
                for (CallSite call : model.calls) {
                    if (matchFunctionName(call.name, name, new HashMap<>())) forbidden.add(call.op);
                }
            }
        }
        return forbidden.isEmpty() || model.pathAvoiding(from, to, forbidden);
    }

    /**
     * Ops that give the bound variable a new value:
     *  - the definition of the bound value itself (met again only around a loop),
     *  - any other definition of the same decompiler variable, or of a variable
     *    it was copied to or from,
     *  - a loop-header phi that merges in a value produced inside the loop
     *    (the next iteration's value of a loop-carried variable).
     * Casts into unnamed temporaries, plain merge phis and call side-effect
     * markers are not assignments.
     */
    private List<PcodeOp> assignmentsTo(Varnode value) {
        List<PcodeOp> cached = assignmentCache.get(value);
        if (cached != null) return cached;
        Set<Varnode> aliasSet = aliasTracker != null ? aliasTracker.getAliases(value)
            : Collections.singleton(value);
        Set<HighVariable> highs = new HashSet<>();
        for (Varnode alias : aliasSet) {
            HighVariable high = alias.getHigh();
            if (high != null && !(high instanceof HighConstant)) highs.add(high);
        }
        List<PcodeOp> result = new ArrayList<>();
        for (PcodeOpAST op : model.ops) {
            Varnode output = op.getOutput();
            if (output == null) continue;
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.INDIRECT) continue;
            HighVariable high = output.getHigh();
            boolean sameVariable = high != null && highs.contains(high);
            if (!output.equals(value) && !sameVariable) continue;
            if (opcode == PcodeOp.MULTIEQUAL) {
                if (mergesLoopValue(op)) result.add(op);
                continue;
            }
            if (output.equals(value) || !(high instanceof HighOther)) result.add(op);
        }
        assignmentCache.put(value, result);
        return result;
    }

    /** A phi one of whose inputs is produced later, in a loop around the phi. */
    private boolean mergesLoopValue(PcodeOp phi) {
        Varnode output = phi.getOutput();
        for (int i = 0; i < phi.getNumInputs(); i++) {
            Varnode input = phi.getInput(i);
            if (input == null || input.equals(output)) continue;
            PcodeOp def = input.getDef();
            if (def != null && model.canExecuteAfter(phi, def) && model.canExecuteAfter(def, phi)) return true;
        }
        return false;
    }

    /**
     * Check if a P-Code opcode is a comparison operation
     */
    private static boolean isComparisonOpcode(int opcode) {
        return opcode == PcodeOp.INT_EQUAL ||
               opcode == PcodeOp.INT_NOTEQUAL ||
               opcode == PcodeOp.INT_SLESS ||
               opcode == PcodeOp.INT_SLESSEQUAL ||
               opcode == PcodeOp.INT_LESS ||
               opcode == PcodeOp.INT_LESSEQUAL;
    }

    private static boolean isOrderedComparison(int opcode) {
        return opcode == PcodeOp.INT_SLESS || opcode == PcodeOp.INT_SLESSEQUAL
            || opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_LESSEQUAL;
    }

    // ====================================================================
    // Value helpers
    // ====================================================================

    private static Varnode stripCopies(Varnode vn) {
        for (int i = 0; i < 16 && vn != null; i++) {
            PcodeOp def = vn.getDef();
            if (def == null) break;
            int opcode = def.getOpcode();
            if (opcode != PcodeOp.COPY && opcode != PcodeOp.CAST) break;
            if (def.getInput(0) == null) break;
            vn = def.getInput(0);
        }
        return vn;
    }

    private static Varnode stripExtensions(Varnode vn) {
        for (int i = 0; i < 16 && vn != null; i++) {
            PcodeOp def = vn.getDef();
            if (def == null) break;
            int opcode = def.getOpcode();
            if (opcode != PcodeOp.COPY && opcode != PcodeOp.CAST
                    && opcode != PcodeOp.INT_ZEXT && opcode != PcodeOp.INT_SEXT) break;
            if (def.getInput(0) == null) break;
            vn = def.getInput(0);
        }
        return vn;
    }

    private static long signedValue(Varnode constant) {
        long value = constant.getOffset();
        int bits = constant.getSize() * 8;
        if (bits <= 0 || bits >= 64) return value;
        long shift = 64 - bits;
        return (value << shift) >> shift;
    }

    private static boolean constantEquals(Varnode constant, long literal) {
        int bits = constant.getSize() * 8;
        if (bits <= 0 || bits >= 64) return constant.getOffset() == literal;
        long mask = (1L << bits) - 1;
        return (constant.getOffset() & mask) == (literal & mask);
    }

    private static DataType baseType(DataType type) {
        while (type instanceof TypeDef typedef) type = typedef.getBaseDataType();
        return type;
    }

    /**
     * Strict varnode matching for UAF/double-free detection.
     *
     * Two varnodes match when they are the same SSA value or instances of the
     * same decompiler variable. For example: local_10->obj and local_10 do NOT
     * match, even though they are related: the freed pointer was local_10->obj
     * (a field load), which is a different value from local_10.
     */
    private boolean varnodeMatchesExact(Varnode a, Varnode b) {
        // Direct equality
        if (a.equals(b)) return true;

        HighVariable hvA = a.getHigh();
        HighVariable hvB = b.getHigh();

        if (hvA != null && hvB != null) {
            // Must be the exact same high variable
            if (!hvA.equals(hvB)) return false;
            Varnode repA = hvA.getRepresentative();
            Varnode repB = hvB.getRepresentative();
            if (repA != null && repB != null && repA.equals(repB)) {
                return true;
            }
        }

        // If both are defined by the same operation, they're the same value
        PcodeOp defA = a.getDef();
        PcodeOp defB = b.getDef();
        return defA != null && defB != null && defA.equals(defB);
    }

    // ====================================================================
    // Per-function model: calls, statements, control flow, stack layout
    // ====================================================================

    private static final class CallSite {
        final PcodeOpAST op;
        /** Name as printed by the decompiler. */
        final String name;
        /** Name of the (thunk-resolved) target function, when known. */
        final String resolvedName;
        CallSite(PcodeOpAST op, String name, String resolvedName) {
            this.op = op;
            this.name = name;
            this.resolvedName = resolvedName;
        }
        String summaryName() { return resolvedName != null ? resolvedName : name; }
    }

    private static final class StackSymbol {
        final StackVarRef ref;
        final DataType type;
        final long size;
        StackSymbol(StackVarRef ref, DataType type, long size) {
            this.ref = ref;
            this.type = type;
            this.size = size;
        }
    }

    private final class FunctionModel {
        final HighFunction highFunc;
        final List<PcodeOpAST> ops = new ArrayList<>();
        final List<CallSite> calls = new ArrayList<>();
        final Map<SequenceNumber, CallSite> callBySeq = new HashMap<>();
        final List<ClangStatement> statements = new ArrayList<>();
        final IdentityHashMap<ClangStatement, Integer> statementIndex = new IdentityHashMap<>();
        final Map<SequenceNumber, ClangStatement> statementBySeq = new HashMap<>();
        final Map<Address, ClangStatement> statementByAddress = new HashMap<>();
        final Map<Address, List<PcodeOpAST>> opsByAddress = new HashMap<>();
        final List<StackSymbol> stackSymbols = new ArrayList<>();
        final TreeMap<Long, StackSymbol> stackByOffset = new TreeMap<>();
        private final List<PcodeBlockBasic> blocks;
        private final IdentityHashMap<PcodeBlock, Integer> blockIndex = new IdentityHashMap<>();
        private final BitSet[] reach;
        private BitSet[] dominators;
        private final Register stackPointer;
        private final Map<SequenceNumber, Boolean> feedsBranchCache = new HashMap<>();

        FunctionModel(HighFunction highFunc, ClangNode root) {
            this.highFunc = highFunc;
            this.stackPointer = program.getCompilerSpec().getStackPointer();
            this.blocks = new ArrayList<>(highFunc.getBasicBlocks());
            for (int i = 0; i < blocks.size(); i++) blockIndex.put(blocks.get(i), i);
            this.reach = new BitSet[blocks.size()];

            Map<SequenceNumber, String> printedNames = new HashMap<>();
            if (root != null) indexMarkup(root, null, printedNames);

            Iterator<PcodeOpAST> it = highFunc.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                ops.add(op);
                opsByAddress.computeIfAbsent(op.getSeqnum().getTarget(), k -> new ArrayList<>()).add(op);
            }
            for (PcodeOpAST op : ops) {
                int opcode = op.getOpcode();
                if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) continue;
                String resolved = resolveCallee(op);
                String printed = printedNames.get(op.getSeqnum());
                String name = printed != null ? printed : resolved;
                if (name == null) continue;      // indirect call with no recoverable name
                CallSite call = new CallSite(op, name, resolved);
                calls.add(call);
                callBySeq.put(op.getSeqnum(), call);
            }

            LocalSymbolMap symbols = highFunc.getLocalSymbolMap();
            if (symbols != null) {
                Iterator<HighSymbol> symbolIt = symbols.getSymbols();
                while (symbolIt.hasNext()) {
                    HighSymbol symbol = symbolIt.next();
                    try {
                        VariableStorage storage = symbol.getStorage();
                        if (storage == null || !storage.isStackStorage()) continue;
                        long offset = storage.getStackOffset();
                        long size = Math.max(1, symbol.getSize());
                        StackSymbol entry = new StackSymbol(
                            new StackVarRef(symbol.getName(), offset, size), symbol.getDataType(), size);
                        stackSymbols.add(entry);
                        stackByOffset.put(offset, entry);
                    } catch (RuntimeException ignored) {
                        // symbol without usable storage
                    }
                }
            }
        }

        private void indexMarkup(ClangNode node, ClangStatement enclosing, Map<SequenceNumber, String> printedNames) {
            if (node instanceof ClangStatement stmt) {
                statementIndex.put(stmt, statements.size());
                statements.add(stmt);
                enclosing = stmt;
            }
            if (node instanceof ClangToken token) {
                PcodeOp op = token.getPcodeOp();
                if (op != null) {
                    if (token instanceof ClangFuncNameToken) {
                        printedNames.putIfAbsent(op.getSeqnum(), token.getText());
                    }
                    if (enclosing != null) {
                        statementBySeq.putIfAbsent(op.getSeqnum(), enclosing);
                        statementByAddress.putIfAbsent(op.getSeqnum().getTarget(), enclosing);
                    }
                }
            }
            if (node instanceof ClangTokenGroup group) {
                for (int i = 0; i < group.numChildren(); i++) {
                    indexMarkup(group.Child(i), enclosing, printedNames);
                }
            }
        }

        private String resolveCallee(PcodeOp callOp) {
            Varnode target = callOp.getInput(0);
            if (target == null || !target.isAddress()) return null;
            try {
                Function callee = program.getFunctionManager().getFunctionAt(target.getAddress());
                if (callee == null) return null;
                if (callee.isThunk() && callee.getThunkedFunction(true) != null) {
                    callee = callee.getThunkedFunction(true);
                }
                return callee.getName();
            } catch (RuntimeException e) {
                return null;
            }
        }

        // ---- statements ----

        ClangStatement statementFor(PcodeOp op) {
            ClangStatement stmt = statementBySeq.get(op.getSeqnum());
            return stmt != null ? stmt : statementByAddress.get(op.getSeqnum().getTarget());
        }

        Integer statementIndex(PcodeOp op) {
            ClangStatement stmt = statementFor(op);
            return stmt == null ? null : statementIndex.get(stmt);
        }

        /** Every p-code op at any instruction the statement's tokens come from. */
        List<PcodeOpAST> statementOps(ClangStatement stmt) {
            Set<Address> addresses = new LinkedHashSet<>();
            collectTokenAddresses(stmt, addresses);
            if (stmt.getMinAddress() != null) addresses.add(stmt.getMinAddress());
            List<PcodeOpAST> result = new ArrayList<>();
            for (Address address : addresses) {
                List<PcodeOpAST> at = opsByAddress.get(address);
                if (at != null) result.addAll(at);
            }
            return result;
        }

        private void collectTokenAddresses(ClangNode node, Set<Address> out) {
            if (node instanceof ClangToken token && token.getPcodeOp() != null) {
                out.add(token.getPcodeOp().getSeqnum().getTarget());
            }
            if (node instanceof ClangTokenGroup group) {
                for (int i = 0; i < group.numChildren(); i++) collectTokenAddresses(group.Child(i), out);
            }
        }

        // ---- control flow ----

        private int blockOf(PcodeOp op) {
            PcodeBlock block = op.getParent();
            if (block == null) return -1;
            Integer index = blockIndex.get(block);
            if (index != null) return index;
            int own = block.getIndex();
            return own >= 0 && own < blocks.size() ? own : -1;
        }

        private BitSet reachableFrom(int block) {
            BitSet set = reach[block];
            if (set != null) return set;
            set = new BitSet(blocks.size());
            Deque<Integer> pending = new ArrayDeque<>();
            pending.add(block);
            while (!pending.isEmpty()) {
                PcodeBlock current = blocks.get(pending.removeFirst());
                for (int i = 0; i < current.getOutSize(); i++) {
                    Integer next = blockIndex.get(current.getOut(i));
                    if (next != null && !set.get(next)) {
                        set.set(next);
                        pending.addLast(next);
                    }
                }
            }
            reach[block] = set;
            return set;
        }

        /** CFG reachability filters mutually exclusive arms; it does not solve predicates. */
        boolean canExecuteAfter(PcodeOp first, PcodeOp second) {
            int a = blockOf(first), b = blockOf(second);
            if (a < 0 || b < 0) {
                return first.getSeqnum().getTarget().compareTo(second.getSeqnum().getTarget()) < 0;
            }
            if (a == b && first.getSeqnum().getOrder() < second.getSeqnum().getOrder()) return true;
            return reachableFrom(a).get(b);
        }

        boolean inLoop(PcodeOp op) {
            int block = blockOf(op);
            return block >= 0 && reachableFrom(block).get(block);
        }

        /** {@code first} executes on every path that reaches {@code second}. */
        boolean dominates(PcodeOp first, PcodeOp second) {
            int a = blockOf(first), b = blockOf(second);
            if (a < 0 || b < 0) return false;
            if (a == b) return first.getSeqnum().getOrder() < second.getSeqnum().getOrder();
            if (dominators == null) computeDominators();
            return dominators[b].get(a);
        }

        private void computeDominators() {
            int n = blocks.size();
            dominators = new BitSet[n];
            for (int i = 0; i < n; i++) {
                dominators[i] = new BitSet(n);
                if (blocks.get(i).getInSize() == 0) dominators[i].set(i);
                else dominators[i].set(0, n);
            }
            boolean changed = true;
            while (changed) {
                changed = false;
                for (int i = 0; i < n; i++) {
                    PcodeBlock block = blocks.get(i);
                    if (block.getInSize() == 0) continue;
                    BitSet next = new BitSet(n);
                    next.set(0, n);
                    for (int p = 0; p < block.getInSize(); p++) {
                        Integer pred = blockIndex.get(block.getIn(p));
                        if (pred != null) next.and(dominators[pred]);
                    }
                    next.set(i);
                    if (!next.equals(dominators[i])) {
                        dominators[i] = next;
                        changed = true;
                    }
                }
            }
        }

        /** Is there a CFG path from {@code from} to {@code to} that executes none of {@code forbidden}? */
        boolean pathAvoiding(PcodeOp from, PcodeOp to, List<PcodeOp> forbidden) {
            int a = blockOf(from), b = blockOf(to);
            if (a < 0 || b < 0) return true;
            int orderFrom = from.getSeqnum().getOrder(), orderTo = to.getSeqnum().getOrder();
            Map<Integer, List<Integer>> blocked = new HashMap<>();
            for (PcodeOp op : forbidden) {
                if (sameOp(op, from) || sameOp(op, to)) continue;
                int block = blockOf(op);
                if (block >= 0) blocked.computeIfAbsent(block, k -> new ArrayList<>()).add(op.getSeqnum().getOrder());
            }
            List<Integer> inA = blocked.getOrDefault(a, List.of());
            if (a == b && orderFrom < orderTo) {
                boolean clean = true;
                for (int order : inA) {
                    if (order > orderFrom && order < orderTo) { clean = false; break; }
                }
                if (clean) return true;
            }
            for (int order : inA) {
                if (order > orderFrom) return false;       // cannot leave the starting block
            }
            BitSet visited = new BitSet(blocks.size());
            Deque<Integer> pending = new ArrayDeque<>();
            enqueueSuccessors(a, visited, pending);
            while (!pending.isEmpty()) {
                int current = pending.removeFirst();
                List<Integer> here = blocked.getOrDefault(current, List.of());
                if (current == b) {
                    boolean clean = true;
                    for (int order : here) {
                        if (order < orderTo) { clean = false; break; }
                    }
                    if (clean) return true;
                }
                if (!here.isEmpty()) continue;
                enqueueSuccessors(current, visited, pending);
            }
            return false;
        }

        private void enqueueSuccessors(int block, BitSet visited, Deque<Integer> pending) {
            PcodeBlock current = blocks.get(block);
            for (int i = 0; i < current.getOutSize(); i++) {
                Integer next = blockIndex.get(current.getOut(i));
                if (next != null && !visited.get(next)) {
                    visited.set(next);
                    pending.addLast(next);
                }
            }
        }

        // ---- branches and value families ----

        /** The op's boolean result decides a conditional branch. */
        boolean feedsBranch(PcodeOp op) {
            Boolean cached = feedsBranchCache.get(op.getSeqnum());
            if (cached != null) return cached;
            boolean result = false;
            Varnode output = op.getOutput();
            if (output != null) {
                Set<Varnode> seen = new HashSet<>();
                Deque<Varnode> pending = new ArrayDeque<>();
                pending.add(output);
                seen.add(output);
                search:
                while (!pending.isEmpty() && seen.size() < 64) {
                    Iterator<PcodeOp> uses = pending.removeFirst().getDescendants();
                    while (uses != null && uses.hasNext()) {
                        PcodeOp use = uses.next();
                        int opcode = use.getOpcode();
                        if (opcode == PcodeOp.CBRANCH) { result = true; break search; }
                        boolean logical = opcode == PcodeOp.BOOL_NEGATE || opcode == PcodeOp.BOOL_AND
                            || opcode == PcodeOp.BOOL_OR || opcode == PcodeOp.BOOL_XOR
                            || opcode == PcodeOp.COPY || opcode == PcodeOp.CAST
                            || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_AND
                            || opcode == PcodeOp.INT_OR
                            || ((opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL)
                                && use.getInput(1) != null && use.getInput(1).isConstant());
                        if (logical && use.getOutput() != null && seen.add(use.getOutput())) {
                            pending.add(use.getOutput());
                        }
                    }
                }
            }
            feedsBranchCache.put(op.getSeqnum(), result);
            return result;
        }

        /**
         * Varnodes that hold "the same value": back through copies, casts and
         * extensions to the original, then forward through the same plus phi
         * nodes and call side-effect markers. With {@code arithmetic}, forward
         * also through +, -, * and shifts by a constant, so that a check of
         * {@code n + 1} counts as a check of {@code n}.
         */
        Set<Varnode> family(Varnode value, boolean arithmetic) {
            Set<Varnode> family = new LinkedHashSet<>();
            Varnode current = value;
            for (int i = 0; i < 16 && current != null; i++) {
                family.add(current);
                PcodeOp def = current.getDef();
                if (def == null || !isValuePreserving(def)) break;
                current = def.getInput(0);
            }
            Deque<Varnode> pending = new ArrayDeque<>(family);
            while (!pending.isEmpty() && family.size() < 256) {
                Varnode vn = pending.removeFirst();
                Iterator<PcodeOp> uses = vn.getDescendants();
                while (uses != null && uses.hasNext()) {
                    PcodeOp use = uses.next();
                    Varnode output = use.getOutput();
                    if (output == null) continue;
                    int opcode = use.getOpcode();
                    boolean follow = isValuePreserving(use) && vn.equals(use.getInput(0));
                    if (opcode == PcodeOp.MULTIEQUAL) follow = true;
                    if (opcode == PcodeOp.INDIRECT) follow = vn.equals(use.getInput(0));
                    if (!follow && arithmetic && (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB
                            || opcode == PcodeOp.INT_MULT || opcode == PcodeOp.INT_LEFT
                            || opcode == PcodeOp.PTRADD || opcode == PcodeOp.PTRSUB)) {
                        Varnode other = vn.equals(use.getInput(0)) ? use.getInput(1) : use.getInput(0);
                        follow = other != null && other.isConstant();
                    }
                    if (follow && family.add(output)) pending.addLast(output);
                }
            }
            return family;
        }

        private boolean isValuePreserving(PcodeOp op) {
            switch (op.getOpcode()) {
                case PcodeOp.COPY:
                case PcodeOp.CAST:
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_SEXT:
                    return true;
                case PcodeOp.SUBPIECE:
                    return op.getInput(1) != null && op.getInput(1).isConstant() && op.getInput(1).getOffset() == 0;
                default:
                    return false;
            }
        }

        /**
         * Comparisons that decide a branch and involve a member of the family.
         * With a constant, only comparisons against that constant (32-bit
         * sign-extension tolerant).
         */
        List<PcodeOp> comparisons(Set<Varnode> family, Long constant) {
            List<PcodeOp> result = new ArrayList<>();
            Set<SequenceNumber> seen = new HashSet<>();
            for (Varnode member : family) {
                Iterator<PcodeOp> uses = member.getDescendants();
                while (uses != null && uses.hasNext()) {
                    PcodeOp use = uses.next();
                    if (!isComparisonOpcode(use.getOpcode()) || !feedsBranch(use)) continue;
                    if (constant != null) {
                        Varnode other = member.equals(use.getInput(0)) ? use.getInput(1) : use.getInput(0);
                        if (other == null || !other.isConstant()) continue;
                        long actual = other.getOffset();
                        if (actual != constant && (actual & 0xFFFFFFFFL) != (constant & 0xFFFFFFFFL)) continue;
                    }
                    if (seen.add(use.getSeqnum())) result.add(use);
                }
            }
            return result;
        }

        // ---- addresses and buffers ----

        boolean isStackPointer(Varnode vn) {
            return vn != null && stackPointer != null && vn.isRegister()
                && vn.getOffset() == stackPointer.getOffset();
        }

        Varnode constant(long value, int size) {
            return new Varnode(program.getAddressFactory().getConstantAddress(value), Math.max(size, 1));
        }

        /** Offset in the stack frame when {@code vn} is the address of (part of) a local. */
        Long stackOffset(Varnode vn) {
            long extra = 0;
            for (int i = 0; i < 16 && vn != null; i++) {
                PcodeOp def = vn.getDef();
                if (def == null) return null;
                int opcode = def.getOpcode();
                Varnode in0 = def.getInput(0);
                Varnode in1 = def.getNumInputs() > 1 ? def.getInput(1) : null;
                if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                    vn = in0;
                } else if (opcode == PcodeOp.PTRSUB && in1 != null && in1.isConstant()) {
                    if (isStackPointer(in0)) return in1.getOffset() + extra;
                    extra += in1.getOffset();
                    vn = in0;
                } else if (opcode == PcodeOp.INT_ADD && in1 != null && in1.isConstant()) {
                    extra += in1.getOffset();
                    vn = in0;
                } else if (opcode == PcodeOp.PTRADD && in1 != null && in1.isConstant()
                        && def.getInput(2) != null && def.getInput(2).isConstant()) {
                    extra += in1.getOffset() * def.getInput(2).getOffset();
                    vn = in0;
                } else {
                    return null;
                }
            }
            return null;
        }

        /** Start offset of the local that contains a stack offset (or the offset itself). */
        long stackVariableKey(long offset) {
            Map.Entry<Long, StackSymbol> entry = stackByOffset.floorEntry(offset);
            if (entry != null && entry.getValue().ref.contains(offset)) return entry.getKey();
            return offset;
        }

        /** The pointer an access is based on: strips casts and constant / indexed offsets. */
        Varnode pointerBase(Varnode address) {
            Varnode vn = address;
            for (int i = 0; i < 16; i++) {
                PcodeOp def = vn.getDef();
                if (def == null) break;
                int opcode = def.getOpcode();
                Varnode in0 = def.getInput(0);
                if (in0 == null) break;
                if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                    vn = in0;
                } else if (opcode == PcodeOp.PTRADD) {
                    vn = in0;
                } else if (opcode == PcodeOp.PTRSUB && !isStackPointer(in0) && !in0.isConstant()) {
                    vn = in0;
                } else if (opcode == PcodeOp.INT_ADD && def.getInput(1) != null && def.getInput(1).isConstant()) {
                    vn = in0;
                } else {
                    break;
                }
            }
            return vn;
        }

        /**
         * Two pointer values denote the same buffer: the same value, the same
         * local (any offset into it), the same global address, the same pointer
         * variable, or structurally equal address arithmetic.
         */
        boolean sameBuffer(Varnode a, Varnode b, int depth) {
            return sameAddress(a, b, depth, false);
        }

        /**
         * @param strict compare values, not variables: two versions of one
         *        pointer variable (p before and after {@code p = p->next}) are
         *        different. Used when a pattern variable is matched again;
         *        buffer-content tracking uses the lenient form.
         */
        boolean sameAddress(Varnode a, Varnode b, int depth, boolean strict) {
            if (a == null || b == null || depth > 12) return false;
            a = stripCopies(a);
            b = stripCopies(b);
            if (a.equals(b)) return true;
            Long stackA = stackOffset(a), stackB = stackOffset(b);
            if (stackA != null || stackB != null) {
                return stackA != null && stackB != null
                    && stackVariableKey(stackA) == stackVariableKey(stackB);
            }
            if (a.isConstant() || b.isConstant()) {
                // Equal addresses are the same global; two NULLs are not a buffer.
                return a.isConstant() && b.isConstant() && a.getOffset() == b.getOffset()
                    && (depth > 0 || a.getOffset() != 0);
            }
            HighVariable highA = a.getHigh(), highB = b.getHigh();
            if (!strict && highA != null && highA.equals(highB) && !(highA instanceof HighOther)
                    && !(highA instanceof HighConstant)) {
                return true;
            }
            PcodeOp da = a.getDef(), db = b.getDef();
            if (da == null || db == null || da.getOpcode() != db.getOpcode()
                    || da.getNumInputs() != db.getNumInputs()) return false;
            int code = da.getOpcode();
            if (code != PcodeOp.PTRSUB && code != PcodeOp.PTRADD && code != PcodeOp.INT_ADD) return false;
            for (int i = 0; i < da.getNumInputs(); i++) {
                if (!sameAddress(da.getInput(i), db.getInput(i), depth + 1, strict)) return false;
            }
            return true;
        }

        /** {@code value} is read from the local whose address is {@code pointer}. */
        boolean storedIn(Varnode value, Varnode pointer) {
            if (value == null || pointer == null) return false;
            Address address = value.getAddress();
            if (address == null || !address.isStackAddress()) return false;
            Long target = stackOffset(pointer);
            return target != null && stackVariableKey(address.getOffset()) == stackVariableKey(target);
        }
    }

    // ====================================================================
    // Reporting
    // ====================================================================

    private void addMatch(TaintQuery query, List<PcodeOp> anchors, Map<String, Object> bindings) {
        PcodeOp first = anchors.get(0);
        PcodeOp last = anchors.get(anchors.size() - 1);
        Function function = model.highFunc.getFunction();
        Address address = locationOf(first, function);
        Address sinkAddress = locationOf(last, function);

        // Deduplicate: one match per (start, sink) location in a function
        for (QueryMatch existing : matches) {
            if (existing.function.equals(function) && Objects.equals(existing.address, address)
                    && Objects.equals(existing.sinkAddress, sinkAddress)) {
                return;
            }
        }

        QueryMatch match = new QueryMatch();
        match.function = function;
        match.address = address;
        match.sinkAddress = sinkAddress;
        String firstCode = codeOf(first);
        match.sinkCode = codeOf(last);
        match.matchedCode = sameOp(first, last) ? firstCode : firstCode + "  ...  " + match.sinkCode;
        match.bindings = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : bindings.entrySet()) {
            if (!e.getKey().startsWith(TaintQuery.INTERNAL_PREFIX)) match.bindings.put(e.getKey(), e.getValue());
        }
        ClangStatement firstStatement = model.statementFor(first);
        match.matchedTokens = firstStatement != null ? collectTokens(firstStatement) : new ArrayList<>();
        match.confidence = 1.0f;
        for (PcodeOp anchor : anchors) {
            match.trace.add(locationOf(anchor, function) + ": " + codeOf(anchor));
        }

        matches.add(match);

        logPanel.logSuccess("Match: " + match.function.getName() + " @ " + match.address);
        logPanel.logInfo("  Code: " + match.matchedCode);
        for (Map.Entry<String, Object> e : match.bindings.entrySet()) {
            logPanel.logInfo("  " + e.getKey() + " = " + formatBinding(e.getValue()));
        }
    }

    private Address locationOf(PcodeOp op, Function function) {
        ClangStatement stmt = model.statementFor(op);
        if (stmt != null && stmt.getMinAddress() != null) return stmt.getMinAddress();
        Address target = op.getSeqnum().getTarget();
        return target != null ? target : function.getEntryPoint();
    }

    private String codeOf(PcodeOp op) {
        ClangStatement stmt = model.statementFor(op);
        if (stmt != null) return extractCodeText(stmt);
        CallSite call = model.callBySeq.get(op.getSeqnum());
        return call != null ? call.name + "(...)" : op.toString();
    }

    /**
     * Match function name with strict rules.
     * 
     * Matching rules:
     * - If pattern is a variable ($func), bind to any function name
     * - If pattern is a literal, require exact match OR common wrapper patterns:
     *   - __wrap_X matches X (linker wrapper)
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
        
        // Qualified name matching: if pattern contains "::", allow matching
        // the called name against the full qualified pattern or vice versa
        // e.g., pattern "std::__cxx11::string::find" matches called "find" 
        //   if calledName is the unqualified tail
        // or calledName "std::__cxx11::basic_string<>::find" matches pattern
        //   "std::__cxx11::string::find" by containing the key parts
        if (patternName.contains("::")) {
            // Extract the final component of the qualified name
            String patternTail = patternName.substring(patternName.lastIndexOf("::") + 2);
            // Check if called name ends with the same tail and contains key namespace parts
            if (calledName.equals(patternTail)) {
                return true;
            }
            // Check if the called name contains the pattern (for demangled names)
            if (calledName.contains(patternName)) {
                return true;
            }
            // Check if pattern contains the called name (calledName might be shorter)
            if (patternName.contains(calledName) && calledName.length() > 3) {
                return true;
            }
        }
        // Also handle the reverse: calledName is qualified, pattern is simple
        if (calledName.contains("::") && !patternName.contains("::")) {
            String calledTail = calledName.substring(calledName.lastIndexOf("::") + 2);
            if (calledTail.equals(patternName)) {
                return true;
            }
        }
        
        // Common wrapper patterns (strict)
        if (calledName.equals("__wrap_" + patternName)) {
            return true;
        }
        if (calledName.equals("__" + patternName)) {
            return true;
        }
        // _FORTIFY_SOURCE wrappers: __memcpy_chk, __snprintf_chk, __printf_chk, etc.
        // The "_chk" suffix is always on the __-prefixed name; the fortified
        // function shares the semantics of the base function for taint purposes.
        if (calledName.equals("__" + patternName + "_chk")) {
            return true;
        }
        if (calledName.equals(patternName + "_chk")) {
            return true;
        }
        // PLT / import / glibc internal stripping
        if (stripWrapperPrefixes(calledName).equals(patternName)) {
            return true;
        }

        // No match
        return false;
    }

    /**
     * When matching an `__X_chk` FORTIFY wrapper against the plain-function
     * pattern `X(...)`, some wrappers insert extra arguments *before* / *between*
     * the user-visible args (e.g. `__printf_chk(flag, fmt, ...)` vs `printf(fmt, ...)`).
     * For those families we need to remap pattern-arg index → actual call-input index.
     *
     * Returns null when no remapping is needed (the default `inputs[i+1]` mapping
     * is correct — this is the case for families where FORTIFY only appends a
     * `__bos`/`destlen` argument at the end, like `__memcpy_chk`/`__strcpy_chk`).
     *
     * When non-null, `result[i]` is the offset from `inputs[1]` for pattern arg i,
     * i.e. the actual varnode is `inputs[1 + result[i]]`.
     *
     * Only consulted when calledName ends with `_chk`.
     */
    private static int[] getFortifyArgMapping(String calledName, String patternName) {
        if (calledName == null || !calledName.endsWith("_chk")) return null;
        String stripped = calledName;
        if (stripped.startsWith("__")) stripped = stripped.substring(2);
        stripped = stripped.substring(0, stripped.length() - 4);
        if (!stripped.equals(patternName)) return null;
        switch (stripped) {
            // printf family: FORTIFY inserts a leading `flag` argument.
            case "printf":     return new int[]{1};            // __printf_chk(flag, fmt, ...)
            case "vprintf":    return new int[]{1, 2};         // __vprintf_chk(flag, fmt, ap)
            case "fprintf":    return new int[]{0, 2};         // __fprintf_chk(stream, flag, fmt, ...)
            case "vfprintf":   return new int[]{0, 2, 3};      // __vfprintf_chk(stream, flag, fmt, ap)
            case "dprintf":    return new int[]{0, 2};         // __dprintf_chk(fd, flag, fmt, ...)
            // sprintf family: FORTIFY inserts `flag` and `slen` between dst and fmt.
            case "sprintf":    return new int[]{0, 3};         // __sprintf_chk(dst, flag, slen, fmt, ...)
            case "vsprintf":   return new int[]{0, 3, 4};      // __vsprintf_chk(dst, flag, slen, fmt, ap)
            case "snprintf":   return new int[]{0, 1, 4};      // __snprintf_chk(dst, size, flag, slen, fmt, ...)
            case "vsnprintf":  return new int[]{0, 1, 4, 5};   // __vsnprintf_chk(dst, size, flag, slen, fmt, ap)
            case "asprintf":   return new int[]{0, 2};         // __asprintf_chk(result, flag, fmt, ...)
            case "obstack_printf":  return new int[]{0, 2};
            case "obstack_vprintf": return new int[]{0, 2, 3};
            // fgets: FORTIFY inserts `buflen` between buf and the user's `n` arg.
            case "fgets":          return new int[]{0, 2, 3}; // __fgets_chk(buf, buflen, n, fp)
            case "fgets_unlocked": return new int[]{0, 2, 3};
            default:
                // memcpy/memmove/mempcpy/strcpy/strncpy/strcat/strncat/read/pread/recv/... :
                // FORTIFY only appends a trailing `__bos`/`destlen` argument. The default
                // inputs[i+1] mapping is correct — return null to use it.
                return null;
        }
    }

    /**
     * Strip common wrapper / mangling prefixes and suffixes so that
     * '__memcpy_chk', 'memcpy@plt', '__imp_memcpy', '_memcpy' all reduce
     * to 'memcpy' for pattern matching. Conservative: only strip if we
     * recognize the prefix/suffix.
     */
    private static String stripWrapperPrefixes(String name) {
        if (name == null) return "";
        String n = name;
        // Trim @plt / @got / @version suffixes
        int at = n.indexOf('@');
        if (at > 0) n = n.substring(0, at);
        // Common glibc/linker prefixes
        String[] prefixes = {"__imp_", "__wrap_", "__isoc99_", "__isoc23_", "__", "_"};
        for (String p : prefixes) {
            if (n.startsWith(p) && n.length() > p.length()) {
                n = n.substring(p.length());
                break;
            }
        }
        // Fortify suffix
        if (n.endsWith("_chk")) {
            n = n.substring(0, n.length() - 4);
        }
        return n;
    }

    /**
     * Match a truncation cast pattern on the RHS of an assignment.
     * Recognises `(type)$var` where type is an integer type narrower than the source.
     * The corresponding p-code is typically SUBPIECE, INT_AND-with-mask, or CAST with
     * a smaller output size. Every instruction the statement covers is examined.
     *
     * Example DSL: `$small = (int)$big;`
     * Binds `$small` to the op's output and `$big` to the source varnode.
     *
     * @return the narrowing op, or null when the statement does not match
     */
    private PcodeOp matchTruncCast(String lhs, String rhs, ClangStatement stmt, Map<String, Object> bindings) {
        // Match (type)$var  —  type may have one or more identifier words ("unsigned int")
        java.util.regex.Pattern castPat = java.util.regex.Pattern.compile(
            "^\\(\\s*([\\w\\s]+?)\\s*\\)\\s*(\\$\\w+)\\s*$");
        java.util.regex.Matcher m = castPat.matcher(rhs);
        if (!m.matches()) return null;

        String typeName = m.group(1).trim().toLowerCase().replaceAll("\\s+", " ");
        String rhsVar = m.group(2);
        int targetBits = castBitWidth(typeName);
        if (targetBits <= 0) return null;
        int targetBytes = targetBits / 8;

        for (PcodeOpAST op : model.statementOps(stmt)) {
            int opcode = op.getOpcode();
            Varnode output = op.getOutput();
            if (output == null) continue;

            // SUBPIECE(v, 0) taking low bytes, output size == targetBytes
            if (opcode == PcodeOp.SUBPIECE) {
                Varnode src = op.getInput(0);
                Varnode lowOff = op.getInput(1);
                if (src == null || lowOff == null) continue;
                if (lowOff.isConstant() && lowOff.getOffset() == 0 &&
                    output.getSize() == targetBytes && src.getSize() > targetBytes) {
                    if (bindOutputAndSource(lhs, rhsVar, output, src, bindings, op)) return op;
                }
            }
            // INT_AND v, mask — where mask is (1 << targetBits) - 1
            else if (opcode == PcodeOp.INT_AND) {
                Varnode a = op.getInput(0);
                Varnode b = op.getInput(1);
                Varnode maskVn = b != null && b.isConstant() ? b : (a != null && a.isConstant() ? a : null);
                Varnode srcVn = maskVn == b ? a : b;
                if (maskVn != null && srcVn != null) {
                    long expectedMask = targetBits >= 64 ? -1L : ((1L << targetBits) - 1L);
                    if (maskVn.getOffset() == expectedMask) {
                        if (bindOutputAndSource(lhs, rhsVar, output, srcVn, bindings, op)) return op;
                    }
                }
            }
            // CAST with narrower output
            else if (opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) {
                Varnode src = op.getInput(0);
                if (src != null && output.getSize() == targetBytes && src.getSize() > targetBytes) {
                    if (bindOutputAndSource(lhs, rhsVar, output, src, bindings, op)) return op;
                }
            }
            // INT_2COMP etc. — not a truncation.
        }
        return null;
    }

    private boolean bindOutputAndSource(String lhsPat, String rhsPat,
                                        Varnode output, Varnode src,
                                        Map<String, Object> bindings, PcodeOp site) {
        Map<String, Object> trial = new HashMap<>(bindings);
        if (lhsPat != null && lhsPat.startsWith("$")) {
            if (!bindVariable(lhsPat, output, trial, site)) return false;
        }
        if (rhsPat != null && rhsPat.startsWith("$")) {
            if (!bindVariable(rhsPat, src, trial, site)) return false;
        }
        bindings.putAll(trial);
        return true;
    }

    /**
     * Bit width for a C integer type name in a truncation cast.
     * Returns -1 when the type isn't a recognised narrowing integer type.
     */
    private static int castBitWidth(String typeName) {
        if (typeName == null) return -1;
        switch (typeName) {
            case "char": case "int8_t": case "uint8_t": case "signed char":
            case "unsigned char": case "byte":
                return 8;
            case "short": case "short int": case "int16_t": case "uint16_t":
            case "signed short": case "unsigned short": case "unsigned short int":
            case "word":
                return 16;
            case "int": case "int32_t": case "uint32_t": case "signed int":
            case "unsigned int": case "uint": case "dword":
                return 32;
            default:
                return -1;
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
    private String formatBinding(Object value) {
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
     * Decompile a function (C markup and p-code from the same run)
     */
    private DecompileResults decompile(Function func) {
        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(func, 30, null);
            if (results != null && results.decompileCompleted()) {
                return results;
            }
        } finally {
            decompiler.dispose();
        }
        return null;
    }

    // ====================================================================
    // Taint and value analysis behind the WHERE constraints
    // ====================================================================

    private enum TaintKind { ANY, EXTERNAL, NAMED }

    private static final class TaintMode {
        static final TaintMode ANY = new TaintMode(TaintKind.ANY, null);
        static final TaintMode EXTERNAL = new TaintMode(TaintKind.EXTERNAL, null);
        final TaintKind kind;
        final String source;
        TaintMode(TaintKind kind, String source) {
            this.kind = kind;
            this.source = source;
        }
        String key() { return kind + ":" + source; }
    }

    /**
     * How a library call writes through its pointer arguments. Indices are
     * zero-based positions in the plain (un-fortified) signature.
     */
    private static final class WriteSpec {
        final int dest;            // written argument
        final boolean destRest;    // ... and every argument after it (scanf family)
        final int[] sources;       // arguments copied into dest
        final int sourceRest;      // every argument from this index on is copied too (-1: none)
        final boolean input;       // dest receives external input
        final boolean overwrites;  // dest's previous content is replaced entirely

        WriteSpec(int dest, boolean destRest, int[] sources, int sourceRest, boolean input, boolean overwrites) {
            this.dest = dest;
            this.destRest = destRest;
            this.sources = sources;
            this.sourceRest = sourceRest;
            this.input = input;
            this.overwrites = overwrites;
        }
    }

    private static final Map<String, WriteSpec> WRITE_SPECS = new HashMap<>();
    static {
        // dst <- src, replacing dst
        for (String n : List.of("strcpy", "stpcpy", "strncpy", "stpncpy", "strlcpy", "wcscpy", "wcsncpy",
                "lstrcpyA", "lstrcpyW", "lstrcpynA", "lstrcpynW", "StrCpyA", "StrCpyW")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[]{1}, -1, false, true));
        }
        // dst <- dst + src
        for (String n : List.of("strcat", "strncat", "strlcat", "wcscat", "wcsncat", "lstrcatA", "lstrcatW",
                "StrCatA", "StrCatW")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[]{1}, -1, false, false));
        }
        // raw copies: may fill only part of dst, so they never clear earlier taint
        for (String n : List.of("memcpy", "memmove", "mempcpy", "memccpy", "wmemcpy", "wmemmove", "CopyMemory",
                "RtlCopyMemory")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[]{1}, -1, false, false));
        }
        WRITE_SPECS.put("bcopy", new WriteSpec(1, false, new int[]{0}, -1, false, false));
        // formatted output: the format and every following argument reach dst
        for (String n : List.of("sprintf", "vsprintf", "wsprintfA", "wsprintfW", "wvsprintfA", "wvsprintfW")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[0], 1, false, true));
        }
        for (String n : List.of("snprintf", "vsnprintf", "swprintf", "vswprintf", "_snprintf", "_vsnprintf",
                "_snwprintf", "StringCchPrintfA", "StringCchPrintfW", "StringCbPrintfA", "StringCbPrintfW")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[0], 2, false, true));
        }
        // parsing: every output argument derives from the scanned string
        WRITE_SPECS.put("sscanf", new WriteSpec(2, true, new int[]{0}, -1, false, false));
        WRITE_SPECS.put("vsscanf", new WriteSpec(2, true, new int[]{0}, -1, false, false));
        // direct input into a buffer argument
        for (String n : List.of("read", "pread", "pread64", "recv", "recvfrom", "ReadFile", "InternetReadFile",
                "GetEnvironmentVariableA", "GetEnvironmentVariableW", "GetWindowTextA", "GetWindowTextW",
                "GetDlgItemTextA", "GetDlgItemTextW")) {
            WRITE_SPECS.put(n, new WriteSpec(1, false, new int[0], -1, true, false));
        }
        for (String n : List.of("fread", "fread_unlocked", "fgets", "fgets_unlocked", "gets", "fgetws", "getwd",
                "getpass")) {
            WRITE_SPECS.put(n, new WriteSpec(0, false, new int[0], -1, true, false));
        }
        WRITE_SPECS.put("scanf", new WriteSpec(1, true, new int[0], -1, true, false));
        WRITE_SPECS.put("vscanf", new WriteSpec(1, true, new int[0], -1, true, false));
        WRITE_SPECS.put("fscanf", new WriteSpec(2, true, new int[0], -1, true, false));
        WRITE_SPECS.put("vfscanf", new WriteSpec(2, true, new int[0], -1, true, false));
    }

    private static WriteSpec writeSpec(String calledName) {
        if (calledName == null) return null;
        WriteSpec spec = WRITE_SPECS.get(calledName);
        return spec != null ? spec : WRITE_SPECS.get(stripWrapperPrefixes(calledName));
    }

    /** Index into a call's inputs for logical argument {@code index} (FORTIFY aware). */
    private static int inputIndex(String calledName, int index) {
        int[] map = getFortifyArgMapping(calledName, stripWrapperPrefixes(calledName));
        if (map == null || map.length == 0) return index + 1;
        if (index < map.length) return 1 + map[index];
        return 1 + map[map.length - 1] + (index - map.length + 1);
    }

    private class TaintContextImpl implements TaintQuery.TaintContext {
        private static final int TAINT_DEPTH_LIMIT = 10;

        private final TaintMatrixConverter.CsrData data;
        private final FunctionModel fm;
        private final HighFunction highFunc;
        private PcodeOp useSite;
        private int[] forwardStart;
        private int[] forwardEdges;
        private final Map<String, BitSet> reachCache = new HashMap<>();

        public TaintContextImpl(TaintMatrixConverter.CsrData data, FunctionModel fm) {
            this.data = data;
            this.fm = fm;
            this.highFunc = fm.highFunc;
        }

        @Override
        public void setUseSite(Object site) {
            useSite = site instanceof PcodeOp op ? op : null;
        }

        // ---- taint ----

        @Override
        public boolean isTainted(Object var) {
            return var instanceof Varnode vn && tainted(vn, useSite, TaintMode.ANY, new HashSet<>(), 0);
        }

        @Override
        public boolean isTaintedExternal(Object var) {
            return var instanceof Varnode vn && tainted(vn, useSite, TaintMode.EXTERNAL, new HashSet<>(), 0);
        }

        /**
         * Source-specific taint: does {@code var} carry data that originates from a
         * call to the named source (e.g. read / recv / fgets) rather than from any
         * source? Falls back to plain isTainted() when no source name is given.
         */
        @Override
        public boolean isTaintedBySource(Object var, String sourceName) {
            if (sourceName == null || sourceName.isEmpty()) return isTainted(var);
            return var instanceof Varnode vn
                && tainted(vn, useSite, new TaintMode(TaintKind.NAMED, sourceName), new HashSet<>(), 0);
        }

        /**
         * Is {@code value}, as used at {@code site}, derived from a taint source?
         *
         * 1. Value flow inside the function (reachability over the taint matrix).
         * 2. Buffer contents: an earlier call on the path wrote input - or data
         *    that is itself tainted - into the buffer the value points to (or
         *    into the local the value is read from).
         * 3. Return values of user functions that return source data.
         * 4. The same questions for the values this one is computed from, with
         *    buffer contents judged where they are consumed (the call that
         *    takes them, the load that reads them).
         */
        private boolean tainted(Varnode value, PcodeOp site, TaintMode mode, Set<Object> visited, int depth) {
            if (value == null || depth > TAINT_DEPTH_LIMIT) return false;
            if (!visited.add(Arrays.asList(value, site == null ? null : site.getSeqnum()))) return false;

            Integer id = data.varnodeToId.get(value);
            if (id != null && reach(mode).get(id)) return true;

            if (site != null && bufferTainted(value, site, mode, visited, depth)) return true;

            PcodeOp def = value.getDef();
            if (def == null) return false;
            int opcode = def.getOpcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                if (calleeReturnsSource(def, mode)) return true;
                // Like the matrix, treat a return value as derived from the
                // arguments - here including the contents of buffers passed in
                // (strlen(buf), atoi(buf), strdup(buf), ...).
                for (int i = 1; i < def.getNumInputs(); i++) {
                    if (tainted(def.getInput(i), def, mode, visited, depth + 1)) return true;
                }
                return false;
            }
            if (opcode == PcodeOp.INDIRECT) {
                return tainted(def.getInput(0), site, mode, visited, depth + 1);
            }
            if (opcode == PcodeOp.LOAD) {
                return tainted(def.getInput(1), def, mode, visited, depth + 1);
            }
            if (!isTaintPassThroughOp(opcode)) return false;
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode input = def.getInput(i);
                if (input != null && tainted(input, site, mode, visited, depth + 1)) return true;
            }
            return false;
        }

        /**
         * Destination-buffer summaries, applied in program order: some call that
         * can execute before {@code site} filled this buffer with input, or
         * copied / formatted tainted data into it, and no later call that always
         * runs before {@code site} replaced the content.
         */
        private boolean bufferTainted(Varnode value, PcodeOp site, TaintMode mode, Set<Object> visited, int depth) {
            for (CallSite call : fm.calls) {
                String name = call.summaryName();
                WriteSpec spec = writeSpec(name);
                if (spec == null) continue;
                if (sameOp(call.op, site) || !fm.canExecuteAfter(call.op, site)) continue;
                if (!writesTo(call, name, spec, value)) continue;
                if (overwrittenBefore(call, site, value)) continue;
                if (spec.input) {
                    if (mode.kind != TaintKind.NAMED || TaintMatrixConverter.nameMatches(name, mode.source)) {
                        return true;
                    }
                    continue;
                }
                int inputs = call.op.getNumInputs();
                for (int source : spec.sources) {
                    int index = inputIndex(name, source);
                    if (index < inputs && tainted(call.op.getInput(index), call.op, mode, visited, depth + 1)) {
                        return true;
                    }
                }
                if (spec.sourceRest >= 0) {
                    for (int index = inputIndex(name, spec.sourceRest); index < inputs; index++) {
                        if (tainted(call.op.getInput(index), call.op, mode, visited, depth + 1)) return true;
                    }
                }
            }
            return false;
        }

        private boolean writesTo(CallSite call, String name, WriteSpec spec, Varnode value) {
            int inputs = call.op.getNumInputs();
            int first = inputIndex(name, spec.dest);
            int last = spec.destRest ? inputs - 1 : first;
            for (int index = first; index <= last && index < inputs; index++) {
                Varnode dest = call.op.getInput(index);
                if (fm.sameBuffer(value, dest, 0) || fm.storedIn(value, dest)) return true;
            }
            return false;
        }

        /** A later call replaces the buffer on every path from {@code writer} to {@code site}. */
        private boolean overwrittenBefore(CallSite writer, PcodeOp site, Varnode value) {
            for (CallSite other : fm.calls) {
                if (other == writer || sameOp(other.op, site)) continue;
                String name = other.summaryName();
                WriteSpec spec = writeSpec(name);
                if (spec == null || !spec.overwrites) continue;
                if (!fm.canExecuteAfter(writer.op, other.op) || fm.canExecuteAfter(other.op, writer.op)) continue;
                if (!fm.dominates(other.op, site)) continue;
                if (writesTo(other, name, spec, value)) return true;
            }
            return false;
        }

        private boolean calleeReturnsSource(PcodeOp callOp, TaintMode mode) {
            Function callee = resolveCallee(callOp);
            if (callee == null) return false;
            switch (mode.kind) {
                case EXTERNAL: return functionReturnsSource(callee, null, true);
                case NAMED:    return functionReturnsSource(callee, mode.source, false);
                default:       return functionReturnsSource(callee, null, false);
            }
        }

        // ---- matrix reachability (unweighted: long chains do not decay) ----

        private BitSet reach(TaintMode mode) {
            BitSet cached = reachCache.get(mode.key());
            if (cached != null) return cached;
            Set<Integer> seeds = new HashSet<>();
            if (mode.kind == TaintKind.NAMED) {
                for (Varnode origin : sourceOriginVarnodes(mode.source)) {
                    Integer id = data.varnodeToId.get(origin);
                    if (id != null) seeds.add(id);
                }
            } else {
                boolean parametersCount = mode.kind == TaintKind.ANY || isProgramEntry();
                for (Map.Entry<Integer, TaintMatrixConverter.NodeInfo> e : data.nodeInfo.entrySet()) {
                    TaintMatrixConverter.NodeInfo info = e.getValue();
                    if (!info.isSource) continue;
                    if (!parametersCount && info.type == TaintMatrixConverter.NodeInfo.NodeType.PARAMETER) continue;
                    seeds.add(e.getKey());
                }
            }
            BitSet result = forwardClosure(seeds);
            reachCache.put(mode.key(), result);
            return result;
        }

        /** argc/argv/envp of the program entry point are external input. */
        private boolean isProgramEntry() {
            String name = highFunc.getFunction().getName();
            return name.equals("main") || name.equals("wmain") || name.equals("_tmain")
                || name.equals("WinMain") || name.equals("wWinMain");
        }

        private BitSet forwardClosure(Collection<Integer> seeds) {
            int n = data.numNodes;
            BitSet seen = new BitSet(Math.max(n, 1));
            if (n == 0 || data.rowPtr == null) return seen;
            if (forwardStart == null) {
                // The CSR rows list each node's predecessors; invert once.
                forwardStart = new int[n + 1];
                for (int edge = 0; edge < data.colInd.length; edge++) forwardStart[data.colInd[edge] + 1]++;
                for (int i = 0; i < n; i++) forwardStart[i + 1] += forwardStart[i];
                forwardEdges = new int[data.colInd.length];
                int[] cursor = Arrays.copyOf(forwardStart, n);
                for (int to = 0; to < n; to++) {
                    for (int edge = data.rowPtr[to]; edge < data.rowPtr[to + 1]; edge++) {
                        forwardEdges[cursor[data.colInd[edge]]++] = to;
                    }
                }
            }
            Deque<Integer> pending = new ArrayDeque<>();
            for (int seed : seeds) {
                if (seed >= 0 && seed < n && !seen.get(seed)) {
                    seen.set(seed);
                    pending.add(seed);
                }
            }
            while (!pending.isEmpty()) {
                int node = pending.removeFirst();
                for (int edge = forwardStart[node]; edge < forwardStart[node + 1]; edge++) {
                    int next = forwardEdges[edge];
                    if (!seen.get(next)) {
                        seen.set(next);
                        pending.addLast(next);
                    }
                }
            }
            return seen;
        }

        /**
         * Varnodes that hold data coming directly out of a call to {@code sourceName}
         * within this function. Buffer contents are handled separately by
         * bufferTainted so a later read cannot taint an earlier use.
         */
        private Set<Varnode> sourceOriginVarnodes(String sourceName) {
            Set<Varnode> origins = new HashSet<>();
            for (PcodeOpAST op : fm.ops) {
                int opc = op.getOpcode();
                if (opc != PcodeOp.CALL && opc != PcodeOp.CALLIND && opc != PcodeOp.CALLOTHER) continue;
                String callee = calleeName(op.getInput(0));
                if (callee == null || !TaintMatrixConverter.nameMatches(callee, sourceName)) continue;

                Varnode out = op.getOutput();
                if (out != null) origins.add(out);
            }
            return origins;
        }

        /** Resolve a call op's target to its (thunk-resolved) callee function, or null. */
        private Function resolveCallee(PcodeOp callOp) {
            Varnode target = callOp.getInput(0);
            if (target == null || !target.isAddress()) return null;
            Function callee;
            try {
                callee = highFunc.getFunction().getProgram()
                    .getFunctionManager().getFunctionAt(target.getAddress());
            } catch (Exception e) {
                return null;
            }
            if (callee == null) return null;
            if (callee.isThunk() && callee.getThunkedFunction(true) != null) {
                callee = callee.getThunkedFunction(true);
            }
            return callee;
        }

        private String calleeName(Varnode target) {
            if (target == null || !target.isAddress()) return null;
            Function f;
            try {
                f = highFunc.getFunction().getProgram()
                    .getFunctionManager().getFunctionAt(target.getAddress());
            } catch (Exception e) {
                return null;
            }
            if (f == null) return null;
            if (f.isThunk() && f.getThunkedFunction(true) != null) {
                f = f.getThunkedFunction(true);
            }
            return f.getName();
        }

        @Override
        public boolean flowsTo(Object src, Object dst) {
            if (!(src instanceof Varnode srcVn) || !(dst instanceof Varnode dstVn)) {
                return false;
            }

            Integer srcId = data.varnodeToId.get(srcVn);
            Integer dstId = data.varnodeToId.get(dstVn);

            if (srcId == null || dstId == null) return false;

            String key = "node:" + srcId;
            BitSet reachable = reachCache.get(key);
            if (reachable == null) {
                reachable = forwardClosure(List.of(srcId));
                reachCache.put(key, reachable);
            }
            return reachable.get(dstId);
        }

        // ---- checks, bounds and relations ----

        /** Comparisons that decide a branch and involve the value (see FunctionModel.family). */
        private List<PcodeOp> checksOf(Varnode value, boolean arithmetic) {
            return fm.comparisons(fm.family(value, arithmetic), null);
        }

        private boolean isPointerValue(Varnode value) {
            for (Varnode member : fm.family(value, false)) {
                HighVariable high = member.getHigh();
                if (high != null && baseType(high.getDataType()) instanceof Pointer) return true;
            }
            return false;
        }

        @Override
        public boolean isUnchecked(Object var) {
            if (!(var instanceof Varnode value) || value.isConstant()) return false;
            if (isPointerValue(value)) {
                // A pointer is checked by comparing it with a constant (NULL,
                // MAP_FAILED); comparing it with another pointer in a loop is not a check.
                Set<Varnode> family = fm.family(value, false);
                for (PcodeOp cmp : fm.comparisons(family, null)) {
                    Varnode other = family.contains(cmp.getInput(0)) ? cmp.getInput(1) : cmp.getInput(0);
                    if (other != null && stripCopies(other).isConstant()) return false;
                }
                return true;
            }
            return checksOf(value, true).isEmpty();
        }

        @Override
        public boolean isBounded(Object var) {
            return var instanceof Varnode value && bounded(value, 0);
        }

        private boolean bounded(Varnode value, int depth) {
            if (stripCopies(value).isConstant()) return true;
            for (PcodeOp cmp : checksOf(value, true)) {
                if (isOrderedComparison(cmp.getOpcode())) return true;
            }
            // min() / clamp: "m = a < b ? a : b", "if (n > 64) n = 64". The
            // merged value is bounded when every value merged into it is.
            if (depth >= 2) return false;
            PcodeOp def = stripExtensions(value).getDef();
            if (def == null || def.getOpcode() != PcodeOp.MULTIEQUAL) return false;
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode input = def.getInput(i);
                if (input == null || input.equals(def.getOutput())) continue;
                if (!bounded(input, depth + 1)) return false;
            }
            return true;
        }

        @Override
        public boolean isNonNegativeChecked(Object var) {
            if (!(var instanceof Varnode value)) return false;
            if (stripCopies(value).isConstant()) return true;
            Set<Varnode> family = fm.family(value, false);
            for (PcodeOp cmp : fm.comparisons(family, null)) {
                int opcode = cmp.getOpcode();
                if (opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_LESSEQUAL) return true;
                if (opcode != PcodeOp.INT_SLESS && opcode != PcodeOp.INT_SLESSEQUAL) continue;
                Varnode other = family.contains(cmp.getInput(0)) ? cmp.getInput(1) : cmp.getInput(0);
                if (other == null || !other.isConstant()) continue;
                long bound = signedValue(other);
                if (bound >= -1 && bound <= 1) return true;
            }
            return false;
        }

        @Override
        public boolean isOverflowChecked(Object a, Object b) {
            List<Varnode> operands = new ArrayList<>();
            if (a instanceof Varnode va) operands.add(va);
            if (b instanceof Varnode vb) operands.add(vb);
            if (operands.isEmpty()) return false;

            boolean allBounded = true;
            Set<Varnode> families = new HashSet<>();
            for (Varnode operand : operands) {
                if (!isBounded(operand)) allBounded = false;
                families.addAll(fm.family(operand, false));
            }
            if (allBounded) return true;

            // "a > MAX / b", "total / a != b", __builtin_mul_overflow: a division
            // or carry test on an operand is an explicit overflow check.
            for (Varnode member : families) {
                Iterator<PcodeOp> uses = member.getDescendants();
                while (uses != null && uses.hasNext()) {
                    switch (uses.next().getOpcode()) {
                        case PcodeOp.INT_DIV:
                        case PcodeOp.INT_SDIV:
                        case PcodeOp.INT_REM:
                        case PcodeOp.INT_SREM:
                        case PcodeOp.INT_CARRY:
                        case PcodeOp.INT_SCARRY:
                        case PcodeOp.INT_SBORROW:
                            return true;
                        default:
                            break;
                    }
                }
            }
            return false;
        }

        @Override
        public boolean isSigned(Object var) {
            if (!(var instanceof Varnode value)) return false;
            Varnode current = value;
            for (int i = 0; i < 16 && current != null; i++) {
                PcodeOp def = current.getDef();
                if (def != null && def.getOpcode() == PcodeOp.INT_SEXT) return true;
                if (def != null && def.getOpcode() == PcodeOp.INT_ZEXT) return false;
                if (def == null || (def.getOpcode() != PcodeOp.COPY && def.getOpcode() != PcodeOp.CAST)) break;
                current = def.getInput(0);
            }
            if (current == null || current.isConstant()) return false;
            // Otherwise trust the type of a real variable only; the type the
            // decompiler guesses for an unnamed intermediate is not evidence.
            HighVariable high = current.getHigh();
            if (high instanceof HighOther) return false;
            DataType type = high == null ? null : baseType(high.getDataType());
            return type instanceof AbstractIntegerDataType integer && integer.isSigned();
        }

        @Override
        public boolean isSame(Object a, Object b) {
            if (a == null || b == null) return false;
            if (a.equals(b)) return true;
            if (!(a instanceof Varnode va) || !(b instanceof Varnode vb)) return false;
            if (fm.sameAddress(va, vb, 0, true)) return true;
            Set<Varnode> family = fm.family(va, false);
            if (family.contains(vb)) return true;
            for (Varnode member : fm.family(vb, false)) {
                if (family.contains(member)) return true;
            }
            return false;
        }

        /** Non-constant values {@code value} is computed from (not through calls or memory). */
        private Set<Varnode> derivation(Varnode value) {
            Set<Varnode> seen = new LinkedHashSet<>();
            Deque<Varnode> pending = new ArrayDeque<>();
            pending.add(value);
            while (!pending.isEmpty() && seen.size() < 128) {
                Varnode vn = pending.removeFirst();
                if (vn == null || vn.isConstant() || !seen.add(vn)) continue;
                PcodeOp def = vn.getDef();
                if (def == null) continue;
                int opcode = def.getOpcode();
                if (opcode == PcodeOp.INDIRECT) {
                    // the variable as it was before a call that may have touched it
                    pending.addLast(def.getInput(0));
                    continue;
                }
                if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || opcode == PcodeOp.CALLOTHER
                        || opcode == PcodeOp.LOAD || !isTaintPassThroughOp(opcode)) continue;
                for (int i = 0; i < def.getNumInputs(); i++) pending.addLast(def.getInput(i));
            }
            return seen;
        }

        @Override
        public boolean isRelated(Object a, Object b) {
            if (isSame(a, b)) return true;
            if (!(a instanceof Varnode va) || !(b instanceof Varnode vb)) return false;
            Set<Varnode> fromA = derivation(va), fromB = derivation(vb);
            for (Varnode vn : fromA) {
                if (fromB.contains(vn)) return true;
            }
            // Two reads of the same memory location: malloc(pkt->len) ... memcpy(.., pkt->len),
            // or two calls of one function on the same arguments: malloc(strlen(s) + 1) ...
            // memcpy(.., strlen(s) + 1).
            for (Varnode x : fromA) {
                PcodeOp defA = x.getDef();
                if (defA == null) continue;
                for (Varnode y : fromB) {
                    PcodeOp defB = y.getDef();
                    if (defB == null || defA.getOpcode() != defB.getOpcode()) continue;
                    if (defA.getOpcode() == PcodeOp.LOAD
                            && fm.sameAddress(defA.getInput(1), defB.getInput(1), 0, true)) {
                        return true;
                    }
                    if (defA.getOpcode() == PcodeOp.CALL && sameCall(defA, defB)) return true;
                }
            }
            // Compared with each other: "if (m <= n)"
            for (PcodeOpAST op : fm.ops) {
                if (!isComparisonOpcode(op.getOpcode()) || !fm.feedsBranch(op)) continue;
                Set<Varnode> left = derivation(op.getInput(0)), right = derivation(op.getInput(1));
                if ((intersects(left, fromA) && intersects(right, fromB))
                        || (intersects(left, fromB) && intersects(right, fromA))) {
                    return true;
                }
            }
            return false;
        }

        /** Two calls of the same function with the same arguments. */
        private boolean sameCall(PcodeOp a, PcodeOp b) {
            if (a.getNumInputs() != b.getNumInputs() || a.getNumInputs() < 2) return false;
            Varnode targetA = a.getInput(0), targetB = b.getInput(0);
            if (targetA == null || targetB == null || !targetA.isAddress() || !targetB.isAddress()
                    || !targetA.getAddress().equals(targetB.getAddress())) return false;
            for (int i = 1; i < a.getNumInputs(); i++) {
                Varnode x = a.getInput(i), y = b.getInput(i);
                boolean equalConstants = x != null && y != null && x.isConstant() && y.isConstant()
                    && x.getOffset() == y.getOffset();
                if (!equalConstants && !fm.sameAddress(x, y, 0, true)) return false;
            }
            return true;
        }

        private boolean intersects(Set<Varnode> a, Set<Varnode> b) {
            for (Varnode vn : a) {
                if (b.contains(vn)) return true;
            }
            return false;
        }

        @Override
        public boolean isReturnedBy(Object var, List<String> functionNames) {
            if (!(var instanceof Varnode value)) return false;
            // The call result itself, or a value computed from it: strlen(s) + 1
            for (Varnode member : derivation(value)) {
                PcodeOp def = member.getDef();
                if (def == null) continue;
                CallSite call = fm.callBySeq.get(def.getSeqnum());
                if (call != null && nameInList(call, functionNames)) return true;
            }
            return false;
        }

        @Override
        public boolean isInLoop(Object var, Object site) {
            if (site instanceof PcodeOp op) return fm.inLoop(op);
            if (var instanceof Varnode value && value.getDef() != null) return fm.inLoop(value.getDef());
            return false;
        }

        @Override
        public Long constantValue(Object var) {
            if (var instanceof Long number) return number;
            if (var instanceof Varnode value) {
                Varnode stripped = stripCopies(value);
                if (stripped.isConstant()) return stripped.getOffset();
            }
            return null;
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
            if (vn.getHigh() instanceof HighParam) return true;

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
    }

    // A call to an input API is insufficient: the wrapper must return data
    // derived from it. Cache per source and bound recursion/decompiler work.
    private final Map<String, Boolean> returnSourceCache = new HashMap<>();
    private int returnSourceDepth;

    /**
     * Does {@code callee} return data that comes from a taint source?
     *
     * @param sourceName   restrict to one named source, or null for any
     * @param externalOnly when no source is named: the callee's own parameters
     *                     do not count as sources (tainted_ext)
     */
    private boolean functionReturnsSource(Function callee, String sourceName, boolean externalOnly) {
        if (callee == null || returnSourceDepth >= 3) return false;
        if (callee.isThunk() && callee.getThunkedFunction(true) != null) {
            callee = callee.getThunkedFunction(true);
        }
        if (sourceName == null ? TaintMatrixConverter.isTaintSource(callee.getName())
                : TaintMatrixConverter.nameMatches(callee.getName(), sourceName)) return true;
        if (callee.isExternal()) return false;
        String key = callee.getEntryPoint() + "|" + sourceName + "|" + externalOnly + "|" + returnSourceDepth;
        Boolean cached = returnSourceCache.get(key);
        if (cached != null) return cached;
        returnSourceCache.put(key, false);
        DecompInterface decompiler = new DecompInterface();
        returnSourceDepth++;
        try {
            if (!decompiler.openProgram(program)) return false;
            DecompileResults result = decompiler.decompileFunction(callee, 30,
                ghidra.util.task.TaskMonitor.DUMMY);
            HighFunction hf = result.getHighFunction();
            if (!result.decompileCompleted() || hf == null) return false;
            TaintContextImpl context = new TaintContextImpl(converter.convert(hf), new FunctionModel(hf, null));
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.RETURN) continue;
                context.setUseSite(op);
                for (int i = 1; i < op.getNumInputs(); i++) {
                    Varnode value = op.getInput(i);
                    if (value.isConstant()) continue;
                    boolean fromSource = sourceName != null ? context.isTaintedBySource(value, sourceName)
                        : externalOnly ? context.isTaintedExternal(value) : context.isTainted(value);
                    if (fromSource) {
                        returnSourceCache.put(key, true);
                        return true;
                    }
                }
            }
            return false;
        } finally {
            returnSourceDepth--;
            decompiler.dispose();
        }
    }

    /** Opcodes through which taint flows unchanged from inputs to output. */
    private static boolean isTaintPassThroughOp(int op) {
        switch (op) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_2COMP:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.SUBPIECE:
            case PcodeOp.PIECE:
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_MULT:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_AND:
            case PcodeOp.INT_OR:
            case PcodeOp.INT_XOR:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SRIGHT:
            case PcodeOp.LOAD:
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.INDIRECT:
                return true;
            default:
                return false;
        }
    }

    public List<QueryMatch> getMatches() {
        return matches;
    }
}
