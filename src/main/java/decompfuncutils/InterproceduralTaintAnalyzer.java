/*
 * InterproceduralTaintAnalyzer - Follows calls N levels deep for taint analysis
 */
package decompfuncutils;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class InterproceduralTaintAnalyzer {
    
    private final Program program;
    private final DecompInterface decompiler;
    private final TaintMatrixConverter converter;
    private final GpuTaintEngine engine;
    private final TaintLogPanel logPanel;
    
    private int maxDepth = 3;
    private int maxIterations = 30;
    private float taintThreshold = 0.1f;
    
    // Cache decompiled functions to avoid re-decompiling
    private Map<Address, HighFunction> decompileCache = new HashMap<>();
    
    // Track visited functions to avoid infinite recursion
    private Set<Address> visitedInCurrentPath = new HashSet<>();
    
    // Results
    private List<TaintPath> foundPaths = new ArrayList<>();
    private Map<Address, Set<Integer>> taintedParamsPerFunction = new HashMap<>();
    
    public static class TaintPath {
        public List<String> functionChain = new ArrayList<>();
        public List<Address> addressChain = new ArrayList<>();
        public String sinkName;
        public String sinkFunction;
        public float finalTaint;
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < functionChain.size(); i++) {
                if (i > 0) sb.append(" → ");
                sb.append(functionChain.get(i));
            }
            sb.append(" → [SINK: ").append(sinkName).append("]");
            return sb.toString();
        }
    }
    
    public static class CallSite {
        public Address callAddress;
        public Address targetAddress;
        public String targetName;
        public List<Integer> taintedArgIndices = new ArrayList<>();
        public List<Float> argTaintLevels = new ArrayList<>();
    }
    
    public InterproceduralTaintAnalyzer(Program program, TaintLogPanel logPanel) {
        this.program = program;
        this.logPanel = logPanel;
        this.converter = new TaintMatrixConverter();
        this.engine = new GpuTaintEngine();
        
        // Initialize decompiler
        this.decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }
    
    public void setMaxDepth(int depth) {
        this.maxDepth = depth;
    }
    
    public void setMaxIterations(int iterations) {
        this.maxIterations = iterations;
    }
    
    public List<TaintPath> getFoundPaths() {
        return foundPaths;
    }
    
    /**
     * Run inter-procedural taint analysis starting from a specific varnode
     */
    public void analyze(HighFunction startFunc, Varnode startVarnode, boolean forward, TaskMonitor monitor) {
        foundPaths.clear();
        visitedInCurrentPath.clear();
        taintedParamsPerFunction.clear();
        
        if (startFunc == null || startVarnode == null) {
            logPanel.logWarning("Invalid start point for analysis");
            return;
        }
        
        Function func = startFunc.getFunction();
        String startVarName = getVarnodeName(startVarnode, startFunc);
        
        logPanel.logHeader("INTER-PROCEDURAL TAINT ANALYSIS");
        logPanel.logInfo("Start function: " + func.getName() + " @ " + func.getEntryPoint());
        logPanel.logInfo("Start variable: " + startVarName);
        logPanel.logInfo("Direction: " + (forward ? "FORWARD (where does it flow?)" : "BACKWARD (what reaches it?)"));
        logPanel.logInfo("Max call depth: " + maxDepth);
        logPanel.logSeparator();
        
        // Start recursive analysis
        List<String> currentPath = new ArrayList<>();
        currentPath.add(func.getName());
        
        analyzeFunction(startFunc, startVarnode, forward, 0, currentPath, monitor);
        
        // Summary
        logPanel.logSeparator();
        logPanel.logHeader("ANALYSIS COMPLETE");
        logPanel.logInfo("Functions analyzed: " + decompileCache.size());
        logPanel.logInfo("Dangerous paths found: " + foundPaths.size());
        
        if (!foundPaths.isEmpty()) {
            logPanel.logSeparator();
            logPanel.logHeader("DANGEROUS PATHS");
            for (TaintPath path : foundPaths) {
                logPanel.logSinkReached(path.sinkName, path.sinkFunction, path.finalTaint);
                logPanel.logInfo("  Path: " + path.toString());
            }
        }
    }
    
    /**
     * Analyze a single function and recurse into calls
     */
    private void analyzeFunction(HighFunction highFunc, Varnode startVarnode, 
                                  boolean forward, int depth, List<String> pathSoFar, 
                                  TaskMonitor monitor) {
        
        if (depth > maxDepth) {
            logPanel.logWarning("Max depth reached, stopping recursion");
            return;
        }
        
        if (monitor.isCancelled()) return;
        
        Function func = highFunc.getFunction();
        Address funcAddr = func.getEntryPoint();
        
        // Check for recursion
        if (visitedInCurrentPath.contains(funcAddr)) {
            logPanel.logWarning("Recursion detected at " + func.getName() + ", skipping");
            return;
        }
        visitedInCurrentPath.add(funcAddr);
        
        try {
            logPanel.logCallEnter(func.getName(), funcAddr, depth);
            
            // Build the data flow matrix for this function
            logPanel.logInfo("Building matrix for " + func.getName() + "...");
            TaintMatrixConverter.CsrData data = converter.convert(highFunc);
            
            if (data.numNodes == 0) {
                logPanel.logWarning("No data flow nodes found in " + func.getName());
                return;
            }
            
            // Log matrix stats
            Set<Integer> sources = converter.findSources(data);
            Set<Integer> sinks = converter.findSinks(data);
            logPanel.logMatrixStats(data.numNodes, data.numEdges, sources.size(), sinks.size());
            
            // Build node name map for logging
            Map<Integer, String> nodeNames = new HashMap<>();
            for (Map.Entry<Varnode, Integer> entry : data.varnodeToId.entrySet()) {
                nodeNames.put(entry.getValue(), getVarnodeName(entry.getKey(), highFunc));
            }
            
            // Log the matrix (first N edges)
            if (data.numEdges > 0 && data.numEdges <= 50) {
                logPanel.logSparseMatrix(data.rowPtr, data.colInd, data.values, nodeNames, 20);
            }
            
            // For backward analysis, use transpose
            TaintMatrixConverter.CsrData workingData = forward ? data : converter.buildTranspose(data);
            
            // Find start node
            Integer startId = workingData.varnodeToId.get(startVarnode);
            if (startId == null) {
                // Try to find by matching criteria
                startId = findMatchingNode(startVarnode, workingData, highFunc);
            }
            
            if (startId == null) {
                logPanel.logWarning("Start variable not found in " + func.getName() + " data flow graph");
                return;
            }
            
            // Initialize taint vector
            float[] taintVector = new float[workingData.numNodes];
            taintVector[startId] = 1.0f;
            logPanel.logTaint(nodeNames.getOrDefault(startId, "start"), 1.0f, depth);
            
            // Run propagation with logging
            runTaintPropagationWithLogging(workingData, taintVector, nodeNames, depth);
            
            // Check for sinks reached
            checkSinksReached(workingData, taintVector, func.getName(), pathSoFar, depth);
            
            // Find call sites where tainted data flows to arguments
            if (depth < maxDepth) {
                List<CallSite> taintedCalls = findTaintedCallSites(highFunc, workingData, taintVector);
                
                for (CallSite call : taintedCalls) {
                    if (monitor.isCancelled()) break;
                    
                    logPanel.logInfo("Tainted call found: " + call.targetName + 
                        " with " + call.taintedArgIndices.size() + " tainted args");
                    
                    // Decompile and analyze the called function
                    HighFunction calleeFunc = decompileFunction(call.targetAddress, monitor);
                    if (calleeFunc != null) {
                        // For each tainted argument, propagate into callee
                        for (int i = 0; i < call.taintedArgIndices.size(); i++) {
                            int argIdx = call.taintedArgIndices.get(i);
                            float argTaint = call.argTaintLevels.get(i);
                            
                            Varnode paramVarnode = getParameterVarnode(calleeFunc, argIdx);
                            if (paramVarnode != null) {
                                List<String> newPath = new ArrayList<>(pathSoFar);
                                newPath.add(call.targetName);
                                
                                analyzeFunction(calleeFunc, paramVarnode, forward, 
                                              depth + 1, newPath, monitor);
                            }
                        }
                    }
                }
            }
            
            logPanel.logCallExit(func.getName(), depth);
            
        } finally {
            visitedInCurrentPath.remove(funcAddr);
        }
    }
    
    /**
     * Run taint propagation with detailed logging
     */
    private void runTaintPropagationWithLogging(TaintMatrixConverter.CsrData data,
                                                 float[] taintVector,
                                                 Map<Integer, String> nodeNames,
                                                 int depth) {
        float[] tempVector = new float[data.numNodes];
        
        for (int iter = 0; iter < maxIterations; iter++) {
            float maxChange = 0.0f;
            int newlyTainted = 0;
            
            // SpMV: temp = A * taint
            for (int row = 0; row < data.numNodes; row++) {
                float sum = 0.0f;
                int start = data.rowPtr[row];
                int end = data.rowPtr[row + 1];
                
                for (int j = start; j < end; j++) {
                    int col = data.colInd[j];
                    sum += data.values[j] * taintVector[col];
                }
                
                tempVector[row] = Math.min(1.0f, sum);
            }
            
            // Merge and track changes
            for (int i = 0; i < data.numNodes; i++) {
                float newVal = Math.max(taintVector[i], tempVector[i]);
                float change = Math.abs(newVal - taintVector[i]);
                if (change > maxChange) maxChange = change;
                if (taintVector[i] < taintThreshold && newVal >= taintThreshold) {
                    newlyTainted++;
                }
                taintVector[i] = newVal;
            }
            
            // Count total tainted
            int taintedCount = 0;
            for (float v : taintVector) {
                if (v >= taintThreshold) taintedCount++;
            }
            
            // Log this iteration (only if something changed)
            if (iter < 5 || newlyTainted > 0 || iter == maxIterations - 1) {
                logPanel.logPropagationStep(iter + 1, taintedCount, maxChange);
            }
            
            // Early termination
            if (maxChange < 0.0001f) {
                logPanel.logInfo("  Converged at iteration " + (iter + 1));
                break;
            }
        }
        
        // Log final tainted variables
        logPanel.logInfo("Tainted variables:");
        List<Map.Entry<Integer, Float>> sorted = new ArrayList<>();
        for (int i = 0; i < taintVector.length; i++) {
            if (taintVector[i] >= taintThreshold) {
                sorted.add(Map.entry(i, taintVector[i]));
            }
        }
        sorted.sort((a, b) -> Float.compare(b.getValue(), a.getValue()));
        
        int shown = 0;
        for (Map.Entry<Integer, Float> entry : sorted) {
            if (shown++ >= 15) {
                logPanel.logInfo("  ... and " + (sorted.size() - 15) + " more");
                break;
            }
            logPanel.logTaint(nodeNames.getOrDefault(entry.getKey(), "node_" + entry.getKey()), 
                             entry.getValue(), depth + 1);
        }
    }
    
    /**
     * Check if any sinks were reached by tainted data
     */
    private void checkSinksReached(TaintMatrixConverter.CsrData data, float[] taintVector,
                                   String funcName, List<String> pathSoFar, int depth) {
        Set<Integer> sinks = converter.findSinks(data);
        
        for (int sinkId : sinks) {
            if (taintVector[sinkId] >= taintThreshold) {
                TaintMatrixConverter.NodeInfo info = data.nodeInfo.get(sinkId);
                String sinkName = info != null ? info.name : "unknown_sink";
                
                TaintPath path = new TaintPath();
                path.functionChain = new ArrayList<>(pathSoFar);
                path.sinkName = sinkName;
                path.sinkFunction = funcName;
                path.finalTaint = taintVector[sinkId];
                foundPaths.add(path);
                
                logPanel.logSinkReached(sinkName, funcName, taintVector[sinkId]);
            }
        }
    }
    
    /**
     * Find call sites where tainted data flows into arguments
     */
    private List<CallSite> findTaintedCallSites(HighFunction highFunc, 
                                                 TaintMatrixConverter.CsrData data,
                                                 float[] taintVector) {
        List<CallSite> calls = new ArrayList<>();
        
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                Varnode[] inputs = op.getInputs();
                if (inputs.length < 1) continue;
                
                // Get call target
                Varnode target = inputs[0];
                Address targetAddr = null;
                String targetName = "unknown";
                
                if (target.isAddress()) {
                    targetAddr = target.getAddress();
                    Function targetFunc = program.getFunctionManager().getFunctionAt(targetAddr);
                    if (targetFunc != null) {
                        targetName = targetFunc.getName();
                    }
                }
                
                if (targetAddr == null) continue;
                
                // Check which arguments are tainted
                CallSite call = new CallSite();
                call.callAddress = op.getSeqnum().getTarget();
                call.targetAddress = targetAddr;
                call.targetName = targetName;
                
                for (int i = 1; i < inputs.length; i++) {
                    Varnode arg = inputs[i];
                    if (arg == null) continue;
                    
                    Integer argId = data.varnodeToId.get(arg);
                    if (argId != null && taintVector[argId] >= taintThreshold) {
                        call.taintedArgIndices.add(i - 1);  // 0-indexed parameter
                        call.argTaintLevels.add(taintVector[argId]);
                    }
                }
                
                if (!call.taintedArgIndices.isEmpty()) {
                    calls.add(call);
                }
            }
        }
        
        return calls;
    }
    
    /**
     * Get the varnode for a function parameter
     */
    private Varnode getParameterVarnode(HighFunction func, int paramIndex) {
        LocalSymbolMap lsm = func.getLocalSymbolMap();
        if (lsm == null) return null;
        
        if (paramIndex >= lsm.getNumParams()) return null;
        
        HighVariable param = lsm.getParam(paramIndex);
        if (param == null) return null;
        
        return param.getRepresentative();
    }
    
    /**
     * Decompile a function (with caching)
     */
    private HighFunction decompileFunction(Address funcAddr, TaskMonitor monitor) {
        if (decompileCache.containsKey(funcAddr)) {
            return decompileCache.get(funcAddr);
        }
        
        Function func = program.getFunctionManager().getFunctionAt(funcAddr);
        if (func == null) return null;
        
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            return null;
        }
        
        HighFunction hf = results.getHighFunction();
        decompileCache.put(funcAddr, hf);
        return hf;
    }
    
    /**
     * Get a human-readable name for a varnode
     */
    private String getVarnodeName(Varnode vn, HighFunction func) {
        if (vn == null) return "null";
        
        HighVariable hv = vn.getHigh();
        if (hv != null) {
            String name = hv.getName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
        }
        
        if (vn.isRegister()) {
            return "reg_" + vn.getOffset();
        } else if (vn.isConstant()) {
            return "const_0x" + Long.toHexString(vn.getOffset());
        } else if (vn.isUnique()) {
            return "tmp_" + Long.toHexString(vn.getOffset());
        } else if (vn.isAddress()) {
            return "mem_" + vn.getAddress();
        }
        
        return "var_" + vn.getOffset();
    }
    
    /**
     * Try to find a matching node when exact varnode match fails
     */
    private Integer findMatchingNode(Varnode target, TaintMatrixConverter.CsrData data, HighFunction func) {
        // Try matching by high variable
        HighVariable targetHv = target.getHigh();
        if (targetHv != null) {
            for (Map.Entry<Varnode, Integer> entry : data.varnodeToId.entrySet()) {
                HighVariable hv = entry.getKey().getHigh();
                if (hv != null && hv.equals(targetHv)) {
                    return entry.getValue();
                }
            }
        }
        
        // Try matching by offset for parameters
        for (Map.Entry<Varnode, Integer> entry : data.varnodeToId.entrySet()) {
            Varnode vn = entry.getKey();
            if (vn.getOffset() == target.getOffset() && 
                vn.getSize() == target.getSize()) {
                return entry.getValue();
            }
        }
        
        return null;
    }
    
    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
        }
        decompileCache.clear();
    }
}
