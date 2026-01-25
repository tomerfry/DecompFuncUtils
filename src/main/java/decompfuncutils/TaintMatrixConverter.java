/*
 * TaintMatrixConverter - Converts P-Code/High-Level IR to Sparse Matrix (CSR format)
 * 
 * Maps data flow relationships into a sparse adjacency matrix for GPU-accelerated
 * taint propagation using SpMV (Sparse Matrix-Vector multiplication).
 */
package decompfuncutils;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.*;

/**
 * Converts decompiled function representation to sparse matrix format.
 * 
 * The matrix M[i][j] = weight means data flows FROM node j TO node i.
 * This allows taint propagation via: tainted' = M * tainted
 * 
 * Node types:
 * - Varnodes (registers, memory, constants, uniques)
 * - Function parameters (for inter-procedural tracking)
 * - Memory locations (for pointer tracking)
 */
public class TaintMatrixConverter {
    
    // Edge weights for different flow types
    public static final float WEIGHT_DIRECT = 1.0f;      // Direct assignment: x = y
    public static final float WEIGHT_ARITHMETIC = 0.9f;  // Arithmetic: x = y + z
    public static final float WEIGHT_MEMORY = 0.85f;     // Memory ops: *p = x, x = *p
    public static final float WEIGHT_CALL_ARG = 0.8f;    // Function call argument
    public static final float WEIGHT_CALL_RET = 0.75f;   // Function return value
    public static final float WEIGHT_CONDITIONAL = 0.5f; // Conditional influence
    
    /**
     * CSR (Compressed Sparse Row) format for GPU transfer
     */
    public static class CsrData {
        public int numNodes;
        public int numEdges;
        public int[] rowPtr;    // Row pointers (size = numNodes + 1)
        public int[] colInd;    // Column indices (size = numEdges)
        public float[] values;  // Edge weights (size = numEdges)
        
        // Bidirectional mapping
        public Map<Varnode, Integer> varnodeToId;
        public Map<Integer, Varnode> idToVarnode;
        
        // Node metadata
        public Map<Integer, NodeInfo> nodeInfo;
        
        // For building incrementally
        private List<List<Edge>> adjacencyList;
        
        public CsrData() {
            varnodeToId = new HashMap<>();
            idToVarnode = new HashMap<>();
            nodeInfo = new HashMap<>();
            adjacencyList = new ArrayList<>();
        }
        
        public int getOrCreateNode(Varnode vn) {
            if (varnodeToId.containsKey(vn)) {
                return varnodeToId.get(vn);
            }
            int id = numNodes++;
            varnodeToId.put(vn, id);
            idToVarnode.put(id, vn);
            adjacencyList.add(new ArrayList<>());
            nodeInfo.put(id, new NodeInfo(vn));
            return id;
        }
        
        public void addEdge(int from, int to, float weight) {
            adjacencyList.get(to).add(new Edge(from, weight));
            numEdges++;
        }
        
        /**
         * Build CSR format arrays for GPU transfer
         */
        public void buildCsr() {
            rowPtr = new int[numNodes + 1];
            colInd = new int[numEdges];
            values = new float[numEdges];
            
            int idx = 0;
            for (int row = 0; row < numNodes; row++) {
                rowPtr[row] = idx;
                List<Edge> edges = adjacencyList.get(row);
                // Sort by column for better cache locality
                edges.sort(Comparator.comparingInt(e -> e.col));
                for (Edge e : edges) {
                    colInd[idx] = e.col;
                    values[idx] = e.weight;
                    idx++;
                }
            }
            rowPtr[numNodes] = idx;
            
            // Free adjacency list memory
            adjacencyList = null;
        }
        
        /**
         * Get nodes that are tainted given a threshold
         */
        public Set<Varnode> getTaintedVarnodes(float[] taintVector, float threshold) {
            Set<Varnode> tainted = new HashSet<>();
            for (int i = 0; i < numNodes; i++) {
                if (taintVector[i] >= threshold) {
                    Varnode vn = idToVarnode.get(i);
                    if (vn != null) {
                        tainted.add(vn);
                    }
                }
            }
            return tainted;
        }
    }
    
    private static class Edge {
        int col;
        float weight;
        Edge(int col, float weight) {
            this.col = col;
            this.weight = weight;
        }
    }
    
    /**
     * Metadata about each node for analysis
     */
    public static class NodeInfo {
        public enum NodeType {
            REGISTER, MEMORY, CONSTANT, UNIQUE, PARAMETER, RETURN_VALUE, CALL_SITE
        }
        
        public NodeType type;
        public String name;
        public Address address;
        public boolean isSource;  // User input, network, etc.
        public boolean isSink;    // Dangerous function arg, etc.
        
        public NodeInfo(Varnode vn) {
            if (vn == null) {
                type = NodeType.UNIQUE;
                name = "null";
                return;
            }
            
            if (vn.isRegister()) {
                type = NodeType.REGISTER;
                name = "reg_" + vn.getOffset();
            } else if (vn.isConstant()) {
                type = NodeType.CONSTANT;
                name = "const_" + vn.getOffset();
            } else if (vn.isUnique()) {
                type = NodeType.UNIQUE;
                name = "u_" + Long.toHexString(vn.getOffset());
            } else if (vn.isAddress()) {
                type = NodeType.MEMORY;
                name = "mem_" + vn.getAddress();
                address = vn.getAddress();
            } else {
                type = NodeType.UNIQUE;
                name = "var_" + vn.getOffset();
            }
        }
    }
    
    // Known dangerous sinks (function names -> parameter indices that are dangerous)
    private static final Map<String, Set<Integer>> DANGEROUS_SINKS = new HashMap<>();
    static {
        // Format string vulnerabilities
        DANGEROUS_SINKS.put("printf", Set.of(0));
        DANGEROUS_SINKS.put("sprintf", Set.of(1));
        DANGEROUS_SINKS.put("snprintf", Set.of(2));
        DANGEROUS_SINKS.put("fprintf", Set.of(1));
        DANGEROUS_SINKS.put("syslog", Set.of(1));
        
        // Command injection
        DANGEROUS_SINKS.put("system", Set.of(0));
        DANGEROUS_SINKS.put("popen", Set.of(0));
        DANGEROUS_SINKS.put("execve", Set.of(0, 1));
        DANGEROUS_SINKS.put("execl", Set.of(0));
        DANGEROUS_SINKS.put("execlp", Set.of(0));
        
        // Memory corruption
        DANGEROUS_SINKS.put("memcpy", Set.of(2));
        DANGEROUS_SINKS.put("memmove", Set.of(2));
        DANGEROUS_SINKS.put("strcpy", Set.of(1));
        DANGEROUS_SINKS.put("strncpy", Set.of(2));
        DANGEROUS_SINKS.put("strcat", Set.of(1));
        DANGEROUS_SINKS.put("gets", Set.of(0));
        
        // SQL injection (if using embedded SQL)
        DANGEROUS_SINKS.put("sqlite3_exec", Set.of(1));
        DANGEROUS_SINKS.put("mysql_query", Set.of(1));
    }
    
    // Known taint sources
    private static final Set<String> TAINT_SOURCES = Set.of(
        "recv", "recvfrom", "recvmsg",
        "read", "fread", "fgets", "gets",
        "scanf", "fscanf", "sscanf",
        "getenv", "getchar", "fgetc",
        "accept", "listen"
    );
    
    /**
     * Convert a HighFunction to CSR sparse matrix
     */
    public CsrData convert(HighFunction highFunc) {
        CsrData data = new CsrData();
        
        if (highFunc == null) {
            return data;
        }
        
        // Process all P-Code operations
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            processOperation(data, op, highFunc);
        }
        
        // Mark sources and sinks
        markSourcesAndSinks(data, highFunc);
        
        // Finalize to CSR format
        data.buildCsr();
        
        return data;
    }
    
    /**
     * Convert from ClangTokenGroup (decompiled C view)
     */
    public CsrData convertFromClang(ClangTokenGroup root, HighFunction highFunc) {
        CsrData data = new CsrData();
        
        // First pass: collect all variable tokens and their varnodes
        collectVarnodes(root, data);
        
        // Second pass: analyze statements for data flow
        analyzeClangStatements(root, data);
        
        // Also process P-Code for completeness
        if (highFunc != null) {
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                processOperation(data, op, highFunc);
            }
            markSourcesAndSinks(data, highFunc);
        }
        
        data.buildCsr();
        return data;
    }
    
    private void collectVarnodes(ClangNode node, CsrData data) {
        if (node instanceof ClangVariableToken varToken) {
            Varnode vn = varToken.getVarnode();
            if (vn != null) {
                data.getOrCreateNode(vn);
            }
        }
        
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                collectVarnodes(group.Child(i), data);
            }
        }
    }
    
    private void analyzeClangStatements(ClangNode node, CsrData data) {
        if (node instanceof ClangStatement stmt) {
            analyzeStatement(stmt, data);
        }
        
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                analyzeClangStatements(group.Child(i), data);
            }
        }
    }
    
    private void analyzeStatement(ClangStatement stmt, CsrData data) {
        // Find assignment patterns: lhs = rhs
        List<ClangVariableToken> vars = new ArrayList<>();
        collectVariableTokens(stmt, vars);
        
        // Simple heuristic: first var is often the destination
        // More complex analysis would parse the operator tokens
        if (vars.size() >= 2) {
            ClangVariableToken dest = vars.get(0);
            Varnode destVn = dest.getVarnode();
            if (destVn != null) {
                int destId = data.getOrCreateNode(destVn);
                
                for (int i = 1; i < vars.size(); i++) {
                    Varnode srcVn = vars.get(i).getVarnode();
                    if (srcVn != null && !srcVn.equals(destVn)) {
                        int srcId = data.getOrCreateNode(srcVn);
                        data.addEdge(srcId, destId, WEIGHT_ARITHMETIC);
                    }
                }
            }
        }
    }
    
    private void collectVariableTokens(ClangNode node, List<ClangVariableToken> vars) {
        if (node instanceof ClangVariableToken varToken) {
            vars.add(varToken);
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                collectVariableTokens(group.Child(i), vars);
            }
        }
    }
    
    /**
     * Process a single P-Code operation to extract data flow edges
     */
    private void processOperation(CsrData data, PcodeOpAST op, HighFunction highFunc) {
        Varnode output = op.getOutput();
        Varnode[] inputs = op.getInputs();
        int opcode = op.getOpcode();
        
        switch (opcode) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
                // Direct data flow
                if (output != null && inputs.length > 0 && inputs[0] != null) {
                    addDataFlowEdge(data, inputs[0], output, WEIGHT_DIRECT);
                }
                break;
                
            case PcodeOp.LOAD:
                // Memory read: output = *inputs[1]
                if (output != null && inputs.length > 1 && inputs[1] != null) {
                    addDataFlowEdge(data, inputs[1], output, WEIGHT_MEMORY);
                }
                break;
                
            case PcodeOp.STORE:
                // Memory write: *inputs[1] = inputs[2]
                if (inputs.length > 2 && inputs[1] != null && inputs[2] != null) {
                    // Create a synthetic node for the memory location
                    addDataFlowEdge(data, inputs[2], inputs[1], WEIGHT_MEMORY);
                }
                break;
                
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
                // Arithmetic: taint propagates from all inputs to output
                if (output != null) {
                    for (Varnode input : inputs) {
                        if (input != null && !input.isConstant()) {
                            addDataFlowEdge(data, input, output, WEIGHT_ARITHMETIC);
                        }
                    }
                }
                break;
                
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
                processCall(data, op, highFunc);
                break;
                
            case PcodeOp.RETURN:
                // Return value flows from input to caller
                if (inputs.length > 1 && inputs[1] != null) {
                    int retId = data.getOrCreateNode(inputs[1]);
                    NodeInfo info = data.nodeInfo.get(retId);
                    if (info != null) {
                        info.type = NodeInfo.NodeType.RETURN_VALUE;
                    }
                }
                break;
                
            case PcodeOp.CBRANCH:
            case PcodeOp.BRANCHIND:
                // Conditional branch: condition influences control flow
                // We track this for control-flow based taint
                if (inputs.length > 1 && inputs[1] != null) {
                    int condId = data.getOrCreateNode(inputs[1]);
                    NodeInfo info = data.nodeInfo.get(condId);
                    if (info != null) {
                        // Mark as influencing control flow
                    }
                }
                break;
                
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.INDIRECT:
                // SSA phi nodes: all inputs flow to output
                if (output != null) {
                    for (Varnode input : inputs) {
                        if (input != null) {
                            addDataFlowEdge(data, input, output, WEIGHT_DIRECT);
                        }
                    }
                }
                break;
                
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
                // Pointer arithmetic: base pointer taint propagates
                if (output != null && inputs.length > 0 && inputs[0] != null) {
                    addDataFlowEdge(data, inputs[0], output, WEIGHT_MEMORY);
                }
                break;
                
            default:
                // Generic: all non-constant inputs flow to output
                if (output != null) {
                    for (Varnode input : inputs) {
                        if (input != null && !input.isConstant()) {
                            addDataFlowEdge(data, input, output, WEIGHT_ARITHMETIC);
                        }
                    }
                }
                break;
        }
    }
    
    /**
     * Process function calls for inter-procedural taint
     */
    private void processCall(CsrData data, PcodeOpAST op, HighFunction highFunc) {
        Varnode[] inputs = op.getInputs();
        Varnode output = op.getOutput();
        
        if (inputs.length == 0) return;
        
        // First input is the call target
        Varnode target = inputs[0];
        String funcName = getFunctionName(target, highFunc);
        
        // Track call arguments
        for (int i = 1; i < inputs.length; i++) {
            if (inputs[i] != null) {
                int argId = data.getOrCreateNode(inputs[i]);
                NodeInfo info = data.nodeInfo.get(argId);
                if (info != null) {
                    // Check if this is a dangerous sink parameter
                    if (funcName != null && DANGEROUS_SINKS.containsKey(funcName)) {
                        if (DANGEROUS_SINKS.get(funcName).contains(i - 1)) {
                            info.isSink = true;
                        }
                    }
                }
                
                // Return value is tainted by all arguments (conservative)
                if (output != null) {
                    addDataFlowEdge(data, inputs[i], output, WEIGHT_CALL_ARG);
                }
            }
        }
        
        // Mark return value
        if (output != null) {
            int retId = data.getOrCreateNode(output);
            NodeInfo info = data.nodeInfo.get(retId);
            if (info != null) {
                info.type = NodeInfo.NodeType.CALL_SITE;
                // Check if this is a taint source
                if (funcName != null && TAINT_SOURCES.contains(funcName)) {
                    info.isSource = true;
                }
            }
        }
    }
    
    private String getFunctionName(Varnode target, HighFunction highFunc) {
        if (target == null || highFunc == null) return null;
        
        try {
            if (target.isAddress()) {
                Function func = highFunc.getFunction().getProgram()
                    .getFunctionManager().getFunctionAt(target.getAddress());
                if (func != null) {
                    return func.getName();
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    private void addDataFlowEdge(CsrData data, Varnode from, Varnode to, float weight) {
        if (from == null || to == null) return;
        if (from.equals(to)) return;  // No self-loops
        
        int fromId = data.getOrCreateNode(from);
        int toId = data.getOrCreateNode(to);
        data.addEdge(fromId, toId, weight);
    }
    
    /**
     * Mark function parameters as potential sources
     */
    private void markSourcesAndSinks(CsrData data, HighFunction highFunc) {
        if (highFunc == null) return;
        
        // Mark function parameters as potential taint sources
        LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
        if (lsm != null) {
            int paramCount = lsm.getNumParams();
            for (int i = 0; i < paramCount; i++) {
                HighVariable param = lsm.getParam(i);
                if (param != null) {
                    Varnode rep = param.getRepresentative();
                    if (rep != null && data.varnodeToId.containsKey(rep)) {
                        int id = data.varnodeToId.get(rep);
                        NodeInfo info = data.nodeInfo.get(id);
                        if (info != null) {
                            info.type = NodeInfo.NodeType.PARAMETER;
                            info.name = param.getName();
                            // Parameters are potential sources
                            info.isSource = true;
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Build the transpose matrix for backward taint analysis
     * (finding what sources can reach a sink)
     */
    public CsrData buildTranspose(CsrData original) {
        CsrData transpose = new CsrData();
        transpose.varnodeToId = original.varnodeToId;
        transpose.idToVarnode = original.idToVarnode;
        transpose.nodeInfo = original.nodeInfo;
        transpose.numNodes = original.numNodes;
        
        // Initialize adjacency list
        for (int i = 0; i < original.numNodes; i++) {
            transpose.adjacencyList.add(new ArrayList<>());
        }
        
        // Reverse all edges
        for (int row = 0; row < original.numNodes; row++) {
            int start = original.rowPtr[row];
            int end = original.rowPtr[row + 1];
            for (int j = start; j < end; j++) {
                int col = original.colInd[j];
                float weight = original.values[j];
                // Original: col -> row, Transpose: row -> col
                transpose.adjacencyList.get(col).add(new Edge(row, weight));
                transpose.numEdges++;
            }
        }
        
        transpose.buildCsr();
        return transpose;
    }
    
    /**
     * Find all nodes marked as sinks
     */
    public Set<Integer> findSinks(CsrData data) {
        Set<Integer> sinks = new HashSet<>();
        for (Map.Entry<Integer, NodeInfo> entry : data.nodeInfo.entrySet()) {
            if (entry.getValue().isSink) {
                sinks.add(entry.getKey());
            }
        }
        return sinks;
    }
    
    /**
     * Find all nodes marked as sources
     */
    public Set<Integer> findSources(CsrData data) {
        Set<Integer> sources = new HashSet<>();
        for (Map.Entry<Integer, NodeInfo> entry : data.nodeInfo.entrySet()) {
            if (entry.getValue().isSource) {
                sources.add(entry.getKey());
            }
        }
        return sources;
    }
}
