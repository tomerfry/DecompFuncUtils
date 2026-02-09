/*
 * AliasTracker - SSA-based alias analysis for pointer variables
 * 
 * Builds alias sets by tracing COPY chains and MULTIEQUAL (PHI) nodes
 * in Ghidra's SSA form. Two varnodes are considered aliases if they
 * represent the same logical pointer value.
 * 
 * This enables the query matcher to detect use-after-free patterns
 * even when the freed pointer and the used pointer are different
 * variables that happen to hold the same address.
 */
package decompfuncutils;

import ghidra.program.model.pcode.*;
import java.util.*;

public class AliasTracker {
    
    // Maps each varnode to its alias set ID
    private final Map<Varnode, Integer> aliasSetId = new HashMap<>();
    // Maps set ID to all varnodes in that set
    private final Map<Integer, Set<Varnode>> aliasSets = new HashMap<>();
    private int nextSetId = 0;
    
    public AliasTracker(HighFunction highFunc) {
        buildAliasSets(highFunc);
    }
    
    private void buildAliasSets(HighFunction highFunc) {
        // Phase 1: Group by HighVariable (decompiler's own merge)
        // All varnodes sharing a HighVariable are trivially aliased
        Map<HighVariable, Set<Varnode>> hvGroups = new HashMap<>();
        Set<Varnode> allVarnodes = new HashSet<>();
        
        Iterator<PcodeOpAST> allOps = highFunc.getPcodeOps();
        while (allOps.hasNext()) {
            PcodeOpAST op = allOps.next();
            if (op.getOutput() != null) allVarnodes.add(op.getOutput());
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input != null) allVarnodes.add(input);
            }
        }
        
        for (Varnode vn : allVarnodes) {
            HighVariable hv = vn.getHigh();
            if (hv != null) {
                hvGroups.computeIfAbsent(hv, k -> new HashSet<>()).add(vn);
            }
        }
        
        // Each HV group becomes an initial alias set
        for (Set<Varnode> group : hvGroups.values()) {
            int setId = nextSetId++;
            aliasSets.put(setId, new HashSet<>(group));
            for (Varnode vn : group) {
                aliasSetId.put(vn, setId);
            }
        }
        
        // Phase 2: Trace COPY/CAST chains to merge alias sets
        // If we see: vn_b = COPY vn_a, merge their sets
        allOps = highFunc.getPcodeOps();
        while (allOps.hasNext()) {
            PcodeOpAST op = allOps.next();
            int opcode = op.getOpcode();
            
            if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                Varnode output = op.getOutput();
                Varnode input = op.getInput(0);
                if (output != null && input != null) {
                    mergeSets(output, input);
                }
            }
            
            // MULTIEQUAL (PHI): all inputs and output are the same logical variable
            if (opcode == PcodeOp.MULTIEQUAL) {
                Varnode output = op.getOutput();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    if (output != null && input != null) {
                        mergeSets(output, input);
                    }
                }
            }
            
            // PTRSUB with offset 0 is effectively a cast/alias
            if (opcode == PcodeOp.PTRSUB) {
                Varnode output = op.getOutput();
                Varnode base = op.getInput(0);
                Varnode offset = op.getInput(1);
                if (output != null && base != null && offset != null 
                    && offset.isConstant() && offset.getOffset() == 0) {
                    mergeSets(output, base);
                }
            }
        }
    }
    
    private void mergeSets(Varnode a, Varnode b) {
        Integer setA = aliasSetId.get(a);
        Integer setB = aliasSetId.get(b);
        
        if (setA == null && setB == null) {
            int newSet = nextSetId++;
            Set<Varnode> group = new HashSet<>();
            group.add(a);
            group.add(b);
            aliasSets.put(newSet, group);
            aliasSetId.put(a, newSet);
            aliasSetId.put(b, newSet);
        } else if (setA == null) {
            aliasSets.get(setB).add(a);
            aliasSetId.put(a, setB);
        } else if (setB == null) {
            aliasSets.get(setA).add(b);
            aliasSetId.put(b, setA);
        } else if (!setA.equals(setB)) {
            // Merge setB into setA
            Set<Varnode> groupB = aliasSets.remove(setB);
            if (groupB != null) {
                aliasSets.get(setA).addAll(groupB);
                for (Varnode vn : groupB) {
                    aliasSetId.put(vn, setA);
                }
            }
        }
    }
    
    /**
     * Check if two varnodes are aliases (same logical pointer value)
     */
    public boolean areAliases(Varnode a, Varnode b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        
        Integer setA = aliasSetId.get(a);
        Integer setB = aliasSetId.get(b);
        return setA != null && setA.equals(setB);
    }
    
    /**
     * Get all varnodes that alias with the given varnode
     */
    public Set<Varnode> getAliases(Varnode vn) {
        if (vn == null) return Collections.emptySet();
        Integer setId = aliasSetId.get(vn);
        if (setId == null) return Collections.singleton(vn);
        Set<Varnode> result = aliasSets.get(setId);
        return result != null ? Collections.unmodifiableSet(result) : Collections.singleton(vn);
    }
    
    /**
     * Get statistics about alias sets (for logging/debugging)
     */
    public String getStats() {
        int totalSets = aliasSets.size();
        int totalVarnodes = aliasSetId.size();
        int maxSetSize = aliasSets.values().stream()
            .mapToInt(Set::size)
            .max()
            .orElse(0);
        return String.format("AliasTracker: %d sets, %d varnodes, max set size %d",
            totalSets, totalVarnodes, maxSetSize);
    }
}