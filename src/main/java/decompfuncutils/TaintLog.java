/*
 * TaintLog - logging abstraction for the taint engine.
 *
 * Decouples the taint matcher / inter-procedural analyzer from the Swing-based
 * TaintLogPanel so the engine can run headless (e.g. analyzeHeadless, automated
 * tests, or MCP calls with no PluginTool) where constructing a ComponentProvider
 * is impossible. TaintLogPanel implements this for the GUI; StringTaintLog
 * implements it for headless string capture.
 */
package decompfuncutils;

import ghidra.program.model.address.Address;

import java.util.Map;

public interface TaintLog {
    void logHeader(String text);
    void logInfo(String text);
    void logMatrix(String text);
    void logEdge(String from, String to, float weight);
    void logTaint(String varName, float taintLevel, int depth);
    void logCallEnter(String funcName, Address addr, int depth);
    void logCallExit(String funcName, int depth);
    void logSinkReached(String sinkName, String funcName, float taintLevel);
    void logWarning(String text);
    void logSuccess(String text);
    void logMatrixStats(int nodes, int edges, int sources, int sinks);
    void logSparseMatrix(int[] rowPtr, int[] colInd, float[] values,
                         Map<Integer, String> nodeNames, int maxDisplay);
    void logPropagationStep(int iteration, int taintedCount, float maxChange);
    void logSeparator();
    void clear();
}
