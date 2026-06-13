package decompfuncutils.mcp;

import decompfuncutils.TaintLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;

/**
 * Headless {@link TaintLog} that collects log output into a StringBuilder instead
 * of rendering to a Swing panel. Used by the MCP taint tools and headless tests.
 *
 * Implements TaintLog directly (rather than extending the Swing TaintLogPanel) so
 * it can be constructed without a PluginTool / display — the constructor's tool
 * argument is accepted for call-site compatibility but unused.
 */
public class StringTaintLog implements TaintLog {

    private final StringBuilder log = new StringBuilder();

    public StringTaintLog(PluginTool tool) {
        // tool is intentionally unused; kept for source compatibility with callers.
    }

    @Override
    public void logHeader(String text) {
        log.append("=== ").append(text).append(" ===\n");
    }

    @Override
    public void logInfo(String text) {
        log.append("[INFO] ").append(text).append("\n");
    }

    @Override
    public void logMatrix(String text) {
        log.append("[MATRIX] ").append(text).append("\n");
    }

    @Override
    public void logEdge(String from, String to, float weight) {
        log.append("[EDGE] ").append(from).append(" -> ").append(to)
           .append(" (weight=").append(String.format("%.2f", weight)).append(")\n");
    }

    @Override
    public void logTaint(String varName, float taintLevel, int depth) {
        log.append("[TAINT] ").append(varName)
           .append(" level=").append(String.format("%.3f", taintLevel))
           .append(" depth=").append(depth).append("\n");
    }

    @Override
    public void logCallEnter(String funcName, Address addr, int depth) {
        log.append("[CALL+] ").append("  ".repeat(depth))
           .append(funcName).append(" @ ").append(addr).append("\n");
    }

    @Override
    public void logCallExit(String funcName, int depth) {
        log.append("[CALL-] ").append("  ".repeat(depth))
           .append(funcName).append("\n");
    }

    @Override
    public void logSinkReached(String sinkName, String funcName, float taintLevel) {
        log.append("[SINK!] ").append(sinkName).append(" in ").append(funcName)
           .append(" (taint=").append(String.format("%.3f", taintLevel)).append(")\n");
    }

    @Override
    public void logWarning(String text) {
        log.append("[WARN] ").append(text).append("\n");
    }

    @Override
    public void logSuccess(String text) {
        log.append("[OK] ").append(text).append("\n");
    }

    @Override
    public void logMatrixStats(int nodes, int edges, int sources, int sinks) {
        log.append("[STATS] nodes=").append(nodes).append(" edges=").append(edges)
           .append(" sources=").append(sources).append(" sinks=").append(sinks).append("\n");
    }

    @Override
    public void logSparseMatrix(int[] rowPtr, int[] colInd, float[] values,
                                 java.util.Map<Integer, String> nodeNames, int maxDisplay) {
        log.append("[MATRIX] CSR: ").append(rowPtr.length - 1).append(" rows, ")
           .append(colInd.length).append(" non-zeros\n");
    }

    @Override
    public void logPropagationStep(int iteration, int taintedCount, float maxChange) {
        log.append("[PROP] iter=").append(iteration)
           .append(" tainted=").append(taintedCount)
           .append(" maxChange=").append(String.format("%.4f", maxChange)).append("\n");
    }

    @Override
    public void logSeparator() {
        log.append("---\n");
    }

    /** Get the collected log output. */
    public String getOutput() {
        return log.toString();
    }

    /** Clear the collected log. */
    public void clear() {
        log.setLength(0);
    }
}
