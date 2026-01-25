/*
 * TaintLogPanel - Logging window for Taint Analysis
 * Shows matrices, data flow edges, call traversal, and taint propagation details
 */
package decompfuncutils;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import docking.WindowPosition;
import ghidra.program.model.address.Address;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TaintLogPanel extends ComponentProviderAdapter {
    
    private JTextPane logPane;
    private StyledDocument doc;
    private JScrollPane scrollPane;
    private JPanel mainPanel;
    
    // Styles for different log types
    private Style styleHeader;
    private Style styleInfo;
    private Style styleMatrix;
    private Style styleEdge;
    private Style styleTaint;
    private Style styleCall;
    private Style styleSink;
    private Style styleWarning;
    private Style styleSuccess;
    
    private SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS");
    
    public TaintLogPanel(PluginTool tool, String owner) {
        super(tool, "Taint Analysis Log", owner);
        buildPanel();
        setTitle("Taint Analysis Log");
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setIcon(null);
    }
    
    private void buildPanel() {
        mainPanel = new JPanel(new BorderLayout());
        
        logPane = new JTextPane();
        logPane.setEditable(false);
        logPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logPane.setBackground(new Color(30, 30, 30));
        
        doc = logPane.getStyledDocument();
        setupStyles();
        
        scrollPane = new JScrollPane(logPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        
        // Toolbar with clear button
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clear());
        toolbar.add(clearBtn);
        
        JButton copyBtn = new JButton("Copy All");
        copyBtn.addActionListener(e -> {
            logPane.selectAll();
            logPane.copy();
            logPane.setCaretPosition(doc.getLength());
        });
        toolbar.add(copyBtn);
        
        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
    }
    
    private void setupStyles() {
        Style defaultStyle = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
        
        styleHeader = doc.addStyle("header", defaultStyle);
        StyleConstants.setForeground(styleHeader, new Color(100, 200, 255));
        StyleConstants.setBold(styleHeader, true);
        StyleConstants.setFontSize(styleHeader, 14);
        
        styleInfo = doc.addStyle("info", defaultStyle);
        StyleConstants.setForeground(styleInfo, new Color(200, 200, 200));
        
        styleMatrix = doc.addStyle("matrix", defaultStyle);
        StyleConstants.setForeground(styleMatrix, new Color(150, 150, 255));
        StyleConstants.setFontFamily(styleMatrix, Font.MONOSPACED);
        
        styleEdge = doc.addStyle("edge", defaultStyle);
        StyleConstants.setForeground(styleEdge, new Color(180, 180, 100));
        
        styleTaint = doc.addStyle("taint", defaultStyle);
        StyleConstants.setForeground(styleTaint, new Color(255, 150, 100));
        
        styleCall = doc.addStyle("call", defaultStyle);
        StyleConstants.setForeground(styleCall, new Color(100, 255, 200));
        StyleConstants.setBold(styleCall, true);
        
        styleSink = doc.addStyle("sink", defaultStyle);
        StyleConstants.setForeground(styleSink, new Color(255, 100, 100));
        StyleConstants.setBold(styleSink, true);
        
        styleWarning = doc.addStyle("warning", defaultStyle);
        StyleConstants.setForeground(styleWarning, new Color(255, 200, 100));
        
        styleSuccess = doc.addStyle("success", defaultStyle);
        StyleConstants.setForeground(styleSuccess, new Color(100, 255, 100));
        StyleConstants.setBold(styleSuccess, true);
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
    
    public void clear() {
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException e) {
            // ignore
        }
    }
    
    private void append(String text, Style style) {
        SwingUtilities.invokeLater(() -> {
            try {
                doc.insertString(doc.getLength(), text, style);
                logPane.setCaretPosition(doc.getLength());
            } catch (BadLocationException e) {
                // ignore
            }
        });
    }
    
    private String timestamp() {
        return "[" + timeFormat.format(new Date()) + "] ";
    }
    
    // ============ Public logging methods ============
    
    public void logHeader(String text) {
        append("\n" + timestamp() + "═══ " + text + " ═══\n", styleHeader);
    }
    
    public void logInfo(String text) {
        append(timestamp() + text + "\n", styleInfo);
    }
    
    public void logMatrix(String text) {
        append(text + "\n", styleMatrix);
    }
    
    public void logEdge(String from, String to, float weight) {
        append(String.format("  %s ──(%.2f)──> %s\n", from, weight, to), styleEdge);
    }
    
    public void logTaint(String varName, float taintLevel, int depth) {
        String indent = "  ".repeat(depth);
        String bar = "█".repeat(Math.max(1, (int)(taintLevel * 20)));
        append(String.format("%s%s: %.3f %s\n", indent, varName, taintLevel, bar), styleTaint);
    }
    
    public void logCallEnter(String funcName, Address addr, int depth) {
        String indent = "  ".repeat(depth);
        append(String.format("%s┌─► CALL %s @ %s\n", indent, funcName, addr), styleCall);
    }
    
    public void logCallExit(String funcName, int depth) {
        String indent = "  ".repeat(depth);
        append(String.format("%s└── EXIT %s\n", indent, funcName), styleCall);
    }
    
    public void logSinkReached(String sinkName, String funcName, float taintLevel) {
        append(String.format("  ⚠ SINK REACHED: %s in %s (taint=%.3f)\n", sinkName, funcName, taintLevel), styleSink);
    }
    
    public void logWarning(String text) {
        append(timestamp() + "⚠ " + text + "\n", styleWarning);
    }
    
    public void logSuccess(String text) {
        append(timestamp() + "✓ " + text + "\n", styleSuccess);
    }
    
    public void logMatrixStats(int nodes, int edges, int sources, int sinks) {
        append(String.format("  Nodes: %d | Edges: %d | Sources: %d | Sinks: %d\n", 
            nodes, edges, sources, sinks), styleMatrix);
    }
    
    public void logSparseMatrix(int[] rowPtr, int[] colInd, float[] values, 
                                java.util.Map<Integer, String> nodeNames, int maxDisplay) {
        append("  CSR Matrix (showing up to " + maxDisplay + " edges):\n", styleMatrix);
        append("  rowPtr: [", styleMatrix);
        for (int i = 0; i < Math.min(rowPtr.length, 10); i++) {
            append(rowPtr[i] + (i < Math.min(rowPtr.length, 10) - 1 ? ", " : ""), styleMatrix);
        }
        if (rowPtr.length > 10) append("...", styleMatrix);
        append("]\n", styleMatrix);
        
        int displayed = 0;
        for (int row = 0; row < rowPtr.length - 1 && displayed < maxDisplay; row++) {
            int start = rowPtr[row];
            int end = rowPtr[row + 1];
            String rowName = nodeNames.getOrDefault(row, "node_" + row);
            for (int j = start; j < end && displayed < maxDisplay; j++) {
                int col = colInd[j];
                String colName = nodeNames.getOrDefault(col, "node_" + col);
                append(String.format("    [%d]%s <- [%d]%s : %.2f\n", 
                    row, rowName, col, colName, values[j]), styleMatrix);
                displayed++;
            }
        }
        if (colInd.length > maxDisplay) {
            append("    ... (" + (colInd.length - maxDisplay) + " more edges)\n", styleMatrix);
        }
    }
    
    public void logPropagationStep(int iteration, int taintedCount, float maxChange) {
        append(String.format("  Iteration %d: %d tainted, max_change=%.4f\n", 
            iteration, taintedCount, maxChange), styleTaint);
    }
    
    public void logSeparator() {
        append("─".repeat(60) + "\n", styleInfo);
    }
}
