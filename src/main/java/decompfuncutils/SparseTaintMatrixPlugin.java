/*
 * SparseTaintMatrixPlugin - Inter-procedural Taint Analysis for Ghidra
 * 
 * Features:
 * - Sparse matrix representation for efficient taint propagation
 * - Inter-procedural analysis (follows calls N levels deep)
 * - Detailed logging panel showing matrices, edges, and propagation
 * - Visual highlighting in decompiler
 */
package decompfuncutils;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.program.model.pcode.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.KeyBindingData;
import docking.ActionContext;
import docking.WindowPosition;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskLauncher;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.*;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Sparse Matrix Taint Analysis",
    description = "Inter-procedural taint analysis using sparse matrices with detailed logging."
)
public class SparseTaintMatrixPlugin extends ProgramPlugin {
    
    // Highlighting colors
    private static final Color COLOR_TAINT_HIGH = new Color(255, 80, 80);
    private static final Color COLOR_TAINT_MEDIUM = new Color(255, 160, 80);
    private static final Color COLOR_TAINT_LOW = new Color(255, 220, 100);
    private static final Color COLOR_SOURCE = new Color(80, 255, 120);
    private static final Color COLOR_SINK = new Color(255, 80, 255);
    private static final Color COLOR_CALL_TAINTED = new Color(100, 200, 255);
    
    // Thresholds
    private static final float THRESHOLD_HIGH = 0.7f;
    private static final float THRESHOLD_MEDIUM = 0.3f;
    private static final float THRESHOLD_LOW = 0.1f;
    
    // Settings
    private int maxIterations = 30;
    private int maxCallDepth = 3;
    
    // Components
    private TaintLogPanel logPanel;
    private TaintQueryPanel queryPanel;
    private TaintMatrixConverter converter;
    private GpuTaintEngine engine;
    private InterproceduralTaintAnalyzer currentAnalyzer;
    
    // Current analysis state
    private TaintMatrixConverter.CsrData currentData;
    private float[] currentTaintVector;
    
    public SparseTaintMatrixPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "=== SparseTaintMatrixPlugin initializing ===");
        
        converter = new TaintMatrixConverter();
        engine = new GpuTaintEngine();
        
        // Create log panel
        logPanel = new TaintLogPanel(tool, getName());
        tool.addComponentProvider(logPanel, false);
        
        // Create query panel
        queryPanel = new TaintQueryPanel(tool, getName(), logPanel);
        tool.addComponentProvider(queryPanel, false);
        
        createActions();
        
        Msg.info(this, "=== SparseTaintMatrixPlugin ready ===");
        Msg.info(this, "Right-click on variable in Decompiler → Taint Analysis menu");
    }
    
    private void createActions() {
        // Show Log Panel
        DockingAction showLogAction = new DockingAction("Show Taint Log", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                tool.showComponentProvider(logPanel, true);
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return true;
            }
        };
        showLogAction.setMenuBarData(new MenuData(new String[] { "Window", "Taint Analysis Log" }));
        tool.addAction(showLogAction);
        
        // Show Query Panel
        DockingAction showQueryAction = new DockingAction("Show Taint Query Editor", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                tool.showComponentProvider(queryPanel, true);
                // Update context if in decompiler
                if (context instanceof DecompilerActionContext dac) {
                    updateQueryContext(dac);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return true;
            }
        };
        showQueryAction.setMenuBarData(new MenuData(new String[] { "Window", "Taint Query Editor" }));
        tool.addAction(showQueryAction);
        
        // Run Query (from context menu)
        DockingAction runQueryAction = new DockingAction("Run Taint Query", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(queryPanel, true);
                    tool.showComponentProvider(logPanel, true);
                    updateQueryContext(dac);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        runQueryAction.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Open Query Editor" }, null, "TaintAnalysis"));
        tool.addAction(runQueryAction);
        
        // Forward Taint (Inter-procedural)
        DockingAction forwardTaintAction = new DockingAction("Forward Taint (Inter-procedural)", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(logPanel, true);
                    runInterproceduralTaint(dac, true);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return isValidTaintContext(context);
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        forwardTaintAction.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Forward Taint (follows calls)" }, null, "TaintAnalysis"));
        forwardTaintAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 
            KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK));
        tool.addAction(forwardTaintAction);
        
        // Backward Taint (Inter-procedural)
        DockingAction backwardTaintAction = new DockingAction("Backward Taint (Inter-procedural)", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(logPanel, true);
                    runInterproceduralTaint(dac, false);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return isValidTaintContext(context);
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        backwardTaintAction.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Backward Taint (follows calls)" }, null, "TaintAnalysis"));
        tool.addAction(backwardTaintAction);
        
        // Single Function Forward Taint (faster, no call following)
        DockingAction singleFuncForward = new DockingAction("Forward Taint (single function)", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(logPanel, true);
                    runSingleFunctionTaint(dac, true);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return isValidTaintContext(context);
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        singleFuncForward.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Forward Taint (this function only)" }, null, "TaintAnalysis"));
        tool.addAction(singleFuncForward);
        
        // Single Function Backward Taint
        DockingAction singleFuncBackward = new DockingAction("Backward Taint (single function)", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(logPanel, true);
                    runSingleFunctionTaint(dac, false);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return isValidTaintContext(context);
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        singleFuncBackward.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Backward Taint (this function only)" }, null, "TaintAnalysis"));
        tool.addAction(singleFuncBackward);
        
        // Show Sources & Sinks
        DockingAction showSourcesSinks = new DockingAction("Show Sources/Sinks", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    tool.showComponentProvider(logPanel, true);
                    showSourcesAndSinks(dac);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        showSourcesSinks.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Highlight Sources & Sinks" }, null, "TaintAnalysis"));
        tool.addAction(showSourcesSinks);
        
        // Clear Highlights
        DockingAction clearAction = new DockingAction("Clear Taint Highlights", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    clearHighlights(dac);
                }
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };
        clearAction.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Clear Highlights" }, null, "TaintAnalysis"));
        clearAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_ESCAPE, 0));
        tool.addAction(clearAction);
        
        // Settings
        DockingAction settingsAction = new DockingAction("Taint Analysis Settings", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showSettingsDialog();
            }
            @Override
            public boolean isValidContext(ActionContext context) {
                return true;
            }
        };
        settingsAction.setPopupMenuData(new MenuData(
            new String[] { "Taint Analysis", "Settings..." }, null, "TaintAnalysis"));
        tool.addAction(settingsAction);
    }
    
    private boolean isValidTaintContext(ActionContext context) {
        if (!(context instanceof DecompilerActionContext dac)) return false;
        ClangToken token = dac.getTokenAtCursor();
        return token instanceof ClangVariableToken;
    }
    
    // ===================== Inter-procedural Analysis =====================
    
    private void runInterproceduralTaint(DecompilerActionContext dac, boolean forward) {
        ClangToken token = dac.getTokenAtCursor();
        if (!(token instanceof ClangVariableToken varToken)) {
            tool.setStatusInfo("Please select a variable");
            return;
        }
        
        Varnode startVarnode = varToken.getVarnode();
        if (startVarnode == null) {
            tool.setStatusInfo("Could not resolve variable");
            return;
        }
        
        HighFunction highFunc = dac.getHighFunction();
        if (highFunc == null) {
            tool.setStatusInfo("No decompiled function");
            return;
        }
        
        Program program = dac.getProgram();
        
        TaskLauncher.launch(new Task("Inter-procedural Taint Analysis", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                logPanel.clear();
                
                // Create analyzer
                if (currentAnalyzer != null) {
                    currentAnalyzer.dispose();
                }
                currentAnalyzer = new InterproceduralTaintAnalyzer(program, logPanel);
                currentAnalyzer.setMaxDepth(maxCallDepth);
                currentAnalyzer.setMaxIterations(maxIterations);
                
                // Run analysis
                currentAnalyzer.analyze(highFunc, startVarnode, forward, monitor);
                
                // Update UI
                SwingUtilities.invokeLater(() -> {
                    // Highlight current function
                    highlightCurrentFunction(dac, forward, startVarnode);
                    
                    // Show results
                    java.util.List<InterproceduralTaintAnalyzer.TaintPath> paths = 
                        currentAnalyzer.getFoundPaths();
                    
                    if (paths.isEmpty()) {
                        tool.setStatusInfo("Analysis complete - no dangerous sinks reached");
                    } else {
                        tool.setStatusInfo("Found " + paths.size() + " path(s) to dangerous sinks!");
                    }
                });
            }
        });
    }
    
    private void highlightCurrentFunction(DecompilerActionContext dac, boolean forward, Varnode startVarnode) {
        HighFunction highFunc = dac.getHighFunction();
        if (highFunc == null) return;
        
        TaintMatrixConverter.CsrData data = converter.convert(highFunc);
        if (!forward) {
            data = converter.buildTranspose(data);
        }
        
        Integer startId = data.varnodeToId.get(startVarnode);
        if (startId == null) return;
        
        float[] taintVector = new float[data.numNodes];
        taintVector[startId] = 1.0f;
        
        engine.runTaintPropagation(data.numNodes, data.numEdges,
            data.rowPtr, data.colInd, data.values, taintVector, maxIterations);
        
        currentData = data;
        currentTaintVector = taintVector;
        
        ClangTokenGroup root = dac.getCCodeModel();
        if (root != null) {
            highlightTaintedTokens(root, taintVector, data);
        }
        
        DecompilerPanel panel = dac.getDecompilerPanel();
        if (panel != null) panel.repaint();
    }
    
    // ===================== Single Function Analysis =====================
    
    private void runSingleFunctionTaint(DecompilerActionContext dac, boolean forward) {
        ClangToken token = dac.getTokenAtCursor();
        if (!(token instanceof ClangVariableToken varToken)) {
            tool.setStatusInfo("Please select a variable");
            return;
        }
        
        Varnode startVarnode = varToken.getVarnode();
        if (startVarnode == null) {
            tool.setStatusInfo("Could not resolve variable");
            return;
        }
        
        HighFunction highFunc = dac.getHighFunction();
        if (highFunc == null) {
            tool.setStatusInfo("No decompiled function");
            return;
        }
        
        logPanel.clear();
        Function func = highFunc.getFunction();
        
        logPanel.logHeader("SINGLE FUNCTION TAINT ANALYSIS");
        logPanel.logInfo("Function: " + func.getName() + " @ " + func.getEntryPoint());
        logPanel.logInfo("Direction: " + (forward ? "FORWARD" : "BACKWARD"));
        logPanel.logSeparator();
        
        // Build matrix
        logPanel.logInfo("Building data flow matrix...");
        TaintMatrixConverter.CsrData data = converter.convert(highFunc);
        
        Set<Integer> sources = converter.findSources(data);
        Set<Integer> sinks = converter.findSinks(data);
        logPanel.logMatrixStats(data.numNodes, data.numEdges, sources.size(), sinks.size());
        
        // Build node names
        Map<Integer, String> nodeNames = new HashMap<>();
        for (Map.Entry<Varnode, Integer> entry : data.varnodeToId.entrySet()) {
            nodeNames.put(entry.getValue(), getVarnodeName(entry.getKey(), highFunc));
        }
        
        // Log edges
        logPanel.logInfo("Data flow edges:");
        int edgeCount = 0;
        for (int row = 0; row < data.numNodes && edgeCount < 30; row++) {
            int start = data.rowPtr[row];
            int end = data.rowPtr[row + 1];
            String rowName = nodeNames.getOrDefault(row, "node_" + row);
            for (int j = start; j < end && edgeCount < 30; j++) {
                int col = data.colInd[j];
                String colName = nodeNames.getOrDefault(col, "node_" + col);
                logPanel.logEdge(colName, rowName, data.values[j]);
                edgeCount++;
            }
        }
        if (data.numEdges > 30) {
            logPanel.logInfo("  ... and " + (data.numEdges - 30) + " more edges");
        }
        
        // For backward, use transpose
        TaintMatrixConverter.CsrData workingData = forward ? data : converter.buildTranspose(data);
        
        // Find start node
        Integer startId = workingData.varnodeToId.get(startVarnode);
        if (startId == null) {
            logPanel.logWarning("Start variable not found in data flow graph");
            tool.setStatusInfo("Variable not in data flow graph");
            return;
        }
        
        String startName = nodeNames.getOrDefault(startId, "start");
        logPanel.logInfo("Start variable: " + startName + " (node " + startId + ")");
        logPanel.logSeparator();
        
        // Initialize taint
        float[] taintVector = new float[workingData.numNodes];
        taintVector[startId] = 1.0f;
        
        // Run propagation with logging
        logPanel.logInfo("Running taint propagation...");
        long startTime = System.currentTimeMillis();
        
        float[] tempVector = new float[workingData.numNodes];
        for (int iter = 0; iter < maxIterations; iter++) {
            float maxChange = 0.0f;
            
            // SpMV
            for (int row = 0; row < workingData.numNodes; row++) {
                float sum = 0.0f;
                int start = workingData.rowPtr[row];
                int end = workingData.rowPtr[row + 1];
                for (int j = start; j < end; j++) {
                    sum += workingData.values[j] * taintVector[workingData.colInd[j]];
                }
                tempVector[row] = Math.min(1.0f, sum);
            }
            
            // Merge
            for (int i = 0; i < workingData.numNodes; i++) {
                float newVal = Math.max(taintVector[i], tempVector[i]);
                float change = Math.abs(newVal - taintVector[i]);
                if (change > maxChange) maxChange = change;
                taintVector[i] = newVal;
            }
            
            int taintedCount = 0;
            for (float v : taintVector) if (v >= THRESHOLD_LOW) taintedCount++;
            
            logPanel.logPropagationStep(iter + 1, taintedCount, maxChange);
            
            if (maxChange < 0.0001f) {
                logPanel.logSuccess("Converged at iteration " + (iter + 1));
                break;
            }
        }
        
        long elapsed = System.currentTimeMillis() - startTime;
        logPanel.logSeparator();
        logPanel.logInfo("Propagation complete in " + elapsed + " ms");
        
        // Log tainted variables
        logPanel.logHeader("TAINTED VARIABLES");
        java.util.List<Map.Entry<Integer, Float>> tainted = new ArrayList<>();
        for (int i = 0; i < taintVector.length; i++) {
            if (taintVector[i] >= THRESHOLD_LOW) {
                tainted.add(Map.entry(i, taintVector[i]));
            }
        }
        tainted.sort((a, b) -> Float.compare(b.getValue(), a.getValue()));
        
        for (Map.Entry<Integer, Float> entry : tainted) {
            logPanel.logTaint(nodeNames.getOrDefault(entry.getKey(), "node_" + entry.getKey()), 
                             entry.getValue(), 0);
        }
        
        // Check sinks
        logPanel.logSeparator();
        logPanel.logHeader("SINK ANALYSIS");
        boolean sinkReached = false;
        for (int sinkId : sinks) {
            if (taintVector[sinkId] >= THRESHOLD_LOW) {
                TaintMatrixConverter.NodeInfo info = data.nodeInfo.get(sinkId);
                String sinkName = info != null ? info.name : "unknown";
                logPanel.logSinkReached(sinkName, func.getName(), taintVector[sinkId]);
                sinkReached = true;
            }
        }
        if (!sinkReached) {
            logPanel.logSuccess("No dangerous sinks reached by tainted data");
        }
        
        // Store results and highlight
        currentData = forward ? data : workingData;
        currentTaintVector = taintVector;
        
        ClangTokenGroup root = dac.getCCodeModel();
        if (root != null) {
            highlightTaintedTokens(root, taintVector, workingData);
        }
        
        DecompilerPanel panel = dac.getDecompilerPanel();
        if (panel != null) panel.repaint();
        
        tool.setStatusInfo(String.format("Taint analysis: %d variables tainted (%d ms)", 
            tainted.size(), elapsed));
    }
    
    // ===================== Sources & Sinks =====================
    
    private void showSourcesAndSinks(DecompilerActionContext dac) {
        HighFunction highFunc = dac.getHighFunction();
        if (highFunc == null) {
            tool.setStatusInfo("No decompiled function");
            return;
        }
        
        logPanel.clear();
        Function func = highFunc.getFunction();
        
        logPanel.logHeader("SOURCES & SINKS ANALYSIS");
        logPanel.logInfo("Function: " + func.getName());
        logPanel.logSeparator();
        
        TaintMatrixConverter.CsrData data = converter.convert(highFunc);
        Set<Integer> sources = converter.findSources(data);
        Set<Integer> sinks = converter.findSinks(data);
        
        logPanel.logHeader("TAINT SOURCES (" + sources.size() + ")");
        Set<Varnode> sourceVarnodes = new HashSet<>();
        for (int id : sources) {
            Varnode vn = data.idToVarnode.get(id);
            if (vn != null) {
                sourceVarnodes.add(vn);
                TaintMatrixConverter.NodeInfo info = data.nodeInfo.get(id);
                String name = info != null ? info.name : "unknown";
                logPanel.logInfo("  [SOURCE] " + name);
            }
        }
        
        logPanel.logSeparator();
        logPanel.logHeader("DANGEROUS SINKS (" + sinks.size() + ")");
        Set<Varnode> sinkVarnodes = new HashSet<>();
        for (int id : sinks) {
            Varnode vn = data.idToVarnode.get(id);
            if (vn != null) {
                sinkVarnodes.add(vn);
                TaintMatrixConverter.NodeInfo info = data.nodeInfo.get(id);
                String name = info != null ? info.name : "unknown";
                logPanel.logInfo("  [SINK] " + name);
            }
        }
        
        // Highlight
        ClangTokenGroup root = dac.getCCodeModel();
        if (root != null) {
            highlightSourcesSinks(root, sourceVarnodes, sinkVarnodes);
        }
        
        DecompilerPanel panel = dac.getDecompilerPanel();
        if (panel != null) panel.repaint();
        
        tool.setStatusInfo(String.format("Found %d sources, %d sinks", sources.size(), sinks.size()));
    }
    
    // ===================== Highlighting =====================
    
    private void highlightTaintedTokens(ClangNode node, float[] taintVector, 
                                        TaintMatrixConverter.CsrData data) {
        if (node instanceof ClangVariableToken varToken) {
            Varnode vn = varToken.getVarnode();
            if (vn != null) {
                Integer id = data.varnodeToId.get(vn);
                if (id != null && id < taintVector.length) {
                    float taint = taintVector[id];
                    if (taint >= THRESHOLD_HIGH) {
                        varToken.setHighlight(COLOR_TAINT_HIGH);
                    } else if (taint >= THRESHOLD_MEDIUM) {
                        varToken.setHighlight(COLOR_TAINT_MEDIUM);
                    } else if (taint >= THRESHOLD_LOW) {
                        varToken.setHighlight(COLOR_TAINT_LOW);
                    }
                }
            }
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                highlightTaintedTokens(group.Child(i), taintVector, data);
            }
        }
    }
    
    private void highlightSourcesSinks(ClangNode node, Set<Varnode> sources, Set<Varnode> sinks) {
        if (node instanceof ClangVariableToken varToken) {
            Varnode vn = varToken.getVarnode();
            if (vn != null) {
                if (sinks.contains(vn)) {
                    varToken.setHighlight(COLOR_SINK);
                } else if (sources.contains(vn)) {
                    varToken.setHighlight(COLOR_SOURCE);
                }
            }
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                highlightSourcesSinks(group.Child(i), sources, sinks);
            }
        }
    }
    
    private void clearHighlights(DecompilerActionContext dac) {
        ClangTokenGroup root = dac.getCCodeModel();
        if (root != null) {
            clearHighlightsRecursive(root);
        }
        DecompilerPanel panel = dac.getDecompilerPanel();
        if (panel != null) panel.repaint();
        
        currentData = null;
        currentTaintVector = null;
        
        tool.setStatusInfo("Highlights cleared");
    }
    
    private void clearHighlightsRecursive(ClangNode node) {
        if (node instanceof ClangToken token) {
            token.setHighlight(null);
        }
        if (node instanceof ClangTokenGroup group) {
            for (int i = 0; i < group.numChildren(); i++) {
                clearHighlightsRecursive(group.Child(i));
            }
        }
    }
    
    // ===================== Utilities =====================
    
    private String getVarnodeName(Varnode vn, HighFunction func) {
        if (vn == null) return "null";
        HighVariable hv = vn.getHigh();
        if (hv != null && hv.getName() != null) {
            return hv.getName();
        }
        if (vn.isRegister()) return "reg_" + vn.getOffset();
        if (vn.isConstant()) return "0x" + Long.toHexString(vn.getOffset());
        if (vn.isUnique()) return "tmp_" + Long.toHexString(vn.getOffset());
        return "var_" + vn.getOffset();
    }
    
    private void showSettingsDialog() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        
        JPanel iterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        iterPanel.add(new JLabel("Max iterations:"));
        JSpinner iterSpinner = new JSpinner(new SpinnerNumberModel(maxIterations, 1, 100, 5));
        iterPanel.add(iterSpinner);
        panel.add(iterPanel);
        
        JPanel depthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        depthPanel.add(new JLabel("Max call depth:"));
        JSpinner depthSpinner = new JSpinner(new SpinnerNumberModel(maxCallDepth, 1, 10, 1));
        depthPanel.add(depthSpinner);
        panel.add(depthPanel);
        
        panel.add(new JLabel(" "));
        panel.add(new JLabel("Engine: " + engine.getGpuStatus()));
        
        int result = JOptionPane.showConfirmDialog(tool.getToolFrame(), panel,
            "Taint Analysis Settings", JOptionPane.OK_CANCEL_OPTION);
        
        if (result == JOptionPane.OK_OPTION) {
            maxIterations = (Integer) iterSpinner.getValue();
            maxCallDepth = (Integer) depthSpinner.getValue();
            logPanel.logInfo("Settings updated: iterations=" + maxIterations + ", depth=" + maxCallDepth);
        }
    }
    
    @Override
    protected void dispose() {
        if (currentAnalyzer != null) {
            currentAnalyzer.dispose();
        }
        super.dispose();
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        if (queryPanel != null) {
            queryPanel.setProgram(program);
        }
    }
    
    private void updateQueryContext(DecompilerActionContext dac) {
        Program program = dac.getProgram();
        HighFunction highFunc = dac.getHighFunction();
        Function func = highFunc != null ? highFunc.getFunction() : null;
        queryPanel.setContext(program, func, highFunc);
    }
}
