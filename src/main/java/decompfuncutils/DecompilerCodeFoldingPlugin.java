/*
 * DecompilerCodeFoldingPlugin
 *
 * Adds scope folding (code collapsing) to Ghidra's Decompiler panel.
 * A sidebar margin with +/- markers lets users toggle the visibility of
 * brace-delimited scopes ({…}) such as if/else blocks, loops, and
 * function bodies.
 *
 * Licensed under the Apache License 2.0 (same as the parent project).
 */

package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;

import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Window;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Decompiler Code Folding",
    description = "Adds scope folding (+/- markers) to the Decompiler panel, "
                + "allowing users to collapse and expand brace-delimited scopes."
)
//@formatter:on
public class DecompilerCodeFoldingPlugin extends ProgramPlugin {

    private final Map<DecompilerPanel, FoldMarginPanel> installedMargins = new IdentityHashMap<>();
    private Timer panelDiscoveryTimer;
    private DockingAction toggleFoldAction;
    private DockingAction foldAllAction;
    private DockingAction unfoldAllAction;

    public DecompilerCodeFoldingPlugin(PluginTool tool) {
        super(tool);
        createActions();
        panelDiscoveryTimer = new Timer(1500, e -> discoverPanels());
        panelDiscoveryTimer.setRepeats(true);
        panelDiscoveryTimer.start();
    }

    // =======================================================================
    // Actions
    // =======================================================================

    private void createActions() {
        toggleFoldAction = new DockingAction("Toggle Fold at Cursor", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                if (ctx instanceof DecompilerActionContext dac) toggleFoldAtCursor(dac);
            }
            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
        };
        toggleFoldAction.setPopupMenuData(
                new MenuData(new String[] { "Toggle Fold" }, null, "Decompile"));
        toggleFoldAction.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK));
        toggleFoldAction.setDescription("Collapse or expand the scope at the cursor line");
        tool.addAction(toggleFoldAction);

        foldAllAction = new DockingAction("Fold All Scopes", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                if (ctx instanceof DecompilerActionContext dac) doSetAllFolds(dac, true);
            }
            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
        };
        foldAllAction.setPopupMenuData(
                new MenuData(new String[] { "Fold All Scopes" }, null, "Decompile"));
        foldAllAction.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_MINUS,
                        InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        tool.addAction(foldAllAction);

        unfoldAllAction = new DockingAction("Unfold All Scopes", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                if (ctx instanceof DecompilerActionContext dac) doSetAllFolds(dac, false);
            }
            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
            @Override
            public boolean isAddToPopup(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
        };
        unfoldAllAction.setPopupMenuData(
                new MenuData(new String[] { "Unfold All Scopes" }, null, "Decompile"));
        unfoldAllAction.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_EQUALS,
                        InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        tool.addAction(unfoldAllAction);
    }

    // =======================================================================
    // Panel discovery
    // =======================================================================

    private void discoverPanels() {
        if (tool == null) return;
        Set<DecompilerPanel> livePanels = new HashSet<>();
        for (Window w : Window.getWindows()) {
            if (w.isShowing()) findAllDecompilerPanels(w, livePanels);
        }
        for (DecompilerPanel panel : livePanels) {
            if (!installedMargins.containsKey(panel)) installMargin(panel);
        }
        Iterator<Map.Entry<DecompilerPanel, FoldMarginPanel>> it =
                installedMargins.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<DecompilerPanel, FoldMarginPanel> entry = it.next();
            if (!livePanels.contains(entry.getKey())) {
                entry.getValue().dispose();
                it.remove();
            }
        }
    }

    private void findAllDecompilerPanels(Component c, Set<DecompilerPanel> out) {
        if (c instanceof DecompilerPanel dp) { out.add(dp); return; }
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) findAllDecompilerPanels(child, out);
        }
    }

    // =======================================================================
    // Margin installation
    // =======================================================================

    private void installMargin(DecompilerPanel panel) {
        try {
            FoldMarginPanel margin = new FoldMarginPanel(panel);
            installedMargins.put(panel, margin);
            SwingUtilities.invokeLater(() -> injectMarginComponent(panel, margin));
        } catch (Exception ex) {
            Msg.error(this, "Failed to install fold margin", ex);
        }
    }

    /**
     * Inject the fold-margin panel so it scrolls in sync with the FieldPanel.
     *
     * Strategy (in order of preference):
     * 1. If the FieldPanel lives inside a JScrollPane, set the margin as
     *    the scroll pane's row header view.  Swing will then scroll the
     *    margin automatically — no manual yOffset painting needed.
     * 2. Fallback: add to DecompilerPanel WEST and rely on manual yOffset.
     */
    private void injectMarginComponent(DecompilerPanel panel, FoldMarginPanel margin) {
        try {
            FieldPanel fp = getFieldPanel(panel);
            if (fp != null) {
                margin.attachToFieldPanel(fp);
            }

            // --- Strategy 1: JScrollPane row header ---
            javax.swing.JScrollPane scrollPane = findScrollPaneFor(fp);
            if (scrollPane != null) {
                // If there's already a row header, wrap both together
                Component existingHeader = null;
                if (scrollPane.getRowHeader() != null) {
                    existingHeader = scrollPane.getRowHeader().getView();
                }
                if (existingHeader != null) {
                    JPanel wrapper = new JPanel();
                    wrapper.setLayout(new BoxLayout(wrapper, BoxLayout.X_AXIS));
                    wrapper.setOpaque(false);
                    wrapper.add(margin);
                    wrapper.add(existingHeader);
                    scrollPane.setRowHeaderView(wrapper);
                } else {
                    scrollPane.setRowHeaderView(margin);
                }
                scrollPane.revalidate();
                scrollPane.repaint();
                margin.setInsideScrollPane(true);
                Msg.info(this, "Fold margin installed as JScrollPane row header");
                return;
            }

            // --- Strategy 2: BorderLayout WEST fallback ---
            Msg.info(this, "No JScrollPane found — falling back to WEST injection");
            java.awt.LayoutManager lm = panel.getLayout();

            if (lm instanceof BorderLayout bl) {
                Component west = bl.getLayoutComponent(BorderLayout.WEST);

                if (west instanceof JComponent box) {
                    box.add(margin, 0);
                    box.revalidate();
                    box.repaint();
                    Msg.info(this, "Fold margin added to existing WEST box");
                } else {
                    JPanel wrapper = new JPanel();
                    wrapper.setLayout(new BoxLayout(wrapper, BoxLayout.X_AXIS));
                    wrapper.setOpaque(false);
                    wrapper.add(margin);
                    if (west != null) {
                        panel.remove(west);
                        wrapper.add(west);
                    }
                    panel.add(wrapper, BorderLayout.WEST);
                    panel.revalidate();
                    panel.repaint();
                    Msg.info(this, "Fold margin injected as new WEST wrapper");
                }
            } else {
                panel.add(margin, BorderLayout.WEST);
                panel.revalidate();
                panel.repaint();
                Msg.warn(this, "DecompilerPanel layout is not BorderLayout: " + lm);
            }
        } catch (Exception ex) {
            Msg.error(this, "Failed to inject fold margin component", ex);
        }
    }

    /**
     * Walk up from a component to find the enclosing JScrollPane.
     */
    private javax.swing.JScrollPane findScrollPaneFor(Component c) {
        if (c == null) return null;
        Component parent = c.getParent();
        while (parent != null) {
            if (parent instanceof javax.swing.JScrollPane sp) return sp;
            if (parent instanceof JViewport) {
                Component vpParent = parent.getParent();
                if (vpParent instanceof javax.swing.JScrollPane sp) return sp;
            }
            parent = parent.getParent();
        }
        return null;
    }

    // =======================================================================
    // Action handlers
    // =======================================================================

    private void toggleFoldAtCursor(DecompilerActionContext ctx) {
        DecompilerPanel panel = findDecompilerPanelFromContext(ctx);
        FoldMarginPanel margin = (panel != null) ? installedMargins.get(panel) : null;
        if (margin == null) return;

        // DecompilerActionContext.getLineNumber() is typically 1-based.
        // Our internal visible line indices are 0-based.
        int lineFromCtx = ctx.getLineNumber();
        Msg.info(this, "Toggle fold: ctx.getLineNumber() = " + lineFromCtx);
        margin.toggleFoldAtVisibleLine(lineFromCtx);
    }

    private void doSetAllFolds(DecompilerActionContext ctx, boolean collapsed) {
        DecompilerPanel panel = findDecompilerPanelFromContext(ctx);
        FoldMarginPanel margin = (panel != null) ? installedMargins.get(panel) : null;
        if (margin == null) return;
        margin.setAllFolds(collapsed);
    }

    private DecompilerPanel findDecompilerPanelFromContext(DecompilerActionContext ctx) {
        try {
            Component source = ctx.getSourceComponent();
            if (source != null) {
                Component c = source;
                while (c != null) {
                    if (c instanceof DecompilerPanel dp) return dp;
                    c = c.getParent();
                }
            }
        } catch (Exception ignored) {}
        if (!installedMargins.isEmpty()) {
            return installedMargins.keySet().iterator().next();
        }
        return null;
    }

    // =======================================================================
    // Reflection helpers
    // =======================================================================

    private FieldPanel getFieldPanel(DecompilerPanel panel) {
        try {
            Method m = DecompilerPanel.class.getMethod("getFieldPanel");
            return (FieldPanel) m.invoke(panel);
        } catch (Exception ignored) {}
        for (String fieldName : new String[] { "fieldPanel", "codeViewer" }) {
            try {
                java.lang.reflect.Field f = DecompilerPanel.class.getDeclaredField(fieldName);
                f.setAccessible(true);
                Object val = f.get(panel);
                if (val instanceof FieldPanel fp) return fp;
            } catch (Exception ignored) {}
        }
        Msg.warn(this, "Could not access FieldPanel from DecompilerPanel");
        return null;
    }

    private static boolean setFieldPanelModel(FieldPanel fp, LayoutModel model) {
        try {
            Method m = FieldPanel.class.getMethod("setLayoutModel", LayoutModel.class);
            m.invoke(fp, model);
            Msg.info(DecompilerCodeFoldingPlugin.class, "Model swapped via setLayoutModel()");
            return true;
        } catch (Exception ignored) {}

        for (String fieldName : new String[] { "model", "layoutModel" }) {
            try {
                java.lang.reflect.Field f = FieldPanel.class.getDeclaredField(fieldName);
                f.setAccessible(true);
                f.set(fp, model);
                try {
                    Method reset = FieldPanel.class.getDeclaredMethod("modelChanged");
                    reset.setAccessible(true);
                    reset.invoke(fp);
                } catch (Exception ignored2) {}
                fp.invalidate();
                fp.revalidate();
                fp.repaint();
                Msg.info(DecompilerCodeFoldingPlugin.class,
                        "Model swapped via reflection field: " + fieldName);
                return true;
            } catch (Exception ignored) {}
        }
        Msg.warn(DecompilerCodeFoldingPlugin.class,
                "Could not set LayoutModel on FieldPanel — folding will be visual-only");
        return false;
    }

    // =======================================================================
    // Dispose
    // =======================================================================

    @Override
    protected void dispose() {
        if (panelDiscoveryTimer != null) {
            panelDiscoveryTimer.stop();
            panelDiscoveryTimer = null;
        }
        for (FoldMarginPanel m : installedMargins.values()) m.dispose();
        installedMargins.clear();
        if (toggleFoldAction != null) tool.removeAction(toggleFoldAction);
        if (foldAllAction != null) tool.removeAction(foldAllAction);
        if (unfoldAllAction != null) tool.removeAction(unfoldAllAction);
        super.dispose();
    }

    // =======================================================================
    // FoldRegion
    // =======================================================================

    static class FoldRegion {
        final int startLine;   // 0-based: line with '{'
        int endLine;           // 0-based: line with '}'
        final int depth;
        boolean collapsed = false;
        final List<FoldRegion> children = new ArrayList<>();

        FoldRegion(int startLine, int depth) {
            this.startLine = startLine;
            this.endLine = startLine;
            this.depth = depth;
        }

        @Override
        public String toString() {
            return "Fold[" + startLine + ".." + endLine + " d=" + depth
                    + (collapsed ? " COLLAPSED" : "") + "]";
        }
    }

    // =======================================================================
    // FilteringLayoutModel
    // =======================================================================

    static class FilteringLayoutModel implements LayoutModel {

        private final LayoutModel delegate;
        private final List<LayoutModelListener> listeners = new ArrayList<>();
        private BigInteger[] visibleToReal = new BigInteger[0];
        private Set<BigInteger> hiddenRealLines = Collections.emptySet();

        FilteringLayoutModel(LayoutModel delegate) {
            this.delegate = delegate;
            rebuildFromDelegate();
        }

        LayoutModel getDelegate() { return delegate; }

        void setHiddenLines(Set<Integer> hiddenOrigLines) {
            hiddenRealLines = new HashSet<>();
            for (int line : hiddenOrigLines) {
                hiddenRealLines.add(BigInteger.valueOf(line));
            }
            rebuildFromDelegate();
            notifyModelSizeChanged();
        }

        void clearHidden() {
            hiddenRealLines = Collections.emptySet();
            rebuildFromDelegate();
            notifyModelSizeChanged();
        }

        private void rebuildFromDelegate() {
            BigInteger realCount = delegate.getNumIndexes();
            List<BigInteger> visible = new ArrayList<>();
            BigInteger idx = BigInteger.ZERO;
            while (idx.compareTo(realCount) < 0) {
                if (!hiddenRealLines.contains(idx)) visible.add(idx);
                idx = idx.add(BigInteger.ONE);
            }
            visibleToReal = visible.toArray(new BigInteger[0]);
        }

        private BigInteger toReal(BigInteger visibleIndex) {
            int vi = visibleIndex.intValueExact();
            if (vi >= 0 && vi < visibleToReal.length) return visibleToReal[vi];
            return visibleIndex;
        }

        @Override public BigInteger getNumIndexes() {
            return BigInteger.valueOf(visibleToReal.length);
        }
        @Override public Layout getLayout(BigInteger index) {
            return delegate.getLayout(toReal(index));
        }
        @Override public boolean isUniform() { return delegate.isUniform(); }
        @Override public Dimension getPreferredViewSize() { return delegate.getPreferredViewSize(); }
        @Override public BigInteger getIndexAfter(BigInteger index) {
            BigInteger next = index.add(BigInteger.ONE);
            return next.compareTo(getNumIndexes()) >= 0 ? null : next;
        }
        @Override public BigInteger getIndexBefore(BigInteger index) {
            return index.compareTo(BigInteger.ONE) < 0 ? null : index.subtract(BigInteger.ONE);
        }
        @Override public void addLayoutModelListener(LayoutModelListener l) { listeners.add(l); }
        @Override public void removeLayoutModelListener(LayoutModelListener l) { listeners.remove(l); }
        @Override public void flushChanges() { delegate.flushChanges(); }

        private void notifyModelSizeChanged() {
            IndexMapper identity = value -> value;
            for (LayoutModelListener l : new ArrayList<>(listeners)) {
                l.modelSizeChanged(identity);
            }
        }
    }

    // =======================================================================
    // FoldMarginPanel
    // =======================================================================

    class FoldMarginPanel extends JPanel implements MouseListener {

        private static final int MARGIN_WIDTH = 18;
        private static final int ICON_SIZE = 9;

        private final DecompilerPanel decompPanel;
        private FieldPanel fieldPanel;
        private boolean insideScrollPane = false;

        private List<FoldRegion> regions = Collections.emptyList();
        private Map<Integer, FoldRegion> regionByStartLine = Collections.emptyMap();
        private List<FoldRegion> allRegionsFlat = Collections.emptyList();
        private int totalLines = 0;

        private FilteringLayoutModel filteringModel;
        private LayoutModel originalModel;
        private boolean modelSwapped = false;

        private int[] visibleToOriginal = new int[0];
        private int[] originalToVisible = new int[0];

        private LayoutModelListener originalModelListener;
        private boolean applyingFoldState = false;
        private BigInteger lastKnownDelegateSize = BigInteger.ZERO;

        FoldMarginPanel(DecompilerPanel decompPanel) {
            this.decompPanel = decompPanel;
            setPreferredSize(new Dimension(MARGIN_WIDTH, Short.MAX_VALUE));
            setMinimumSize(new Dimension(MARGIN_WIDTH, 0));
            setMaximumSize(new Dimension(MARGIN_WIDTH, Short.MAX_VALUE));
            setOpaque(true);
            addMouseListener(this);
            setToolTipText("");
        }

        void setInsideScrollPane(boolean inside) {
            this.insideScrollPane = inside;
        }

        void attachToFieldPanel(FieldPanel fp) {
            this.fieldPanel = fp;
            this.originalModel = fp.getLayoutModel();
            this.lastKnownDelegateSize = originalModel.getNumIndexes();

            filteringModel = new FilteringLayoutModel(originalModel);
            modelSwapped = setFieldPanelModel(fp, filteringModel);

            if (!modelSwapped) {
                Msg.warn(this, "Could not swap FieldPanel model — "
                        + "fold markers will show but lines won't hide.");
            }

            // Listen to original model for genuine decompilation changes
            originalModelListener = new LayoutModelListener() {
                @Override
                public void modelSizeChanged(IndexMapper indexMapper) {
                    if (applyingFoldState) return;
                    BigInteger currentSize = originalModel.getNumIndexes();
                    if (!currentSize.equals(lastKnownDelegateSize)) {
                        lastKnownDelegateSize = currentSize;
                        SwingUtilities.invokeLater(() -> onNewDecompilation());
                    }
                }
                @Override
                public void dataChanged(BigInteger start, BigInteger end) {
                    if (applyingFoldState) return;
                    BigInteger currentSize = originalModel.getNumIndexes();
                    if (!currentSize.equals(lastKnownDelegateSize)) {
                        lastKnownDelegateSize = currentSize;
                        SwingUtilities.invokeLater(() -> onNewDecompilation());
                    }
                }
            };
            originalModel.addLayoutModelListener(originalModelListener);

            // Track scroll for margin repaint (only needed for WEST fallback)
            Container parent = fp.getParent();
            if (parent instanceof JViewport vp) {
                vp.addChangeListener(e -> repaint());
            }

            // Track resize
            fp.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) { repaint(); }
            });

            onNewDecompilation();
        }

        void dispose() {
            if (originalModel != null && originalModelListener != null) {
                originalModel.removeLayoutModelListener(originalModelListener);
            }
            if (modelSwapped && fieldPanel != null && originalModel != null) {
                setFieldPanelModel(fieldPanel, originalModel);
            }
            removeMouseListener(this);
        }

        // -------------------------------------------------------------------
        // New decompilation
        // -------------------------------------------------------------------

        private void onNewDecompilation() {
            List<String> lines = getDecompiledLines(originalModel);
            totalLines = lines.size();
            regions = parseFoldRegions(lines);
            regionByStartLine = new HashMap<>();
            allRegionsFlat = new ArrayList<>();
            for (FoldRegion r : regions) {
                addAllToMap(r, regionByStartLine);
                collectAllFlat(r, allRegionsFlat);
            }
            Msg.info(this, "Parsed " + allRegionsFlat.size() + " fold regions from "
                    + totalLines + " lines");
            for (FoldRegion r : allRegionsFlat) {
                Msg.info(this, "  " + r);
            }
            applyFoldState();
        }

        // -------------------------------------------------------------------
        // Apply fold state
        // -------------------------------------------------------------------

        private void applyFoldState() {
            applyingFoldState = true;
            try {
                Set<Integer> hiddenLines = new HashSet<>();
                collectHiddenLines(regions, hiddenLines);

                List<Integer> vis = new ArrayList<>(totalLines);
                originalToVisible = new int[totalLines];
                Arrays.fill(originalToVisible, -1);
                for (int i = 0; i < totalLines; i++) {
                    if (!hiddenLines.contains(i)) {
                        originalToVisible[i] = vis.size();
                        vis.add(i);
                    }
                }
                visibleToOriginal = vis.stream().mapToInt(Integer::intValue).toArray();

                Msg.info(this, "Fold state: " + hiddenLines.size() + " hidden lines, "
                        + visibleToOriginal.length + " visible lines");

                if (filteringModel != null) {
                    filteringModel.setHiddenLines(hiddenLines);
                }
            } finally {
                applyingFoldState = false;
            }

            repaint();
            if (fieldPanel != null) {
                fieldPanel.invalidate();
                fieldPanel.revalidate();
                fieldPanel.repaint();
            }
            if (decompPanel != null) {
                decompPanel.revalidate();
                decompPanel.repaint();
            }
        }

        // -------------------------------------------------------------------
        // Parsing
        // -------------------------------------------------------------------

        private void addAllToMap(FoldRegion r, Map<Integer, FoldRegion> map) {
            map.put(r.startLine, r);
            for (FoldRegion c : r.children) addAllToMap(c, map);
        }

        private void collectAllFlat(FoldRegion r, List<FoldRegion> out) {
            out.add(r);
            for (FoldRegion c : r.children) collectAllFlat(c, out);
        }

        private List<String> getDecompiledLines(LayoutModel model) {
            if (model == null) return Collections.emptyList();
            List<String> lines = new ArrayList<>();
            BigInteger numIndexes = model.getNumIndexes();
            BigInteger idx = BigInteger.ZERO;
            while (idx.compareTo(numIndexes) < 0) {
                Layout layout = model.getLayout(idx);
                if (layout != null) {
                    StringBuilder sb = new StringBuilder();
                    for (int fi = 0; fi < layout.getNumFields(); fi++) {
                        Field f = layout.getField(fi);
                        if (f != null) sb.append(f.getText());
                    }
                    lines.add(sb.toString());
                } else {
                    lines.add("");
                }
                idx = idx.add(BigInteger.ONE);
            }
            return lines;
        }

        private List<FoldRegion> parseFoldRegions(List<String> lines) {
            List<FoldRegion> topLevel = new ArrayList<>();
            Deque<FoldRegion> stack = new ArrayDeque<>();
            for (int i = 0; i < lines.size(); i++) {
                String cleaned = stripStringLiteralsAndComments(lines.get(i));
                for (char ch : cleaned.toCharArray()) {
                    if (ch == '{') {
                        FoldRegion r = new FoldRegion(i, stack.size());
                        if (stack.isEmpty()) topLevel.add(r);
                        else stack.peek().children.add(r);
                        stack.push(r);
                    } else if (ch == '}') {
                        if (!stack.isEmpty()) {
                            FoldRegion r = stack.pop();
                            r.endLine = i;
                        }
                    }
                }
            }
            removeEmptyRegions(topLevel);
            return topLevel;
        }

        private void removeEmptyRegions(List<FoldRegion> list) {
            Iterator<FoldRegion> it = list.iterator();
            while (it.hasNext()) {
                FoldRegion r = it.next();
                removeEmptyRegions(r.children);
                if (r.endLine <= r.startLine) it.remove();
            }
        }

        private String stripStringLiteralsAndComments(String line) {
            StringBuilder sb = new StringBuilder(line.length());
            boolean inStr = false, inChar = false;
            char prev = 0;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (!inStr && !inChar && c == '/' && i + 1 < line.length()
                        && line.charAt(i + 1) == '/') break;
                if (!inChar && c == '"' && prev != '\\') { inStr = !inStr; prev = c; continue; }
                if (!inStr && c == '\'' && prev != '\\') { inChar = !inChar; prev = c; continue; }
                if (!inStr && !inChar) sb.append(c);
                prev = c;
            }
            return sb.toString();
        }

        // -------------------------------------------------------------------
        // Fold / unfold
        // -------------------------------------------------------------------

        void toggleFoldAtVisibleLine(int lineParam) {
            FoldRegion found = tryFindRegionAtVisible(lineParam);
            if (found == null) {
                found = tryFindRegionAtVisible(lineParam - 1);
            }
            if (found == null && lineParam + 1 < visibleToOriginal.length) {
                found = tryFindRegionAtVisible(lineParam + 1);
            }

            if (found != null) {
                Msg.info(this, "Toggling " + found + " → " + (found.collapsed ? "EXPAND" : "COLLAPSE"));
                found.collapsed = !found.collapsed;
                applyFoldState();
            } else {
                Msg.info(this, "No fold region found for visible line " + lineParam);
            }
        }

        private FoldRegion tryFindRegionAtVisible(int visibleLine) {
            if (visibleLine < 0 || visibleLine >= visibleToOriginal.length) return null;
            int origLine = visibleToOriginal[visibleLine];

            FoldRegion exact = regionByStartLine.get(origLine);
            if (exact != null) return exact;

            FoldRegion best = null;
            for (FoldRegion r : allRegionsFlat) {
                if (r.depth == 0) continue;
                if (origLine > r.startLine && origLine <= r.endLine) {
                    if (best == null || r.depth > best.depth) {
                        best = r;
                    }
                }
            }
            return best;
        }

        void setAllFolds(boolean collapsed) {
            setAllFoldsRecursive(regions, collapsed);
            applyFoldState();
        }

        private void setAllFoldsRecursive(List<FoldRegion> list, boolean collapsed) {
            for (FoldRegion r : list) {
                if (collapsed && r.depth == 0) {
                    setAllFoldsRecursive(r.children, true);
                } else {
                    r.collapsed = collapsed;
                    setAllFoldsRecursive(r.children, collapsed);
                }
            }
        }

        private void collectHiddenLines(List<FoldRegion> list, Set<Integer> hidden) {
            for (FoldRegion r : list) {
                if (r.collapsed) {
                    for (int l = r.startLine + 1; l < r.endLine; l++) {
                        hidden.add(l);
                    }
                } else {
                    collectHiddenLines(r.children, hidden);
                }
            }
        }

        private int toOriginalLine(int visibleLine) {
            if (visibleLine >= 0 && visibleLine < visibleToOriginal.length) {
                return visibleToOriginal[visibleLine];
            }
            return visibleLine;
        }

        // -------------------------------------------------------------------
        // Painting
        // -------------------------------------------------------------------

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);

                // Background
                Color bg = decompPanel.getBackground();
                g2.setColor(bg != null ? bg : getBackground());
                g2.fillRect(0, 0, getWidth(), getHeight());

                if (fieldPanel == null) return;
                LayoutModel activeModel = modelSwapped ? filteringModel : originalModel;
                if (activeModel == null) return;

                // When inside a JScrollPane row header, Swing translates
                // the Graphics context for us — yOffset is always 0.
                // When in the WEST fallback, we must manually compensate.
                int yOffset = 0;
                if (!insideScrollPane) {
                    Container parent = fieldPanel.getParent();
                    if (parent instanceof JViewport vp) {
                        yOffset = vp.getViewPosition().y;
                    }
                }

                BigInteger numIndexes = activeModel.getNumIndexes();
                int y = 0;
                int visibleLineIndex = 0;
                BigInteger idx = BigInteger.ZERO;

                while (idx.compareTo(numIndexes) < 0) {
                    Layout layout = activeModel.getLayout(idx);
                    if (layout == null) {
                        idx = idx.add(BigInteger.ONE);
                        continue;
                    }

                    int rowHeight = layout.getHeight();
                    int screenY = y - yOffset;

                    if (screenY + rowHeight >= 0 && screenY < getHeight()) {
                        int origLine = toOriginalLine(visibleLineIndex);
                        FoldRegion r = regionByStartLine.get(origLine);
                        if (r != null) {
                            paintFoldIcon(g2, screenY, rowHeight, r.collapsed);
                        } else {
                            boolean isClosingBrace = false;
                            for (FoldRegion fr : allRegionsFlat) {
                                if (fr.collapsed && fr.endLine == origLine) {
                                    isClosingBrace = true;
                                    break;
                                }
                            }
                            if (!isClosingBrace) {
                                paintScopeLines(g2, origLine, screenY, rowHeight);
                            }
                        }
                    }

                    y += rowHeight;
                    visibleLineIndex++;
                    idx = idx.add(BigInteger.ONE);
                }
            } finally {
                g2.dispose();
            }
        }

        /**
         * Compute the full height of the margin to match the FieldPanel's
         * total content height.  When used as a row header, the JScrollPane
         * needs the preferred height to match the viewport content so that
         * the row header scrolls 1:1.
         */
        @Override
        public Dimension getPreferredSize() {
            if (insideScrollPane && fieldPanel != null) {
                // Match the FieldPanel's full virtual height
                int totalHeight = computeTotalContentHeight();
                return new Dimension(MARGIN_WIDTH, totalHeight);
            }
            return super.getPreferredSize();
        }

        private int computeTotalContentHeight() {
            LayoutModel activeModel = modelSwapped ? filteringModel : originalModel;
            if (activeModel == null) return 0;
            int total = 0;
            BigInteger numIndexes = activeModel.getNumIndexes();
            BigInteger idx = BigInteger.ZERO;
            while (idx.compareTo(numIndexes) < 0) {
                Layout layout = activeModel.getLayout(idx);
                if (layout != null) total += layout.getHeight();
                idx = idx.add(BigInteger.ONE);
            }
            return total;
        }

        private void paintFoldIcon(Graphics2D g, int y, int rowHeight, boolean collapsed) {
            int cx = MARGIN_WIDTH / 2;
            int cy = y + rowHeight / 2;
            int half = ICON_SIZE / 2;

            g.setColor(new Color(140, 140, 140));
            g.drawRect(cx - half, cy - half, ICON_SIZE, ICON_SIZE);
            g.setColor(new Color(240, 240, 240));
            g.fillRect(cx - half + 1, cy - half + 1, ICON_SIZE - 1, ICON_SIZE - 1);
            g.setColor(new Color(80, 80, 80));
            g.setStroke(new BasicStroke(1.2f));
            g.drawLine(cx - half + 2, cy, cx + half - 2, cy);
            if (collapsed) {
                g.drawLine(cx, cy - half + 2, cx, cy + half - 2);
            }
        }

        private void paintScopeLines(Graphics2D g, int origLine, int y, int rowHeight) {
            g.setColor(new Color(200, 200, 200));
            g.setStroke(new BasicStroke(1f));
            int cx = MARGIN_WIDTH / 2;
            for (FoldRegion r : allRegionsFlat) {
                if (!r.collapsed && origLine > r.startLine && origLine < r.endLine) {
                    g.drawLine(cx, y, cx, y + rowHeight);
                    break;
                }
            }
        }

        // -------------------------------------------------------------------
        // Tooltip
        // -------------------------------------------------------------------

        @Override
        public String getToolTipText(MouseEvent event) {
            int visLine = getVisibleLineAtY(event.getY());
            int origLine = toOriginalLine(visLine);
            FoldRegion r = regionByStartLine.get(origLine);
            if (r != null) {
                int span = r.endLine - r.startLine;
                return (r.collapsed ? "[+] Expand" : "[-] Collapse")
                        + " scope (" + span + " lines)";
            }
            return null;
        }

        // -------------------------------------------------------------------
        // Mouse handling
        // -------------------------------------------------------------------

        @Override
        public void mouseClicked(MouseEvent e) {
            if (e.getButton() != MouseEvent.BUTTON1) return;
            int visLine = getVisibleLineAtY(e.getY());
            int origLine = toOriginalLine(visLine);
            FoldRegion r = regionByStartLine.get(origLine);
            if (r != null) {
                Msg.info(this, "Gutter click on " + r
                        + " → " + (r.collapsed ? "EXPAND" : "COLLAPSE"));
                r.collapsed = !r.collapsed;
                applyFoldState();
            }
        }

        @Override public void mousePressed(MouseEvent e) {}
        @Override public void mouseReleased(MouseEvent e) {}
        @Override public void mouseEntered(MouseEvent e) {
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        }
        @Override public void mouseExited(MouseEvent e) {
            setCursor(Cursor.getDefaultCursor());
        }

        private int getVisibleLineAtY(int mouseY) {
            if (fieldPanel == null) return 0;
            LayoutModel activeModel = modelSwapped ? filteringModel : originalModel;
            if (activeModel == null) return 0;

            // When inside a scroll pane row header, mouseY is already
            // in the scrolled coordinate space — no offset needed.
            int targetY = mouseY;
            if (!insideScrollPane) {
                Container parent = fieldPanel.getParent();
                if (parent instanceof JViewport vp) {
                    targetY = mouseY + vp.getViewPosition().y;
                }
            }

            int y = 0;
            int lineIndex = 0;
            BigInteger numIndexes = activeModel.getNumIndexes();
            BigInteger idx = BigInteger.ZERO;

            while (idx.compareTo(numIndexes) < 0) {
                Layout layout = activeModel.getLayout(idx);
                if (layout == null) { idx = idx.add(BigInteger.ONE); continue; }
                int rowH = layout.getHeight();
                if (targetY >= y && targetY < y + rowH) return lineIndex;
                y += rowH;
                lineIndex++;
                idx = idx.add(BigInteger.ONE);
            }
            return lineIndex;
        }
    }
}