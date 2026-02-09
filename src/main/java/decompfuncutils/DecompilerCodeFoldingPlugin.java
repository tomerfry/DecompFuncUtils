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
import docking.widgets.fieldpanel.support.AnchoredLayout;

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
    private final Set<FieldPanel> marginInstalledOnFieldPanel =
            Collections.newSetFromMap(new IdentityHashMap<>());

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
            if (!installedMargins.containsKey(panel)) {
                FieldPanel fp = getFieldPanel(panel);
                if (fp != null && marginInstalledOnFieldPanel.contains(fp)) continue;
                installMargin(panel);
            }
        }
        Iterator<Map.Entry<DecompilerPanel, FoldMarginPanel>> it =
                installedMargins.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<DecompilerPanel, FoldMarginPanel> entry = it.next();
            if (!livePanels.contains(entry.getKey())) {
                FoldMarginPanel margin = entry.getValue();
                if (margin.fieldPanel != null) {
                    marginInstalledOnFieldPanel.remove(margin.fieldPanel);
                }
                margin.dispose();
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

    private void injectMarginComponent(DecompilerPanel panel, FoldMarginPanel margin) {
        try {
            FieldPanel fp = getFieldPanel(panel);
            if (fp == null) {
                Msg.warn(this, "Could not find FieldPanel — cannot install fold margin");
                installedMargins.remove(panel);
                return;
            }
            if (marginInstalledOnFieldPanel.contains(fp)) {
                installedMargins.remove(panel);
                return;
            }

            margin.attachToFieldPanel(fp);
            marginInstalledOnFieldPanel.add(fp);

            java.awt.LayoutManager lm = panel.getLayout();
            if (lm instanceof BorderLayout bl) {
                Component west = bl.getLayoutComponent(BorderLayout.WEST);
                if (west instanceof Container c && containsFoldMargin(c)) {
                    return;
                }
                if (west instanceof JComponent box) {
                    box.add(margin, 0);
                    box.revalidate();
                    box.repaint();
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
                }
            } else {
                panel.add(margin, BorderLayout.WEST);
                panel.revalidate();
                panel.repaint();
            }
            Msg.info(this, "Fold margin installed");
        } catch (Exception ex) {
            Msg.error(this, "Failed to inject fold margin component", ex);
        }
    }

    private boolean containsFoldMargin(Container c) {
        for (Component child : c.getComponents()) {
            if (child instanceof FoldMarginPanel) return true;
            if (child instanceof Container cc && containsFoldMargin(cc)) return true;
        }
        return false;
    }

    // =======================================================================
    // Action handlers
    // =======================================================================

    private void toggleFoldAtCursor(DecompilerActionContext ctx) {
        DecompilerPanel panel = findDecompilerPanelFromContext(ctx);
        FoldMarginPanel margin = (panel != null) ? installedMargins.get(panel) : null;
        if (margin == null) return;
        margin.toggleFoldAtVisibleLine(ctx.getLineNumber());
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
        if (installedMargins.size() == 1) {
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
        return null;
    }

    private static boolean setFieldPanelModel(FieldPanel fp, LayoutModel model) {
        try {
            Method m = FieldPanel.class.getMethod("setLayoutModel", LayoutModel.class);
            m.invoke(fp, model);
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
                return true;
            } catch (Exception ignored) {}
        }
        return false;
    }

    /**
     * Try to register a LayoutListener on the FieldPanel via reflection.
     * FieldPanel implements IndexedScrollable; it calls layoutsChanged()
     * on registered LayoutListeners whenever the visible area changes.
     */
    private static boolean addLayoutListener(FieldPanel fp, Object listener) {
        // Try addLayoutListener(LayoutListener)
        try {
            Class<?> listenerClass = Class.forName(
                    "docking.widgets.fieldpanel.listener.LayoutListener");
            Method m = FieldPanel.class.getMethod("addLayoutListener", listenerClass);
            m.invoke(fp, listener);
            Msg.info(DecompilerCodeFoldingPlugin.class,
                    "Registered LayoutListener on FieldPanel");
            return true;
        } catch (Exception ex) {
            Msg.info(DecompilerCodeFoldingPlugin.class,
                    "addLayoutListener failed: " + ex.getMessage());
        }
        return false;
    }

    private static boolean removeLayoutListener(FieldPanel fp, Object listener) {
        try {
            Class<?> listenerClass = Class.forName(
                    "docking.widgets.fieldpanel.listener.LayoutListener");
            Method m = FieldPanel.class.getMethod("removeLayoutListener", listenerClass);
            m.invoke(fp, listener);
            return true;
        } catch (Exception ignored) {}
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
        marginInstalledOnFieldPanel.clear();
        if (toggleFoldAction != null) tool.removeAction(toggleFoldAction);
        if (foldAllAction != null) tool.removeAction(foldAllAction);
        if (unfoldAllAction != null) tool.removeAction(unfoldAllAction);
        super.dispose();
    }

    // =======================================================================
    // FoldRegion
    // =======================================================================

    static class FoldRegion {
        final int startLine;
        int endLine;
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
            for (int line : hiddenOrigLines) hiddenRealLines.add(BigInteger.valueOf(line));
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
            for (LayoutModelListener l : new ArrayList<>(listeners)) l.modelSizeChanged(identity);
        }
    }

    // =======================================================================
    // VisibleRow — snapshot of a visible layout's position
    // =======================================================================

    /**
     * Represents a single visible row as reported by FieldPanel's
     * LayoutListener.layoutsChanged(). Stores the layout model index
     * and the Y pixel offset on screen.
     */
    static class VisibleRow {
        final int modelIndex;  // index into the (filtered) layout model
        final int yPos;        // Y offset on screen (can be negative if partially scrolled off)
        final int height;

        VisibleRow(int modelIndex, int yPos, int height) {
            this.modelIndex = modelIndex;
            this.yPos = yPos;
            this.height = height;
        }
    }

    // =======================================================================
    // FoldMarginPanel
    // =======================================================================

    class FoldMarginPanel extends JPanel implements MouseListener {

        private static final int MARGIN_WIDTH = 18;
        private static final int ICON_SIZE = 9;

        private final DecompilerPanel decompPanel;
        FieldPanel fieldPanel;

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

        /**
         * Current visible rows, updated by the LayoutListener callback.
         * This is the KEY to scroll synchronization — Ghidra's FieldPanel
         * tells us exactly which layouts are visible and where they are
         * positioned on screen.
         */
        private volatile List<VisibleRow> currentVisibleRows = Collections.emptyList();

        /** Proxy LayoutListener — we need to implement via reflection */
        private Object layoutListenerProxy;

        FoldMarginPanel(DecompilerPanel decompPanel) {
            this.decompPanel = decompPanel;
            setPreferredSize(new Dimension(MARGIN_WIDTH, Short.MAX_VALUE));
            setMinimumSize(new Dimension(MARGIN_WIDTH, 0));
            setMaximumSize(new Dimension(MARGIN_WIDTH, Short.MAX_VALUE));
            setOpaque(true);
            addMouseListener(this);
            setToolTipText("");
        }

        void attachToFieldPanel(FieldPanel fp) {
            this.fieldPanel = fp;
            this.originalModel = fp.getLayoutModel();
            this.lastKnownDelegateSize = originalModel.getNumIndexes();

            filteringModel = new FilteringLayoutModel(originalModel);
            modelSwapped = setFieldPanelModel(fp, filteringModel);

            // Listen to original model for new decompilations
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

            // === CRITICAL: Register LayoutListener for scroll sync ===
            // FieldPanel calls layoutsChanged(List<AnchoredLayout>) on every
            // scroll, resize, and model change. This is how margins stay synced.
            registerLayoutListener(fp);

            // Fallback: also listen to JViewport changes
            Container parent = fp.getParent();
            if (parent instanceof JViewport vp) {
                vp.addChangeListener(e -> repaint());
            }

            fp.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) { repaint(); }
            });

            onNewDecompilation();
        }

        /**
         * Register as a LayoutListener via dynamic proxy (since we can't
         * directly implement the interface from an extension class).
         */
        private void registerLayoutListener(FieldPanel fp) {
            try {
                Class<?> listenerClass = Class.forName(
                        "docking.widgets.fieldpanel.listener.LayoutListener");

                layoutListenerProxy = java.lang.reflect.Proxy.newProxyInstance(
                        listenerClass.getClassLoader(),
                        new Class<?>[] { listenerClass },
                        (proxy, method, args) -> {
                            if ("layoutsChanged".equals(method.getName()) && args != null
                                    && args.length == 1) {
                                onLayoutsChanged((List<?>) args[0]);
                            }
                            return null;
                        });

                addLayoutListener(fp, layoutListenerProxy);
                Msg.info(this, "LayoutListener proxy registered for scroll sync");
            } catch (Exception ex) {
                Msg.warn(this, "Could not register LayoutListener: " + ex.getMessage()
                        + " — falling back to viewport-based scroll sync");
            }
        }

        /**
         * Called by FieldPanel on every scroll/resize. The list contains
         * AnchoredLayout objects with getIndex() (BigInteger) and getYPos() (int).
         */
        @SuppressWarnings("unchecked")
        private void onLayoutsChanged(List<?> layouts) {
            try {
                List<VisibleRow> rows = new ArrayList<>(layouts.size());
                for (Object obj : layouts) {
                    // AnchoredLayout has: getIndex() → BigInteger, getYPos() → int,
                    // getHeight() → int
                    Method getIndex = obj.getClass().getMethod("getIndex");
                    Method getYPos = obj.getClass().getMethod("getYPos");
                    Method getHeight = obj.getClass().getMethod("getHeight");

                    BigInteger index = (BigInteger) getIndex.invoke(obj);
                    int yPos = (Integer) getYPos.invoke(obj);
                    int height = (Integer) getHeight.invoke(obj);

                    rows.add(new VisibleRow(index.intValue(), yPos, height));
                }
                currentVisibleRows = rows;
                repaint();
            } catch (Exception ex) {
                // If reflection fails once, log it; it will keep failing
                // but we still repaint with what we have
                repaint();
            }
        }

        void dispose() {
            if (originalModel != null && originalModelListener != null) {
                originalModel.removeLayoutModelListener(originalModelListener);
            }
            if (fieldPanel != null && layoutListenerProxy != null) {
                removeLayoutListener(fieldPanel, layoutListenerProxy);
            }
            if (modelSwapped && fieldPanel != null && originalModel != null) {
                setFieldPanelModel(fieldPanel, originalModel);
            }
            removeMouseListener(this);
            Container myParent = getParent();
            if (myParent != null) {
                myParent.remove(this);
                myParent.revalidate();
                myParent.repaint();
            }
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
            boolean inStr = false, inChar = false, inBlock = false;
            char prev = 0;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                // End block comment
                if (inBlock) {
                    if (c == '/' && prev == '*') { inBlock = false; prev = 0; }
                    else prev = c;
                    continue;
                }
                // Start block comment /* ... */
                if (!inStr && !inChar && c == '*' && prev == '/') {
                    inBlock = true;
                    // Remove the '/' we already appended
                    if (sb.length() > 0) sb.setLength(sb.length() - 1);
                    prev = c;
                    continue;
                }
                // Single-line comment //
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
            if (found == null) found = tryFindRegionAtVisible(lineParam - 1);
            if (found == null && lineParam + 1 < visibleToOriginal.length) {
                found = tryFindRegionAtVisible(lineParam + 1);
            }
            if (found != null) {
                found.collapsed = !found.collapsed;
                applyFoldState();
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
                    if (best == null || r.depth > best.depth) best = r;
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
                    for (int l = r.startLine + 1; l < r.endLine; l++) hidden.add(l);
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
        // Painting — uses LayoutListener visible rows
        // -------------------------------------------------------------------

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);

                Color bg = decompPanel.getBackground();
                g2.setColor(bg != null ? bg : getBackground());
                g2.fillRect(0, 0, getWidth(), getHeight());

                if (fieldPanel == null) return;

                List<VisibleRow> rows = currentVisibleRows;
                if (!rows.isEmpty()) {
                    // LayoutListener path — paint only visible rows at their
                    // exact screen Y positions (the correct Ghidra way)
                    paintFromVisibleRows(g2, rows);
                } else {
                    // Fallback path — compute from model (may not scroll correctly
                    // but at least shows icons initially)
                    paintFromModel(g2);
                }
            } finally {
                g2.dispose();
            }
        }

        /**
         * Paint using the visible row snapshots from LayoutListener.
         * Each VisibleRow carries the model index and the exact Y position
         * on screen, so this is guaranteed to be scroll-synced.
         */
        private void paintFromVisibleRows(Graphics2D g2, List<VisibleRow> rows) {
            for (VisibleRow row : rows) {
                int visibleLineIndex = row.modelIndex;
                int origLine = toOriginalLine(visibleLineIndex);
                int screenY = row.yPos;
                int rowHeight = row.height;

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
        }

        /**
         * Fallback paint path: iterate the layout model from the beginning.
         * Used when LayoutListener hasn't fired yet (e.g. initial load).
         */
        private void paintFromModel(Graphics2D g2) {
            LayoutModel activeModel = modelSwapped ? filteringModel : originalModel;
            if (activeModel == null) return;

            // Try viewport offset
            int yOffset = 0;
            if (fieldPanel != null) {
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
                if (layout == null) { idx = idx.add(BigInteger.ONE); continue; }
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
                if (screenY > getHeight()) break;
                y += rowHeight;
                visibleLineIndex++;
                idx = idx.add(BigInteger.ONE);
            }
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

        /**
         * Map a mouse Y coordinate to a visible line index.
         * Uses the LayoutListener visible rows for accuracy.
         */
        private int getVisibleLineAtY(int mouseY) {
            // Use LayoutListener data if available
            List<VisibleRow> rows = currentVisibleRows;
            if (!rows.isEmpty()) {
                for (VisibleRow row : rows) {
                    if (mouseY >= row.yPos && mouseY < row.yPos + row.height) {
                        return row.modelIndex;
                    }
                }
                // If click is below all visible rows, return last
                if (!rows.isEmpty()) {
                    return rows.get(rows.size() - 1).modelIndex;
                }
            }

            // Fallback: iterate model
            if (fieldPanel == null) return 0;
            LayoutModel activeModel = modelSwapped ? filteringModel : originalModel;
            if (activeModel == null) return 0;

            int yOffset = 0;
            Container parent = fieldPanel.getParent();
            if (parent instanceof JViewport vp) yOffset = vp.getViewPosition().y;
            int targetY = mouseY + yOffset;

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