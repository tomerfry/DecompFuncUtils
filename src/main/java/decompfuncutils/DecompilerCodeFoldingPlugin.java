/*
 * DecompilerCodeFoldingPlugin
 *
 * Adds code folding to Ghidra's Decompiler panel. A sidebar margin with
 * +/- markers allows collapsing/expanding brace-delimited scopes.
 *
 * Architecture:
 *   - FilteringLayoutModel wraps the real model, hiding collapsed lines.
 *   - FieldPanel.setLayoutModel() is used to swap in/out the filter.
 *   - FieldPanel.getVisibleLayouts() is used for scroll-synced painting.
 *   - Discovery timer re-injects the margin on buildPanels() removeAll().
 *
 * Licensed under the Apache License 2.0.
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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.Timer;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Decompiler Code Folding",
    description = "Adds scope folding to the Decompiler panel."
)
//@formatter:on
public class DecompilerCodeFoldingPlugin extends ProgramPlugin {

    private final Map<DecompilerPanel, FoldState> states = new IdentityHashMap<>();
    private Timer discoveryTimer;
    private DockingAction toggleFoldAction, foldAllAction, unfoldAllAction;

    public DecompilerCodeFoldingPlugin(PluginTool tool) {
        super(tool);
        createActions();
        discoveryTimer = new Timer(1200, e -> discoverAndMaintain());
        discoveryTimer.setRepeats(true);
        discoveryTimer.start();
    }

    // ===================================================================
    // Actions
    // ===================================================================

    private void createActions() {
        toggleFoldAction = makeAction("Toggle Fold at Cursor",
                KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK,
                ctx -> { FoldState s = stateFromCtx(ctx); if (s != null) s.toggleFold(ctx.getLineNumber()); });
        foldAllAction = makeAction("Fold All Scopes",
                KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK,
                ctx -> { FoldState s = stateFromCtx(ctx); if (s != null) s.setAllFolds(true); });
        unfoldAllAction = makeAction("Unfold All Scopes",
                KeyEvent.VK_EQUALS, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK,
                ctx -> { FoldState s = stateFromCtx(ctx); if (s != null) s.setAllFolds(false); });
    }

    private DockingAction makeAction(String name, int key, int mods,
                                     java.util.function.Consumer<DecompilerActionContext> handler) {
        DockingAction a = new DockingAction(name, getName()) {
            @Override public void actionPerformed(ActionContext ctx) {
                if (ctx instanceof DecompilerActionContext dac) handler.accept(dac);
            }
            @Override public boolean isEnabledForContext(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
            @Override public boolean isAddToPopup(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
        };
        a.setPopupMenuData(new MenuData(new String[] { name }, null, "Decompile"));
        a.setKeyBindingData(new KeyBindingData(key, mods));
        tool.addAction(a);
        return a;
    }

    private FoldState stateFromCtx(DecompilerActionContext ctx) {
        try {
            Component c = ctx.getSourceComponent();
            while (c != null) {
                if (c instanceof DecompilerPanel dp) return states.get(dp);
                c = c.getParent();
            }
        } catch (Exception ignored) {}
        if (states.size() == 1) return states.values().iterator().next();
        return null;
    }

    // ===================================================================
    // Discovery
    // ===================================================================

    private void discoverAndMaintain() {
        if (tool == null) return;
        Set<DecompilerPanel> live = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Window w : Window.getWindows())
            if (w.isShowing()) collectPanels(w, live);

        for (DecompilerPanel dp : live) {
            if (!states.containsKey(dp))
                states.put(dp, new FoldState(dp));
        }
        for (var e : states.entrySet())
            if (live.contains(e.getKey())) e.getValue().ensureInjected();

        states.keySet().retainAll(live);
    }

    private void collectPanels(Component c, Set<DecompilerPanel> out) {
        if (c instanceof DecompilerPanel dp) { out.add(dp); return; }
        if (c instanceof Container ct)
            for (Component ch : ct.getComponents()) collectPanels(ch, out);
    }

    // ===================================================================
    // Reflection helpers
    // ===================================================================

    static FieldPanel getFieldPanel(DecompilerPanel dp) {
        try {
            Method m = DecompilerPanel.class.getMethod("getFieldPanel");
            return (FieldPanel) m.invoke(dp);
        } catch (Exception ignored) {}
        for (String name : new String[] { "fieldPanel", "codeViewer" }) {
            try {
                java.lang.reflect.Field f = DecompilerPanel.class.getDeclaredField(name);
                f.setAccessible(true);
                Object v = f.get(dp);
                if (v instanceof FieldPanel fp) return fp;
            } catch (Exception ignored) {}
        }
        return null;
    }

    static boolean fpSetModel(FieldPanel fp, LayoutModel model) {
        try {
            Method m = FieldPanel.class.getMethod("setLayoutModel", LayoutModel.class);
            m.invoke(fp, model);
            Msg.info(DecompilerCodeFoldingPlugin.class,
                    "setLayoutModel succeeded, new model has " + model.getNumIndexes() + " indexes");
            return true;
        } catch (Exception ex) {
            Msg.error(DecompilerCodeFoldingPlugin.class,
                    "setLayoutModel FAILED: " + ex.getMessage(), ex);
        }
        return false;
    }

    // ===================================================================
    // Dispose
    // ===================================================================

    @Override
    protected void dispose() {
        if (discoveryTimer != null) { discoveryTimer.stop(); discoveryTimer = null; }
        for (FoldState s : states.values()) s.dispose();
        states.clear();
        if (toggleFoldAction != null) tool.removeAction(toggleFoldAction);
        if (foldAllAction != null) tool.removeAction(foldAllAction);
        if (unfoldAllAction != null) tool.removeAction(unfoldAllAction);
        super.dispose();
    }

    // ===================================================================
    // FoldRegion
    // ===================================================================

    static class FoldRegion {
        final int startLine, depth;
        int endLine;
        boolean collapsed = false;
        final List<FoldRegion> children = new ArrayList<>();
        FoldRegion(int s, int d) { startLine = s; depth = d; endLine = s; }
    }

    // ===================================================================
    // FilteringLayoutModel — hides collapsed lines
    // ===================================================================

    static class FilteringLayoutModel implements LayoutModel {
        private final LayoutModel delegate;
        private final List<LayoutModelListener> listeners = new ArrayList<>();
        private BigInteger[] visToReal = new BigInteger[0];

        FilteringLayoutModel(LayoutModel delegate) {
            this.delegate = delegate;
        }

        LayoutModel getDelegate() { return delegate; }

        /** Map from visible index to real index */
        int toRealLine(int visibleIndex) {
            if (visibleIndex >= 0 && visibleIndex < visToReal.length)
                return visToReal[visibleIndex].intValue();
            return visibleIndex;
        }

        void applyHidden(Set<Integer> hiddenLines) {
            BigInteger realCount = delegate.getNumIndexes();
            List<BigInteger> vis = new ArrayList<>();
            for (BigInteger i = BigInteger.ZERO; i.compareTo(realCount) < 0;
                 i = i.add(BigInteger.ONE)) {
                if (!hiddenLines.contains(i.intValue())) vis.add(i);
            }
            visToReal = vis.toArray(new BigInteger[0]);
            for (LayoutModelListener l : new ArrayList<>(listeners))
                l.modelSizeChanged(v -> v);
        }

        private BigInteger toReal(BigInteger vi) {
            int i = vi.intValue();
            return (i >= 0 && i < visToReal.length) ? visToReal[i] : vi;
        }

        @Override public BigInteger getNumIndexes() { return BigInteger.valueOf(visToReal.length); }
        @Override public Layout getLayout(BigInteger index) { return delegate.getLayout(toReal(index)); }
        @Override public boolean isUniform() { return delegate.isUniform(); }
        @Override public Dimension getPreferredViewSize() { return delegate.getPreferredViewSize(); }
        @Override public BigInteger getIndexAfter(BigInteger i) {
            BigInteger n = i.add(BigInteger.ONE);
            return n.compareTo(getNumIndexes()) >= 0 ? null : n;
        }
        @Override public BigInteger getIndexBefore(BigInteger i) {
            return i.compareTo(BigInteger.ONE) < 0 ? null : i.subtract(BigInteger.ONE);
        }
        @Override public void addLayoutModelListener(LayoutModelListener l) { listeners.add(l); }
        @Override public void removeLayoutModelListener(LayoutModelListener l) { listeners.remove(l); }
        @Override public void flushChanges() { delegate.flushChanges(); }
    }

    // ===================================================================
    // FoldState — per-DecompilerPanel
    // ===================================================================

    class FoldState {
        final DecompilerPanel decompPanel;
        final FoldMarginPanel margin;
        FieldPanel fieldPanel;

        List<FoldRegion> topRegions = Collections.emptyList();
        Map<Integer, FoldRegion> regionByStart = Collections.emptyMap();
        List<FoldRegion> allFlat = Collections.emptyList();
        int totalLines = 0;

        // Model management
        LayoutModel originalModel;          // the "real" model from Ghidra
        FilteringLayoutModel filterModel;   // our wrapper
        boolean modelSwapped = false;

        // Listener on the original model to detect new decompilations
        LayoutModelListener origModelListener;
        BigInteger lastOrigSize = BigInteger.ZERO;
        boolean insideFoldApply = false;

        FoldState(DecompilerPanel dp) {
            this.decompPanel = dp;
            this.margin = new FoldMarginPanel(this);
        }

        void ensureInjected() {
            // Check if margin is still in the DecompilerPanel tree
            if (margin.isDisplayable() && isAncestor(decompPanel, margin)) {
                // Still injected — just verify field panel hasn't changed
                FieldPanel fp = getFieldPanel(decompPanel);
                if (fp != null && fp != fieldPanel) rebindFieldPanel(fp);
                return;
            }

            // Need to (re)inject
            FieldPanel fp = getFieldPanel(decompPanel);
            if (fp == null) return;
            rebindFieldPanel(fp);

            LayoutManager lm = decompPanel.getLayout();
            if (!(lm instanceof BorderLayout bl)) return;

            Component west = bl.getLayoutComponent(BorderLayout.WEST);
            if (west instanceof Container c && containsComp(c, margin)) return;

            if (west instanceof JComponent box) {
                box.add(margin, 0);
                box.revalidate();
                box.repaint();
            } else {
                JPanel wrapper = new JPanel();
                wrapper.setLayout(new BoxLayout(wrapper, BoxLayout.X_AXIS));
                wrapper.setOpaque(false);
                wrapper.add(margin);
                if (west != null) { decompPanel.remove(west); wrapper.add(west); }
                decompPanel.add(wrapper, BorderLayout.WEST);
                decompPanel.revalidate();
                decompPanel.repaint();
            }
        }

        private boolean isAncestor(Container a, Component c) {
            while (c != null) { if (c == a) return true; c = c.getParent(); }
            return false;
        }
        private boolean containsComp(Container c, Component t) {
            for (Component ch : c.getComponents()) {
                if (ch == t) return true;
                if (ch instanceof Container cc && containsComp(cc, t)) return true;
            }
            return false;
        }

        // --- FieldPanel binding ---

        private void rebindFieldPanel(FieldPanel fp) {
            if (fp == this.fieldPanel) return;

            // Restore original model on old field panel
            restoreOriginalModel();
            detachOrigListener();

            this.fieldPanel = fp;
            this.originalModel = fp.getLayoutModel();
            this.lastOrigSize = originalModel.getNumIndexes();

            // Listen to the original model for size changes (new decompilations)
            origModelListener = new LayoutModelListener() {
                @Override public void modelSizeChanged(IndexMapper m) { onOrigModelChanged(); }
                @Override public void dataChanged(BigInteger s, BigInteger e) { onOrigModelChanged(); }
            };
            originalModel.addLayoutModelListener(origModelListener);

            // Parse and apply
            reparseAndApply();
        }

        private void detachOrigListener() {
            if (originalModel != null && origModelListener != null)
                originalModel.removeLayoutModelListener(origModelListener);
            origModelListener = null;
        }

        private void onOrigModelChanged() {
            if (insideFoldApply) return;
            BigInteger sz = originalModel.getNumIndexes();
            if (!sz.equals(lastOrigSize)) {
                lastOrigSize = sz;
                SwingUtilities.invokeLater(this::reparseAndApply);
            }
        }

        // --- Parse & apply folds ---

        void reparseAndApply() {
            // Read lines from the ORIGINAL model (not our filter)
            List<String> lines = readLinesFrom(originalModel);
            totalLines = lines.size();
            topRegions = parseFoldRegions(lines);
            regionByStart = new HashMap<>();
            allFlat = new ArrayList<>();
            for (FoldRegion r : topRegions) flattenRegion(r);

            applyFoldState();
        }

        void applyFoldState() {
            if (fieldPanel == null || originalModel == null) return;

            insideFoldApply = true;
            try {
                Set<Integer> hidden = new HashSet<>();
                collectHidden(topRegions, hidden);

                Msg.info(this, "applyFoldState: " + hidden.size() + " hidden lines");

                if (hidden.isEmpty()) {
                    restoreOriginalModel();
                } else {
                    // Save current view position so we can restore after model swap
                    BigInteger topIndex = BigInteger.ZERO;
                    int topYPos = 0;
                    try {
                        List<AnchoredLayout> vis = fieldPanel.getVisibleLayouts();
                        if (vis != null && !vis.isEmpty()) {
                            topIndex = vis.get(0).getIndex();
                            topYPos = vis.get(0).getYPos();
                        }
                    } catch (Exception ignored) {}

                    filterModel = new FilteringLayoutModel(originalModel);
                    filterModel.applyHidden(hidden);

                    boolean ok = fpSetModel(fieldPanel, filterModel);
                    Msg.info(this, "setLayoutModel returned: " + ok);
                    if (ok) {
                        modelSwapped = true;
                    }
                }
            } catch (Exception ex) {
                Msg.error(this, "applyFoldState failed", ex);
            } finally {
                insideFoldApply = false;
            }

            margin.repaint();
            fieldPanel.repaint();
        }

        private void restoreOriginalModel() {
            if (modelSwapped && fieldPanel != null && originalModel != null) {
                fpSetModel(fieldPanel, originalModel);
                modelSwapped = false;
            }
            filterModel = null;
        }

        private void collectHidden(List<FoldRegion> list, Set<Integer> hidden) {
            for (FoldRegion r : list) {
                if (r.collapsed) {
                    for (int l = r.startLine + 1; l < r.endLine; l++) hidden.add(l);
                    // Don't recurse into children — they're already hidden
                } else {
                    collectHidden(r.children, hidden);
                }
            }
        }

        private void flattenRegion(FoldRegion r) {
            regionByStart.put(r.startLine, r);
            allFlat.add(r);
            for (FoldRegion c : r.children) flattenRegion(c);
        }

        private List<String> readLinesFrom(LayoutModel model) {
            if (model == null) return Collections.emptyList();
            BigInteger n = model.getNumIndexes();
            List<String> lines = new ArrayList<>(n.intValue());
            BigInteger idx = BigInteger.ZERO;
            while (idx.compareTo(n) < 0) {
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

        // --- Fold toggling ---

        void toggleFold(int line) {
            // The line number from the context is in the VISIBLE model's space
            // Convert to original line if we have a filter active
            int origLine = line;
            if (modelSwapped && filterModel != null) {
                origLine = filterModel.toRealLine(line);
            }

            FoldRegion r = findRegion(origLine);
            if (r == null) r = findRegion(origLine - 1);
            if (r == null) r = findRegion(origLine + 1);
            if (r != null) {
                r.collapsed = !r.collapsed;
                applyFoldState();
            }
        }

        void setAllFolds(boolean collapsed) {
            setAllRec(topRegions, collapsed);
            applyFoldState();
        }

        private void setAllRec(List<FoldRegion> list, boolean collapsed) {
            for (FoldRegion r : list) {
                r.collapsed = (collapsed && r.depth == 0) ? false : collapsed;
                setAllRec(r.children, collapsed);
            }
        }

        private FoldRegion findRegion(int line) {
            if (line < 0 || line >= totalLines) return null;
            FoldRegion exact = regionByStart.get(line);
            if (exact != null) return exact;
            FoldRegion best = null;
            for (FoldRegion r : allFlat) {
                if (r.depth == 0) continue;
                if (line > r.startLine && line <= r.endLine)
                    if (best == null || r.depth > best.depth) best = r;
            }
            return best;
        }

        void dispose() {
            restoreOriginalModel();
            detachOrigListener();
            Container p = margin.getParent();
            if (p != null) { p.remove(margin); p.revalidate(); }
        }
    }

    // ===================================================================
    // Parsing
    // ===================================================================

    static List<FoldRegion> parseFoldRegions(List<String> lines) {
        List<FoldRegion> top = new ArrayList<>();
        Deque<FoldRegion> stack = new ArrayDeque<>();
        for (int i = 0; i < lines.size(); i++) {
            String clean = stripCommentsAndStrings(lines.get(i));
            for (char ch : clean.toCharArray()) {
                if (ch == '{') {
                    FoldRegion r = new FoldRegion(i, stack.size());
                    if (stack.isEmpty()) top.add(r);
                    else stack.peek().children.add(r);
                    stack.push(r);
                } else if (ch == '}') {
                    if (!stack.isEmpty()) stack.pop().endLine = i;
                }
            }
        }
        pruneEmpty(top);
        return top;
    }

    private static void pruneEmpty(List<FoldRegion> list) {
        var it = list.iterator();
        while (it.hasNext()) {
            FoldRegion r = it.next();
            pruneEmpty(r.children);
            if (r.endLine <= r.startLine) it.remove();
        }
    }

    static String stripCommentsAndStrings(String line) {
        StringBuilder sb = new StringBuilder(line.length());
        boolean inStr = false, inChar = false, inBlock = false;
        char prev = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inBlock) {
                if (c == '/' && prev == '*') { inBlock = false; prev = 0; }
                else prev = c;
                continue;
            }
            if (!inStr && !inChar && c == '*' && prev == '/') {
                inBlock = true;
                if (sb.length() > 0) sb.setLength(sb.length() - 1);
                prev = c;
                continue;
            }
            if (!inStr && !inChar && c == '/' && i + 1 < line.length()
                    && line.charAt(i + 1) == '/') break;
            if (!inChar && c == '"' && prev != '\\') { inStr = !inStr; prev = c; continue; }
            if (!inStr && c == '\'' && prev != '\\') { inChar = !inChar; prev = c; continue; }
            if (!inStr && !inChar) sb.append(c);
            prev = c;
        }
        return sb.toString();
    }

    // ===================================================================
    // FoldMarginPanel — the visual gutter
    // ===================================================================

    static class FoldMarginPanel extends JPanel implements MouseListener {

        private static final int W = 18, ICO = 9;
        private final FoldState state;

        FoldMarginPanel(FoldState state) {
            this.state = state;
            setPreferredSize(new Dimension(W, Short.MAX_VALUE));
            setMinimumSize(new Dimension(W, 0));
            setMaximumSize(new Dimension(W, Short.MAX_VALUE));
            setOpaque(true);
            addMouseListener(this);
            setToolTipText("");
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);

                Color bg = state.decompPanel.getBackground();
                g2.setColor(bg != null ? bg : getBackground());
                g2.fillRect(0, 0, getWidth(), getHeight());

                FieldPanel fp = state.fieldPanel;
                if (fp == null) return;

                List<AnchoredLayout> layouts;
                try { layouts = fp.getVisibleLayouts(); }
                catch (Exception ex) { return; }
                if (layouts == null || layouts.isEmpty()) return;

                boolean filtered = state.modelSwapped && state.filterModel != null;

                for (AnchoredLayout al : layouts) {
                    int visIdx = al.getIndex().intValue();
                    // Map visible index → original line for region lookup
                    int origLine = filtered
                            ? state.filterModel.toRealLine(visIdx)
                            : visIdx;
                    int y = al.getYPos();
                    int h = al.getHeight();

                    FoldRegion r = state.regionByStart.get(origLine);
                    if (r != null) {
                        drawIcon(g2, y, h, r.collapsed);
                    } else {
                        drawScope(g2, origLine, y, h);
                    }
                }
            } finally {
                g2.dispose();
            }
        }

        private void drawIcon(Graphics2D g, int y, int h, boolean collapsed) {
            int cx = W / 2, cy = y + h / 2, half = ICO / 2;
            g.setColor(new Color(140, 140, 140));
            g.drawRect(cx - half, cy - half, ICO, ICO);
            g.setColor(new Color(240, 240, 240));
            g.fillRect(cx - half + 1, cy - half + 1, ICO - 1, ICO - 1);
            g.setColor(new Color(80, 80, 80));
            g.setStroke(new BasicStroke(1.2f));
            g.drawLine(cx - half + 2, cy, cx + half - 2, cy);
            if (collapsed) g.drawLine(cx, cy - half + 2, cx, cy + half - 2);
        }

        private void drawScope(Graphics2D g, int origLine, int y, int h) {
            for (FoldRegion r : state.allFlat) {
                if (!r.collapsed && origLine > r.startLine && origLine < r.endLine) {
                    g.setColor(new Color(80, 80, 80, 60));
                    g.setStroke(new BasicStroke(1f));
                    g.drawLine(W / 2, y, W / 2, y + h);
                    break;
                }
            }
        }

        // --- Mouse ---

        @Override public void mouseClicked(MouseEvent e) {
            if (e.getButton() != MouseEvent.BUTTON1) return;
            int origLine = origLineAtY(e.getY());
            Msg.info(this, "mouseClicked at Y=" + e.getY() + " → origLine=" + origLine);
            if (origLine < 0) return;
            FoldRegion r = state.regionByStart.get(origLine);
            if (r != null) {
                r.collapsed = !r.collapsed;
                Msg.info(this, "Toggling fold at line " + origLine + " → collapsed=" + r.collapsed);
                state.applyFoldState();
            } else {
                Msg.info(this, "No fold region at origLine=" + origLine);
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

        @Override public String getToolTipText(MouseEvent e) {
            int origLine = origLineAtY(e.getY());
            if (origLine < 0) return null;
            FoldRegion r = state.regionByStart.get(origLine);
            if (r == null) return null;
            return (r.collapsed ? "[+] Expand" : "[-] Collapse")
                    + " (" + (r.endLine - r.startLine) + " lines)";
        }

        /** Map mouse Y → original line number (accounting for filter). */
        private int origLineAtY(int mouseY) {
            FieldPanel fp = state.fieldPanel;
            if (fp == null) return -1;
            try {
                List<AnchoredLayout> layouts = fp.getVisibleLayouts();
                if (layouts == null) return -1;
                boolean filtered = state.modelSwapped && state.filterModel != null;
                for (AnchoredLayout al : layouts) {
                    if (mouseY >= al.getYPos() && mouseY < al.getYPos() + al.getHeight()) {
                        int visIdx = al.getIndex().intValue();
                        return filtered ? state.filterModel.toRealLine(visIdx) : visIdx;
                    }
                }
            } catch (Exception ignored) {}
            return -1;
        }
    }
}