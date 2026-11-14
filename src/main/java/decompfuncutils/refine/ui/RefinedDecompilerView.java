package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.RefineResult;
import decompfuncutils.refine.Rewrite;
import ghidra.program.model.address.Address;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Everything inside the Refined Decompiler window: the refined code, the list of rewrites behind
 * it, the configuration that produced it, and a status line. Plain Swing with no dependency on a
 * running tool, so it can be built and exercised on its own.
 */
public final class RefinedDecompilerView extends JPanel {
    private final RefinedCodeView code = new RefinedCodeView();
    private final RefineConfigPanel configPanel;
    private final JLabel status = new JLabel(" ");
    private final RewriteTableModel tableModel = new RewriteTableModel();
    private final JTable table = new JTable(tableModel);
    private final JSplitPane vertical, horizontal;
    private final JScrollPane configScroll, tableScroll;
    private RefineResult shown;
    private boolean original;
    private Address highlight;

    /**
     * @param onConfigChange called whenever the user changes the configuration
     * @param onNavigate called with a machine address the user asked to go to
     */
    public RefinedDecompilerView(RefineConfig initial, Runnable onConfigChange, Consumer<Address> onNavigate) {
        super(new BorderLayout());
        configPanel = new RefineConfigPanel(initial, onConfigChange);
        code.onNavigate(a -> {
            highlight = a;
            onNavigate.accept(a);
        });
        JScrollPane codeScroll = new JScrollPane(code);
        codeScroll.getVerticalScrollBar().setUnitIncrement(16);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setMaxWidth(110);
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setMaxWidth(260);
        table.getColumnModel().getColumn(0).setCellRenderer(new StatusRenderer());
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            Rewrite rw = tableModel.rewriteAt(table.getSelectedRow());
            if (rw != null && !original) code.reveal(rw);
        });
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                Rewrite rw = tableModel.rewriteAt(table.rowAtPoint(e.getPoint()));
                if (e.getClickCount() == 2 && rw != null && rw.address != null) onNavigate.accept(rw.address);
            }
        });
        tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(400, 130));

        vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT, codeScroll, tableScroll);
        vertical.setResizeWeight(0.78);
        vertical.setBorder(BorderFactory.createEmptyBorder());
        configScroll = new JScrollPane(configPanel);
        configScroll.getVerticalScrollBar().setUnitIncrement(16);
        configScroll.setPreferredSize(new Dimension(360, 400));
        configScroll.setMinimumSize(new Dimension(120, 100));
        horizontal = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, vertical, configScroll);
        horizontal.setResizeWeight(0.68);
        horizontal.setBorder(BorderFactory.createEmptyBorder());

        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) { arrange(); }
        });
        status.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
        add(horizontal, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        showHint("Place the cursor in a function to see it refined.");
    }

    /** Narrower than this, the configuration goes under the code instead of beside it. */
    private static final int SIDE_BY_SIDE_WIDTH = 900;

    /**
     * Code and configuration side by side when the window is wide enough for both, stacked when
     * it is docked as a narrow column -- where side by side would leave neither readable.
     */
    private void arrange() {
        int wanted = getWidth() >= SIDE_BY_SIDE_WIDTH ? JSplitPane.HORIZONTAL_SPLIT : JSplitPane.VERTICAL_SPLIT;
        if (horizontal.getOrientation() == wanted) return;
        horizontal.setOrientation(wanted);
        horizontal.setResizeWeight(wanted == JSplitPane.HORIZONTAL_SPLIT ? 0.68 : 0.55);
        if (configScroll.isVisible()) {
            javax.swing.SwingUtilities.invokeLater(() ->
                horizontal.setDividerLocation(wanted == JSplitPane.HORIZONTAL_SPLIT ? 0.66 : 0.55));
        }
    }

    public RefineConfigPanel configPanel() { return configPanel; }
    public RefinedCodeView code() { return code; }
    public RefineResult shown() { return shown; }
    public String statusText() { return status.getText(); }
    public int rewriteRows() { return tableModel.getRowCount(); }

    /** Show a finished refinement. */
    public void showResult(RefineResult result) {
        shown = result;
        tableModel.set(result);
        redisplay();
        boolean bad = result.validation != null && result.validation.outcome == RefineResult.Validation.Outcome.DIFFERS;
        status.setForeground(bad ? errorColor() : getForeground());
        status.setText(result.summary());
        StringBuilder notes = new StringBuilder();
        for (String m : result.messages) notes.append(notes.length() > 0 ? "<br>" : "").append(m.replace("&", "&amp;").replace("<", "&lt;"));
        status.setToolTipText(notes.length() == 0 ? null : "<html>" + notes + "</html>");
    }

    /** Switch between the refined code and what the decompiler printed. */
    public void showOriginal(boolean on) {
        original = on;
        redisplay();
    }

    private void redisplay() {
        if (shown == null) return;
        if (original) code.showPlain(shown.original);
        else {
            code.show(shown);
            if (highlight != null) code.highlightAddress(highlight);
        }
    }

    /** Mark the line for a listing address, now or as soon as there is code to mark it in. */
    public void highlight(Address address) {
        highlight = address;
        if (shown != null && !original) code.highlightAddress(address);
    }

    public void showHint(String text) {
        shown = null;
        tableModel.set(null);
        code.showPlain("/* " + text + " */");
        status.setForeground(getForeground());
        status.setText(" ");
        status.setToolTipText(null);
    }

    public void showFailure(String function, Throwable problem) {
        shown = null;
        tableModel.set(null);
        code.showPlain("/* " + function + " could not be refined:\n   " + problem + " */");
        status.setForeground(errorColor());
        status.setText("Refinement failed: " + problem.getMessage());
    }

    public void showBusy(String function) {
        status.setForeground(getForeground());
        status.setText("Refining " + function + " ...");
    }

    public void setRewritesVisible(boolean on) {
        tableScroll.setVisible(on);
        vertical.setDividerSize(on ? 6 : 0);
        vertical.resetToPreferredSizes();
        revalidate();
    }

    public void setConfigVisible(boolean on) {
        configScroll.setVisible(on);
        horizontal.setDividerSize(on ? 6 : 0);
        horizontal.resetToPreferredSizes();
        revalidate();
    }

    private static Color errorColor() { return RefinedCodeView.dark() ? new Color(0xff8080) : new Color(0xb00020); }

    /** Rewrites first, in the order they happened, then the engine's notes. */
    private static final class RewriteTableModel extends AbstractTableModel {
        private final List<Rewrite> rewrites = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();
        private static final String[] COLUMNS = {"Status", "Rule", "Was", "Now"};

        void set(RefineResult result) {
            rewrites.clear();
            notes.clear();
            if (result != null) {
                rewrites.addAll(result.log);
                notes.addAll(result.messages);
            }
            fireTableDataChanged();
        }

        Rewrite rewriteAt(int row) { return row >= 0 && row < rewrites.size() ? rewrites.get(row) : null; }

        @Override public int getRowCount() { return rewrites.size() + notes.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override public Object getValueAt(int row, int column) {
            if (row >= rewrites.size()) {
                String note = notes.get(row - rewrites.size());
                return switch (column) {
                    case 0 -> "note";
                    case 2 -> note;
                    default -> "";
                };
            }
            Rewrite rw = rewrites.get(row);
            return switch (column) {
                case 0 -> rw.status.name().toLowerCase();
                case 1 -> rw.rule;
                case 2 -> rw.before;
                default -> rw.status == Rewrite.Status.REFUTED ? rw.after + "   -- " + rw.detail : rw.after;
            };
        }
    }

    private final class StatusRenderer extends DefaultTableCellRenderer {
        @Override public Component getTableCellRendererComponent(JTable t, Object value, boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, column);
            Rewrite rw = tableModel.rewriteAt(row);
            if (!selected) c.setBackground(rw == null ? t.getBackground() : RefinedCodeView.tint(rw.status, t.getBackground()));
            if (c instanceof JComponent jc) jc.setToolTipText(rw == null ? String.valueOf(tableModel.getValueAt(row, 2)) : RefinedCodeView.describe(rw));
            return c;
        }
    }
}
