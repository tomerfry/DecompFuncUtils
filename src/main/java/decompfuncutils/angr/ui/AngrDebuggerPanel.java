package decompfuncutils.angr.ui;

import decompfuncutils.angr.AngrHooks;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

/**
 * The debugger's view: a launch bar, step buttons, a status banner that says in a sentence what
 * just happened, the registers, and tabs for the stack, calls, memory, output, paths, symbols and
 * imports.
 *
 * <p>It is plain Swing and knows nothing about Ghidra's docking or about angr: it shows the
 * snapshot it is given and reports what the user asked for through {@link Actions}. That keeps it
 * usable - and testable - without a tool window.
 */
public class AngrDebuggerPanel extends JPanel {

    /** What the user can ask for. Implemented by {@link AngrDebuggerController}. */
    public interface Actions {
        void start(String function, String argumentsText, boolean symbolicImports, boolean strictMemory);

        void step(String kind);

        void pause();

        void stop();

        void selectPath(int id);

        void dropPath(int id);

        /** @param value null to let the solver pick */
        void concretize(Map<String, Object> target, String value);

        void concretizeAll();

        void symbolize(String register, String name);

        void setValue(Map<String, Object> target, String value);

        void setWatches(String text);

        void goTo(String hexAddress);

        void refreshImports();

        void saveHook(AngrHooks.Hook hook);

        void deleteHook(String name);

        /** A hook to start from for this target: the saved one if there is one, else a template. */
        AngrHooks.Hook hookFor(String target);
    }

    private final Actions actions;
    private final Palette palette = new Palette();
    private final Font mono;

    // launch bar
    private final JTextField functionField = new JTextField(18);
    private final JTextField argumentsField = new JTextField(30);
    private final JCheckBox symbolicImports = new JCheckBox("Unknown imports return symbolic values", true);
    private final JCheckBox strictMemory = new JCheckBox("Fault on unmapped memory", true);
    private final JLabel hintLabel = new JLabel(" ");
    private final Map<String, JButton> buttons = new LinkedHashMap<>();

    // status
    private final JPanel banner = new JPanel(new BorderLayout(0, 2));
    private final JLabel bannerTitle = new JLabel();
    private final JTextArea bannerDetail = new JTextArea(2, 40);

    // data
    private final JTabbedPane tabs = new JTabbedPane();
    private final Map<String, JTable> tables = new LinkedHashMap<>();
    private final Map<String, List<Map<String, Object>>> rows = new HashMap<>();
    private final JTextArea output = new JTextArea();
    private final JTextField watchField = new JTextField(30);
    private final JLabel importsNote = new JLabel(" ");

    private Map<String, Object> snapshot;
    private boolean running;

    /** Where the views live when each is a window of its own rather than a tab of this panel. */
    public interface ViewHost {
        /** Brings a view to the front, e.g. Paths when execution forks. */
        void showView(String name);

        /** The number of rows a view holds changed; shown next to its title. */
        void countChanged(String name, int count);
    }

    private final Map<String, JComponent> views = new LinkedHashMap<>();
    private final boolean detached;
    private ViewHost viewHost;

    /** The debugger as one panel: controls on top, registers left, everything else in tabs. */
    public AngrDebuggerPanel(Actions actions) {
        this(actions, false);
    }

    /**
     * @param detached true to make this panel only the control strip (launch bar, step buttons,
     *                 banner) and leave the views to be placed by the caller - see {@link #view}
     */
    public AngrDebuggerPanel(Actions actions, boolean detached) {
        super(new BorderLayout(0, 6));
        this.actions = actions;
        this.detached = detached;
        Font base = UIManager.getFont("Table.font");
        this.mono = new Font(Font.MONOSPACED, Font.PLAIN, base == null ? 12 : base.getSize());
        setBorder(new EmptyBorder(6, 6, 6, 6));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(launchBar());
        top.add(stepBar());
        top.add(Box.createVerticalStrut(4));
        top.add(banner());
        add(top, BorderLayout.NORTH);

        JComponent registers = registersPane();
        views.put("Registers", registers);
        JComponent tabbed = tabsPane();
        if (!detached) {
            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, registers, tabbed);
            split.setResizeWeight(0.34);
            split.setBorder(null);
            add(split, BorderLayout.CENTER);
        }

        showState(null, false);
    }

    // ---------------------------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------------------------

    private JComponent launchBar() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 2, 2, 4);
        c.gridy = 0;
        c.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel("Function"), c);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0.3;
        functionField.setToolTipText("Function name or address. Right-click a function in the Listing "
            + "or Decompiler and choose 'Debug Function with angr' to fill this in.");
        panel.add(functionField, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        panel.add(new JLabel("Arguments"), c);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0.7;
        argumentsField.setFont(mono);
        argumentsField.setToolTipText("<html>Comma-separated, as you would write the call:<br>"
            + "<code>\"hello\", 5, 0x10</code> &nbsp; strings become pointers to the text<br>"
            + "<code>{\"buffer\": 64}</code> &nbsp; pointer to 64 zero bytes (an out-parameter)<br>"
            + "<code>{\"bytes\": \"deadbeef\"}</code> &nbsp; pointer to those bytes<br>"
            + "<code>{\"struct\": [3, 4, \"label\"]}</code> &nbsp; pointer to a packed struct<br>"
            + "<code>{\"symbolicBytes\": 16}</code>, <code>{\"symbolicInt\": 32}</code> &nbsp; unknown input</html>");
        panel.add(argumentsField, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        JButton start = button("Start", "Start debugging the function (replaces the current session)",
            () -> actions.start(functionField.getText().strip(), argumentsField.getText().strip(),
                symbolicImports.isSelected(), strictMemory.isSelected()));
        start.setFont(start.getFont().deriveFont(Font.BOLD));
        panel.add(start, c);
        functionField.addActionListener(e -> start.doClick());
        argumentsField.addActionListener(e -> start.doClick());

        return panel;
    }

    /** The step buttons, then the two launch options and how Ghidra thinks the function is called. */
    private JComponent stepBar() {
        JPanel steps = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        steps.add(button("Step Into", "Execute one instruction, entering calls (F8)", () -> actions.step("into")));
        steps.add(button("Step Over", "Execute one instruction, running a call to its return (F10)",
            () -> actions.step("over")));
        steps.add(button("Step Out", "Run until the current function returns (F12)", () -> actions.step("out")));
        steps.add(button("Continue", "Run to the next breakpoint, fork, return or fault (F5)",
            () -> actions.step("continue")));
        steps.add(Box.createHorizontalStrut(10));
        steps.add(button("Pause", "Interrupt a run", actions::pause));
        steps.add(button("Stop", "End the session", actions::stop));
        steps.add(Box.createHorizontalStrut(14));

        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        symbolicImports.setToolTipText("<html>An import angr has no model for, and you wrote no hook for, "
            + "returns an <b>unknown</b> value.<br>Branches that depend on it stop the debugger so you can "
            + "choose a side.<br>Unticked, such imports return 0. Libraries missing from the project are "
            + "fine either way.</html>");
        strictMemory.setToolTipText("<html>Stop with a fault when the function touches an address Ghidra has "
            + "no memory block for -<br>the usual sign of a pointer nobody supplied. Untick for firmware that "
            + "reads unmapped peripherals.</html>");
        options.add(symbolicImports);
        options.add(strictMemory);
        hintLabel.setForeground(palette.muted);

        // The hint takes whatever width is left and is cut short, not wrapped, when there is
        // little; its tooltip always has all of it.
        JPanel right = new JPanel(new BorderLayout(8, 0));
        right.add(options, BorderLayout.WEST);
        right.add(hintLabel, BorderLayout.CENTER);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(steps, BorderLayout.WEST);
        panel.add(right, BorderLayout.CENTER);
        return panel;
    }

    private JComponent banner() {
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 5, 0, 0, palette.info), new EmptyBorder(5, 9, 5, 6)));
        bannerTitle.setFont(bannerTitle.getFont().deriveFont(Font.BOLD, bannerTitle.getFont().getSize() + 1f));
        banner.add(bannerTitle, BorderLayout.NORTH);
        // Two wrapped lines, always: the explanation is read in full at any dock width, and the
        // tables below do not jump when its length changes.
        bannerDetail.setEditable(false);
        bannerDetail.setFocusable(false);
        bannerDetail.setOpaque(false);
        bannerDetail.setLineWrap(true);
        bannerDetail.setWrapStyleWord(true);
        bannerDetail.setBorder(null);
        bannerDetail.setFont(bannerTitle.getFont().deriveFont(Font.PLAIN, bannerTitle.getFont().getSize() - 1f));
        banner.add(bannerDetail, BorderLayout.CENTER);
        banner.setAlignmentX(LEFT_ALIGNMENT);
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(banner, BorderLayout.CENTER);
        return wrap;
    }

    private JComponent registersPane() {
        JTable table = table("registers", "Register", "Value", "Notes");
        table.getColumnModel().getColumn(0).setPreferredWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(150);
        table.getColumnModel().getColumn(2).setPreferredWidth(170);
        table.setToolTipText("Right-click a register to set it, concretize it or make it symbolic. "
            + "Double-click to go to the address it holds.");
        JPopupMenu menu = new JPopupMenu();
        menu.add(item("Set Value...", () -> withRegister(row -> {
            String value = prompt("New value for " + row.get("name") + " (a number, or \"text\" for a pointer to a string)",
                text(row.get("value")));
            if (value != null) {
                actions.setValue(Map.of("register", text(row.get("name"))), value);
            }
        })));
        menu.add(item("Concretize...", () -> withRegister(row -> {
            if (row.get("symbolic") == null) {
                showMessage(row.get("name") + " is already concrete.", false);
                return;
            }
            String value = prompt("Value to fix " + row.get("name") + " at (leave as is to accept the solver's choice)",
                text(row.get("example")));
            if (value != null) {
                actions.concretize(Map.of("register", text(row.get("name"))), value.isBlank() ? null : value);
            }
        })));
        menu.add(item("Make Symbolic...", () -> withRegister(row -> {
            String name = prompt("Name for the unknown value in " + row.get("name"), text(row.get("name")));
            if (name != null) {
                actions.symbolize(text(row.get("name")), name.isBlank() ? null : name);
            }
        })));
        table.setComponentPopupMenu(menu);
        onDoubleClick(table, "registers", "value");
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private JComponent tabsPane() {
        JTable stack = table("stack", "Address", "Offset", "Value", "Notes");
        stack.getColumnModel().getColumn(0).setPreferredWidth(125);
        stack.getColumnModel().getColumn(1).setPreferredWidth(50);
        stack.getColumnModel().getColumn(2).setPreferredWidth(125);
        stack.getColumnModel().getColumn(3).setPreferredWidth(150);
        onDoubleClick(stack, "stack", "value");
        addView("Stack", new JScrollPane(stack));

        JTable calls = table("calls", "Call", "From");
        calls.getColumnModel().getColumn(0).setPreferredWidth(400);
        calls.getColumnModel().getColumn(1).setPreferredWidth(230);
        onDoubleClick(calls, "calls", "fromAddress");
        addView("Calls", new JScrollPane(calls));

        JTable memory = table("memory", "What", "Address", "Size", "Bytes", "Text");
        memory.getColumnModel().getColumn(3).setPreferredWidth(260);
        onDoubleClick(memory, "memory", "address");
        JPanel watchBar = new JPanel(new BorderLayout(6, 0));
        watchBar.setBorder(new EmptyBorder(3, 3, 3, 3));
        watchBar.add(new JLabel("Watch"), BorderLayout.WEST);
        watchField.setToolTipText("Memory to show after every stop: symbols or addresses, comma-separated, "
            + "each optionally followed by :length. Example: g_config:16, 0x104000");
        watchBar.add(watchField, BorderLayout.CENTER);
        JButton apply = button("Apply Watches", "Show these ranges after every stop",
            () -> actions.setWatches(watchField.getText()));
        watchField.addActionListener(e -> apply.doClick());
        watchBar.add(apply, BorderLayout.EAST);
        JPanel memoryPanel = new JPanel(new BorderLayout());
        memoryPanel.add(watchBar, BorderLayout.NORTH);
        memoryPanel.add(new JScrollPane(memory), BorderLayout.CENTER);
        addView("Memory", memoryPanel);

        output.setEditable(false);
        output.setFont(mono);
        addView("Output", new JScrollPane(output));

        JTable paths = table("paths", "", "Path", "Status", "Location", "Condition taken");
        paths.getColumnModel().getColumn(0).setMaxWidth(26);
        paths.getColumnModel().getColumn(1).setMaxWidth(50);
        paths.getColumnModel().getColumn(2).setMaxWidth(110);
        paths.getColumnModel().getColumn(3).setPreferredWidth(220);
        paths.getColumnModel().getColumn(4).setPreferredWidth(300);
        JPanel pathButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        pathButtons.add(button("Switch to Path", "Continue debugging on the selected path",
            () -> withSelected("paths", row -> actions.selectPath(number(row.get("id"))))));
        pathButtons.add(button("Drop Path", "Discard the selected path",
            () -> withSelected("paths", row -> actions.dropPath(number(row.get("id"))))));
        pathButtons.add(muted("A branch on an unknown value splits execution; each side is a path."));
        paths.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    withSelected("paths", row -> actions.selectPath(number(row.get("id"))));
                }
            }
        });
        JPanel pathsPanel = new JPanel(new BorderLayout());
        pathsPanel.add(pathButtons, BorderLayout.NORTH);
        pathsPanel.add(new JScrollPane(paths), BorderLayout.CENTER);
        addView("Paths", pathsPanel);

        JTable symbols = table("symbols", "Symbol", "Bits", "Value", "State");
        symbols.getColumnModel().getColumn(0).setPreferredWidth(240);
        JPanel symbolButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        symbolButtons.add(button("Concretize...", "Fix the selected unknown at a value",
            () -> withSelected("symbols", row -> {
                String suggestion = text(row.get("value") != null ? row.get("value") : row.get("example"));
                String value = prompt("Value for " + row.get("name")
                    + " (leave as is to accept the solver's choice)", suggestion);
                if (value != null) {
                    actions.concretize(Map.of("symbol", text(row.get("name"))), value.isBlank() ? null : value);
                }
            })));
        symbolButtons.add(button("Concretize All", "Fix every unknown at one consistent set of values",
            actions::concretizeAll));
        symbolButtons.add(muted("Unknown values this path depends on."));
        JPanel symbolsPanel = new JPanel(new BorderLayout());
        symbolsPanel.add(symbolButtons, BorderLayout.NORTH);
        symbolsPanel.add(new JScrollPane(symbols), BorderLayout.CENTER);
        addView("Symbols", symbolsPanel);

        JTable imports = table("imports", "Target", "Library", "In project", "Handled by");
        imports.getColumnModel().getColumn(0).setPreferredWidth(190);
        imports.getColumnModel().getColumn(3).setPreferredWidth(230);
        JPanel importButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        importButtons.add(button("Write Hook...", "Write or edit a Python replacement for the selected import",
            () -> withSelected("imports", row -> editHook(text(row.get("target"))))));
        importButtons.add(button("New Hook...", "Write a Python hook for any function or address", () -> {
            String target = prompt("Function name or address to hook", functionField.getText().strip());
            if (target != null && !target.isBlank()) {
                editHook(target.strip());
            }
        }));
        importButtons.add(button("Enable / Disable", "Switch the selected hook on or off",
            () -> withSelected("imports", row -> {
                AngrHooks.Hook hook = hookOf(row);
                if (hook != null) {
                    hook.enabled = !hook.enabled;
                    actions.saveHook(hook);
                }
            })));
        importButtons.add(button("Delete Hook", "Delete the selected hook", () -> withSelected("imports", row -> {
            if (row.get("hook") != null) {
                actions.deleteHook(text(row.get("hook")));
            }
        })));
        importButtons.add(button("Refresh", "Re-read the imports and hooks", actions::refreshImports));
        imports.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    withSelected("imports", row -> editHook(text(row.get("target"))));
                }
            }
        });
        importsNote.setForeground(palette.muted);
        importsNote.setBorder(new EmptyBorder(2, 5, 4, 5));
        JPanel importsTop = new JPanel(new BorderLayout());
        importsTop.add(importButtons, BorderLayout.NORTH);
        importsTop.add(importsNote, BorderLayout.SOUTH);
        JPanel importsPanel = new JPanel(new BorderLayout());
        importsPanel.add(importsTop, BorderLayout.NORTH);
        importsPanel.add(new JScrollPane(imports), BorderLayout.CENTER);
        addView("Imports & Hooks", importsPanel);
        if (!detached) {
            tabs.addChangeListener(e -> {
                if (tabs.getSelectedIndex() == tabs.getTabCount() - 1 && rows.get("imports") == null) {
                    actions.refreshImports();
                }
            });
        }
        return tabs;
    }

    private void addView(String name, JComponent component) {
        views.put(name, component);
        if (!detached) {
            tabs.addTab(name, component);
        }
    }

    /** The names of the views, in display order: Registers, Stack, Calls, Memory, ... */
    public Set<String> viewNames() {
        return Collections.unmodifiableSet(views.keySet());
    }

    /** One view's component, for a caller that places the views itself (detached mode). */
    public JComponent view(String name) {
        return views.get(name);
    }

    public void setViewHost(ViewHost host) {
        this.viewHost = host;
    }

    /** False until the Imports &amp; Hooks view has been filled once. */
    public boolean importsLoaded() {
        return rows.get("imports") != null;
    }

    /** Empties the Imports &amp; Hooks view, so it is fetched again for another program. */
    public void forgetImports() {
        rows.remove("imports");
        ((DefaultTableModel) tables.get("imports").getModel()).setRowCount(0);
        importsNote.setText(" ");
    }

    private JTable table(String key, String... columns) {
        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(model);
        table.setFont(mono);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setRowHeight(Math.max(table.getRowHeight(), mono.getSize() + 7));
        table.setDefaultRenderer(Object.class, new RowRenderer(key));
        tables.put(key, table);
        return table;
    }

    private JButton button(String name, String tooltip, Runnable action) {
        JButton button = new JButton(name);
        button.setToolTipText(tooltip);
        button.addActionListener(e -> action.run());
        button.setFocusable(false);
        buttons.put(name, button);
        return button;
    }

    private static JMenuItem item(String name, Runnable action) {
        JMenuItem item = new JMenuItem(name);
        item.addActionListener(e -> action.run());
        return item;
    }

    private JLabel muted(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(palette.muted);
        return label;
    }

    private void onDoubleClick(JTable table, String key, String field) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    withSelected(key, row -> {
                        if (row.get(field) instanceof String address && address.startsWith("0x")) {
                            actions.goTo(address);
                        }
                    });
                }
            }
        });
    }

    private void withRegister(java.util.function.Consumer<Map<String, Object>> use) {
        withSelected("registers", use);
    }

    private void withSelected(String key, java.util.function.Consumer<Map<String, Object>> use) {
        JTable table = tables.get(key);
        List<Map<String, Object>> data = rows.get(key);
        int selected = table.getSelectedRow();
        if (data == null || selected < 0 || selected >= data.size()) {
            showMessage("Select a row first.", false);
            return;
        }
        use.accept(data.get(selected));
    }

    private String prompt(String message, String initial) {
        return (String) JOptionPane.showInputDialog(this, message, "angr Debugger",
            JOptionPane.PLAIN_MESSAGE, null, null, initial == null ? "" : initial);
    }

    // ---------------------------------------------------------------------------------------
    // Hook editor
    // ---------------------------------------------------------------------------------------

    private AngrHooks.Hook hookOf(Map<String, Object> row) {
        return row.get("hookObject") instanceof AngrHooks.Hook hook ? hook : null;
    }

    private void editHook(String target) {
        AngrHooks.Hook hook = actions.hookFor(target);
        if (hook == null) {
            return;
        }
        JTextField name = new JTextField(hook.name, 22);
        JTextField targetField = new JTextField(hook.target, 22);
        JComboBox<String> kind = new JComboBox<>(new String[] { "replace the function", "run at the address, then continue" });
        kind.setSelectedIndex(AngrHooks.KIND_INLINE.equals(hook.kind) ? 1 : 0);
        JSpinner skip = new JSpinner(new SpinnerNumberModel(hook.skip, 0, 4096, 1));
        JCheckBox enabled = new JCheckBox("Enabled", hook.enabled);
        JTextArea code = new JTextArea(hook.code, 20, 84);
        code.setFont(mono);
        code.setTabSize(4);

        JPanel fields = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        fields.add(new JLabel("Name"));
        fields.add(name);
        fields.add(new JLabel("Target"));
        fields.add(targetField);
        fields.add(kind);
        fields.add(new JLabel("skip bytes"));
        fields.add(skip);
        fields.add(enabled);
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(fields, BorderLayout.NORTH);
        panel.add(new JScrollPane(code), BorderLayout.CENTER);
        panel.add(muted("Saved as a .py file. It is compiled on save and applied to the running session at once."),
            BorderLayout.SOUTH);

        int answer = JOptionPane.showConfirmDialog(this, panel, "Python hook for " + target,
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return;
        }
        AngrHooks.Hook edited = new AngrHooks.Hook();
        edited.name = name.getText().strip();
        edited.target = targetField.getText().strip();
        edited.kind = kind.getSelectedIndex() == 1 ? AngrHooks.KIND_INLINE : AngrHooks.KIND_REPLACE;
        edited.skip = (Integer) skip.getValue();
        edited.enabled = enabled.isSelected();
        edited.code = code.getText();
        actions.saveHook(edited);
    }

    // ---------------------------------------------------------------------------------------
    // Showing things
    // ---------------------------------------------------------------------------------------

    public void setFunction(String name) {
        functionField.setText(name == null ? "" : name);
    }

    public void setArguments(String text) {
        argumentsField.setText(text == null ? "" : text);
    }

    public String getFunction() {
        return functionField.getText().strip();
    }

    /** A line under the launch bar: how Ghidra thinks the function is called. */
    public void setHint(String text) {
        hintLabel.setText(text == null || text.isBlank() ? " " : text);
        hintLabel.setToolTipText(text == null || text.isBlank() ? null : text);
    }

    /** A one-off message in the banner, for instance why an action was refused. */
    public void showMessage(String message, boolean error) {
        bannerDetail.setText(message);
        bannerDetail.setToolTipText(message);
        bannerDetail.setForeground(error ? palette.error : palette.text);
        if (error) {
            setStripe(palette.error);
        }
    }

    /**
     * Shows a session snapshot, or the idle state when there is none.
     *
     * @param running true while a step or run is in progress
     */
    @SuppressWarnings("unchecked")
    public void showState(Map<String, Object> newSnapshot, boolean isRunning) {
        this.snapshot = newSnapshot;
        this.running = isRunning;
        boolean session = snapshot != null;
        String status = session ? text(snapshot.get("status")) : "";
        boolean steppable = session && !running && "paused".equals(status);
        for (String name : List.of("Step Into", "Step Over", "Step Out", "Continue")) {
            buttons.get(name).setEnabled(steppable);
        }
        buttons.get("Pause").setEnabled(session && running);
        buttons.get("Stop").setEnabled(session);
        buttons.get("Start").setEnabled(!running);
        buttons.get("Start").setText(session ? "Restart" : "Start");
        for (String name : List.of("Switch to Path", "Drop Path", "Concretize...", "Concretize All", "Apply Watches")) {
            buttons.get(name).setEnabled(session && !running);
        }
        bannerDetail.setForeground(palette.text);

        if (!session) {
            setBanner(palette.muted, "No session",
                "Enter a function and its arguments and press Start - or right-click a function in the "
                    + "Listing and choose Debug Function with angr.");
            for (String key : List.of("registers", "stack", "calls", "memory", "paths", "symbols")) {
                fill(key, List.of());
            }
            output.setText("");
            retitle();
            return;
        }
        if (running) {
            setBanner(palette.muted, "Running...", "Pause interrupts the run; Stop ends the session.");
            return;
        }

        fillRegisters((List<Map<String, Object>>) snapshot.getOrDefault("registers", List.of()));
        fillStack(snapshot.get("stack"));
        fillCalls((List<Map<String, Object>>) snapshot.getOrDefault("calls", List.of()));
        fillMemory();
        fillPaths((List<Map<String, Object>>) snapshot.getOrDefault("paths", List.of()));
        fillSymbols((List<Map<String, Object>>) snapshot.getOrDefault("symbols", List.of()));
        StringBuilder text = new StringBuilder();
        if (snapshot.get("stdout") instanceof String out) {
            text.append(out);
        }
        if (snapshot.get("stderr") instanceof String err) {
            text.append(text.length() > 0 ? "\n--- stderr ---\n" : "").append(err);
        }
        output.setText(text.toString());
        retitle();
        describe(status);
    }

    private void describe(String status) {
        String stop = text(snapshot.get("stop"));
        String where = text(snapshot.get("pc"))
            + (snapshot.get("location") != null ? "   " + snapshot.get("location") : "");
        String tail = snapshot.get("instructions") + " instructions"
            + (snapshot.get("flags") != null ? "   flags: " + snapshot.get("flags") : "")
            + pathSuffix();
        switch (status) {
            case "returned": {
                Object value = snapshot.get("returnValue");
                String shown = "";
                if (value instanceof Map<?, ?> rv) {
                    shown = rv.get("hex") != null ? rv.get("hex") + "  (" + rv.get("signed") + ")"
                        : "symbolic, e.g. " + rv.get("example");
                    if (rv.get("string") != null) {
                        shown += "  \"" + rv.get("string") + "\"";
                    }
                }
                setBanner(palette.ok, "Returned " + shown, tail + "   Restart to run it again"
                    + (rows.get("paths").size() > 1 ? ", or switch to another path." : "."));
                break;
            }
            case "fault": {
                Map<?, ?> fault = snapshot.get("fault") instanceof Map<?, ?> f ? f : Map.of();
                setBanner(palette.error, "Fault at " + where,
                    text(fault.get("message")) + (fault.get("hint") != null ? " - " + fault.get("hint") : "")
                        + " The state shown is the one just before the failing instruction.");
                break;
            }
            case "exited":
                setBanner(palette.warn, "The program terminated itself", tail);
                break;
            case "symbolic_jump":
                setBanner(palette.warn, "The next address is unknown at " + where,
                    "It depends on an unknown value. Concretize it in the Symbols tab to go on.");
                break;
            default:
                if ("fork".equals(stop)) {
                    String guard = "";
                    for (Map<String, Object> row : rows.get("paths")) {
                        if (Boolean.TRUE.equals(row.get("current")) && row.get("guard") != null) {
                            guard = " This path assumes " + row.get("guard") + ".";
                        }
                    }
                    setBanner(palette.warn, "Forked at " + where,
                        "The branch depends on an unknown value, so execution split." + guard
                            + " Keep stepping to follow it, or pick another in the Paths tab.");
                    selectTab("Paths");
                }
                else {
                    String why = switch (stop) {
                        case "breakpoint" -> "Breakpoint.  ";
                        case "timeout", "paused" -> "Interrupted.  ";
                        case "max_steps" -> "Step limit reached.  ";
                        case "selected" -> "Path selected.  ";
                        case "start" -> "Ready at the first instruction.  ";
                        default -> "";
                    };
                    setBanner(palette.info, "Paused at " + where, why + tail);
                }
        }
        if (snapshot.get("warnings") instanceof List<?> warnings && !warnings.isEmpty()) {
            bannerDetail.setText(bannerDetail.getText() + "  Note: " + warnings.get(0));
        }
    }

    private String pathSuffix() {
        int count = rows.get("paths") == null ? 0 : rows.get("paths").size();
        return count > 1 ? "   path " + snapshot.get("path") + " of " + count : "";
    }

    private void setBanner(Color stripe, String title, String detail) {
        setStripe(stripe);
        bannerTitle.setText(title);
        bannerTitle.setForeground(stripe == palette.muted ? palette.text : stripe);
        bannerDetail.setText(detail);
        bannerDetail.setToolTipText(detail);
    }

    private void setStripe(Color color) {
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 5, 0, 0, color), new EmptyBorder(5, 9, 5, 6)));
    }

    // ---- tables ----

    private void fillRegisters(List<Map<String, Object>> registers) {
        List<Object[]> data = new ArrayList<>();
        for (Map<String, Object> row : registers) {
            data.add(new Object[] { row.get("name"), valueOf(row), notesOf(row) });
        }
        fill("registers", registers, data);
    }

    @SuppressWarnings("unchecked")
    private void fillStack(Object stack) {
        List<Map<String, Object>> words = stack instanceof Map<?, ?> m && m.get("words") instanceof List<?> l
            ? (List<Map<String, Object>>) l : List.of();
        List<Object[]> data = new ArrayList<>();
        for (Map<String, Object> row : words) {
            data.add(new Object[] { row.get("address"), "+0x" + Long.toHexString(number(row.get("offset"))),
                valueOf(row), notesOf(row) });
        }
        fill("stack", words, data);
    }

    private void fillCalls(List<Map<String, Object>> calls) {
        List<Map<String, Object>> shown = new ArrayList<>();
        List<Object[]> data = new ArrayList<>();
        for (Map<String, Object> call : calls) {
            Map<String, Object> row = new LinkedHashMap<>(call);
            String from = text(call.get("from"));
            // "0x1019b7 (check_password+0x17)" - keep the address for navigation
            row.put("fromAddress", from.contains(" ") ? from.substring(0, from.indexOf(' ')) : from);
            String line;
            if (call.get("log") != null) {
                line = "    # " + call.get("log") + "   [" + call.get("hook") + "]";
            }
            else {
                String indent = "  ".repeat(Math.max(0, number(call.get("depth")) - 1));
                String arguments = call.get("args") instanceof List<?> list
                    ? String.join(", ", list.stream().map(String::valueOf).toList()) : "";
                line = indent + call.get("call") + "(" + arguments + ")"
                    + (call.get("returned") != null ? "  ->  " + call.get("returned") : "")
                    + (Boolean.TRUE.equals(call.get("python")) ? "   [python hook]"
                        : Boolean.TRUE.equals(call.get("stubbed")) ? "   [stub]" : "");
            }
            shown.add(row);
            data.add(new Object[] { line, from });
        }
        fill("calls", shown, data);
        JTable table = tables.get("calls");
        if (table.getRowCount() > 0) {
            table.scrollRectToVisible(table.getCellRect(table.getRowCount() - 1, 0, true));
        }
    }

    @SuppressWarnings("unchecked")
    private void fillMemory() {
        List<Map<String, Object>> shown = new ArrayList<>();
        List<Object[]> data = new ArrayList<>();
        for (String key : List.of("memory", "buffers", "writes")) {
            if (!(snapshot.get(key) instanceof List<?> list)) {
                continue;
            }
            for (Object o : list) {
                Map<String, Object> row = (Map<String, Object>) o;
                if (row.get("address") == null) {
                    continue;
                }
                String what = switch (key) {
                    case "memory" -> "watch " + text(row.get("name"));
                    case "buffers" -> text(row.get("arg")) + (Boolean.TRUE.equals(row.get("changed")) ? " (changed)" : "");
                    default -> "written: " + text(row.get("symbol") != null ? row.get("symbol") : row.get("region"));
                };
                Object size = row.get("size") != null ? row.get("size") : row.get("length");
                shown.add(row);
                data.add(new Object[] { what, row.get("address"), size, spaced(text(row.get("hex"))),
                    row.get("string") != null ? "\"" + row.get("string") + "\"" : "" });
            }
        }
        fill("memory", shown, data);
    }

    private void fillPaths(List<Map<String, Object>> paths) {
        List<Object[]> data = new ArrayList<>();
        for (Map<String, Object> row : paths) {
            String location = text(row.get("pc")) + (row.get("pcLabel") != null ? "  " + row.get("pcLabel") : "");
            data.add(new Object[] { Boolean.TRUE.equals(row.get("current")) ? ">" : "", row.get("id"),
                row.get("status"), location, text(row.get("guard")) });
        }
        fill("paths", paths, data);
    }

    private void fillSymbols(List<Map<String, Object>> symbols) {
        List<Object[]> data = new ArrayList<>();
        for (Map<String, Object> row : symbols) {
            boolean fixed = row.get("value") != null;
            data.add(new Object[] { row.get("name"), row.get("bits"),
                fixed ? row.get("value") : "e.g. " + text(row.get("example")), fixed ? "fixed" : "free" });
        }
        fill("symbols", symbols, data);
    }

    /**
     * Shows the Imports &amp; Hooks tab: every import with how it is handled, then hooks on
     * anything that is not an import.
     */
    public void showImports(List<Map<String, Object>> imports, List<AngrHooks.Hook> hooks, String problem) {
        List<Map<String, Object>> shown = new ArrayList<>();
        List<Object[]> data = new ArrayList<>();
        Set<String> listed = new HashSet<>();
        int missing = 0;
        int stubs = 0;
        Map<String, AngrHooks.Hook> byName = new HashMap<>();
        for (AngrHooks.Hook hook : hooks) {
            byName.put(hook.name, hook);
        }
        for (Map<String, Object> entry : imports) {
            Map<String, Object> row = new LinkedHashMap<>(entry);
            row.put("target", entry.get("name"));
            AngrHooks.Hook hook = entry.get("hook") == null ? null : byName.get(text(entry.get("hook")));
            String handled = text(entry.get("handledBy"));
            if (hook != null) {
                row.put("hookObject", hook);
                listed.add(hook.name);
                handled = "python hook: " + hook.name;
            }
            else if ("angr model".equals(handled)) {
                handled = "angr model";
            }
            else {
                handled = symbolicImports.isSelected() ? "unknown value (symbolic)" : "returns 0";
                stubs++;
            }
            boolean inProject = Boolean.TRUE.equals(entry.get("libraryInProject"));
            if (entry.get("library") != null && !inProject) {
                missing++;
            }
            row.put("stub", hook == null && !"angr model".equals(entry.get("handledBy")));
            shown.add(row);
            data.add(new Object[] { entry.get("name"), entry.get("library") == null ? "(unknown)" : entry.get("library"),
                entry.get("library") == null ? "" : inProject ? "yes" : "no", handled });
        }
        for (AngrHooks.Hook hook : hooks) {
            if (listed.contains(hook.name)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("target", hook.target);
            row.put("hook", hook.name);
            row.put("hookObject", hook);
            shown.add(row);
            data.add(new Object[] { hook.target, "(this program)", "",
                "python hook: " + hook.name + (hook.enabled ? "" : "  (disabled)")
                    + (AngrHooks.KIND_INLINE.equals(hook.kind) ? "  [runs at address]" : "") });
        }
        fill("imports", shown, data);
        if (problem != null) {
            importsNote.setText(problem);
            importsNote.setToolTipText(problem);
            importsNote.setForeground(palette.error);
        }
        else {
            importsNote.setForeground(palette.muted);
            importsNote.setText(imports.size() + " imports, " + stubs + " with no model or hook"
                + (missing > 0 ? ", " + missing + " from libraries not in the project" : "")
                + ". Double-click one to write a Python replacement.");
            importsNote.setToolTipText("<html>None of this blocks a run: an import is never followed into its "
                + "library, so the library does not have to be in the project.<br>Each call is handled by your "
                + "Python hook, else angr's own model of the function, else a stub that returns an unknown value "
                + "(or 0).</html>");
        }
        retitle();
    }

    private void fill(String key, List<Map<String, Object>> data) {
        fill(key, data, List.of());
    }

    private void fill(String key, List<Map<String, Object>> data, List<Object[]> cells) {
        JTable table = tables.get(key);
        int selected = table.getSelectedRow();
        rows.put(key, new ArrayList<>(data));
        DefaultTableModel model = (DefaultTableModel) table.getModel();
        model.setRowCount(0);
        for (Object[] row : cells) {
            model.addRow(row);
        }
        if (selected >= 0 && selected < model.getRowCount()) {
            table.setRowSelectionInterval(selected, selected);
        }
    }

    private void retitle() {
        for (String name : List.of("Calls", "Paths", "Symbols", "Memory")) {
            int count = rows.get(name.toLowerCase()) == null ? 0 : rows.get(name.toLowerCase()).size();
            if (!detached) {
                tabs.setTitleAt(indexOfBase(name), count > 0 ? name + " (" + count + ")" : name);
            }
            if (viewHost != null) {
                viewHost.countChanged(name, count);
            }
        }
    }

    private int indexOfBase(String name) {
        for (int i = 0; i < tabs.getTabCount(); i++) {
            String title = tabs.getTitleAt(i);
            if (title.equals(name) || title.startsWith(name + " (")) {
                return i;
            }
        }
        return -1;
    }

    private static String valueOf(Map<String, Object> row) {
        if (row.get("value") != null) {
            return text(row.get("value"));
        }
        return row.get("symbolic") != null ? "<symbolic>" : "";
    }

    private static String notesOf(Map<String, Object> row) {
        StringBuilder sb = new StringBuilder();
        if (row.get("symbolic") != null) {
            sb.append(row.get("symbolic"));
            if (row.get("example") != null) {
                sb.append("  e.g. ").append(row.get("example"));
            }
            else if (Boolean.TRUE.equals(row.get("pinned"))) {
                sb.append("  (fixed)");
            }
        }
        if (row.get("label") != null) {
            sb.append(sb.length() > 0 ? "  " : "").append(row.get("label"));
        }
        if (row.get("string") != null) {
            sb.append(sb.length() > 0 ? "  " : "").append('"').append(row.get("string")).append('"');
        }
        return sb.toString();
    }

    private static String spaced(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 1 < hex.length() && i < 64; i += 2) {
            sb.append(hex, i, i + 2).append(' ');
        }
        return hex.length() > 64 ? sb + "..." : sb.toString().stripTrailing();
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static int number(Object value) {
        return value instanceof Number n ? n.intValue() : 0;
    }

    // ---- for tests and the provider ----

    public JButton button(String name) {
        return buttons.get(name);
    }

    public JTable table(String name) {
        return tables.get(name);
    }

    public List<Map<String, Object>> rows(String name) {
        return rows.getOrDefault(name, List.of());
    }

    public String bannerTitle() {
        return bannerTitle.getText();
    }

    public String bannerDetail() {
        return bannerDetail.getText();
    }

    public String outputText() {
        return output.getText();
    }

    public JTabbedPane tabs() {
        return tabs;
    }

    /** Brings a view forward: its tab here, or its window when the views are detached. */
    public void selectTab(String name) {
        if (viewHost != null) {
            viewHost.showView(name);
        }
        if (detached) {
            return;
        }
        int index = indexOfBase(name);
        if (index >= 0) {
            tabs.setSelectedIndex(index);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Look
    // ---------------------------------------------------------------------------------------

    /** Colours that read on both light and dark themes, chosen from the panel background. */
    private static final class Palette {
        final Color text;
        final Color muted;
        final Color ok;
        final Color error;
        final Color warn;
        final Color info;
        final Color changed;

        Palette() {
            Color background = UIManager.getColor("Panel.background");
            Color foreground = UIManager.getColor("Label.foreground");
            boolean dark = background != null
                && (background.getRed() * 299 + background.getGreen() * 587 + background.getBlue() * 114) / 1000 < 128;
            text = foreground != null ? foreground : (dark ? Color.WHITE : Color.BLACK);
            muted = dark ? new Color(0xA0A4AB) : new Color(0x666B73);
            ok = dark ? new Color(0x7BC47F) : new Color(0x2E7D32);
            error = dark ? new Color(0xF08A84) : new Color(0xC62828);
            warn = dark ? new Color(0xF2B866) : new Color(0xA85B00);
            info = dark ? new Color(0x82B4F0) : new Color(0x1E5FB4);
            changed = dark ? new Color(0xF2B866) : new Color(0xB3261E);
        }
    }

    /** Marks what the last step changed, unknown values, and rows that deserve attention. */
    private final class RowRenderer extends DefaultTableCellRenderer {
        private final String key;

        RowRenderer(String key) {
            this.key = key;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            List<Map<String, Object>> data = rows.get(key);
            Map<String, Object> entry = data != null && row < data.size() ? data.get(row) : Map.of();
            Font font = mono;
            Color color = selected ? table.getSelectionForeground() : table.getForeground();
            if (!selected) {
                switch (key) {
                    case "registers":
                        if (Boolean.TRUE.equals(entry.get("changed"))) {
                            color = palette.changed;
                            font = mono.deriveFont(Font.BOLD);
                        }
                        else if (entry.get("symbolic") != null && column > 0) {
                            color = palette.warn;
                        }
                        break;
                    case "stack":
                        if (entry.get("symbolic") != null && column >= 2) {
                            color = palette.warn;
                        }
                        break;
                    case "paths":
                        if (Boolean.TRUE.equals(entry.get("current"))) {
                            font = mono.deriveFont(Font.BOLD);
                        }
                        break;
                    case "symbols":
                        if (entry.get("value") == null) {
                            color = palette.warn;
                        }
                        break;
                    case "calls":
                        if (entry.get("log") != null) {
                            color = palette.muted;
                        }
                        else if (Boolean.TRUE.equals(entry.get("stubbed"))) {
                            color = palette.warn;
                        }
                        break;
                    case "imports":
                        if (column == 3) {
                            color = entry.get("hookObject") != null ? palette.ok
                                : Boolean.TRUE.equals(entry.get("stub")) ? palette.warn : color;
                        }
                        break;
                    default:
                        break;
                }
            }
            c.setFont(font);
            c.setForeground(color);
            String shown = value == null ? "" : String.valueOf(value);
            setToolTipText(shown.length() > 12 ? shown : null);
            return c;
        }
    }
}
