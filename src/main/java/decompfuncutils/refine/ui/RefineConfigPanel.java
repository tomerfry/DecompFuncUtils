package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.pass.RefinePass;
import decompfuncutils.refine.pass.RefinePasses;
import decompfuncutils.refine.rules.Rule;
import decompfuncutils.refine.rules.RuleSet;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.Scrollable;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Editor for a {@link RefineConfig}. Every control writes straight into the configuration and
 * reports the change, so whoever owns the panel can re-run the engine while the user is still
 * adjusting -- which is the point: the refined code is a function of this panel.
 */
public final class RefineConfigPanel extends JPanel implements Scrollable {
    /** Ready-made configurations offered at the top of the panel. */
    public static final Map<String, java.util.function.Supplier<RefineConfig>> PRESETS = presets();

    private RefineConfig config;
    private final Runnable onChange;
    private boolean loading;
    private JLabel ruleStatus;
    private JComboBox<String> presetBox;

    public RefineConfigPanel(RefineConfig config, Runnable onChange) {
        this.config = config.copy();
        this.onChange = onChange;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
        rebuild();
    }

    /** The configuration as currently edited. The caller should copy it before handing it to another thread. */
    public RefineConfig config() { return config; }

    /** Replace the configuration and show it. Does not report a change. */
    public void setConfig(RefineConfig replacement) {
        config = replacement.copy();
        rebuild();
    }

    private static Map<String, java.util.function.Supplier<RefineConfig>> presets() {
        Map<String, java.util.function.Supplier<RefineConfig>> m = new LinkedHashMap<>();
        m.put("Default", RefineConfig::defaults);
        m.put("Proved rewrites only", () -> {
            RefineConfig c = RefineConfig.defaults();
            c.rejectUnverified = true;
            // These justify themselves by testing, not proof.
            for (String id : new String[] {"fold-temps", "select", "loop-idioms", "stores", "inline", "const-calls"}) c.pass(id).enabled = false;
            return c;
        });
        m.put("Everything", () -> {
            RefineConfig c = RefineConfig.defaults();
            for (RuleSet.Group g : RuleSet.builtin().groups.values()) c.ruleGroups.put(g.name, true);
            c.pass("select").params.put("evidence", "always");
            c.pass("opaque").params.put("loops", true);
            c.maxRounds = 8;
            return c;
        });
        m.put("Decompiler output (no passes)", RefineConfig::passthrough);
        return m;
    }

    private void changed() {
        if (loading) return;
        if (presetBox != null && presetBox.getSelectedIndex() != 0) {
            loading = true;
            presetBox.setSelectedIndex(0);
            loading = false;
        }
        onChange.run();
    }

    // ------------------------------------------------------------------ layout

    private void rebuild() {
        loading = true;
        removeAll();
        add(presetRow());
        add(section("Passes", "Run top to bottom, repeated while they keep changing the code. Order matters: use the arrows."));
        for (int i = 0; i < config.passes.size(); i++) add(passRow(i));
        add(section("Rule groups", "Built-in rewrite rules, used by the 'Rewrite rules' pass."));
        for (RuleSet.Group g : RuleSet.builtin().groups.values()) add(groupRow(g));
        add(section("Your rules", "name: pattern => replacement where guard.   $x any expression, $c:const a constant."));
        add(rulesEditor());
        add(section("Verification", "How a rewrite earns its place."));
        add(verificationRows());
        add(section("Output", null));
        add(outputRows());
        add(Box.createVerticalGlue());
        loading = false;
        revalidate();
        repaint();
    }

    private static <T extends JComponent> T left(T c) {
        c.setAlignmentX(Component.LEFT_ALIGNMENT);
        return c;
    }

    private JComponent section(String title, String hint) {
        JPanel p = left(new JPanel());
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(12, 0, 4, 0));
        JLabel t = left(new JLabel(title));
        t.setFont(t.getFont().deriveFont(Font.BOLD));
        p.add(t);
        if (hint != null) p.add(hint(hint));
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }

    /** Explanatory text that wraps to whatever width the panel has. */
    private static JComponent hint(String text) {
        JTextArea h = left(new JTextArea(text) {
            @Override public Dimension getMaximumSize() { return new Dimension(Integer.MAX_VALUE, getPreferredSize().height); }
        });
        h.setEditable(false);
        h.setFocusable(false);
        h.setOpaque(false);
        h.setLineWrap(true);
        h.setWrapStyleWord(true);
        h.setBorder(BorderFactory.createEmptyBorder());
        Font base = new JLabel().getFont();
        h.setFont(base.deriveFont(base.getSize2D() - 1f));
        h.setForeground(RefinedCodeView.dark() ? new Color(0x9a9a9a) : new Color(0x666666));
        return h;
    }

    /**
     * One line of controls, laid out left to right at their natural sizes. It never wraps: in a
     * narrow window the line is clipped at the right edge rather than folded under itself.
     */
    private JPanel row() {
        JPanel p = left(new JPanel() {
            @Override public Component add(Component c) {
                if (getComponentCount() > 0) super.add(Box.createHorizontalStrut(5));
                if (c instanceof JComponent jc && !(c instanceof JLabel) && !(c instanceof JCheckBox)) jc.setMaximumSize(jc.getPreferredSize());
                return super.add(c);
            }
        });
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 0));
        return p;
    }

    private static JPanel cap(JPanel p) {
        if (p.getLayout() instanceof BoxLayout) p.add(Box.createHorizontalGlue());
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }

    private JComponent presetRow() {
        JPanel p = row();
        p.add(new JLabel("Preset"));
        presetBox = new JComboBox<>();
        presetBox.addItem("(custom)");
        for (String name : PRESETS.keySet()) presetBox.addItem(name);
        String current = config.toJson();
        for (Map.Entry<String, java.util.function.Supplier<RefineConfig>> e : PRESETS.entrySet()) {
            if (e.getValue().get().toJson().equals(current)) presetBox.setSelectedItem(e.getKey());
        }
        presetBox.addActionListener(e -> {
            if (loading || presetBox.getSelectedIndex() <= 0) return;
            String keepRules = config.userRules;
            config = PRESETS.get((String) presetBox.getSelectedItem()).get();
            config.userRules = keepRules;   // a preset is about the engine, not about what you wrote
            String chosen = (String) presetBox.getSelectedItem();
            rebuild();
            loading = true;
            presetBox.setSelectedItem(chosen);
            loading = false;
            onChange.run();
        });
        p.add(presetBox);
        return cap(p);
    }

    private JComponent passRow(int index) {
        RefineConfig.PassSetting setting = config.passes.get(index);
        RefinePass pass = RefinePasses.byId(setting.id);
        JPanel box = left(new JPanel());
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        JPanel head = left(new JPanel(new BorderLayout(4, 0)));
        JCheckBox enabled = new JCheckBox(pass.title(), setting.enabled);
        enabled.setToolTipText("<html><body style='width:380px'>" + pass.description() + "<br><br><i>id: " + pass.id() + "</i></body></html>");
        head.add(enabled, BorderLayout.CENTER);
        JPanel arrows = new JPanel(new FlowLayout(FlowLayout.RIGHT, 1, 0));
        arrows.add(arrow("▲", "Run earlier", index > 0, () -> movePass(index, -1)));
        arrows.add(arrow("▼", "Run later", index < config.passes.size() - 1, () -> movePass(index, 1)));
        head.add(arrows, BorderLayout.EAST);
        box.add(cap(head));
        JPanel params = left(new JPanel());
        params.setLayout(new BoxLayout(params, BoxLayout.Y_AXIS));
        params.setBorder(BorderFactory.createEmptyBorder(0, 22, 2, 0));
        for (RefinePass.Param p : pass.params()) params.add(paramRow(setting, p));
        params.setVisible(setting.enabled && !pass.params().isEmpty());
        box.add(params);
        enabled.addActionListener(e -> {
            setting.enabled = enabled.isSelected();
            params.setVisible(setting.enabled && !pass.params().isEmpty());
            revalidate();
            changed();
        });
        return box;
    }

    private JButton arrow(String glyph, String tip, boolean enabled, Runnable action) {
        JButton b = new JButton(glyph);
        b.setMargin(new Insets(0, 3, 0, 3));
        b.setFont(b.getFont().deriveFont(9f));
        b.setFocusable(false);
        b.setToolTipText(tip);
        b.setEnabled(enabled);
        b.addActionListener(e -> action.run());
        return b;
    }

    private void movePass(int index, int by) {
        RefineConfig.PassSetting s = config.passes.remove(index);
        config.passes.add(index + by, s);
        rebuild();
        changed();
    }

    private JComponent paramRow(RefineConfig.PassSetting setting, RefinePass.Param p) {
        JPanel row = row();
        Object value = setting.params.getOrDefault(p.key, p.defaultValue);
        String tip = "<html><body style='width:340px'>" + p.help + "</body></html>";
        switch (p.type) {
            case BOOL -> {
                JCheckBox box = new JCheckBox(p.label, value instanceof Boolean b ? b : Boolean.parseBoolean(String.valueOf(value)));
                box.setToolTipText(tip);
                box.addActionListener(e -> { setting.params.put(p.key, box.isSelected()); changed(); });
                row.add(box);
            }
            case INT -> {
                int v = value instanceof Number n ? n.intValue() : (Integer) p.defaultValue;
                JSpinner spin = new JSpinner(new SpinnerNumberModel(Math.max(p.min, Math.min(p.max, v)), p.min, p.max, 1));
                spin.setToolTipText(tip);
                ((JSpinner.DefaultEditor) spin.getEditor()).getTextField().setColumns(5);
                spin.addChangeListener(e -> { setting.params.put(p.key, ((Number) spin.getValue()).intValue()); changed(); });
                JLabel label = new JLabel(p.label);
                label.setToolTipText(tip);
                row.add(label);
                row.add(spin);
            }
            case CHOICE -> {
                JComboBox<String> combo = new JComboBox<>(p.choices.toArray(new String[0]));
                String longest = "";
                for (String choice : p.choices) if (choice.length() > longest.length()) longest = choice;
                combo.setPrototypeDisplayValue(longest + "mm");   // room for the arrow in every look and feel
                combo.setSelectedItem(String.valueOf(value));
                combo.setToolTipText(tip);
                combo.addActionListener(e -> { setting.params.put(p.key, combo.getSelectedItem()); changed(); });
                JLabel label = new JLabel(p.label);
                label.setToolTipText(tip);
                row.add(label);
                row.add(combo);
            }
        }
        return cap(row);
    }

    private JComponent groupRow(RuleSet.Group g) {
        JPanel row = row();
        JCheckBox box = new JCheckBox(g.name, config.groupEnabled(g.name, g.enabledByDefault));
        StringBuilder tip = new StringBuilder("<html><b>").append(g.description).append("</b><pre>");
        for (Rule r : g.rules) tip.append(r.source.replace("&", "&amp;").replace("<", "&lt;").replaceAll("\\s+where\\s+", "\n      where ")).append('\n');
        box.setToolTipText(tip.append("</pre></html>").toString());
        box.addActionListener(e -> { config.ruleGroups.put(g.name, box.isSelected()); changed(); });
        row.add(box);
        JLabel what = new JLabel(g.description, SwingConstants.LEFT);
        what.setForeground(RefinedCodeView.dark() ? new Color(0x9a9a9a) : new Color(0x666666));
        what.setFont(what.getFont().deriveFont(what.getFont().getSize2D() - 1f));
        what.setMinimumSize(new Dimension(0, 0));
        what.setToolTipText(g.description);
        row.add(what);
        return cap(row);
    }

    private JComponent rulesEditor() {
        JPanel p = left(new JPanel(new BorderLayout(0, 2)));
        JTextArea area = new JTextArea(config.userRules, 6, 30);
        area.setFont(RefinedCodeView.codeFont());
        area.setLineWrap(false);
        area.setToolTipText("<html>One rule per line, e.g.<pre>times3: ($x &lt;&lt; 1) + $x =&gt; $x * 3\n"
            + "low-byte: $x &amp; 0xff =&gt; (uchar)$x where bits($x) &gt; 8</pre>"
            + "Every match is tested and, where the solver can, proved before it is applied.</html>");
        ruleStatus = new JLabel(" ");
        ruleStatus.setFont(ruleStatus.getFont().deriveFont(ruleStatus.getFont().getSize2D() - 1f));
        describeRules(area.getText());
        area.getDocument().addDocumentListener(new DocumentListener() {
            private void edit() {
                config.userRules = area.getText();
                describeRules(config.userRules);
                changed();
            }
            @Override public void insertUpdate(DocumentEvent e) { edit(); }
            @Override public void removeUpdate(DocumentEvent e) { edit(); }
            @Override public void changedUpdate(DocumentEvent e) { }
        });
        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(320, 120));
        p.add(scroll, BorderLayout.CENTER);
        p.add(ruleStatus, BorderLayout.SOUTH);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 170));
        return p;
    }

    private void describeRules(String text) {
        if (text.isBlank()) {
            ruleStatus.setText("No rules of your own.");
            ruleStatus.setForeground(RefinedCodeView.dark() ? new Color(0x9a9a9a) : new Color(0x666666));
            return;
        }
        RuleSet set = RuleSet.parse(text, "user");
        if (set.problems.isEmpty()) {
            ruleStatus.setText(set.size() + (set.size() == 1 ? " rule" : " rules") + " parsed.");
            ruleStatus.setForeground(RefinedCodeView.dark() ? new Color(0x7fc77f) : new Color(0x1e7a1e));
        } else {
            ruleStatus.setText("<html>" + set.problems.get(0).toString().replace("<", "&lt;")
                + (set.problems.size() > 1 ? " (+" + (set.problems.size() - 1) + " more)" : "") + "</html>");
            ruleStatus.setForeground(RefinedCodeView.dark() ? new Color(0xf08080) : new Color(0xb00020));
        }
    }

    private JComponent verificationRows() {
        JPanel box = left(new JPanel());
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        JPanel mode = row();
        JComboBox<String> how = new JComboBox<>(new String[] {"prove", "test", "off"});
        how.setSelectedItem(config.verification);
        how.setToolTipText("<html>prove: test on concrete inputs, then ask Z3 for a proof<br>test: concrete differential testing only<br>"
            + "off: apply every rewrite unchecked (labelled 'assumed')</html>");
        how.addActionListener(e -> { config.verification = (String) how.getSelectedItem(); changed(); });
        mode.add(new JLabel("Check rewrites by"));
        mode.add(how);
        box.add(cap(mode));
        box.add(check("Refuse rewrites that could not be checked", config.rejectUnverified,
            "Otherwise they are applied and marked as 'assumed'.", v -> config.rejectUnverified = v));
        box.add(spin("Concrete trials per rewrite", config.trials, 1, 1000, "Runs of original against replacement.", v -> config.trials = v));
        box.add(spin("Solver time limit (ms)", config.solverTimeoutMs, 10, 30000, "Per Z3 query; a query that times out falls back to the test result.",
            v -> config.solverTimeoutMs = v));
        box.add(check("Compare refined code with the machine code under the emulator", config.validate,
            "After refining, run the function's instructions and the refined C on the same inputs and report any difference.",
            v -> config.validate = v));
        box.add(spin("Emulator runs", config.validateTrials, 1, 500, "Input sets tried in the whole-function comparison.", v -> config.validateTrials = v));
        return box;
    }

    private JComponent outputRows() {
        JPanel box = left(new JPanel());
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        box.add(spin("Pipeline rounds at most", config.maxRounds, 1, 16, "The pass list repeats while passes keep changing the code.", v -> config.maxRounds = v));
        box.add(check("Bracket shifts and arithmetic inside bitwise operators", config.clarifyParens,
            "(a << 3) | (b >> 5) rather than a << 3 | b >> 5.", v -> config.clarifyParens = v));
        JPanel lit = row();
        JComboBox<String> literals = new JComboBox<>(new String[] {"auto", "hex", "dec"});
        literals.setSelectedItem(config.literals);
        literals.setToolTipText("How constants the engine computed are written. Constants the decompiler printed keep their form.");
        literals.addActionListener(e -> { config.literals = (String) literals.getSelectedItem(); changed(); });
        lit.add(new JLabel("New constants as"));
        lit.add(literals);
        box.add(cap(lit));
        box.add(check("Hide declarations of variables no longer used", config.dropUnusedLocals, "", v -> config.dropUnusedLocals = v));
        box.add(check("Explain what passes declined to rewrite", config.trace,
            "Adds a note for each loop or call a pass examined and left alone, with the reason.", v -> config.trace = v));
        return box;
    }

    private JComponent check(String label, boolean value, String tip, java.util.function.Consumer<Boolean> set) {
        JPanel row = row();
        JCheckBox box = new JCheckBox(label, value);
        if (!tip.isEmpty()) box.setToolTipText(tip);
        box.addActionListener(e -> { set.accept(box.isSelected()); changed(); });
        row.add(box);
        return cap(row);
    }

    private JComponent spin(String label, int value, int min, int max, String tip, java.util.function.IntConsumer set) {
        JPanel row = row();
        JSpinner spin = new JSpinner(new SpinnerNumberModel(Math.max(min, Math.min(max, value)), min, max, 1));
        ((JSpinner.DefaultEditor) spin.getEditor()).getTextField().setColumns(5);
        spin.setToolTipText(tip);
        spin.addChangeListener(e -> { set.accept(((Number) spin.getValue()).intValue()); changed(); });
        JLabel l = new JLabel(label);
        l.setToolTipText(tip);
        row.add(l);
        row.add(spin);
        return cap(row);
    }

    // ------------------------------------------------------------------ Scrollable: fill the width, scroll vertically

    @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
    @Override public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction) { return 16; }
    @Override public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction) { return 160; }
    @Override public boolean getScrollableTracksViewportWidth() { return true; }
    @Override public boolean getScrollableTracksViewportHeight() { return false; }
}
