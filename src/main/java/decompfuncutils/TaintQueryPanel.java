/*
 * TaintQueryPanel - UI for writing and executing taint-aware code pattern queries
 */
package decompfuncutils;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.*;
import docking.WindowPosition;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

public class TaintQueryPanel extends ComponentProviderAdapter {
    
    private JPanel mainPanel;
    private JTextPane queryEditor;
    private JTable resultsTable;
    private DefaultTableModel resultsModel;
    private JComboBox<String> builtinSelector;
    private JLabel statusLabel;
    private JCheckBox searchAllFuncsCheck;
    
    private Program currentProgram;
    private Function currentFunction;
    private HighFunction currentHighFunc;
    private DecompInterface decompiler;
    
    private TaintQueryParser parser;
    private TaintQueryMatcher matcher;
    private TaintLogPanel logPanel;
    
    private List<TaintQueryMatcher.QueryMatch> currentMatches = new ArrayList<>();
    
    // Syntax highlighting styles
    private Style styleKeyword;
    private Style styleVariable;
    private Style styleFunction;
    private Style styleConstraint;
    private Style styleComment;
    private Style styleNormal;
    
    public TaintQueryPanel(PluginTool tool, String owner, TaintLogPanel logPanel) {
        super(tool, "Taint Query", owner);
        this.logPanel = logPanel;
        this.parser = new TaintQueryParser();
        
        buildPanel();
        setTitle("Taint Query Editor");
        setDefaultWindowPosition(WindowPosition.RIGHT);
    }
    
    private void buildPanel() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        // Top panel - builtin patterns and options
        JPanel topPanel = new JPanel(new BorderLayout(5, 0));
        
        JPanel builtinPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        builtinPanel.add(new JLabel("Builtin Patterns:"));
        
        builtinSelector = new JComboBox<>();
        builtinSelector.addItem("-- Select Pattern --");
        for (String name : TaintQueryParser.getRecommendedPatterns().keySet()) {
            builtinSelector.addItem(name);
        }
        builtinSelector.addActionListener(e -> loadBuiltinPattern());
        builtinPanel.add(builtinSelector);
        
        searchAllFuncsCheck = new JCheckBox("Search all functions", false);
        builtinPanel.add(searchAllFuncsCheck);
        
        topPanel.add(builtinPanel, BorderLayout.WEST);
        
        // Help button
        JButton helpBtn = new JButton("?");
        helpBtn.setToolTipText("Query Syntax Help");
        helpBtn.addActionListener(e -> showHelp());
        topPanel.add(helpBtn, BorderLayout.EAST);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Center - split pane with editor and results
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.4);
        
        // Query editor
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.setBorder(new TitledBorder("Query"));
        
        queryEditor = new JTextPane();
        queryEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        queryEditor.setBackground(new Color(40, 44, 52));
        queryEditor.setCaretColor(Color.WHITE);
        setupSyntaxStyles();
        
        // Add syntax highlighting on text change
        queryEditor.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { highlightSyntax(); }
            public void removeUpdate(DocumentEvent e) { highlightSyntax(); }
            public void changedUpdate(DocumentEvent e) { }
        });
        
        JScrollPane editorScroll = new JScrollPane(queryEditor);
        editorScroll.setPreferredSize(new Dimension(400, 150));
        editorPanel.add(editorScroll, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton runBtn = new JButton("▶ Run Query");
        runBtn.addActionListener(e -> runQuery());
        buttonPanel.add(runBtn);
        
        JButton parseBtn = new JButton("Parse");
        parseBtn.addActionListener(e -> parseOnly());
        buttonPanel.add(parseBtn);
        
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            queryEditor.setText("");
            resultsModel.setRowCount(0);
            currentMatches.clear();
        });
        buttonPanel.add(clearBtn);
        
        editorPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        splitPane.setTopComponent(editorPanel);
        
        // Results table
        JPanel resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.setBorder(new TitledBorder("Results"));
        
        resultsModel = new DefaultTableModel(
            new String[] { "Function", "Address", "Match", "Confidence" }, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        
        resultsTable = new JTable(resultsModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(250);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        
        // Double-click to navigate
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    navigateToMatch();
                }
            }
        });
        
        JScrollPane resultsScroll = new JScrollPane(resultsTable);
        resultsPanel.add(resultsScroll, BorderLayout.CENTER);
        
        splitPane.setBottomComponent(resultsPanel);
        
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Status bar
        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(new EmptyBorder(3, 5, 3, 5));
        mainPanel.add(statusLabel, BorderLayout.SOUTH);
        
        // Set default query
        queryEditor.setText("// Enter a query or select a builtin pattern\n" +
            "// Example: strcpy($dst, $src) WHERE tainted($src)\n\n" +
            "PATTERN example {\n" +
            "    strcpy($dst, $src);\n" +
            "} WHERE tainted($src)");
        highlightSyntax();
    }
    
    private void setupSyntaxStyles() {
        StyledDocument doc = queryEditor.getStyledDocument();
        Style defaultStyle = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
        
        styleNormal = doc.addStyle("normal", defaultStyle);
        StyleConstants.setForeground(styleNormal, new Color(171, 178, 191));
        
        styleKeyword = doc.addStyle("keyword", defaultStyle);
        StyleConstants.setForeground(styleKeyword, new Color(198, 120, 221));
        StyleConstants.setBold(styleKeyword, true);
        
        styleVariable = doc.addStyle("variable", defaultStyle);
        StyleConstants.setForeground(styleVariable, new Color(224, 108, 117));
        
        styleFunction = doc.addStyle("function", defaultStyle);
        StyleConstants.setForeground(styleFunction, new Color(97, 175, 239));
        
        styleConstraint = doc.addStyle("constraint", defaultStyle);
        StyleConstants.setForeground(styleConstraint, new Color(152, 195, 121));
        
        styleComment = doc.addStyle("comment", defaultStyle);
        StyleConstants.setForeground(styleComment, new Color(92, 99, 112));
        StyleConstants.setItalic(styleComment, true);
    }
    
    private void highlightSyntax() {
        SwingUtilities.invokeLater(() -> {
            StyledDocument doc = queryEditor.getStyledDocument();
            String text = queryEditor.getText();
            
            // Reset to normal style
            doc.setCharacterAttributes(0, text.length(), styleNormal, true);
            
            // Keywords
            highlightPattern(doc, text, "\\b(PATTERN|WHERE|AND|OR|NOT)\\b", styleKeyword);
            
            // Variables ($var)
            highlightPattern(doc, text, "\\$\\w+", styleVariable);
            
            // Constraint functions
            highlightPattern(doc, text, "\\b(tainted_ext|tainted|flows_to|is_constant|is_param|is_local|unchecked|bounded"
                + "|nonneg_checked|overflow_checked|signed|same|related|returned_by|in_loop|function_is|function_in"
                + "|const_eq|const_ne|const_lt|const_le|const_gt|const_ge)\\s*\\(", styleConstraint);

            // Gap clauses
            highlightPattern(doc, text, "\\b(not|guard):", styleKeyword);

            // Function calls
            highlightPattern(doc, text, "\\b(strcpy|strcat|sprintf|snprintf|memcpy|memmove|printf|system|malloc|calloc"
                + "|realloc|free|gets|read|recv|fopen|open|access|execve|execl|popen)\\b", styleFunction);
            
            // Comments
            highlightPattern(doc, text, "//[^\n]*", styleComment);
        });
    }
    
    private void highlightPattern(StyledDocument doc, String text, String regex, Style style) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex, 
            java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(text);
        
        while (matcher.find()) {
            doc.setCharacterAttributes(matcher.start(), matcher.end() - matcher.start(), style, true);
        }
    }
    
    private void loadBuiltinPattern() {
        String selected = (String) builtinSelector.getSelectedItem();
        if (selected == null || selected.startsWith("--")) return;
        
        String pattern = TaintQueryParser.getBuiltinPattern(selected);
        if (pattern != null) {
            queryEditor.setText(pattern);
            highlightSyntax();
        }
    }
    
    private void parseOnly() {
        String queryText = queryEditor.getText();
        
        try {
            TaintQuery query = parser.parse(queryText);
            statusLabel.setText("Parse OK: " + query.getName() + " - " + 
                query.getPatternElements().size() + " elements, " +
                query.getBoundVariables().size() + " variables");
            
            logPanel.logHeader("PARSED QUERY");
            logPanel.logInfo(query.toString());
            
        } catch (TaintQueryParser.ParseException e) {
            statusLabel.setText("Parse Error: " + e.getMessage());
            logPanel.logWarning("Parse error: " + e.getMessage());
        }
    }
    
    private void runQuery() {
        String queryText = queryEditor.getText();
        
        if (currentProgram == null) {
            statusLabel.setText("Error: No program loaded");
            return;
        }
        
        try {
            TaintQuery query = parser.parse(queryText);
            logPanel.logHeader("RUNNING QUERY: " + query.getName());
            logPanel.logInfo(query.toString());
            
            // Clear previous results
            resultsModel.setRowCount(0);
            currentMatches.clear();
            
            if (searchAllFuncsCheck.isSelected()) {
                // Search all functions
                runQueryAllFunctions(query);
            } else {
                // Search current function only
                if (currentHighFunc == null) {
                    statusLabel.setText("Error: No function selected (use in Decompiler window)");
                    return;
                }
                runQuerySingleFunction(query);
            }
            
        } catch (TaintQueryParser.ParseException e) {
            statusLabel.setText("Parse Error: " + e.getMessage());
            logPanel.logWarning("Parse error: " + e.getMessage());
        }
    }
    
    private void runQuerySingleFunction(TaintQuery query) {
        matcher = new TaintQueryMatcher(currentProgram, logPanel);
        
        List<TaintQueryMatcher.QueryMatch> matches = matcher.matchInFunction(query, currentHighFunc);
        currentMatches = matches;
        
        for (TaintQueryMatcher.QueryMatch match : matches) {
            resultsModel.addRow(new Object[] {
                match.function.getName(),
                match.address.toString(),
                match.matchedCode,
                String.format("%.0f%%", match.confidence * 100)
            });
        }
        
        statusLabel.setText("Found " + matches.size() + " match(es) in " + 
            currentHighFunc.getFunction().getName());
    }
    
    private void runQueryAllFunctions(TaintQuery query) {
        statusLabel.setText("Searching all functions...");
        
        TaskLauncher.launch(new Task("Query All Functions", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                // Create decompiler
                DecompInterface decomp = new DecompInterface();
                DecompileOptions options = new DecompileOptions();
                decomp.setOptions(options);
                decomp.openProgram(currentProgram);
                
                try {
                    matcher = new TaintQueryMatcher(currentProgram, logPanel);
                    List<TaintQueryMatcher.QueryMatch> matches = 
                        matcher.matchInAllFunctions(query, decomp, monitor);
                    currentMatches = matches;
                    
                    SwingUtilities.invokeLater(() -> {
                        for (TaintQueryMatcher.QueryMatch match : matches) {
                            resultsModel.addRow(new Object[] {
                                match.function.getName(),
                                match.address.toString(),
                                match.matchedCode,
                                String.format("%.0f%%", match.confidence * 100)
                            });
                        }
                        statusLabel.setText("Found " + matches.size() + " match(es) in program");
                    });
                } finally {
                    decomp.dispose();
                }
            }
        });
    }
    
    private void navigateToMatch() {
        int row = resultsTable.getSelectedRow();
        if (row < 0 || row >= currentMatches.size()) return;
        
        TaintQueryMatcher.QueryMatch match = currentMatches.get(row);
        
        // Navigate to the address
        if (match.address != null) {
            tool.getService(ghidra.app.services.GoToService.class)
                .goTo(match.address);
        }
    }
    
    private void showHelp() {
        String help = 
            "TAINT QUERY SYNTAX\n" +
            "==================\n\n" +
            "BASIC PATTERN:\n" +
            "  funcname($arg1, $arg2, ...)\n" +
            "  Example: strcpy($dst, $src)\n\n" +
            "FULL PATTERN:\n" +
            "  PATTERN name {\n" +
            "      // C-like code pattern\n" +
            "  } WHERE constraints\n\n" +
            "VARIABLES:\n" +
            "  $name - Binds to a value; a second use must be the same value\n" +
            "  _     - Wildcard (any argument / any value)\n" +
            "  ...   - As an argument: any remaining arguments\n\n" +
            "STATEMENTS (matched in control-flow order):\n" +
            "  f($a, _, ...)           - Call; $f(...) binds the function name\n" +
            "  f(g($x), $a * $b)       - Nested call / arithmetic argument\n" +
            "                            operators: + - * / % << >> & | ^\n" +
            "                            operands: $var, _, numbers\n" +
            "  $p = f(...)             - Call result;  $s = $a * $b;  $x = $y\n" +
            "  *$p                     - Read or write through $p (also $p->f, $p[i])\n" +
            "  *$p = $v                - Write through $p\n" +
            "  $p == 0   $n < $max     - Comparison that decides a branch\n" +
            "  char $buf[$n]           - Local array ($n = size in bytes; [_] any)\n" +
            "  ...                     - Gap: any code in between\n" +
            "  ...{0,5}                - Gap of at most 5 statements\n" +
            "  ... not:$p=_            - Gap in which $p is not reassigned\n" +
            "  ... not:free($p)        - Gap without that call (arguments checked)\n" +
            "  ... not:($p == 0)       - Gap without a branch on that comparison\n" +
            "  ... guard:($p == 0)     - Gap that contains such a branch\n" +
            "  _                       - Exactly one statement in between\n" +
            "  Unknown syntax is reported as a parse error.\n\n" +
            "CONSTRAINTS:\n" +
            "  tainted_ext($var)       - Tainted by real input (getenv, read, recv,\n" +
            "                            fgets, scanf...), directly or through a buffer\n" +
            "                            filled by strcpy/strcat/sprintf/memcpy...\n" +
            "  tainted($var)           - Same, but every function parameter also\n" +
            "                            counts as a source (broader, noisier)\n" +
            "  tainted($var, \"src\")    - Tainted by specific source\n" +
            "  flows_to($a, $b)        - Data flows from $a to $b\n" +
            "  unchecked($var)         - Never compared in a branch condition\n" +
            "                            (pointers: never compared with a constant)\n" +
            "  bounded($var)           - Compared with <, <=, >, >= in a branch\n" +
            "  nonneg_checked($var)    - A branch rejects negative values\n" +
            "  overflow_checked($a,$b) - Operands are bounded, or a division /\n" +
            "                            carry check guards the computation\n" +
            "  signed($var)            - Sign-extended, or a signed variable\n" +
            "  same($a, $b)            - Same value (casts/extensions ignored)\n" +
            "  related($a, $b)         - One derives from the other, both read the\n" +
            "                            same location, or they are compared\n" +
            "  returned_by($v, \"f\",..) - Value is the result of a call to f\n" +
            "  const_eq($a, N)         - Constant comparisons; also const_ne,\n" +
            "                            const_lt, const_le, const_gt, const_ge;\n" +
            "                            second operand: number or $var\n" +
            "  in_loop() / in_loop($v) - Last matched statement / $v's site is in a loop\n" +
            "  function_in($f, \"a\", \"b\") - Bound function name is one of these\n" +
            "  function_is($f, \"a\")    - Bound function name is a\n" +
            "  is_constant($var)       - Variable is a constant\n" +
            "  is_param($var)          - Variable is a parameter\n" +
            "  is_local($var)          - Variable is a local\n" +
            "  NOT constraint          - Negation\n" +
            "  c1 AND c2               - Both must be true\n" +
            "  c1 OR c2                - Either must be true\n\n" +
            "EXAMPLES:\n" +
            "  // Format string vulnerability\n" +
            "  printf($fmt) WHERE tainted_ext($fmt) AND NOT is_constant($fmt)\n\n" +
            "  // Command built in a buffer, then executed\n" +
            "  PATTERN cmd {\n" +
            "      sprintf($buf, ...);\n" +
            "      ...;\n" +
            "      system($buf);\n" +
            "  } WHERE tainted_ext($buf)\n\n" +
            "  // Buffer overflow\n" +
            "  PATTERN bof {\n" +
            "      char $buf[_];\n" +
            "      strcpy($buf, $src);\n" +
            "  } WHERE tainted_ext($src)\n\n" +
            "  // Allocation size overflow\n" +
            "  malloc($a * $b) WHERE tainted_ext($a) AND NOT overflow_checked($a, $b)\n\n" +
            "  // Unchecked allocation\n" +
            "  PATTERN nullderef {\n" +
            "      $p = malloc(_);\n" +
            "      ... not:$p=_;\n" +
            "      *$p;\n" +
            "  } WHERE unchecked($p)\n\n" +
            "  // Use-after-free\n" +
            "  PATTERN uaf {\n" +
            "      free($ptr);\n" +
            "      ... not:$ptr=_;\n" +
            "      *$ptr;\n" +
            "  }";
        
        JTextArea textArea = new JTextArea(help);
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(640, 560));
        
        JOptionPane.showMessageDialog(mainPanel, scrollPane, 
            "Query Syntax Help", JOptionPane.INFORMATION_MESSAGE);
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
    
    // Called from the main plugin to update context
    public void setContext(Program program, Function function, HighFunction highFunc) {
        this.currentProgram = program;
        this.currentFunction = function;
        this.currentHighFunc = highFunc;
        
        if (function != null) {
            statusLabel.setText("Current function: " + function.getName());
        }
    }
    
    public void setProgram(Program program) {
        this.currentProgram = program;
    }
}
