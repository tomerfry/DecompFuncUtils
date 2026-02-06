/*
 * FlowLauncherPlugin
 *
 * A "Search Everywhere" / command-palette style launcher for Ghidra.
 * Press Ctrl+Shift+P (or the configured keybinding) to open a floating
 * search dialog that fuzzy-matches across:
 *
 *   - Functions (name, demangled, address)
 *   - Labels / Symbols
 *   - Defined Strings
 *   - Bookmarks
 *   - Comments (plate, pre, post, EOL)
 *   - Ghidra Actions (command palette)
 *   - Addresses (direct "go to" if input looks like hex)
 *
 * Results are ranked by fuzzy match score and grouped by category.
 * Arrow keys navigate, Enter activates, Esc closes, Tab cycles category filters.
 *
 * Licensed under the Apache License 2.0.
 */

package decompfuncutils;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.KeyBindingData;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.Timer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Flow Launcher",
    description = "Quick-search launcher for navigating functions, symbols, "
                + "strings, bookmarks, comments, actions, and addresses.",
    servicesRequired = { GoToService.class }
)
//@formatter:on
public class FlowLauncherPlugin extends ProgramPlugin {

    private DockingAction openLauncherAction;
    private FlowLauncherDialog dialog;

    public FlowLauncherPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        openLauncherAction = new DockingAction("Open Flow Launcher", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                openLauncher();
            }

            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return true;
            }
        };
        openLauncherAction.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_P,
                        InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        openLauncherAction.setDescription("Open the Flow Launcher search dialog");
        openLauncherAction.setEnabled(true);
        tool.addAction(openLauncherAction);
    }

    private void openLauncher() {
        if (dialog != null && dialog.isVisible()) {
            dialog.toFront();
            dialog.focusInput();
            return;
        }

        // Find a parent frame
        Window parent = null;
        try {
            parent = DockingWindowManager.getActiveInstance().getRootFrame();
        } catch (Exception e) {
            parent = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
        }

        dialog = new FlowLauncherDialog(parent);
        dialog.setVisible(true);
    }

    @Override
    protected void dispose() {
        if (dialog != null) {
            dialog.dispose();
            dialog = null;
        }
        if (openLauncherAction != null) {
            tool.removeAction(openLauncherAction);
        }
        super.dispose();
    }

    // ===================================================================
    // LauncherItem — a single searchable entry
    // ===================================================================

    enum ItemCategory {
        FUNCTION("Function", new Color(86, 156, 214)),     // blue
        SYMBOL("Symbol", new Color(78, 201, 176)),          // teal
        STRING("String", new Color(206, 145, 120)),         // orange
        BOOKMARK("Bookmark", new Color(220, 220, 170)),     // yellow
        COMMENT("Comment", new Color(106, 153, 85)),        // green
        ACTION("Action", new Color(197, 134, 192)),         // purple
        ADDRESS("Address", new Color(181, 206, 168));       // light green

        final String label;
        final Color color;

        ItemCategory(String label, Color color) {
            this.label = label;
            this.color = color;
        }
    }

    static class LauncherItem {
        final String displayName;
        final String searchText;    // lowercase, used for matching
        final String detail;        // secondary info (address, type, etc.)
        final ItemCategory category;
        final Address address;      // may be null for actions
        final String actionName;    // non-null only for ACTION items
        int score;                  // fuzzy match score (higher = better)

        LauncherItem(String displayName, String detail, ItemCategory category,
                     Address address, String actionName) {
            this.displayName = displayName;
            this.searchText = displayName.toLowerCase(Locale.ROOT);
            this.detail = detail;
            this.category = category;
            this.address = address;
            this.actionName = actionName;
            this.score = 0;
        }
    }

    // ===================================================================
    // Index builder — collects searchable items from the program
    // ===================================================================

    private List<LauncherItem> buildIndex() {
        List<LauncherItem> items = new ArrayList<>();

        Program program = currentProgram;
        if (program != null) {
            indexFunctions(program, items);
            indexSymbols(program, items);
            indexStrings(program, items);
            indexBookmarks(program, items);
            indexComments(program, items);
        }

        indexActions(items);

        Msg.info(this, "Flow Launcher indexed " + items.size() + " items");
        return items;
    }

    private void indexFunctions(Program program, List<LauncherItem> items) {
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        int count = 0;
        int limit = 50000; // safety limit
        while (iter.hasNext() && count < limit) {
            Function func = iter.next();
            String name = func.getName();
            String detail = func.getEntryPoint().toString();

            // Include signature info if available
            String sig = func.getPrototypeString(false, false);
            if (sig != null && !sig.isEmpty()) {
                detail = sig;
            }

            items.add(new LauncherItem(name, detail, ItemCategory.FUNCTION,
                    func.getEntryPoint(), null));
            count++;
        }
    }

    private void indexSymbols(Program program, List<LauncherItem> items) {
        SymbolTable symTable = program.getSymbolTable();
        SymbolIterator iter = symTable.getAllSymbols(true);
        int count = 0;
        int limit = 50000;

        // Track function entry points so we don't duplicate
        Set<Address> functionAddrs = ConcurrentHashMap.newKeySet();
        FunctionIterator fiter = program.getFunctionManager().getFunctions(true);
        while (fiter.hasNext()) {
            functionAddrs.add(fiter.next().getEntryPoint());
        }

        while (iter.hasNext() && count < limit) {
            Symbol sym = iter.next();
            if (sym.isDynamic()) continue;
            // Skip function symbols (already indexed)
            if (sym.getSymbolType() == SymbolType.FUNCTION) continue;
            if (functionAddrs.contains(sym.getAddress())) continue;

            String name = sym.getName();
            String detail = sym.getAddress().toString() + " [" + sym.getSymbolType() + "]";
            items.add(new LauncherItem(name, detail, ItemCategory.SYMBOL,
                    sym.getAddress(), null));
            count++;
        }
    }

    private void indexStrings(Program program, List<LauncherItem> items) {
        DataIterator iter = program.getListing().getDefinedData(true);
        int count = 0;
        int limit = 20000;
        while (iter.hasNext() && count < limit) {
            Data data = iter.next();
            if (data.hasStringValue()) {
                try {
                    Object val = data.getValue();
                    if (val instanceof String s && !s.isEmpty()) {
                        String display = s;
                        if (display.length() > 80) {
                            display = display.substring(0, 77) + "...";
                        }
                        String detail = data.getAddress().toString()
                                + " [" + data.getDataType().getName() + "]";
                        items.add(new LauncherItem("\"" + display + "\"", detail,
                                ItemCategory.STRING, data.getAddress(), null));
                        count++;
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    private void indexBookmarks(Program program, List<LauncherItem> items) {
        Iterator<Bookmark> iter = program.getBookmarkManager().getBookmarksIterator();
        int count = 0;
        int limit = 10000;
        while (iter.hasNext() && count < limit) {
            Bookmark bm = iter.next();
            String name = bm.getCategory();
            if (name == null || name.isEmpty()) name = bm.getTypeString();
            String comment = bm.getComment();
            if (comment != null && !comment.isEmpty()) {
                name = name + ": " + comment;
            }
            String detail = bm.getAddress().toString() + " [" + bm.getTypeString() + "]";
            items.add(new LauncherItem(name, detail, ItemCategory.BOOKMARK,
                    bm.getAddress(), null));
            count++;
        }
    }

    private void indexComments(Program program, List<LauncherItem> items) {
        // Use string-based comment type names to avoid deprecated constants.
        // We'll access comments via Listing.getComment(Address, int) with raw int values.
        // Comment type int values: EOL=0, PRE=1, POST=2, PLATE=3 (stable across versions)
        int[] commentTypes = { 0, 1, 2, 3 };
        String[] commentLabels = { "EOL", "Pre", "Post", "Plate" };

        Listing listing = program.getListing();
        CodeUnitIterator iter = listing.getCodeUnits(true);
        int count = 0;
        int limit = 20000;

        while (iter.hasNext() && count < limit) {
            CodeUnit cu = iter.next();
            for (int i = 0; i < commentTypes.length; i++) {
                String comment = null;
                try {
                    // Use reflection to call getComment to avoid deprecation
                    comment = listing.getComment(commentTypes[i], cu.getAddress());
                } catch (Exception ignored) {}

                if (comment != null && !comment.isEmpty()) {
                    String display = comment;
                    if (display.length() > 100) {
                        display = display.substring(0, 97) + "...";
                    }
                    String detail = cu.getAddress().toString()
                            + " [" + commentLabels[i] + " comment]";
                    items.add(new LauncherItem(display, detail, ItemCategory.COMMENT,
                            cu.getAddress(), null));
                    count++;
                }
            }
        }
    }

    private void indexActions(List<LauncherItem> items) {
        try {
            Set<DockingAction> allActions = (Set<DockingAction>)(Set<?>)
                    tool.getAllActions();
            for (DockingAction action : allActions) {
                if (!action.isEnabled()) continue;
                String name = action.getName();
                String owner = action.getOwner();
                String detail = owner;
                javax.swing.KeyStroke kb = action.getKeyBinding();
                if (kb != null) {
                    detail += "  " + kb.toString()
                            .replace("pressed ", "")
                            .replace("ctrl ", "Ctrl+")
                            .replace("shift ", "Shift+")
                            .replace("alt ", "Alt+");
                }
                items.add(new LauncherItem(name, detail, ItemCategory.ACTION,
                        null, action.getName() + "|" + action.getOwner()));
            }
        } catch (Exception e) {
            Msg.warn(this, "Could not enumerate actions: " + e.getMessage());
        }
    }

    // ===================================================================
    // Fuzzy matching
    // ===================================================================

    /**
     * Fuzzy subsequence match with scoring.
     * Returns score > 0 if query is a subsequence of text, 0 otherwise.
     *
     * Scoring bonuses:
     *   - Consecutive character matches
     *   - Match at start of string
     *   - Match after separator (_, -, space, case change)
     *   - Exact prefix match
     */
    static int fuzzyScore(String text, String query) {
        if (query.isEmpty()) return 1; // everything matches empty query
        if (text.isEmpty()) return 0;

        String lowerText = text.toLowerCase(Locale.ROOT);
        String lowerQuery = query.toLowerCase(Locale.ROOT);

        // Quick check: is query a subsequence at all?
        int qi = 0;
        for (int ti = 0; ti < lowerText.length() && qi < lowerQuery.length(); ti++) {
            if (lowerText.charAt(ti) == lowerQuery.charAt(qi)) qi++;
        }
        if (qi < lowerQuery.length()) return 0; // not a subsequence

        // Exact prefix bonus
        if (lowerText.startsWith(lowerQuery)) {
            return 1000 + lowerQuery.length() * 10;
        }

        // Contains as substring bonus
        int substringIdx = lowerText.indexOf(lowerQuery);
        if (substringIdx >= 0) {
            int score = 500 + lowerQuery.length() * 5;
            if (substringIdx == 0) score += 200;
            // Bonus if match starts after a separator
            if (substringIdx > 0) {
                char before = text.charAt(substringIdx - 1);
                if (before == '_' || before == '-' || before == ' ' || before == '.'
                        || Character.isUpperCase(text.charAt(substringIdx))) {
                    score += 100;
                }
            }
            return score;
        }

        // Subsequence scoring
        int score = 100;
        int consecutive = 0;
        qi = 0;
        int lastMatchIdx = -2;

        for (int ti = 0; ti < lowerText.length() && qi < lowerQuery.length(); ti++) {
            if (lowerText.charAt(ti) == lowerQuery.charAt(qi)) {
                qi++;
                if (ti == lastMatchIdx + 1) {
                    consecutive++;
                    score += consecutive * 3; // consecutive bonus
                } else {
                    consecutive = 0;
                }
                // Start of word bonus
                if (ti == 0) score += 15;
                else {
                    char prev = text.charAt(ti - 1);
                    if (prev == '_' || prev == '-' || prev == ' ' || prev == '.'
                            || (Character.isLowerCase(prev) && Character.isUpperCase(text.charAt(ti)))) {
                        score += 10; // word boundary bonus
                    }
                }
                lastMatchIdx = ti;
            }
        }

        return score;
    }

    // ===================================================================
    // Navigate to item
    // ===================================================================

    private void navigateToItem(LauncherItem item) {
        if (item == null) return;

        if (item.category == ItemCategory.ACTION) {
            executeAction(item.actionName);
            return;
        }

        if (item.address != null) {
            GoToService goTo = tool.getService(GoToService.class);
            if (goTo != null && currentProgram != null) {
                goTo.goTo(item.address);
            }
        }
    }

    private void navigateToAddress(String addressStr) {
        if (currentProgram == null) return;
        try {
            AddressFactory factory = currentProgram.getAddressFactory();
            Address addr = factory.getAddress(addressStr);
            if (addr != null) {
                GoToService goTo = tool.getService(GoToService.class);
                if (goTo != null) {
                    goTo.goTo(addr);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Invalid address: " + addressStr);
        }
    }

    private void executeAction(String actionKey) {
        if (actionKey == null) return;
        String[] parts = actionKey.split("\\|", 2);
        String name = parts[0];
        String owner = parts.length > 1 ? parts[1] : null;

        try {
            Set<DockingAction> allActions = (Set<DockingAction>)(Set<?>)
                    tool.getAllActions();
            for (DockingAction action : allActions) {
                if (action.getName().equals(name)
                        && (owner == null || action.getOwner().equals(owner))) {
                    ActionContext ctx = new docking.DefaultActionContext();
                    if (action.isEnabledForContext(ctx)) {
                        action.actionPerformed(ctx);
                        return;
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to execute action: " + name);
        }
    }

    // ===================================================================
    // FlowLauncherDialog — the floating search UI
    // ===================================================================

    class FlowLauncherDialog extends JDialog {

        private static final int DIALOG_WIDTH = 700;
        private static final int MAX_VISIBLE_RESULTS = 15;
        private static final int RESULT_ROW_HEIGHT = 36;

        private final JTextField searchField;
        private final JPanel resultsPanel;
        private final JScrollPane resultsScroll;
        private final JLabel statusLabel;

        private List<LauncherItem> allItems = Collections.emptyList();
        private List<LauncherItem> filteredItems = new ArrayList<>();
        private int selectedIndex = 0;

        /** Currently active category filter, null = all */
        private ItemCategory activeFilter = null;

        /** Category order for Tab cycling */
        private static final ItemCategory[] CATEGORY_CYCLE = {
            null, // "All"
            ItemCategory.FUNCTION,
            ItemCategory.SYMBOL,
            ItemCategory.STRING,
            ItemCategory.BOOKMARK,
            ItemCategory.COMMENT,
            ItemCategory.ACTION,
        };
        private int filterCycleIndex = 0;

        /** Debounce timer for search */
        private Timer searchTimer;

        FlowLauncherDialog(Window parent) {
            super(parent, "Flow Launcher", ModalityType.MODELESS);
            setUndecorated(true);
            setAlwaysOnTop(true);

            // Position centered near top of parent
            if (parent != null) {
                int x = parent.getX() + (parent.getWidth() - DIALOG_WIDTH) / 2;
                int y = parent.getY() + parent.getHeight() / 5;
                setLocation(x, y);
            }

            // Root panel with dark theme
            JPanel root = new JPanel(new BorderLayout());
            root.setBackground(new Color(30, 30, 30));
            root.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(60, 60, 60), 1),
                    BorderFactory.createEmptyBorder(8, 8, 8, 8)));

            // === Search field ===
            searchField = new JTextField();
            searchField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 16));
            searchField.setBackground(new Color(45, 45, 45));
            searchField.setForeground(new Color(220, 220, 220));
            searchField.setCaretColor(new Color(220, 220, 220));
            searchField.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(80, 80, 80), 1),
                    BorderFactory.createEmptyBorder(8, 10, 8, 10)));
            searchField.putClientProperty("JTextField.placeholderText",
                    "Search functions, symbols, strings, actions...");

            // Filter label row
            JPanel topPanel = new JPanel(new BorderLayout(0, 4));
            topPanel.setOpaque(false);
            topPanel.add(searchField, BorderLayout.CENTER);

            JLabel filterLabel = new JLabel(getFilterLabel());
            filterLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            filterLabel.setForeground(new Color(130, 130, 130));
            filterLabel.setBorder(new EmptyBorder(2, 4, 2, 4));
            topPanel.add(filterLabel, BorderLayout.SOUTH);

            root.add(topPanel, BorderLayout.NORTH);

            // === Results panel ===
            resultsPanel = new JPanel();
            resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));
            resultsPanel.setBackground(new Color(30, 30, 30));

            resultsScroll = new JScrollPane(resultsPanel);
            resultsScroll.setBorder(null);
            resultsScroll.setHorizontalScrollBarPolicy(
                    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            resultsScroll.getViewport().setBackground(new Color(30, 30, 30));
            resultsScroll.setPreferredSize(
                    new Dimension(DIALOG_WIDTH - 16,
                            MAX_VISIBLE_RESULTS * RESULT_ROW_HEIGHT));
            root.add(resultsScroll, BorderLayout.CENTER);

            // === Status bar ===
            statusLabel = new JLabel("Loading index...");
            statusLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            statusLabel.setForeground(new Color(100, 100, 100));
            statusLabel.setBorder(new EmptyBorder(6, 4, 0, 4));
            root.add(statusLabel, BorderLayout.SOUTH);

            setContentPane(root);
            setSize(DIALOG_WIDTH, 60); // start small, grow with results
            setResizable(false);

            // === Key handling ===
            searchField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    switch (e.getKeyCode()) {
                        case KeyEvent.VK_ESCAPE:
                            closeDialog();
                            break;
                        case KeyEvent.VK_DOWN:
                            moveSelection(1);
                            e.consume();
                            break;
                        case KeyEvent.VK_UP:
                            moveSelection(-1);
                            e.consume();
                            break;
                        case KeyEvent.VK_ENTER:
                            activateSelected();
                            e.consume();
                            break;
                        case KeyEvent.VK_TAB:
                            cycleFilter(e.isShiftDown() ? -1 : 1);
                            filterLabel.setText(getFilterLabel());
                            doSearch();
                            e.consume();
                            break;
                        case KeyEvent.VK_PAGE_DOWN:
                            moveSelection(MAX_VISIBLE_RESULTS);
                            e.consume();
                            break;
                        case KeyEvent.VK_PAGE_UP:
                            moveSelection(-MAX_VISIBLE_RESULTS);
                            e.consume();
                            break;
                    }
                }
            });

            // Debounced search on text change
            searchTimer = new Timer(100, e -> doSearch());
            searchTimer.setRepeats(false);

            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { searchTimer.restart(); }
                @Override public void removeUpdate(DocumentEvent e) { searchTimer.restart(); }
                @Override public void changedUpdate(DocumentEvent e) { searchTimer.restart(); }
            });

            // Close on focus loss
            addWindowFocusListener(new WindowFocusListener() {
                @Override
                public void windowGainedFocus(WindowEvent e) {}
                @Override
                public void windowLostFocus(WindowEvent e) {
                    // Small delay to allow click on result to register
                    Timer t = new Timer(200, ev -> {
                        if (!FlowLauncherDialog.this.isFocused()) {
                            closeDialog();
                        }
                    });
                    t.setRepeats(false);
                    t.start();
                }
            });

            // Build index in background
            new Thread(() -> {
                allItems = buildIndex();
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText(allItems.size() + " items indexed  |  "
                            + "Tab: filter  |  ↑↓: navigate  |  Enter: go  |  Esc: close");
                    doSearch(); // show initial results
                });
            }, "FlowLauncher-Indexer").start();
        }

        void focusInput() {
            searchField.requestFocusInWindow();
            searchField.selectAll();
        }

        private void closeDialog() {
            setVisible(false);
            dispose();
        }

        // ---------------------------------------------------------------
        // Filter cycling
        // ---------------------------------------------------------------

        private String getFilterLabel() {
            StringBuilder sb = new StringBuilder("  ");
            for (int i = 0; i < CATEGORY_CYCLE.length; i++) {
                ItemCategory cat = CATEGORY_CYCLE[i];
                String label = (cat == null) ? "All" : cat.label;
                if (i == filterCycleIndex) {
                    sb.append("[").append(label).append("]");
                } else {
                    sb.append(" ").append(label).append(" ");
                }
                if (i < CATEGORY_CYCLE.length - 1) sb.append("  ");
            }
            sb.append("     (Tab to switch)");
            return sb.toString();
        }

        private void cycleFilter(int direction) {
            filterCycleIndex = (filterCycleIndex + direction + CATEGORY_CYCLE.length)
                    % CATEGORY_CYCLE.length;
            activeFilter = CATEGORY_CYCLE[filterCycleIndex];
        }

        // ---------------------------------------------------------------
        // Search
        // ---------------------------------------------------------------

        private void doSearch() {
            String query = searchField.getText().trim();
            filteredItems.clear();

            // Check if query looks like a hex address
            boolean looksLikeAddress = false;
            if (query.matches("^(0x)?[0-9a-fA-F]{4,}$")) {
                looksLikeAddress = true;
                String addrStr = query.startsWith("0x") ? query : "0x" + query;
                filteredItems.add(new LauncherItem(
                        "Go to " + addrStr, "Navigate to address",
                        ItemCategory.ADDRESS, null, null));
                filteredItems.get(0).score = 2000; // top priority
            }

            // Score and filter all items
            String lowerQuery = query.toLowerCase(Locale.ROOT);
            for (LauncherItem item : allItems) {
                if (activeFilter != null && item.category != activeFilter) continue;

                int score;
                if (query.isEmpty()) {
                    score = 1; // show all with no query
                } else {
                    score = fuzzyScore(item.displayName, query);
                    // Also try matching against detail (address, etc.)
                    if (score == 0 && item.detail != null) {
                        score = fuzzyScore(item.detail, query) / 2;
                    }
                }

                if (score > 0) {
                    item.score = score;
                    // Category priority boost
                    if (item.category == ItemCategory.FUNCTION) item.score += 5;
                    filteredItems.add(item);
                }
            }

            // Sort by score descending
            filteredItems.sort(Comparator.comparingInt((LauncherItem i) -> i.score).reversed());

            // Limit results
            int maxResults = 200;
            if (filteredItems.size() > maxResults) {
                filteredItems = new ArrayList<>(filteredItems.subList(0, maxResults));
            }

            selectedIndex = 0;
            rebuildResultsUI();
        }

        // ---------------------------------------------------------------
        // Results UI
        // ---------------------------------------------------------------

        private void rebuildResultsUI() {
            resultsPanel.removeAll();

            if (filteredItems.isEmpty()) {
                JLabel empty = new JLabel("  No results found");
                empty.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 13));
                empty.setForeground(new Color(120, 120, 120));
                empty.setAlignmentX(Component.LEFT_ALIGNMENT);
                empty.setBorder(new EmptyBorder(10, 10, 10, 10));
                resultsPanel.add(empty);
            } else {
                int showCount = Math.min(filteredItems.size(), 100);
                for (int i = 0; i < showCount; i++) {
                    resultsPanel.add(createResultRow(filteredItems.get(i), i));
                }
            }

            // Resize dialog to fit
            int rows = Math.min(filteredItems.isEmpty() ? 1 : filteredItems.size(),
                    MAX_VISIBLE_RESULTS);
            int resultsHeight = rows * RESULT_ROW_HEIGHT;
            int totalHeight = 80 + resultsHeight; // header + results + status
            setSize(DIALOG_WIDTH, Math.min(totalHeight, 650));

            resultsPanel.revalidate();
            resultsPanel.repaint();
            resultsScroll.revalidate();

            // Scroll to selection
            ensureSelectionVisible();
        }

        private JPanel createResultRow(LauncherItem item, int index) {
            boolean selected = (index == selectedIndex);

            JPanel row = new JPanel(new BorderLayout(8, 0));
            row.setMaximumSize(new Dimension(Integer.MAX_VALUE, RESULT_ROW_HEIGHT));
            row.setPreferredSize(new Dimension(DIALOG_WIDTH - 30, RESULT_ROW_HEIGHT));
            row.setBackground(selected ? new Color(50, 50, 80) : new Color(30, 30, 30));
            row.setBorder(new EmptyBorder(4, 10, 4, 10));
            row.setAlignmentX(Component.LEFT_ALIGNMENT);

            // Category badge
            JLabel badge = new JLabel(item.category.label);
            badge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
            badge.setForeground(item.category.color);
            badge.setPreferredSize(new Dimension(65, RESULT_ROW_HEIGHT - 8));
            badge.setVerticalAlignment(SwingConstants.CENTER);
            row.add(badge, BorderLayout.WEST);

            // Name and detail
            JPanel textPanel = new JPanel();
            textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
            textPanel.setOpaque(false);

            JLabel nameLabel = new JLabel(item.displayName);
            nameLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
            nameLabel.setForeground(selected ? Color.WHITE : new Color(210, 210, 210));
            nameLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            textPanel.add(nameLabel);

            if (item.detail != null && !item.detail.isEmpty()) {
                JLabel detailLabel = new JLabel(item.detail);
                detailLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
                detailLabel.setForeground(new Color(120, 120, 120));
                detailLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
                textPanel.add(detailLabel);
            }

            row.add(textPanel, BorderLayout.CENTER);

            // Click handler
            final int idx = index;
            row.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    selectedIndex = idx;
                    activateSelected();
                }
                @Override
                public void mouseEntered(MouseEvent e) {
                    selectedIndex = idx;
                    rebuildResultsUI();
                }
            });
            row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            return row;
        }

        // ---------------------------------------------------------------
        // Selection management
        // ---------------------------------------------------------------

        private void moveSelection(int delta) {
            if (filteredItems.isEmpty()) return;
            selectedIndex = Math.max(0, Math.min(filteredItems.size() - 1,
                    selectedIndex + delta));
            rebuildResultsUI();
            ensureSelectionVisible();
        }

        private void ensureSelectionVisible() {
            if (selectedIndex >= 0 && selectedIndex < resultsPanel.getComponentCount()) {
                Component comp = resultsPanel.getComponent(selectedIndex);
                if (comp instanceof JComponent jc) {
                    SwingUtilities.invokeLater(() ->
                            jc.scrollRectToVisible(jc.getBounds()));
                }
            }
        }

        private void activateSelected() {
            if (selectedIndex < 0 || selectedIndex >= filteredItems.size()) return;
            LauncherItem item = filteredItems.get(selectedIndex);

            if (item.category == ItemCategory.ADDRESS) {
                // Parse address from the display name "Go to 0x..."
                String query = searchField.getText().trim();
                String addrStr = query.startsWith("0x") ? query : "0x" + query;
                closeDialog();
                navigateToAddress(addrStr);
            } else {
                closeDialog();
                navigateToItem(item);
            }
        }
    }
}