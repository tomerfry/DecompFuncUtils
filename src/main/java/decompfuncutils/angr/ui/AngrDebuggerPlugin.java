package decompfuncutils.angr.ui;

import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.mcp.tools.AngrEmulateTool;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.UIManager;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The angr Debugger as a set of dockable windows: a control strip (what to debug, the step
 * buttons, and a banner saying what just happened) and one window each for Registers, Stack,
 * Calls, Memory, Output, Paths, Symbols and Imports &amp; Hooks. It draws the program counter and
 * the breakpoints in the Listing and adds an "angr" menu and right-click actions.
 *
 * <p>It is the plugin behind the "angr Debugger" tool in the Tool Chest ({@link AngrDebuggerTool}),
 * and can be added to any other tool that shows a program. The session it shows is the one in
 * {@link AngrDebugger}, shared with the {@code ghidra_angr_debug} MCP tool.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = AngrDebuggerPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "angr Debugger",
    description = "Step a function of the program under angr: registers, stack, calls and memory at " +
                  "every instruction, breakpoints in the Listing, unknown (symbolic) values for imports " +
                  "whose library is missing, concretizing them, and Python replacement hooks. Shares " +
                  "its session with the ghidra_angr_debug MCP tool."
)
//@formatter:on
public class AngrDebuggerPlugin extends ProgramPlugin
        implements AngrDebuggerController.Host, AngrDebuggerPanel.ViewHost {

    public static final String CONTROL_VIEW = "angr Debugger";
    private static final String MENU = "angr";
    private static final String PC_MARKERS = "angr Debugger PC";
    private static final String BREAKPOINT_MARKERS = "angr Debugger Breakpoints";
    private static final String DESTINATION_MARKERS = "angr Debugger Destination";

    private final AngrDebuggerController controller;
    private final Map<String, ViewProvider> providers = new LinkedHashMap<>();
    private final Map<Program, MarkerSet> pcMarkers = new HashMap<>();
    private final Map<Program, MarkerSet> breakpointMarkers = new HashMap<>();
    private final Map<Program, MarkerSet> destinationMarkers = new HashMap<>();
    private final List<DockingAction> actions = new ArrayList<>();
    private ToggleDockingAction followAction;
    private Address lastShown;

    public AngrDebuggerPlugin(PluginTool tool) {
        super(tool);
        controller = new AngrDebuggerController(this::getCurrentProgram, this, true);
        AngrDebuggerPanel panel = controller.panel();
        panel.setViewHost(this);

        // The control strip spans the top; state sits to the right of the code, everything that
        // reads as a list or a log shares the bottom. A saved tool layout overrides all of this.
        provider(CONTROL_VIEW, panel, WindowPosition.TOP, "angr.control", WindowPosition.STACK);
        provider("Registers", panel.view("Registers"), WindowPosition.RIGHT, "angr.state", WindowPosition.STACK);
        provider("Stack", panel.view("Stack"), WindowPosition.RIGHT, "angr.state", WindowPosition.BOTTOM);
        provider("Calls", panel.view("Calls"), WindowPosition.BOTTOM, "angr.trace", WindowPosition.STACK);
        for (String view : List.of("Memory", "Output", "Paths", "Symbols", "Ledger", "Imports & Hooks")) {
            provider(view, panel.view(view), WindowPosition.BOTTOM, "angr.trace", WindowPosition.STACK);
        }
        createActions();
    }

    /** The controller behind the windows; for the tool preview and tests. */
    public AngrDebuggerController controller() {
        return controller;
    }

    // ---- windows ----

    private final class ViewProvider extends ComponentProviderAdapter {
        private final String view;
        private final JComponent component;

        ViewProvider(String view, JComponent component, WindowPosition position, String group,
                WindowPosition inGroup) {
            super(AngrDebuggerPlugin.this.tool, view, AngrDebuggerPlugin.this.getName());
            this.view = view;
            this.component = component;
            setTitle(view);
            setDefaultWindowPosition(position);
            setWindowGroup(group);
            setIntraGroupPosition(inGroup);
            setWindowMenuGroup(AngrDebuggerPluginPackage.NAME);
            addToTool();
            setVisible(true);
        }

        @Override
        public JComponent getComponent() {
            return component;
        }

        @Override
        public void componentShown() {
            loadImports();
        }

        @Override
        public void componentActivated() {
            loadImports();
        }

        /** The import list costs a round trip to angr; fetch it when someone first looks. */
        private void loadImports() {
            if (view.equals("Imports & Hooks") && !controller.panel().importsLoaded()
                    && getCurrentProgram() != null) {
                controller.refreshImports();
            }
        }
    }

    private void provider(String view, JComponent component, WindowPosition position, String group,
            WindowPosition inGroup) {
        providers.put(view, new ViewProvider(view, component, position, group, inGroup));
    }

    @Override
    public void showView(String name) {
        ViewProvider provider = providers.get(name);
        if (provider != null) {
            tool.showComponentProvider(provider, true);
            provider.toFront();
        }
    }

    @Override
    public void countChanged(String name, int count) {
        ViewProvider provider = providers.get(name);
        if (provider != null) {
            provider.setSubTitle(count > 0 ? "(" + count + ")" : "");
            provider.setTabText(count > 0 ? name + " (" + count + ")" : name);
        }
    }

    // ---- actions ----

    private void createActions() {
        step("Continue", "continue", KeyEvent.VK_F5, "1",
            "Run to the next breakpoint, fork, return or fault");
        step("Step Into", "into", KeyEvent.VK_F8, "1", "Execute one instruction, entering calls");
        step("Step Over", "over", KeyEvent.VK_F10, "1",
            "Execute one instruction, running a call through to its return");
        step("Step Out", "out", KeyEvent.VK_F12, "1", "Run until the current function returns");

        DockingAction pause = new DockingAction("angr Pause", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.pause();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                AngrDebugSession session = session();
                return session != null && session.isRunning();
            }
        };
        menu(pause, "Pause", "2", "Interrupt a run in progress");

        DockingAction stop = new DockingAction("angr Stop", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.stop();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return session() != null;
            }
        };
        menu(stop, "Stop", "2", "End the debug session");

        DockingAction debugHere = new DockingAction("Debug Function with angr", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Address address = addressOf(context);
                Program program = getCurrentProgram();
                Function function = program.getFunctionManager().getFunctionContaining(address);
                controller.prepare(program, function);
                showView(CONTROL_VIEW);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                Address address = addressOf(context);
                return address != null
                    && getCurrentProgram().getFunctionManager().getFunctionContaining(address) != null;
            }
        };
        menu(debugHere, "Debug Function at Cursor", "0",
            "Fill in the function at the cursor as the one to debug");
        debugHere.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Debug Function with angr" }, null, "angr"));

        DockingAction runToCursor = new DockingAction("angr Run to Cursor", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.runTo(addressOf(context));
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return addressOf(context) != null && steppable();
            }
        };
        menu(runToCursor, "Run to Cursor", "1", "Run until execution reaches the address at the cursor");
        runToCursor.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Run to Cursor" }, null, "angr"));

        DockingAction toggleBreakpoint = new DockingAction("angr Toggle Breakpoint", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.toggleBreakpoint(getCurrentProgram(), addressOf(context));
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                Address address = addressOf(context);
                return address != null && address.isMemoryAddress();
            }
        };
        menu(toggleBreakpoint, "Toggle Breakpoint", "3", "Set or clear a breakpoint at the cursor");
        toggleBreakpoint.setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
        toggleBreakpoint.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Toggle Breakpoint" }, null, "angr"));

        DockingAction seek = new DockingAction("angr Seek Destination", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.seek();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return steppable() && AngrDebugger.destination(getCurrentProgram()) != null;
            }
        };
        seek.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F9, 0));
        menu(seek, "Seek Destination", "1",
            "Find a way to the destination through every branch on an unknown, and record it in the Ledger");

        DockingAction setDestination = new DockingAction("angr Set Destination", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.setDestination(getCurrentProgram(), addressOf(context));
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                Address address = addressOf(context);
                return address != null && address.isMemoryAddress();
            }
        };
        menu(setDestination, "Set Destination at Cursor", "3",
            "Make the address at the cursor the place Seek Destination tries to get to");
        setDestination.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Set Destination" }, null, "angr"));

        DockingAction clearDestination = new DockingAction("angr Clear Destination", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.setDestination(getCurrentProgram(), null);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null && AngrDebugger.destination(getCurrentProgram()) != null;
            }
        };
        menu(clearDestination, "Clear Destination", "3", "Have no destination");

        DockingAction clearBreakpoints = new DockingAction("angr Clear Breakpoints", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                AngrDebugger.clearBreakpoints(getCurrentProgram());
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null && !AngrDebugger.breakpoints(getCurrentProgram()).isEmpty();
            }
        };
        menu(clearBreakpoints, "Clear All Breakpoints", "3", "Remove every angr Debugger breakpoint");

        followAction = new ToggleDockingAction("angr Follow Program Counter", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                // read where it is used
            }
        };
        followAction.setSelected(true);
        menu(followAction, "Follow Program Counter in Listing", "4",
            "Move the Listing to the current instruction whenever execution stops");
    }

    private void step(String name, String kind, int key, String group, String description) {
        DockingAction action = new DockingAction("angr " + name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.step(kind);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return steppable();
            }
        };
        action.setKeyBindingData(new KeyBindingData(key, 0));
        menu(action, name, group, description);
    }

    private void menu(DockingAction action, String name, String group, String description) {
        action.setMenuBarData(new MenuData(new String[] { MENU, name }, null, group));
        action.setDescription(description);
        tool.addAction(action);
        actions.add(action);
    }

    /** The address an action applies to: where it was invoked, else the Listing cursor. */
    private Address addressOf(ActionContext context) {
        if (getCurrentProgram() == null) {
            return null;
        }
        if (context instanceof ProgramLocationActionContext location
                && location.getProgram() == getCurrentProgram() && location.getAddress() != null) {
            return location.getAddress();
        }
        return currentLocation == null ? null : currentLocation.getAddress();
    }

    private AngrDebugSession session() {
        Program program = getCurrentProgram();
        return program == null ? null : AngrDebugger.session(program);
    }

    private boolean steppable() {
        AngrDebugSession session = session();
        return session != null && !session.isRunning() && "paused".equals(session.status());
    }

    // ---- AngrDebuggerController.Host ----

    @Override
    public void goTo(Program program, Address address) {
        GoToService goTo = tool.getService(GoToService.class);
        if (goTo != null && program == getCurrentProgram()) {
            goTo.goTo(address);
        }
    }

    @Override
    public String configuredPython() {
        return AngrEmulateTool.configuredPython(tool);
    }

    @Override
    public boolean ledgerVisible() {
        ViewProvider ledger = providers.get("Ledger");
        return ledger != null && ledger.isVisible() && ledger.getComponent().isShowing();
    }

    @Override
    public void positionChanged(Program program, AngrDebugSession session) {
        if (program.isClosed()) {
            return;
        }
        Address where = session == null || session.isRunning() ? null : session.pc();
        MarkerService markers = tool.getService(MarkerService.class);
        if (markers != null) {
            MarkerSet breakpoints = breakpointMarkers.computeIfAbsent(program, p ->
                markers.createPointMarker(BREAKPOINT_MARKERS, "Breakpoints of the angr Debugger", p,
                    MarkerService.BREAKPOINT_PRIORITY, true, true, true, breakpointColor(), breakpointIcon()));
            breakpoints.clearAll();
            for (Address address : AngrDebugger.breakpoints(program)) {
                breakpoints.add(address);
            }
            MarkerSet destinations = destinationMarkers.computeIfAbsent(program, p ->
                markers.createPointMarker(DESTINATION_MARKERS, "Where the angr Debugger is trying to get to", p,
                    MarkerService.BREAKPOINT_PRIORITY + 2, true, true, true, destinationColor(), destinationIcon()));
            destinations.clearAll();
            Address destination = AngrDebugger.destination(program);
            if (destination != null && program.getMemory().contains(destination)) {
                destinations.add(destination);
            }
            MarkerSet pc = pcMarkers.computeIfAbsent(program, p ->
                markers.createPointMarker(PC_MARKERS, "Where the angr Debugger is stopped", p,
                    MarkerService.BREAKPOINT_PRIORITY + 1, true, true, true, pcColor(), pcIcon()));
            pc.clearAll();
            if (where != null && program.getMemory().contains(where)) {
                pc.add(where);
            }
        }
        if (where != null && !where.equals(lastShown) && followAction.isSelected()
                && program.getMemory().contains(where)) {
            goTo(program, where);
        }
        lastShown = where;
        tool.contextChanged(providers.get(CONTROL_VIEW));
    }

    /** The marker sets, by kind ("pc", "breakpoints" or "destination"); for the tool preview and tests. */
    public MarkerSet markers(Program program, String kind) {
        return "pc".equals(kind) ? pcMarkers.get(program)
            : "destination".equals(kind) ? destinationMarkers.get(program) : breakpointMarkers.get(program);
    }

    // ---- program lifecycle ----

    @Override
    protected void programActivated(Program program) {
        lastShown = null;
        // The import list on screen belongs to the program that was active before.
        controller.panel().forgetImports();
        controller.refresh();
    }

    @Override
    protected void programDeactivated(Program program) {
        controller.refresh();
    }

    @Override
    protected void programClosed(Program program) {
        removeMarkers(program);
        AngrDebugger.forget(program);
    }

    private void removeMarkers(Program program) {
        MarkerService markers = tool.getService(MarkerService.class);
        MarkerSet pc = pcMarkers.remove(program);
        MarkerSet breakpoints = breakpointMarkers.remove(program);
        MarkerSet destinations = destinationMarkers.remove(program);
        if (markers != null) {
            if (destinations != null) {
                markers.removeMarker(destinations, program);
            }
            if (pc != null) {
                markers.removeMarker(pc, program);
            }
            if (breakpoints != null) {
                markers.removeMarker(breakpoints, program);
            }
        }
    }

    @Override
    protected void dispose() {
        for (Program program : new ArrayList<>(pcMarkers.keySet())) {
            removeMarkers(program);
        }
        controller.dispose();
        for (DockingAction action : actions) {
            tool.removeAction(action);
        }
        for (ViewProvider provider : providers.values()) {
            provider.removeFromTool();
        }
        super.dispose();
    }

    // ---- markers ----

    private static boolean darkTheme() {
        Color background = UIManager.getColor("Panel.background");
        return background != null
            && (background.getRed() * 299 + background.getGreen() * 587 + background.getBlue() * 114) / 1000 < 128;
    }

    private static Color pcColor() {
        return darkTheme() ? new Color(0x2F5E3A) : new Color(0xC9EBCB);
    }

    private static Color breakpointColor() {
        return darkTheme() ? new Color(0x6B2D2D) : new Color(0xF6CFCB);
    }

    private static Color destinationColor() {
        return darkTheme() ? new Color(0x2C4A73) : new Color(0xCFE0F7);
    }

    /** A flag: somewhere to get to. */
    private static Icon destinationIcon() {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(0x1E5FB4));
        g.setStroke(new BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g.drawLine(4, 2, 4, 14);
        g.fillPolygon(new int[] { 5, 13, 5 }, new int[] { 2, 5, 9 }, 3);
        g.dispose();
        return new ImageIcon(image);
    }

    private static Icon pcIcon() {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(0x2E8B3D));
        g.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g.drawLine(2, 8, 12, 8);
        g.fillPolygon(new int[] { 8, 14, 8 }, new int[] { 3, 8, 13 }, 3);
        g.dispose();
        return new ImageIcon(image);
    }

    private static Icon breakpointIcon() {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(0xC62828));
        g.fillOval(3, 3, 10, 10);
        g.dispose();
        return new ImageIcon(image);
    }
}
