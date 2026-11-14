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
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;

/**
 * Puts the angr debugger into a Ghidra tool window: the dockable "angr Debugger" panel, the
 * program counter and breakpoints drawn in the Listing, and right-click actions in the Listing
 * and Decompiler to start on a function, run to the cursor and toggle a breakpoint.
 *
 * <p>The session it shows is the one in {@link AngrDebugger}, shared with the
 * {@code ghidra_angr_debug} MCP tool.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "angr Debugger",
    description = "Step a function of the program under angr: registers, stack, calls and memory at " +
                  "every instruction, breakpoints in the Listing, unknown (symbolic) values for imports " +
                  "whose library is missing, concretizing them, and Python replacement hooks. Shares " +
                  "its session with the ghidra_angr_debug MCP tool."
)
//@formatter:on
public class AngrDebuggerPlugin extends ProgramPlugin implements AngrDebuggerController.Host {

    private static final String PC_MARKERS = "angr Debugger PC";
    private static final String BREAKPOINT_MARKERS = "angr Debugger Breakpoints";

    private final AngrDebuggerController controller;
    private final Provider provider;
    private final Map<Program, MarkerSet> pcMarkers = new HashMap<>();
    private final Map<Program, MarkerSet> breakpointMarkers = new HashMap<>();
    private ToggleDockingAction followAction;
    private Address lastShown;

    public AngrDebuggerPlugin(PluginTool tool) {
        super(tool);
        controller = new AngrDebuggerController(this::getCurrentProgram, this);
        provider = new Provider(tool, getName());
        createActions();
    }

    // ---- the panel in the tool window ----

    private final class Provider extends ComponentProviderAdapter {
        Provider(PluginTool tool, String owner) {
            super(tool, "angr Debugger", owner);
            setTitle("angr Debugger");
            setDefaultWindowPosition(WindowPosition.BOTTOM);
            setWindowMenuGroup("angr");
            addToTool();
        }

        @Override
        public JComponent getComponent() {
            return controller.panel();
        }
    }

    private void createActions() {
        // In the panel's own menu, which is also where their key bindings are listed.
        local("Step Into", KeyEvent.VK_F7, 0, "into");
        local("Step Over", KeyEvent.VK_F8, 0, "over");
        local("Step Out", KeyEvent.VK_F8, InputEvent.SHIFT_DOWN_MASK, "out");
        local("Continue", KeyEvent.VK_F9, 0, "continue");

        followAction = new ToggleDockingAction("Follow Program Counter in Listing", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                // read where it is used
            }
        };
        followAction.setMenuBarData(new MenuData(new String[] { "Follow Program Counter in Listing" }, "z"));
        followAction.setSelected(true);
        followAction.setDescription("Move the Listing to the current instruction whenever execution stops");
        provider.addLocalAction(followAction);

        DockingAction debugHere = new DockingAction("Debug Function with angr", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                ProgramLocationActionContext location = (ProgramLocationActionContext) context;
                Program program = location.getProgram();
                Function function = program.getFunctionManager().getFunctionContaining(location.getAddress());
                controller.prepare(program, function);
                tool.showComponentProvider(provider, true);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return context instanceof ProgramLocationActionContext location
                    && location.getAddress() != null && location.getProgram() != null
                    && location.getProgram().getFunctionManager()
                        .getFunctionContaining(location.getAddress()) != null;
            }
        };
        debugHere.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Debug Function with angr" }, null, "angr"));
        debugHere.setDescription("Open the angr Debugger on the function at the cursor");
        tool.addAction(debugHere);

        DockingAction runToCursor = new DockingAction("angr Run to Cursor", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.runTo(((ProgramLocationActionContext) context).getAddress());
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return context instanceof ProgramLocationActionContext location
                    && location.getAddress() != null && steppable(location.getProgram());
            }
        };
        runToCursor.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Run to Cursor" }, null, "angr"));
        runToCursor.setDescription("Run the angr debug session until it reaches this address");
        tool.addAction(runToCursor);

        DockingAction toggleBreakpoint = new DockingAction("angr Toggle Breakpoint", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                ProgramLocationActionContext location = (ProgramLocationActionContext) context;
                controller.toggleBreakpoint(location.getProgram(), location.getAddress());
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return context instanceof ProgramLocationActionContext location
                    && location.getAddress() != null && location.getProgram() != null
                    && location.getAddress().isMemoryAddress();
            }
        };
        toggleBreakpoint.setPopupMenuData(
            new MenuData(new String[] { "angr Debugger", "Toggle Breakpoint" }, null, "angr"));
        toggleBreakpoint.setDescription("Set or clear an angr Debugger breakpoint at this address");
        tool.addAction(toggleBreakpoint);

        DockingAction show = new DockingAction("Show angr Debugger", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                tool.showComponentProvider(provider, true);
            }
        };
        show.setMenuBarData(new MenuData(new String[] { "Tools", "angr Debugger" }, null, "angr"));
        show.setDescription("Show the angr Debugger panel");
        tool.addAction(show);
    }

    private void local(String name, int key, int modifiers, String kind) {
        DockingAction action = new DockingAction("angr " + name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                controller.step(kind);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return steppable(getCurrentProgram());
            }
        };
        action.setMenuBarData(new MenuData(new String[] { name }, "a"));
        action.setKeyBindingData(new KeyBindingData(key, modifiers));
        action.setDescription(name + " in the angr debug session");
        provider.addLocalAction(action);
    }

    private static boolean steppable(Program program) {
        if (program == null) {
            return false;
        }
        AngrDebugSession session = AngrDebugger.session(program);
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
    public void positionChanged(Program program, AngrDebugSession session) {
        if (program.isClosed()) {
            return;
        }
        MarkerService markers = tool.getService(MarkerService.class);
        if (markers != null) {
            MarkerSet breakpoints = breakpointMarkers.computeIfAbsent(program, p ->
                markers.createPointMarker(BREAKPOINT_MARKERS, "Breakpoints of the angr Debugger", p,
                    MarkerService.BREAKPOINT_PRIORITY, true, true, true, breakpointColor(), breakpointIcon()));
            breakpoints.clearAll();
            for (Address address : AngrDebugger.breakpoints(program)) {
                breakpoints.add(address);
            }
            MarkerSet pc = pcMarkers.computeIfAbsent(program, p ->
                markers.createPointMarker(PC_MARKERS, "Where the angr Debugger is stopped", p,
                    MarkerService.BREAKPOINT_PRIORITY + 1, true, true, true, pcColor(), pcIcon()));
            pc.clearAll();
            Address where = session == null || session.isRunning() ? null : session.pc();
            if (where != null && program.getMemory().contains(where)) {
                pc.add(where);
            }
        }
        Address where = session == null || session.isRunning() ? null : session.pc();
        if (where != null && !where.equals(lastShown) && followAction.isSelected()
                && program.getMemory().contains(where)) {
            goTo(program, where);
        }
        lastShown = where;
        tool.contextChanged(provider);
    }

    // ---- program lifecycle ----

    @Override
    protected void programActivated(Program program) {
        lastShown = null;
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
        if (markers != null) {
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
        for (Program program : new java.util.ArrayList<>(pcMarkers.keySet())) {
            removeMarkers(program);
        }
        controller.dispose();
        provider.removeFromTool();
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
