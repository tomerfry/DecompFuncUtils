package decompfuncutils.angr.ui;

import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.MarkerSet;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.classfinder.ClassSearcher;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import javax.imageio.ImageIO;
import javax.swing.JDialog;
import javax.swing.JFrame;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.Window;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Opens the angr Debugger tool for real - a Ghidra tool window with its plugins, docking and
 * Listing - without going through the Project window. A development aid, run through
 * {@code tests/run_angr_tool_test.ps1}:
 *
 * <ul>
 * <li>{@code export <file>} builds the tool from its plugin packages, lets Ghidra lay the windows
 * out, and writes the tool file that ships as {@value AngrDebuggerTool#RESOURCE}. Re-run it
 * whenever the plugin's windows change or the extension gains a plugin (a tool file lists the
 * extension plugins it already knows, and Ghidra asks about any other on first launch).</li>
 * <li>{@code check <dir> <binary>} opens the tool exactly as shipped on a program, drives a debug
 * session through it, prints {@code CHECK} lines, and saves pictures of the window in the
 * directory. This is the test of everything a headless run cannot reach.</li>
 * </ul>
 */
public class AngrDebuggerToolPreview implements GhidraLaunchable {

    private static final int WIDTH = 1680;
    private static final int HEIGHT = 1000;

    private int failures;
    private GhidraProject ghidraProject;
    private FrontEndTool frontEnd;
    private PluginTool tool;

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: export <tool file>  |  check <output dir> <binary>");
            System.exit(2);
        }
        watchdog(240);
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        Application.initializeApplication(layout, configuration);

        File scratch = Files.createTempDirectory("dfu-angr-tool").toFile();
        int exit = 0;
        try {
            ghidraProject = GhidraProject.createProject(scratch.getAbsolutePath(), "preview", true);
            // Ghidra's core plugins assume the Project window exists (they reach the project and
            // the other tools through it), so create it, as the real launcher does, but never
            // show it.
            Swing.runNow(() -> {
                frontEnd = new FrontEndTool(ghidraProject.getProjectManager());
                frontEnd.setActiveProject(ghidraProject.getProject());
            });
            if (args[0].equals("export")) {
                export(new File(args[1]));
            }
            else {
                check(new File(args[1]), new File(args[2]));
                System.out.println("TOOL_TEST_SUMMARY failures=" + failures);
                System.out.println("TOOL_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
                exit = failures == 0 ? 0 : 1;
            }
        }
        catch (Throwable t) {
            t.printStackTrace(System.out);
            System.out.println("TOOL_TEST_RESULT FAIL (" + t + ")");
            exit = 1;
        }
        // No orderly shutdown: closing a tool asks questions ("Close Program (Busy)"), and nothing
        // here is worth saving. The worker processes exit when their pipes close.
        System.out.flush();
        Runtime.getRuntime().halt(exit);
    }

    // ---------------------------------------------------------------------------------------
    // export: produce the shipped tool file
    // ---------------------------------------------------------------------------------------

    private void export(File output) throws Exception {
        Element config = new Element("TOOL_CONFIG").setAttribute("CONFIG_NAME", "NO_LONGER_USED");
        config.addContent(new Element("SUPPORTED_DATA_TYPE")
            .setAttribute("CLASS_NAME", "ghidra.program.model.listing.Program"));
        config.addContent(new Element("ICON").setAttribute("LOCATION", AngrDebuggerTool.ICON));
        Element toolElement = new Element("TOOL").setAttribute("TOOL_NAME", AngrDebuggerTool.NAME)
            .setAttribute("INSTANCE_NAME", "");
        toolElement.addContent(new Element("OPTIONS"));
        toolElement.addContent(new Element("PACKAGE").setAttribute("NAME", "Ghidra Core"));
        toolElement.addContent(new Element("PACKAGE").setAttribute("NAME", AngrDebuggerPluginPackage.NAME));
        toolElement.addContent(knownExtensions());
        toolElement.addContent(new Element("PREFERENCES"));
        config.addContent(toolElement);

        open(new GhidraToolTemplate(config, "preview"));
        settle();
        // Views of the code browser that have no part in debugging start closed; they stay one
        // click away in the Window menu.
        Swing.runNow(() -> {
            for (String name : List.of("DataTypes Provider", "Console", "Bookmarks", "Program Tree")) {
                ComponentProvider provider = tool.getComponentProvider(name);
                if (provider != null) {
                    tool.showComponentProvider(provider, false);
                }
            }
        });
        settle();
        screenshot(new File(output.getParentFile(), "_angr_tool_export.png"));

        ToolTemplate saved = Swing.runNow(() -> tool.getToolTemplate(true));
        Element xml = saved.saveToXml();
        arrange(xml.getChild("TOOL").getChild("ROOT_NODE"));
        xml.getChild("ICON").setAttribute("LOCATION", AngrDebuggerTool.ICON);
        XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat().setIndent("    "));
        Files.writeString(output.toPath(), outputter.outputString(new Document(xml.detach())),
            StandardCharsets.UTF_8);
        System.out.println("EXPORTED " + output + " (" + output.length() + " bytes), plugins: "
            + tool.getManagedPlugins().size());
    }

    /**
     * Replaces the arrangement Ghidra improvised with the one the tool ships with:
     *
     * <pre>
     * +--------------------------------------------------------------------+
     * | angr Debugger: what to debug, step buttons, what just happened      |
     * +----------+------------------------+-------------------+------------+
     * | Symbol   | Listing                | Decompiler        | Registers  |
     * | Tree     |                        |                   +------------+
     * |          |                        |                   | Stack      |
     * +----------+------------------------+-------------------+------------+
     * | Calls | Memory | Output | Paths | Symbols | Imports &amp; Hooks          |
     * +--------------------------------------------------------------------+
     * </pre>
     *
     * Every other window keeps its saved state (closed) and reopens as a tab at the bottom.
     */
    private static void arrange(Element root) {
        java.util.Map<String, Element> infos = new java.util.LinkedHashMap<>();
        // Windows that were never shown are remembered too, in window nodes of their own.
        for (Element child : new ArrayList<>(root.getChildren())) {
            child.detach();
            collect(child, infos);
        }
        System.out.println("WINDOWS " + infos.keySet());
        String angr = AngrDebuggerPlugin.class.getSimpleName();
        Element control = tabs(0, take(infos, angr, AngrDebuggerPlugin.CONTROL_VIEW, true));
        Element tree = tabs(0, take(infos, "SymbolTreePlugin", "Symbol Tree", true),
            take(infos, "ProgramTreePlugin", "Program Tree", false),
            take(infos, "DataTypeManagerPlugin", "DataTypes Provider", false));
        Element listing = tabs(0, take(infos, "CodeBrowserPlugin", "Listing", true));
        Element decompiler = tabs(0, take(infos, "DecompilePlugin", "Decompiler", true));
        Element registers = tabs(0, take(infos, angr, "Registers", true));
        Element stack = tabs(0, take(infos, angr, "Stack", true));
        List<Element> bottom = new ArrayList<>();
        for (String view : List.of("Calls", "Memory", "Output", "Paths", "Symbols", "Ledger", "Imports & Hooks")) {
            bottom.add(take(infos, angr, view, true));
        }
        for (Element rest : new ArrayList<>(infos.values())) {
            rest.setAttribute("ACTIVE", "false");
            bottom.add(rest);
        }
        Element trace = tabs(0, bottom.toArray(new Element[0]));

        int width = WIDTH - 16;
        int height = HEIGHT - 110;
        int codeHeight = (int) (height * 0.86 * 0.66);
        Element code = split(true, 560, (int) (width * 0.62), codeHeight, listing, decompiler);
        Element state = split(false, 520, (int) (width * 0.22), codeHeight, registers, stack);
        Element middle = split(true, 740, (int) (width * 0.84), codeHeight, code, state);
        Element upper = split(true, 160, width, codeHeight, tree, middle);
        Element work = split(false, 660, width, (int) (height * 0.86), upper, trace);
        root.addContent(split(false, 165, width, height, control, work));
        // Where the window was on this machine means nothing on another.
        root.setAttribute("X_POS", "80");
        root.setAttribute("Y_POS", "40");
        root.setAttribute("WIDTH", String.valueOf(WIDTH));
        root.setAttribute("HEIGHT", String.valueOf(HEIGHT));
        root.setAttribute("EX_STATE", "0");
        root.setAttribute("FOCUSED_OWNER", "CodeBrowserPlugin");
        root.setAttribute("FOCUSED_NAME", "Listing");
        root.setAttribute("FOCUSED_TITLE", "Listing: ");
    }

    private static void collect(Element node, java.util.Map<String, Element> infos) {
        for (Element child : new ArrayList<>(node.getChildren())) {
            if (child.getName().equals("COMPONENT_INFO")) {
                child.detach();
                infos.put(child.getAttributeValue("OWNER") + "/" + child.getAttributeValue("NAME"), child);
            }
            else {
                collect(child, infos);
            }
        }
    }

    private static Element take(java.util.Map<String, Element> infos, String owner, String name, boolean active) {
        Element info = infos.remove(owner + "/" + name);
        if (info == null) {
            // Ghidra has not placed this window yet; describe it the way it would.
            info = new Element("COMPONENT_INFO").setAttribute("NAME", name).setAttribute("OWNER", owner)
                .setAttribute("TITLE", name).setAttribute("GROUP", "Default").setAttribute("INSTANCE_ID", "0");
            System.out.println("NOTE no saved placement for " + owner + "/" + name);
        }
        info.setAttribute("ACTIVE", String.valueOf(active));
        return info;
    }

    private static Element tabs(int top, Element... infos) {
        Element node = new Element("COMPONENT_NODE").setAttribute("TOP_INFO", String.valueOf(top));
        for (Element info : infos) {
            node.addContent(info);
        }
        return node;
    }

    /** @param sideBySide true for left|right, false for top/bottom; divider in thousandths */
    private static Element split(boolean sideBySide, int divider, int width, int height, Element first,
            Element second) {
        Element node = new Element("SPLIT_NODE").setAttribute("WIDTH", String.valueOf(width))
            .setAttribute("HEIGHT", String.valueOf(height))
            .setAttribute("DIVIDER_LOCATION", String.valueOf(divider))
            .setAttribute("ORIENTATION", sideBySide ? "HORIZONTAL" : "VERTICAL");
        node.addContent(first);
        node.addContent(second);
        return node;
    }

    /**
     * The extension plugins the tool file declares it knows. Ghidra asks "New Plugins Found!"
     * about any extension plugin a tool has not seen; listing ours keeps that question from
     * greeting the first launch.
     */
    private static Element knownExtensions() {
        Element extensions = new Element("EXTENSIONS");
        Element extension = new Element("EXTENSION").setAttribute("NAME", "DecompFuncUtils");
        Set<String> names = new TreeSet<>();
        for (Class<? extends Plugin> plugin : ClassSearcher.getClasses(Plugin.class)) {
            if (plugin.getName().startsWith("decompfuncutils.")) {
                names.add(plugin.getName());
            }
        }
        for (String name : names) {
            extension.addContent(new Element("PLUGIN").setAttribute("CLASS", name));
        }
        extensions.addContent(extension);
        return extensions;
    }

    // ---------------------------------------------------------------------------------------
    // check: the shipped tool, on a program, with a session
    // ---------------------------------------------------------------------------------------

    private void check(File directory, File binary) throws Exception {
        directory.mkdirs();
        ToolTemplate template = AngrDebuggerTool.template();
        check("the tool file ships in the extension", template != null, AngrDebuggerTool.RESOURCE);
        if (template == null) {
            return;
        }
        check("it is named for the Tool Chest", AngrDebuggerTool.NAME.equals(template.getName()), template.getName());
        check("it has its own icon", template.getIconURL() != null
            && String.valueOf(template.getIconURL().getLocation()).contains("angr-debugger"),
            template.getIconURL() == null ? null : template.getIconURL().getLocation());
        boolean discovered = false;
        for (ToolTemplate candidate : ghidra.framework.ToolUtils.getDefaultApplicationTools()) {
            discovered |= AngrDebuggerTool.NAME.equals(candidate.getName());
        }
        check("Ghidra discovers it among the default tools", discovered, null);

        // The front-end plugin has seen the project by now.
        check("the Tool Chest of the Project window has the tool",
            ghidraProject.getProject().getLocalToolChest().getToolTemplate(AngrDebuggerTool.NAME) != null,
            java.util.Arrays.stream(ghidraProject.getProject().getLocalToolChest().getToolTemplates())
                .map(ToolTemplate::getName).toList());

        open(template);
        settle();
        check("opening it raises no dialog (no 'New Plugins Found!')", dialogs().isEmpty(), dialogs());

        AngrDebuggerPlugin plugin = null;
        Set<String> pluginNames = new TreeSet<>();
        for (Plugin p : tool.getManagedPlugins()) {
            pluginNames.add(p.getClass().getSimpleName());
            if (p instanceof AngrDebuggerPlugin found) {
                plugin = found;
            }
        }
        check("the angr Debugger plugin is loaded", plugin != null, null);
        check("with the Listing and the Decompiler", pluginNames.contains("CodeBrowserPlugin")
            && pluginNames.contains("DecompilePlugin"), pluginNames.size() + " plugins");
        check("and none of the extension's other plugins", pluginNames.stream()
            .noneMatch(n -> n.startsWith("Mcp") || n.contains("Taint")), pluginNames);
        if (plugin == null) {
            return;
        }

        List<String> missing = new ArrayList<>();
        for (String view : List.of(AngrDebuggerPlugin.CONTROL_VIEW, "Registers", "Stack", "Calls", "Memory",
                "Output", "Paths", "Symbols", "Ledger", "Imports & Hooks", "Listing", "Decompiler")) {
            ComponentProvider provider = tool.getComponentProvider(view);
            if (provider == null || !tool.isVisible(provider)) {
                missing.add(view);
            }
        }
        check("every debugger window is open, beside the Listing and Decompiler", missing.isEmpty(),
            "missing=" + missing);

        Set<String> actions = new TreeSet<>();
        Set<String> keys = new TreeSet<>();
        for (DockingActionIf action : tool.getDockingActionsByOwnerName(plugin.getName())) {
            actions.add(action.getName());
            if (action.getKeyBinding() != null) {
                keys.add(action.getName() + "=" + action.getKeyBinding());
            }
        }
        check("the angr menu actions are registered", actions.containsAll(List.of("angr Continue",
            "angr Step Into", "angr Step Over", "angr Step Out", "angr Pause", "angr Stop",
            "angr Run to Cursor", "angr Toggle Breakpoint", "Debug Function with angr",
            "angr Seek Destination", "angr Set Destination", "angr Clear Destination")), actions);
        check("stepping has the Debugger tool's keys (F5, F8, F10, F12) and K for breakpoints",
            keys.size() >= 5 && String.valueOf(keys).contains("F10"), keys);

        // --- a program ---
        Program program = ghidraProject.importProgram(binary);
        ghidraProject.analyze(program);
        // Otherwise opening it asks "has not been analyzed. Would you like to analyze it now?"
        int transaction = program.startTransaction("mark analyzed");
        ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);
        program.endTransaction(transaction, true);
        ghidraProject.saveAs(program, "/", program.getName(), true);
        ProgramManager programs = tool.getService(ProgramManager.class);
        Swing.runNow(() -> programs.openProgram(program));
        settle();

        AngrDebuggerController controller = plugin.controller();
        AngrDebuggerPanel panel = controller.panel();
        AngrDebuggerPlugin debugger = plugin;
        Function target = program.getListing().getGlobalFunctions("check_password").get(0);
        Swing.runNow(() -> {
            controller.prepare(program, target);
            panel.setArguments("\"nope\"");
            panel.button("Start").doClick();
        });
        controller.await();
        settle();
        AngrDebugSession session = AngrDebugger.session(program);
        check("Start begins a session", session != null && panel.bannerTitle().startsWith("Paused at"),
            panel.bannerTitle() + " | " + controller.lastError());
        if (session == null) {
            screenshot(new File(directory, "_angr_tool_failed.png"));
            return;
        }
        MarkerSet pc = debugger.markers(program, "pc");
        check("the program counter is marked in the Listing", pc != null && pc.contains(session.pc()),
            session.pc());
        CodeViewerService listing = tool.getService(CodeViewerService.class);
        Address cursor = listing.getCurrentLocation() == null ? null : listing.getCurrentLocation().getAddress();
        check("the Listing follows it", session.pc().equals(cursor), "listing=" + cursor + " pc=" + session.pc());

        Address add3 = program.getListing().getGlobalFunctions("add3").get(0).getEntryPoint();
        AngrDebugger.toggleBreakpoint(program, add3);
        settle();
        MarkerSet breakpoints = debugger.markers(program, "breakpoints");
        check("a breakpoint is marked in the Listing", breakpoints != null && breakpoints.contains(add3), add3);
        AngrDebugger.clearBreakpoints(program);

        for (int i = 0; i < 9; i++) {
            Swing.runNow(() -> panel.button("Step Over").doClick());
            controller.await();
        }
        settle();
        check("stepping moves the marker and the Listing with it",
            pc.contains(AngrDebugger.session(program).pc())
                && AngrDebugger.session(program).pc().equals(listing.getCurrentLocation().getAddress()),
            AngrDebugger.session(program).pc());
        check("the Calls window counts the call in its title",
            "(1)".equals(tool.getComponentProvider("Calls").getSubTitle()),
            tool.getComponentProvider("Calls").getSubTitle());
        screenshot(new File(directory, "_angr_tool_1_stepping.png"));

        // --- an unknown import forks, and the Paths window comes forward ---
        Swing.runNow(() -> {
            panel.setFunction("needs_device");
            panel.setArguments("");
            panel.button("Start").doClick();
        });
        controller.await();
        Swing.runNow(() -> panel.button("Continue").doClick());
        controller.await();
        settle();
        check("an unknown import value forks", panel.bannerTitle().startsWith("Forked at"), panel.bannerTitle());
        check("the Paths window is brought forward", tool.isVisible(tool.getComponentProvider("Paths"))
            && tool.getComponentProvider("Paths").getComponent().isShowing(), null);
        screenshot(new File(directory, "_angr_tool_2_forked.png"));

        // --- a destination: marked in the Listing, sought, and the way there written down ---
        Address unlock = program.getListing().getGlobalFunctions("unlock").get(0).getEntryPoint();
        Swing.runNow(() -> {
            controller.setDestination(program, unlock);
            panel.setFunction("gate");
            panel.setArguments("{\"symbolicInt\": 32, \"name\": \"key\"}");
            panel.button("Start").doClick();
        });
        controller.await();
        settle();
        MarkerSet destinationMarker = debugger.markers(program, "destination");
        check("the destination is marked in the Listing", destinationMarker != null
            && destinationMarker.contains(unlock), unlock);
        check("Seek Destination is offered once there is a destination and a session",
            panel.button("Seek Destination").isEnabled(), null);
        Swing.runNow(() -> panel.button("Seek Destination").doClick());
        controller.await();
        settle();
        check("seeking arrives at the destination", panel.bannerTitle().startsWith("Reached the destination")
            && unlock.equals(AngrDebugger.session(program).pc()), panel.bannerTitle() + " | " + controller.lastError());
        check("the Listing is at the destination", unlock.equals(listing.getCurrentLocation().getAddress()),
            listing.getCurrentLocation().getAddress());
        check("the Ledger window comes forward with the way there",
            tool.getComponentProvider("Ledger").getComponent().isShowing()
                && panel.table("ledger").getRowCount() >= 5 && panel.table("unknowns").getRowCount() == 3,
            panel.table("ledger").getRowCount() + " entries, " + panel.table("unknowns").getRowCount() + " unknowns");
        screenshot(new File(directory, "_angr_tool_4_destination.png"));
        Swing.runNow(() -> controller.setDestination(program, null));
        settle();
        check("clearing the destination removes its marker", !destinationMarker.contains(unlock), null);

        Swing.runNow(() -> tool.showComponentProvider(tool.getComponentProvider("Imports & Hooks"), true));
        Swing.runNow(() -> tool.getComponentProvider("Imports & Hooks").toFront());
        long deadline = System.currentTimeMillis() + 30_000;
        while (!panel.importsLoaded() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        controller.await();
        settle();
        check("opening Imports & Hooks fills it", panel.table("imports").getRowCount() >= 5,
            panel.table("imports").getRowCount());
        screenshot(new File(directory, "_angr_tool_3_imports.png"));

        Swing.runNow(() -> panel.button("Stop").doClick());
        controller.await();
        settle();
        check("Stop ends the session and clears the marker", AngrDebugger.session(program) == null
            && !pc.contains(session.pc()), null);
        check("nothing raised a dialog along the way", dialogs().isEmpty(), dialogs());
    }

    // ---------------------------------------------------------------------------------------
    // plumbing
    // ---------------------------------------------------------------------------------------

    private void open(ToolTemplate template) {
        Project project = ghidraProject.getProject();
        Swing.runNow(() -> {
            tool = template.createTool(project);
            JFrame frame = tool.getToolFrame();
            // Out of the way of whoever is using the desktop: the window is painted into an
            // image, never looked at.
            frame.setAutoRequestFocus(false);
            frame.setFocusableWindowState(false);
            tool.setSize(WIDTH, HEIGHT);
            tool.setLocation(-WIDTH - 200, 60);
            tool.setVisible(true);
            tool.setSize(WIDTH, HEIGHT);
        });
    }

    /** Lets queued Swing work and background updates finish. */
    private static void settle() throws InterruptedException {
        for (int i = 0; i < 4; i++) {
            Swing.runNow(() -> { });
            Thread.sleep(350);
        }
        // A fresh profile greets with a tip; it belongs to the Project window, not to the tool.
        Swing.runNow(() -> {
            for (Window window : Window.getWindows()) {
                if (window instanceof JDialog dialog && dialog.isShowing()
                        && "Tip of the Day".equals(dialog.getTitle())) {
                    dialog.dispose();
                }
            }
        });
    }

    private void screenshot(File file) {
        Swing.runNow(() -> {
            try {
                JFrame frame = tool.getToolFrame();
                Container content = frame.getRootPane();
                BufferedImage image = new BufferedImage(content.getWidth(), content.getHeight(),
                    BufferedImage.TYPE_INT_RGB);
                Graphics2D g = image.createGraphics();
                content.paint(g);
                g.dispose();
                ImageIO.write(image, "png", file);
                System.out.println("SCREENSHOT " + file + " " + image.getWidth() + "x" + image.getHeight());
            }
            catch (Exception e) {
                System.out.println("SCREENSHOT failed: " + e);
            }
        });
    }

    /** Titles (and text) of any dialog on screen: there should be none. */
    private static List<String> dialogs() {
        List<String> open = new ArrayList<>();
        Swing.runNow(() -> {
            for (Window window : Window.getWindows()) {
                if (window instanceof JDialog dialog && dialog.isShowing()) {
                    open.add(dialog.getTitle() + ": " + text(dialog.getContentPane(), new StringBuilder()));
                }
            }
        });
        return open;
    }

    private static String text(Component component, StringBuilder sb) {
        if (component instanceof javax.swing.JLabel label && label.getText() != null) {
            sb.append(label.getText()).append(' ');
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                text(child, sb);
            }
        }
        return sb.length() > 300 ? sb.substring(0, 300) : sb.toString();
    }

    private void check(String label, boolean ok, Object detail) {
        String shown = detail == null ? "" : String.valueOf(detail);
        System.out.println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (shown.isEmpty() ? "" : "  (" + (shown.length() > 500 ? shown.substring(0, 500) + "..." : shown) + ")"));
        if (!ok) {
            failures++;
        }
    }

    /** A modal dialog would otherwise hang the run forever; say which one and give up. */
    private static void watchdog(int seconds) {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(seconds * 1000L);
            }
            catch (InterruptedException e) {
                return;
            }
            System.out.println("TOOL_TEST_RESULT FAIL (timed out after " + seconds + " s)");
            for (Window window : Window.getWindows()) {
                if (window.isShowing()) {
                    String title = window instanceof JDialog d ? d.getTitle()
                        : window instanceof JFrame f ? f.getTitle() : window.getClass().getName();
                    System.out.println("  showing: " + window.getClass().getSimpleName() + " '" + title + "' "
                        + (window instanceof JDialog d ? text(d.getContentPane(), new StringBuilder()) : ""));
                }
            }
            System.out.flush();
            Runtime.getRuntime().halt(3);
        }, "angr-tool-preview-watchdog");
        thread.setDaemon(true);
        thread.start();
    }
}
