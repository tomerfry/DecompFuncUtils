package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.RefineResult;
import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Swing;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.Window;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import javax.imageio.ImageIO;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JTextArea;
import org.jdom2.Element;

/**
 * Opens the Refined Decompiler for real -- in a Ghidra tool window with the Listing and the
 * Decompiler beside it -- and checks everything a headless run cannot reach: that the plugin
 * loads, that the window follows the cursor, that changing the configuration changes the code,
 * that clicking a line moves the Listing, that editing the program refreshes the view. A
 * development aid, run through {@code tests/run_refine_gui_test.ps1}:
 *
 * <pre>
 * RefinedDecompilerPreview &lt;output dir&gt; &lt;binary&gt;
 * </pre>
 *
 * It prints {@code CHECK} lines and leaves pictures of the window in the output directory. The
 * window is placed off screen and never takes focus; it is painted into the pictures, not looked
 * at.
 */
public class RefinedDecompilerPreview implements GhidraLaunchable {
    private static final int WIDTH = 1700, HEIGHT = 980;

    private int failures;
    private GhidraProject ghidraProject;
    private FrontEndTool frontEnd;
    private PluginTool tool;
    private RefinedDecompilerView view;

    @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: <output dir> <binary>");
            System.exit(2);
        }
        watchdog(300);
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        Application.initializeApplication(layout, configuration);
        File scratch = Files.createTempDirectory("dfu-refine-gui").toFile();
        int exit;
        try {
            ghidraProject = GhidraProject.createProject(scratch.getAbsolutePath(), "preview", true);
            // Core plugins reach the project through the Project window; create it, never show it.
            Swing.runNow(() -> {
                frontEnd = new FrontEndTool(ghidraProject.getProjectManager());
                frontEnd.setActiveProject(ghidraProject.getProject());
            });
            check(new File(args[0]), new File(args[1]));
            System.out.println("TOOL_TEST_SUMMARY failures=" + failures);
            System.out.println("TOOL_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
            exit = failures == 0 ? 0 : 1;
        } catch (Throwable t) {
            t.printStackTrace(System.out);
            System.out.println("TOOL_TEST_RESULT FAIL (" + t + ")");
            exit = 1;
        }
        // No orderly shutdown: closing a tool asks questions, and nothing here is worth saving.
        System.out.flush();
        Runtime.getRuntime().halt(exit);
    }

    private void check(File directory, File binary) throws Exception {
        directory.mkdirs();

        // A code browser: Ghidra's core plugins, which include the Listing and the Decompiler.
        Element config = new Element("TOOL_CONFIG").setAttribute("CONFIG_NAME", "NO_LONGER_USED");
        config.addContent(new Element("SUPPORTED_DATA_TYPE").setAttribute("CLASS_NAME", "ghidra.program.model.listing.Program"));
        config.addContent(new Element("ICON").setAttribute("LOCATION", "red-dragon.gif"));
        Element toolElement = new Element("TOOL").setAttribute("TOOL_NAME", "RefinedPreview").setAttribute("INSTANCE_NAME", "");
        toolElement.addContent(new Element("OPTIONS"));
        toolElement.addContent(new Element("PACKAGE").setAttribute("NAME", "Ghidra Core"));
        toolElement.addContent(knownExtensions());
        toolElement.addContent(new Element("PREFERENCES"));
        config.addContent(toolElement);
        GhidraToolTemplate template = new GhidraToolTemplate(config, "preview");
        Swing.runNow(() -> {
            tool = template.createTool(ghidraProject.getProject());
            JFrame frame = tool.getToolFrame();
            frame.setAutoRequestFocus(false);
            frame.setFocusableWindowState(false);
            tool.setSize(WIDTH, HEIGHT);
            tool.setLocation(-WIDTH - 200, 60);
            tool.setVisible(true);
            tool.setSize(WIDTH, HEIGHT);
        });
        settle();

        // --- the plugin, added the way File > Configure adds it ---
        String[] addError = new String[1];
        Swing.runNow(() -> {
            try {
                tool.addPlugin(RefinedDecompilerPlugin.class.getName());
            } catch (Exception e) {
                addError[0] = String.valueOf(e);
            }
        });
        settle();
        RefinedDecompilerPlugin plugin = null;
        Set<String> pluginNames = new TreeSet<>();
        for (Plugin p : tool.getManagedPlugins()) {
            pluginNames.add(p.getClass().getSimpleName());
            if (p instanceof RefinedDecompilerPlugin found) plugin = found;
        }
        check("the plugin loads into a code browser", plugin != null && addError[0] == null, addError[0]);
        check("beside the Listing and the Decompiler", pluginNames.contains("CodeBrowserPlugin") && pluginNames.contains("DecompilePlugin"),
            pluginNames.size() + " plugins");
        if (plugin == null) return;
        ComponentProvider provider = tool.getComponentProvider("Refined Decompiler");
        check("it registers its window, closed until asked for", provider != null && !tool.isVisible(provider), null);
        if (provider == null) return;
        check("adding it raises no dialog", dialogs().isEmpty(), dialogs());

        Set<String> actions = new TreeSet<>();
        for (DockingActionIf action : tool.getDockingActionsByOwnerName(plugin.getName())) actions.add(action.getName());
        check("its actions are registered", actions.containsAll(List.of("Refine Again", "Show Decompiler Output", "Show Rewrites",
            "Show Configuration", "Copy Refined Code", "Export Refinement Configuration", "Import Refinement Configuration",
            "Reset Refinement Configuration", "Show Refined Decompiler")), actions);

        // --- a program ---
        Program program = ghidraProject.importProgram(binary);
        ghidraProject.analyze(program);
        int transaction = program.startTransaction("prepare");
        ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);
        // What an analyst would fix first: without it the hash this function computes looks unused.
        FunctionDefinitionDataType signature = new FunctionSignatureParser(program.getDataTypeManager(), null)
            .parse(null, "unsigned int hash_bytes(unsigned char *p, unsigned long n)");
        new ApplyFunctionSignatureCmd(function(program, "hash_bytes").getEntryPoint(), signature, SourceType.USER_DEFINED)
            .applyTo(program, TaskMonitor.DUMMY);
        program.endTransaction(transaction, true);
        ghidraProject.saveAs(program, "/", program.getName(), true);
        ProgramManager programs = tool.getService(ProgramManager.class);
        Swing.runNow(() -> programs.openProgram(program));
        settle();

        // --- the window ---
        Swing.runNow(() -> tool.showComponentProvider(provider, true));
        settle();
        check("the window opens", tool.isVisible(provider) && provider.getComponent() instanceof RefinedDecompilerView
            && provider.getComponent().isShowing(), provider.getComponent().getClass().getName());
        view = (RefinedDecompilerView) provider.getComponent();

        GoToService goTo = tool.getService(GoToService.class);
        CodeViewerService listing = tool.getService(CodeViewerService.class);
        Function hash3 = function(program, "hash3");
        Swing.runNow(() -> goTo.goTo(hash3.getEntryPoint()));
        check("it refines the function under the cursor", await(v -> shows(v, "hash3") && v.code().getText().contains("mix(mix(mix(")),
            text());
        check("the title names the function", "hash3".equals(provider.getSubTitle()), provider.getSubTitle());
        check("the status line reports the emulator's verdict", Swing.runNow(() -> view.statusText()).contains("emulator agrees"),
            Swing.runNow(() -> view.statusText()));
        check("the rewrite list is filled", Swing.runNow(() -> view.rewriteRows()) >= 5, Swing.runNow(() -> view.rewriteRows()));
        screenshot(new File(directory, "_refined_gui_1_inlined_helpers.png"));

        // --- it follows the cursor ---
        Function hashBytes = function(program, "hash_bytes");
        Swing.runNow(() -> goTo.goTo(hashBytes.getEntryPoint()));
        check("moving the cursor to another function refines that one",
            await(v -> shows(v, "hash_bytes") && v.code().getText().contains("uVar1 = mix(p[uVar2], uVar1);")), text());
        screenshot(new File(directory, "_refined_gui_2_loop.png"));

        // --- clicking a line moves the Listing ---
        String body = Swing.runNow(() -> view.code().getText());
        int offset = body.indexOf("uVar1 = mix(");
        Address expected = Swing.runNow(() -> view.code().addressAt(offset));
        Swing.runNow(() -> {
            try {
                Rectangle2D at = view.code().modelToView2D(offset);
                view.code().dispatchEvent(new MouseEvent(view.code(), MouseEvent.MOUSE_CLICKED, System.currentTimeMillis(), 0,
                    (int) at.getX() + 3, (int) at.getCenterY(), 1, false, MouseEvent.BUTTON1));
            } catch (Exception e) {
                System.out.println("click failed: " + e);
            }
        });
        settle();
        Address cursor = listing.getCurrentLocation() == null ? null : listing.getCurrentLocation().getAddress();
        check("clicking a refined line moves the Listing to its address", expected != null && expected.equals(cursor)
            && hashBytes.getBody().contains(cursor), "line=" + expected + " listing=" + cursor);
        check("and the window stays on the same function", shows(view, "hash_bytes"), text());

        // --- the configuration drives the code, live ---
        Function rotl13 = function(program, "rotl13");
        Swing.runNow(() -> goTo.goTo(rotl13.getEntryPoint()));
        check("a rule-based rewrite is shown", await(v -> shows(v, "rotl13") && v.code().getText().contains("rotl(param_1, 0xd)")), text());
        JCheckBox rules = find(view, JCheckBox.class, b -> b.getText().equals("Rewrite rules (idioms)"));
        Swing.runNow(() -> rules.doClick());
        check("switching a pass off updates the code by itself",
            await(v -> shows(v, "rotl13") && v.code().getText().contains("<< 0xd") && !v.code().getText().contains("rotl(")), text());
        screenshot(new File(directory, "_refined_gui_3_pass_off.png"));
        Swing.runNow(() -> rules.doClick());
        check("and switching it back on restores it", await(v -> v.code().getText().contains("rotl(param_1, 0xd)")), text());

        Function mul9 = function(program, "mul9");
        Swing.runNow(() -> goTo.goTo(mul9.getEntryPoint()));
        check("a function with nothing to undo is shown as the decompiler has it", await(v -> shows(v, "mul9")
            && v.code().getText().contains("param_1 * 9")), text());
        JTextArea editor = find(view, JTextArea.class, a -> a.isEditable());
        Swing.runNow(() -> editor.setText("mine: $x * 9 => $x * 8 + $x"));
        check("typing a rule of your own rewrites the code", await(v -> v.code().getText().contains("param_1 * 8 + param_1")), text());
        check("and the rewrite is proved", Swing.runNow(() -> view.shown().log.stream()
            .anyMatch(r -> r.rule.equals("mine") && r.status == decompfuncutils.refine.Rewrite.Status.PROVEN)),
            Swing.runNow(() -> String.valueOf(view.shown().log)));
        screenshot(new File(directory, "_refined_gui_4_user_rule.png"));
        Swing.runNow(() -> editor.setText("wrong: $x * 9 => $x * 8"));
        check("a wrong rule changes nothing and is listed as refuted", await(v -> v.shown() != null
            && v.shown().count(decompfuncutils.refine.Rewrite.Status.REFUTED) == 1 && v.code().getText().contains("param_1 * 9")), text());
        Swing.runNow(() -> editor.setText(""));
        await(v -> v.shown() != null && v.shown().log.isEmpty());

        // --- toolbar ---
        Function sdiv8 = function(program, "sdiv8");
        Swing.runNow(() -> goTo.goTo(sdiv8.getEntryPoint()));
        check("division by a power of two is recovered", await(v -> shows(v, "sdiv8") && v.code().getText().contains("param_1 / 8")), text());
        RefinedDecompilerPlugin owner = plugin;
        toggle(owner, "Show Decompiler Output", true);
        settle();
        check("'Show Decompiler Output' shows what the decompiler printed", text().contains(">> 3") && !text().contains("param_1 / 8"), text());
        toggle(owner, "Show Decompiler Output", false);
        settle();
        check("and switching it off returns to the refined code", text().contains("param_1 / 8"), text());
        toggle(owner, "Show Configuration", false);
        settle();
        JCheckBox hidden = find(view, JCheckBox.class, b -> b.getText().equals("Rewrite rules (idioms)"));
        check("'Show Configuration' hides the configuration", hidden == null || !hidden.isShowing(), null);
        screenshot(new File(directory, "_refined_gui_5_code_only.png"));
        toggle(owner, "Show Configuration", true);
        settle();

        // --- an edit to the program refreshes the view ---
        int rename = program.startTransaction("rename");
        sdiv8.setName("divide_by_eight", SourceType.USER_DEFINED);
        program.endTransaction(rename, true);
        check("renaming the function in the program refreshes the window",
            await(v -> v.code().getText().contains("divide_by_eight(") && v.code().getText().contains("param_1 / 8")), text());
        check("and the title follows", await(v -> "divide_by_eight".equals(provider.getSubTitle())), provider.getSubTitle());

        // --- the configuration is saved with the tool ---
        JCheckBox inline = find(view, JCheckBox.class, b -> b.getText().equals("Recover inlined helper functions"));
        Swing.runNow(() -> inline.doClick());
        settle();
        SaveState state = new SaveState("RefinedDecompilerPlugin");
        owner.writeConfigState(state);
        String saved = state.getString("Refinement Configuration", "");
        check("the tool saves the configuration", !RefineConfig.fromJson(saved).pass("inline").enabled, saved.length() + " chars");
        Swing.runNow(() -> view.configPanel().setConfig(RefineConfig.defaults()));
        Swing.runNow(() -> owner.readConfigState(state));
        check("and restores it", !Swing.runNow(() -> view.configPanel().config().pass("inline").enabled), null);
        Swing.runNow(() -> view.configPanel().setConfig(RefineConfig.defaults()));

        // --- hidden, it does no work; shown again, it catches up ---
        Swing.runNow(() -> tool.showComponentProvider(provider, false));
        settle();
        Swing.runNow(() -> goTo.goTo(hash3.getEntryPoint()));
        settle();
        check("a hidden window does not refine", !shows(view, "hash3"), text());
        Swing.runNow(() -> tool.showComponentProvider(provider, true));
        check("showing it again refines the current function", await(v -> shows(v, "hash3")), text());

        check("nothing raised a dialog along the way", dialogs().isEmpty(), dialogs());
    }

    // ---------------------------------------------------------------------------------------
    // plumbing
    // ---------------------------------------------------------------------------------------

    private static Function function(Program program, String name) {
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name) && !f.isThunk() && !f.isExternal()) return f;
        }
        throw new IllegalStateException("the binary has no function " + name);
    }

    private static boolean shows(RefinedDecompilerView v, String function) {
        RefineResult shown = v.shown();
        return shown != null && shown.function.function != null && shown.function.function.getName().equals(function);
    }

    private String text() { return Swing.runNow(() -> view.code().getText()); }

    /** Wait, without holding the Swing thread, until the view satisfies a condition. */
    private boolean await(Predicate<RefinedDecompilerView> condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            if (Swing.runNow(() -> condition.test(view))) return true;
            Thread.sleep(100);
        }
        return false;
    }

    private void toggle(Plugin owner, String name, boolean selected) {
        Swing.runNow(() -> {
            for (DockingActionIf action : tool.getDockingActionsByOwnerName(owner.getName())) {
                if (action.getName().equals(name) && action instanceof ToggleDockingActionIf toggle) {
                    toggle.setSelected(selected);
                    action.actionPerformed(new DefaultActionContext());
                }
            }
        });
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T find(Container root, Class<T> type, Predicate<T> test) {
        return Swing.runNow(() -> findNow(root, type, test));
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T findNow(Container root, Class<T> type, Predicate<T> test) {
        for (Component c : root.getComponents()) {
            if (type.isInstance(c) && test.test((T) c)) return (T) c;
            if (c instanceof Container inner) {
                T hit = findNow(inner, type, test);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    /** The extension plugins the tool declares it knows, so Ghidra does not ask "New Plugins Found!". */
    private static Element knownExtensions() {
        Element extensions = new Element("EXTENSIONS");
        Element extension = new Element("EXTENSION").setAttribute("NAME", "DecompFuncUtils");
        Set<String> names = new TreeSet<>();
        for (Class<? extends Plugin> plugin : ClassSearcher.getClasses(Plugin.class)) {
            if (plugin.getName().startsWith("decompfuncutils.")) names.add(plugin.getName());
        }
        for (String name : names) extension.addContent(new Element("PLUGIN").setAttribute("CLASS", name));
        extensions.addContent(extension);
        return extensions;
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
                if (window instanceof JDialog dialog && dialog.isShowing() && "Tip of the Day".equals(dialog.getTitle())) dialog.dispose();
            }
        });
    }

    private void screenshot(File file) {
        Swing.runNow(() -> {
            try {
                Container content = tool.getToolFrame().getRootPane();
                BufferedImage image = new BufferedImage(content.getWidth(), content.getHeight(), BufferedImage.TYPE_INT_RGB);
                Graphics2D g = image.createGraphics();
                content.paint(g);
                g.dispose();
                ImageIO.write(image, "png", file);
                System.out.println("SCREENSHOT " + file + " " + image.getWidth() + "x" + image.getHeight());
            } catch (Exception e) {
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
        if (component instanceof javax.swing.JLabel label && label.getText() != null) sb.append(label.getText()).append(' ');
        if (component instanceof Container container) for (Component child : container.getComponents()) text(child, sb);
        return sb.length() > 300 ? sb.substring(0, 300) : sb.toString();
    }

    private void check(String label, boolean ok, Object detail) {
        String shown = detail == null ? "" : String.valueOf(detail).replaceAll("\\s+", " ");
        System.out.println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (ok || shown.isEmpty() ? "" : "  (" + (shown.length() > 500 ? shown.substring(0, 500) + "..." : shown) + ")"));
        if (!ok) failures++;
    }

    /** A modal dialog would otherwise hang the run forever; say which one and give up. */
    private static void watchdog(int seconds) {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(seconds * 1000L);
            } catch (InterruptedException e) {
                return;
            }
            System.out.println("TOOL_TEST_RESULT FAIL (timed out after " + seconds + " s)");
            for (Window window : Window.getWindows()) {
                if (!window.isShowing()) continue;
                String title = window instanceof JDialog d ? d.getTitle() : window instanceof JFrame f ? f.getTitle() : window.getClass().getName();
                System.out.println("  showing: " + window.getClass().getSimpleName() + " '" + title + "' "
                    + (window instanceof JDialog d ? text(d.getContentPane(), new StringBuilder()) : ""));
            }
            System.out.flush();
            Runtime.getRuntime().halt(3);
        }, "refined-decompiler-preview-watchdog");
        thread.setDaemon(true);
        thread.start();
    }
}
