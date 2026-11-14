package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineConfig;
import decompfuncutils.refine.RefineEngine;
import decompfuncutils.refine.RefineResult;
import docking.WindowPosition;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import resources.Icons;

/**
 * The Refined Decompiler window: refined C for the function under the cursor, the list of
 * rewrites behind it, and the configuration that produced it. Editing the configuration re-runs
 * the engine after a short pause, so the code follows the controls.
 *
 * <p>Refinement runs on one background thread. A newer request cancels the one in flight, and a
 * result is only shown if it is still the latest request -- typing in the rule editor never
 * leaves the window showing an answer to an older question.
 */
public final class RefinedDecompilerProvider extends ComponentProviderAdapter {
    private final RefinedDecompilerView view;
    private final Timer debounce;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Refined Decompiler");
        t.setDaemon(true);
        return t;
    });

    private Program program;
    private Function function;
    private long generation;
    private TaskMonitorAdapter running;
    /** Touched only on the worker thread. */
    private RefineEngine engine;

    public RefinedDecompilerProvider(PluginTool tool, String owner, RefineConfig initial, Consumer<Address> navigator) {
        super(tool, "Refined Decompiler", owner);
        setTitle("Refined Decompiler");
        setDefaultWindowPosition(WindowPosition.RIGHT);
        setWindowMenuGroup("Decompiler");
        debounce = new Timer(280, e -> refineNow());
        debounce.setRepeats(false);
        view = new RefinedDecompilerView(initial, this::requestRefine, navigator);
        createActions(owner);
    }

    @Override public JComponent getComponent() { return view; }

    // ------------------------------------------------------------------ actions

    private void createActions(String owner) {
        new ActionBuilder("Refine Again", owner)
            .toolBarIcon(Icons.REFRESH_ICON)
            .description("Run the refinement again for the current function")
            .onAction(c -> refineNow())
            .buildAndInstallLocal(this).markHelpUnnecessary();

        ToggleDockingAction[] original = new ToggleDockingAction[1];
        original[0] = new ToggleActionBuilder("Show Decompiler Output", owner)
            .toolBarIcon(Icons.LEFT_ALTERNATE_ICON)
            .description("Show what the decompiler printed, to compare with the refined code")
            .selected(false)
            .onAction(c -> view.showOriginal(original[0].isSelected()))
            .buildAndInstallLocal(this);
        original[0].markHelpUnnecessary();

        ToggleDockingAction[] rewrites = new ToggleDockingAction[1];
        rewrites[0] = new ToggleActionBuilder("Show Rewrites", owner)
            .toolBarIcon(Icons.INFO_ICON)
            .description("Show the list of rewrites and notes below the code")
            .selected(true)
            .onAction(c -> view.setRewritesVisible(rewrites[0].isSelected()))
            .buildAndInstallLocal(this);
        rewrites[0].markHelpUnnecessary();

        ToggleDockingAction[] configuration = new ToggleDockingAction[1];
        configuration[0] = new ToggleActionBuilder("Show Configuration", owner)
            .toolBarIcon(Icons.CONFIGURE_FILTER_ICON)
            .description("Show the passes, rules and verification settings that shape the refined code")
            .selected(true)
            .onAction(c -> view.setConfigVisible(configuration[0].isSelected()))
            .buildAndInstallLocal(this);
        configuration[0].markHelpUnnecessary();

        new ActionBuilder("Copy Refined Code", owner)
            .toolBarIcon(Icons.COPY_ICON)
            .description("Copy the code shown to the clipboard")
            .onAction(c -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(view.code().getText()), null))
            .buildAndInstallLocal(this).markHelpUnnecessary();

        new ActionBuilder("Export Refinement Configuration", owner)
            .menuPath("Export Configuration...")
            .description("Save the configuration as JSON (the same object ghidra_refine_function accepts as 'config')")
            .onAction(c -> exportConfig())
            .buildAndInstallLocal(this).markHelpUnnecessary();

        new ActionBuilder("Import Refinement Configuration", owner)
            .menuPath("Import Configuration...")
            .description("Load a configuration saved earlier")
            .onAction(c -> importConfig())
            .buildAndInstallLocal(this).markHelpUnnecessary();

        new ActionBuilder("Reset Refinement Configuration", owner)
            .menuPath("Reset Configuration to Defaults")
            .description("Discard every change to the configuration, including your rules")
            .onAction(c -> {
                view.configPanel().setConfig(RefineConfig.defaults());
                requestRefine();
            })
            .buildAndInstallLocal(this).markHelpUnnecessary();
    }

    private void exportConfig() {
        GhidraFileChooser chooser = new GhidraFileChooser(view);
        chooser.setTitle("Export Refinement Configuration");
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setApproveButtonText("Export");
        chooser.setSelectedFile(new File("refine-config.json"));
        File file = chooser.getSelectedFile();
        chooser.close();
        if (file == null) return;
        try {
            Files.writeString(file.toPath(), view.configPanel().config().toJson(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            Msg.showError(this, view, "Export Configuration", "Could not write " + file + ": " + e.getMessage(), e);
        }
    }

    private void importConfig() {
        GhidraFileChooser chooser = new GhidraFileChooser(view);
        chooser.setTitle("Import Refinement Configuration");
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setApproveButtonText("Import");
        File file = chooser.getSelectedFile();
        chooser.close();
        if (file == null) return;
        try {
            view.configPanel().setConfig(RefineConfig.fromJson(Files.readString(file.toPath(), StandardCharsets.UTF_8)));
            requestRefine();
        } catch (Exception e) {
            Msg.showError(this, view, "Import Configuration", "Could not read a configuration from " + file + ": " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------ what the plugin tells us

    public String configJson() { return view.configPanel().config().toJson(); }

    public void setConfigJson(String json) {
        try {
            view.configPanel().setConfig(RefineConfig.fromJson(json));
        } catch (RuntimeException e) {
            Msg.warn(this, "Ignoring a saved refinement configuration that no longer parses: " + e);
        }
    }

    /** The active program changed (null when none is open). */
    public void setProgram(Program p) {
        if (p == program) return;
        program = p;
        function = null;
        cancelRunning();
        generation++;
        setSubTitle("");
        view.showHint(p == null ? "No program is open." : "Place the cursor in a function to see it refined.");
    }

    /** The cursor moved in the listing or the decompiler. */
    public void locationChanged(ProgramLocation location) {
        if (program == null || location == null || location.getAddress() == null) return;
        Address address = location.getAddress();
        Function f = program.getFunctionManager().getFunctionContaining(address);
        if (f == null) return;   // between functions: keep showing the last one
        view.highlight(address);
        if (!f.equals(function)) {
            function = f;
            requestRefine();
        }
    }

    /** The program was edited (a rename, a retype, new code): what we show may be stale. */
    public void programChanged() {
        if (function != null && function.isDeleted()) function = null;
        requestRefine();
    }

    @Override public void componentShown() {
        RefineResult shown = view.shown();
        if (shown == null || function == null || !function.equals(shown.function.function)) requestRefine();
    }

    @Override public void componentHidden() { cancelRunning(); }

    public void dispose() {
        debounce.stop();
        cancelRunning();
        generation++;
        worker.submit(() -> {
            if (engine != null) engine.close();
            engine = null;
        });
        worker.shutdown();
    }

    // ------------------------------------------------------------------ running the engine

    /** Refine soon: collapses a burst of changes (typing a rule, spinning a number) into one run. */
    public void requestRefine() { debounce.restart(); }

    private void cancelRunning() {
        if (running != null) running.cancel();
        running = null;
    }

    private void refineNow() {
        debounce.stop();
        if (!isVisible() || program == null || function == null) return;
        cancelRunning();
        long mine = ++generation;
        Program p = program;
        Function f = function;
        RefineConfig config = view.configPanel().config().copy();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        running = monitor;
        view.showBusy(f.getName());
        worker.submit(() -> {
            try {
                if (p.isClosed()) return;
                if (engine == null || engine.program() != p) {
                    if (engine != null) engine.close();
                    engine = new RefineEngine(p);
                }
                RefineResult result = engine.refine(f, config, monitor);
                SwingUtilities.invokeLater(() -> {
                    if (mine != generation) return;
                    running = null;
                    view.showResult(result);
                    setSubTitle(f.getName());
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    if (mine != generation) return;
                    running = null;
                    view.showFailure(f.getName(), t);
                    Msg.error(this, "Refinement of " + f.getName() + " failed", t);
                });
            }
        });
    }
}
