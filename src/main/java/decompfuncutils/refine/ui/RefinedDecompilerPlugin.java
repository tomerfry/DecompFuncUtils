package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineConfig;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Adds the Refined Decompiler window: a second pane beside the decompiler that shows the function
 * under the cursor after the refinement engine has undone what the optimizer did to it, together
 * with the controls that shape that result.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Refined Decompiler",
    description = "A second-layer analysis over the decompiler's output. Combines the decompiler's syntax tree and p-code, "
        + "the disassembly, Z3 symbolic reasoning and emulation to reverse compiler optimizations and inlining, and shows the "
        + "refined C in its own window. Passes, rewrite rules and verification are configurable, and the output updates as "
        + "the configuration changes."
)
public class RefinedDecompilerPlugin extends ProgramPlugin implements DomainObjectListener {
    private static final String CONFIG_KEY = "Refinement Configuration";

    private final RefinedDecompilerProvider provider;
    private Program listening;

    public RefinedDecompilerPlugin(PluginTool tool) {
        super(tool);
        provider = new RefinedDecompilerProvider(tool, getName(), RefineConfig.defaults(), this::goTo);
        // addToTool, not tool.addComponentProvider: only the former also installs the actions
        // the provider created for its own toolbar and menu.
        provider.addToTool();

        new ActionBuilder("Show Refined Decompiler", getName())
            .popupMenuPath("Refined Decompiler")
            .popupMenuGroup("Decompile")
            .description("Open the Refined Decompiler window for this function")
            .popupWhen(c -> c instanceof DecompilerActionContext)
            .onAction(c -> tool.showComponentProvider(provider, true))
            .buildAndInstall(tool).markHelpUnnecessary();
    }

    @Override protected void programActivated(Program program) {
        listen(program);
        provider.setProgram(program);
        if (currentLocation != null) provider.locationChanged(currentLocation);
    }

    @Override protected void programDeactivated(Program program) {
        listen(null);
        provider.setProgram(null);
    }

    @Override protected void locationChanged(ProgramLocation location) {
        provider.locationChanged(location);
    }

    private void listen(Program program) {
        if (listening != null) listening.removeListener(this);
        listening = program;
        if (program != null) program.addListener(this);
    }

    /** Any edit may change the decompilation; the provider coalesces a burst into one refresh. */
    @Override public void domainObjectChanged(DomainObjectChangedEvent event) {
        provider.programChanged();
    }

    @Override public void writeConfigState(SaveState state) {
        state.putString(CONFIG_KEY, provider.configJson());
    }

    @Override public void readConfigState(SaveState state) {
        String json = state.getString(CONFIG_KEY, null);
        if (json != null) provider.setConfigJson(json);
    }

    @Override protected void dispose() {
        listen(null);
        provider.removeFromTool();
        provider.dispose();
        super.dispose();
    }
}
