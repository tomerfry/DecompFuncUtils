package decompfuncutils;

import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Registers the data-flow hover with the Decompiler. Toggle it under
 * Edit -> Tool Options -> Decompiler Popups -> "Data Flow Display".
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Data Flow Hover",
    description = "Pop-up in the Decompiler showing what affects the hovered variable, call or " +
        "operator and what it affects in turn",
    servicesProvided = { DecompilerHoverService.class }
)
//@formatter:on
public class DataflowDecompilerHoverPlugin extends Plugin {

    private final DataflowDecompilerHover hover;

    public DataflowDecompilerHoverPlugin(PluginTool tool) {
        super(tool);
        hover = new DataflowDecompilerHover(tool);
        registerServiceProvided(DecompilerHoverService.class, hover);
    }

    @Override
    protected void dispose() {
        hover.dispose();
        super.dispose();
    }
}
