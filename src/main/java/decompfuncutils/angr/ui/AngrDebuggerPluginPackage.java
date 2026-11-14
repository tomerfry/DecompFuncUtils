package decompfuncutils.angr.ui;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * The plugin package of the angr Debugger.
 *
 * <p>A tool file names its plugins by package, and only a registered package can be named, so
 * this is what lets the "angr Debugger" tool say "everything in the angr Debugger package"
 * instead of pulling in every other plugin of the extension.
 */
public class AngrDebuggerPluginPackage extends PluginPackage {

    public static final String NAME = "angr Debugger";

    public AngrDebuggerPluginPackage() {
        super(NAME, ResourceManager.loadImage(AngrDebuggerTool.ICON),
            "Step, inspect and steer a function of the program under angr.", FEATURE_PRIORITY);
    }
}
