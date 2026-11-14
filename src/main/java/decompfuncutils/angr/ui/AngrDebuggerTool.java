package decompfuncutils.angr.ui;

import ghidra.framework.ToolUtils;
import ghidra.framework.model.ToolChest;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.preferences.Preferences;

/**
 * The "angr Debugger" tool: a tool of its own in the Project window's Tool Chest, beside
 * CodeBrowser, Debugger and Emulator, rather than a panel inside one of them.
 *
 * <p>Like Ghidra's own tools it is defined by a tool file shipped under {@code defaultTools/}
 * ({@value #RESOURCE}): Ghidra's core plugins for the Listing and Decompiler, the angr Debugger
 * plugin, and a window layout arranged for debugging. Ghidra finds it there by itself, which puts
 * it in the Tool Chest of a new user and in <i>Tools &gt; Import Default Tools...</i> for an
 * existing one; {@link #installOnce} adds it to an existing user's Tool Chest without that step.
 */
public final class AngrDebuggerTool {

    public static final String NAME = "angr Debugger";
    /** The tool file, as a classpath resource. */
    public static final String RESOURCE = "defaultTools/angr_Debugger.tool";
    /** The tool's icon, as a classpath resource. */
    public static final String ICON = "images/angr-debugger.png";

    /** Set once the tool has been offered, so removing it from the Tool Chest sticks. */
    private static final String INSTALLED_PREFERENCE = "DecompFuncUtils.angrDebuggerTool.installed.v1";

    private AngrDebuggerTool() {
    }

    /** The tool as shipped, or null when the tool file is missing from the extension. */
    public static ToolTemplate template() {
        return ToolUtils.readToolTemplate(RESOURCE);
    }

    /**
     * Adds the tool to a Tool Chest that does not have one of that name.
     *
     * @return true when it was added
     */
    public static boolean install(ToolChest chest) {
        if (chest == null || chest.getToolTemplate(NAME) != null) {
            return false;
        }
        ToolTemplate template = template();
        return template != null && chest.addToolTemplate(template);
    }

    /**
     * Adds the tool to the Tool Chest the first time this extension meets it, and never again:
     * a user who then removes the tool has said they do not want it.
     *
     * @return true when it was added now
     */
    public static boolean installOnce(ToolChest chest) {
        if (chest == null || Boolean.parseBoolean(Preferences.getProperty(INSTALLED_PREFERENCE, "false"))) {
            return false;
        }
        boolean added = install(chest);
        Preferences.setProperty(INSTALLED_PREFERENCE, "true");
        Preferences.store();
        return added;
    }
}
