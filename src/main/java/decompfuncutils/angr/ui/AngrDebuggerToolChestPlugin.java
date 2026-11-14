package decompfuncutils.angr.ui;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * Puts the "angr Debugger" tool into the Project window's Tool Chest.
 *
 * <p>Ghidra copies its default tools into a user's Tool Chest only once, when the user first runs
 * it. A tool that arrives later with an extension is merely offered under <i>Tools &gt; Import
 * Default Tools...</i>, which nobody thinks to look at. So this front-end plugin adds the tool
 * the first time it sees a project, and offers a menu item to put it back.
 *
 * <p>Like the MCP session manager it lives in the "Utility" package, which every saved Project
 * window configuration includes, so it loads on the next start with no configuration step.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "angr Debugger tool (DecompFuncUtils)",
    description = "Adds the angr Debugger tool to the Tool Chest of the Project window."
)
//@formatter:on
public class AngrDebuggerToolChestPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener {

    private DockingAction addAction;

    public AngrDebuggerToolChestPlugin(PluginTool tool) {
        super(tool);
        addAction = new DockingAction("Add angr Debugger to Tool Chest", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Project project = tool.getProject();
                if (project == null) {
                    Msg.showInfo(this, null, AngrDebuggerTool.NAME, "Open a project first.");
                    return;
                }
                boolean added = AngrDebuggerTool.install(project.getLocalToolChest());
                Msg.showInfo(this, null, AngrDebuggerTool.NAME, added
                    ? "The angr Debugger tool was added to the Tool Chest."
                    : "The Tool Chest already has an angr Debugger tool. Delete it there first to get a fresh copy.");
            }
        };
        addAction.setMenuBarData(new MenuData(
            new String[] { "Tools", "Add angr Debugger to Tool Chest" }, null, "angr"));
        addAction.setDescription("Add the angr Debugger tool to the Tool Chest of this Project window");
        tool.addAction(addAction);
    }

    @Override
    protected void init() {
        // Nothing here may stop the Project window from coming up.
        try {
            FrontEndService frontEnd = tool.getService(FrontEndService.class);
            if (frontEnd != null) {
                frontEnd.addProjectListener(this);
            }
            installFor(tool.getProject());
        }
        catch (Throwable t) {
            Msg.error(this, "Could not add the angr Debugger tool to the Tool Chest: " + t, t);
        }
    }

    private void installFor(Project project) {
        if (project == null) {
            return;
        }
        if (AngrDebuggerTool.installOnce(project.getLocalToolChest())) {
            Msg.info(this, "Added the '" + AngrDebuggerTool.NAME + "' tool to the Tool Chest");
        }
    }

    @Override
    public void projectOpened(Project project) {
        try {
            installFor(project);
        }
        catch (Throwable t) {
            Msg.error(this, "Could not add the angr Debugger tool to the Tool Chest: " + t, t);
        }
    }

    @Override
    public void projectClosed(Project project) {
        // nothing to undo
    }

    @Override
    protected void dispose() {
        FrontEndService frontEnd = tool.getService(FrontEndService.class);
        if (frontEnd != null) {
            frontEnd.removeProjectListener(this);
        }
        if (addAction != null) {
            tool.removeAction(addAction);
        }
        super.dispose();
    }
}
