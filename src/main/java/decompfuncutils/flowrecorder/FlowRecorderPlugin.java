package decompfuncutils.flowrecorder;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import javax.swing.BoxLayout;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.Dimension;
import java.io.File;
import java.nio.file.Path;
import java.util.List;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Record reverser actions as MCP flow templates",
    description =
        "Toggles recording of a reverser's actions (renames, retypes, comments, " +
        "struct/class creation) and exports them as a templated markdown flow file " +
        "that an MCP agent can later replay on a different binary to reproduce " +
        "complex operations like class definition and code refinement."
)
//@formatter:on
public class FlowRecorderPlugin extends ProgramPlugin {

    private final FlowRecorder recorder = new FlowRecorder();

    private ToggleDockingAction toggleAction;
    private DockingAction saveAction;
    private DockingAction clearAction;

    public FlowRecorderPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        toggleAction = new ToggleDockingAction("Toggle Flow Recording", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                if (isSelected()) {
                    if (currentProgram == null) {
                        Msg.showWarn(this, null, "Flow Recorder",
                            "Open a program before starting recording.");
                        setSelected(false);
                        return;
                    }
                    recorder.reset();
                    recorder.start(currentProgram);
                    tool.setStatusInfo("Flow recording started");
                } else {
                    recorder.stop();
                    tool.setStatusInfo(
                        "Flow recording stopped — " + recorder.getSteps().size() + " steps captured");
                }
            }
        };
        toggleAction.setMenuBarData(
            new MenuData(new String[] { "Tools", "Flow Recorder", "Record" }));
        toggleAction.setDescription("Start/stop recording reverser actions as a flow template");
        tool.addAction(toggleAction);

        saveAction = new DockingAction("Save Flow Recording", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) { saveFlow(); }

            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return !recorder.getSteps().isEmpty();
            }
        };
        saveAction.setMenuBarData(
            new MenuData(new String[] { "Tools", "Flow Recorder", "Save as Markdown..." }));
        saveAction.setDescription("Export recorded flow as a templated markdown file");
        tool.addAction(saveAction);

        clearAction = new DockingAction("Clear Flow Recording", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                recorder.reset();
                tool.setStatusInfo("Flow recording cleared");
            }

            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return !recorder.getSteps().isEmpty();
            }
        };
        clearAction.setMenuBarData(
            new MenuData(new String[] { "Tools", "Flow Recorder", "Clear" }));
        clearAction.setDescription("Discard currently recorded flow steps");
        tool.addAction(clearAction);
    }

    private void saveFlow() {
        List<FlowStep> steps = recorder.getSteps();
        if (steps.isEmpty()) {
            Msg.showInfo(this, null, "Flow Recorder", "No steps recorded yet.");
            return;
        }

        // Prompt for name + description
        JTextField nameField = new JTextField("my_flow");
        JTextArea descField = new JTextArea(4, 30);
        descField.setLineWrap(true);
        descField.setWrapStyleWord(true);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Flow name:"));
        panel.add(nameField);
        panel.add(new JLabel("Description (what this template accomplishes):"));
        panel.add(new JScrollPane(descField));
        panel.setPreferredSize(new Dimension(400, 220));

        int result = JOptionPane.showConfirmDialog(null, panel, "Save Flow Template",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        String name = nameField.getText().trim();
        String description = descField.getText().trim();
        if (name.isEmpty()) name = "flow";

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Flow Template");
        chooser.setFileFilter(new FileNameExtensionFilter("Markdown files", "md"));
        chooser.setSelectedFile(new File(name.replaceAll("[^A-Za-z0-9._-]", "_") + ".md"));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        if (!target.getName().toLowerCase().endsWith(".md")) {
            target = new File(target.getParentFile(), target.getName() + ".md");
        }

        Program src = recorder.getProgram();
        String progName = src != null ? src.getName() : "unknown";
        try {
            FlowMarkdownWriter.write(
                Path.of(target.getAbsolutePath()),
                name, description, progName, steps, recorder.getTemplatizer());
            Msg.showInfo(this, null, "Flow Recorder",
                "Saved " + steps.size() + " step(s) to:\n" + target.getAbsolutePath());
            tool.setStatusInfo("Flow template saved: " + target.getName());
        } catch (Exception e) {
            Msg.showError(this, null, "Flow Recorder",
                "Failed to write flow file: " + e.getMessage(), e);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        // If the program the recorder is attached to goes away, stop cleanly.
        if (recorder.isRecording() && program == recorder.getProgram()) {
            recorder.stop();
            if (toggleAction != null) toggleAction.setSelected(false);
        }
    }

    @Override
    protected void dispose() {
        recorder.stop();
        super.dispose();
    }
}
