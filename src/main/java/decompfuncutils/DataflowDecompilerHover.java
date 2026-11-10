package decompfuncutils;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

/**
 * Decompiler hover that shows, for the variable, call or operator under the cursor,
 * what it is affected by and what it affects (see {@link DataflowSlicer}).
 *
 * It reads the HighFunction the Decompiler already produced and never decompiles,
 * so it is cheap enough for the Swing thread.
 */
public class DataflowDecompilerHover extends AbstractConfigurableHover implements DecompilerHoverService {

    private static final String NAME = "Data Flow Display";
    private static final String DESCRIPTION =
        "Show what affects the hovered variable, call or operator and what it affects in turn.";

    // Relative to other decompiler hovers; the highest priority is asked first and the
    // first non-null popup wins. Above data type / function signature (20) so this shows
    // on variables and call names, below scalar (30) and reference (50).
    private static final int PRIORITY = 25;

    // No field initializers for option-backed state: initializeOptions() runs inside
    // the super constructor, before this class's initializers.

    public DataflowDecompilerHover(PluginTool tool) {
        super(tool, PRIORITY);
    }

    @Override
    protected String getName() {
        return NAME;
    }

    @Override
    protected String getDescription() {
        return DESCRIPTION;
    }

    @Override
    protected String getOptionsCategory() {
        return GhidraOptions.CATEGORY_DECOMPILER_POPUPS;
    }

    @Override
    public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
            FieldLocation fieldLocation, Field field) {
        // programLocation is null on operator tokens, so it is deliberately unused.
        if (!enabled || !(field instanceof ClangTextField)) {
            return null;
        }
        try {
            ClangToken token = ((ClangTextField) field).getToken(fieldLocation);
            if (token == null) {
                return null;
            }
            ClangFunction clangFunction = token.getClangFunction();
            HighFunction high = clangFunction == null ? null : clangFunction.getHighFunction();
            if (high == null) {
                return null;
            }
            if (program == null && high.getFunction() != null) {
                program = high.getFunction().getProgram();
            }
            DataflowSlicer slicer = new DataflowSlicer(program, high);
            DataflowSlicer.Seed seed = slicer.seedFromToken(token);
            if (seed == null) {
                return null;    // let the other hovers have this token
            }
            String html = DataflowSlicer.toHtml(slicer.slice(seed), DataflowSlicer.DEFAULT_MAX_ITEMS);
            return createTooltipComponent(html);
        }
        catch (RuntimeException e) {
            // Hovering must never break the Decompiler.
            Msg.debug(this, "Data flow hover failed: " + e);
            return null;
        }
    }
}
