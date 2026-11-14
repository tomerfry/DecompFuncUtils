import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import decompfuncutils.refine.*;
import decompfuncutils.refine.ui.RefinedDecompilerView;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.swing.*;

/**
 * Diagnostic helper: renders the contents of the Refined Decompiler window for one function to a
 * PNG, off screen, so the view can be looked at without a running tool. The function name is the
 * first script argument (default hash_bytes); REFINE_SNAPSHOT_OUT names the PNG, REFINE_SIGS holds
 * C prototypes (separated by ';') to apply first. Not a regression test.
 *
 *   tests/run_refine_test.ps1 -Script RefineSnapshot.java -ShowAll -ScriptArgs digit_sum
 */
public class RefineSnapshot extends GhidraScript {
    @Override public void run() throws Exception {
        String name = getScriptArgs().length > 0 ? getScriptArgs()[0] : "hash_bytes";
        String out = System.getenv("REFINE_SNAPSHOT_OUT");
        if (out == null) out = name + ".png";
        String sigs = System.getenv("REFINE_SIGS");
        for (String sig : sigs == null ? new String[0] : sigs.split(";")) {
            if (sig.isBlank()) continue;
            var def = new ghidra.app.util.parser.FunctionSignatureParser(currentProgram.getDataTypeManager(), null).parse(null, sig.strip());
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(def.getName())) {
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.getEntryPoint(), def,
                        ghidra.program.model.symbol.SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
                }
            }
        }
        Function fn = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name) && !f.isThunk()) fn = f;
        }
        if (fn == null) throw new IllegalArgumentException("No function " + name);
        RefineResult result;
        try (RefineEngine engine = new RefineEngine(currentProgram)) {
            result = engine.refine(fn, RefineConfig.defaults(), monitor);
        }
        String path = out;
        Function shownFn = fn;
        SwingUtilities.invokeAndWait(() -> {
            RefinedDecompilerView view = new RefinedDecompilerView(RefineConfig.defaults(), () -> { }, a -> { });
            view.showResult(result);
            view.highlight(shownFn.getEntryPoint());
            view.setSize(1280, 760);
            layout(view);
            layout(view);
            BufferedImage img = new BufferedImage(view.getWidth(), view.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            view.printAll(g);
            g.dispose();
            try {
                javax.imageio.ImageIO.write(img, "png", new java.io.File(path));
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        });
        println("REFINE_SNAPSHOT wrote " + out);
    }

    /** Lay a component tree out without ever showing it. */
    private static void layout(Component c) {
        synchronized (c.getTreeLock()) {
            c.doLayout();
            if (c instanceof Container container) for (Component child : container.getComponents()) layout(child);
        }
    }
}
