// Headless regression test for the angr Debugger panel (AngrDebuggerPanel + AngrDebuggerController).
//
// Driven by tests/run_angr_test.ps1 -Script AngrDebuggerPanelHeadlessTest.java. The panel is plain
// Swing, so it is built without a tool window, driven by clicking its real buttons against real
// angr sessions, checked through its tables and banner, and painted off-screen into
// tests/_angr_debugger_*.png so the layout can be looked at. What needs a live Ghidra window -
// docking, markers in the Listing, the right-click actions - is not covered here.
//@category Test
import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.angr.AngrHooks;
import decompfuncutils.angr.ui.AngrDebuggerController;
import decompfuncutils.angr.ui.AngrDebuggerPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;
import java.util.List;

public class AngrDebuggerPanelHeadlessTest extends GhidraScript {

    private int failures = 0;
    private AngrDebuggerController controller;
    private AngrDebuggerPanel panel;
    private final List<String> navigated = new ArrayList<>();
    private volatile Address lastPc;
    private int shots = 0;

    private void check(String label, boolean ok, Object detail) {
        String text = detail == null ? "" : String.valueOf(detail).replace("\n", "\\n");
        println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (text.isEmpty() ? "" : "  (" + (text.length() > 500 ? text.substring(0, 500) + "..." : text) + ")"));
        if (!ok) {
            failures++;
        }
    }

    @Override
    public void run() throws Exception {
        try {
            // The look Ghidra itself uses, when it is available without a display.
            UIManager.setLookAndFeel((LookAndFeel) Class.forName("com.formdev.flatlaf.FlatLightLaf")
                .getDeclaredConstructor().newInstance());
        }
        catch (Throwable t) {
            println("INFO FlatLaf not usable here (" + t + "); using the default look and feel");
        }
        Program program = currentProgram;
        SwingUtilities.invokeAndWait(() -> {
            controller = new AngrDebuggerController(() -> program, new AngrDebuggerController.Host() {
                @Override
                public void goTo(Program p, Address address) {
                    navigated.add(address.toString());
                }

                @Override
                public void positionChanged(Program p, AngrDebugSession session) {
                    lastPc = session == null ? null : session.pc();
                }

                @Override
                public String configuredPython() {
                    return null;
                }
            });
            panel = controller.panel();
        });
        try {
            body();
        }
        finally {
            AngrDebugger.forget(currentProgram);
            controller.dispose();
        }
        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    private void body() throws Exception {
        // --- how arguments are typed ---
        check("arguments: a plain call list", AngrDebuggerController.parseArguments("\"hello\", 5").size() == 2,
            AngrDebuggerController.parseArguments("\"hello\", 5"));
        check("arguments: bare hex is kept as hex text",
            "0x10".equals(AngrDebuggerController.parseArguments("0x10, {\"buffer\": 64}").get(0)),
            AngrDebuggerController.parseArguments("0x10, {\"buffer\": 64}"));
        check("arguments: hex inside a string is left alone",
            "see 0x10".equals(AngrDebuggerController.parseArguments("\"see 0x10\"").get(0)), null);
        check("arguments: empty means none", AngrDebuggerController.parseArguments("  ").isEmpty(), null);
        String bad;
        try {
            bad = "NO ERROR " + AngrDebuggerController.parseArguments("\"unterminated, 5");
        }
        catch (IllegalArgumentException e) {
            bad = e.getMessage();
        }
        check("arguments: a mistake is explained with an example", bad.contains("separated by commas"), bad);

        // --- idle ---
        check("idle banner says how to begin", "No session".equals(panel.bannerTitle())
            && panel.bannerDetail().contains("press Start"), panel.bannerDetail());
        check("idle: step buttons are off, Start is on", !panel.button("Step Into").isEnabled()
            && !panel.button("Continue").isEnabled() && panel.button("Start").isEnabled(), null);

        // --- start on a function, from the launch bar ---
        onEdt(() -> {
            controller.prepare(currentProgram, currentProgram.getListing().getGlobalFunctions("check_password").get(0));
            panel.setArguments("\"nope\"");
        });
        click("Start");
        check("the launch bar was filled in", "check_password".equals(panel.getFunction()), panel.getFunction());
        check("paused at the first instruction", panel.bannerTitle().startsWith("Paused at")
            && panel.bannerTitle().contains("check_password"), panel.bannerTitle());
        check("the banner says it is ready", panel.bannerDetail().contains("Ready at the first instruction"),
            panel.bannerDetail());
        check("registers are listed", panel.table("registers").getRowCount() >= 16,
            panel.table("registers").getRowCount());
        Map<String, Object> rdi = row("registers", "name", "rdi");
        check("a register pointing at text shows the text", "nope".equals(rdi.get("string")), rdi);
        check("the stack is listed", panel.table("stack").getRowCount() >= 8, panel.table("stack").getRowCount());
        check("the argument buffer is in the Memory tab", cells("memory").contains("arg0"), cells("memory"));
        check("step buttons are on, Start became Restart", panel.button("Step Over").isEnabled()
            && "Restart".equals(panel.button("Start").getText()), panel.button("Start").getText());
        check("the host is told where execution is", lastPc != null, lastPc);

        // --- step over the library call ---
        for (int i = 0; i < 14 && !cells("calls").contains("strcmp"); i++) {
            click("Step Over");
        }
        check("the call appears with both strings", cells("calls").contains("strcmp(")
            && cells("calls").contains("\"nope\"") && cells("calls").contains("\"hunter2\""), cells("calls"));
        check("the Calls tab counts them", panel.tabs().getTitleAt(1).equals("Calls (1)"), panel.tabs().getTitleAt(1));
        check("changed registers are marked", panel.rows("registers").stream()
            .anyMatch(r -> Boolean.TRUE.equals(r.get("changed"))), null);
        onEdt(() -> panel.selectTab("Calls"));
        shot("paused");
        click("Continue");
        check("it returns 0 for the wrong password", panel.bannerTitle().startsWith("Returned 0x0"),
            panel.bannerTitle());
        check("finished: step buttons are off again", !panel.button("Step Into").isEnabled(), null);

        // --- an unknown import: fork, paths, symbols ---
        onEdt(() -> {
            panel.setFunction("needs_device");
            panel.setArguments("");
        });
        click("Start");
        click("Continue");
        check("a branch on an unknown value forks", panel.bannerTitle().startsWith("Forked at")
            && panel.bannerDetail().contains("unknown value"), panel.bannerTitle() + " | " + panel.bannerDetail());
        check("both paths are listed and the tab opens", panel.table("paths").getRowCount() == 2
            && panel.tabs().getTitleAt(panel.tabs().getSelectedIndex()).equals("Paths (2)"),
            panel.tabs().getTitleAt(panel.tabs().getSelectedIndex()));
        check("the unknown is in the Symbols tab", panel.table("symbols").getRowCount() == 1
            && cells("symbols").contains("mystery_device_read_ret") && cells("symbols").contains("free"),
            cells("symbols"));
        check("the stubbed call is marked", cells("calls").contains("[stub]"), cells("calls"));
        shot("forked");

        onEdt(() -> panel.table("paths").setRowSelectionInterval(1, 1));
        click("Switch to Path");
        check("Switch to Path moves to the other path", panel.bannerDetail().contains("Path selected")
            && Boolean.TRUE.equals(panel.rows("paths").get(1).get("current")), panel.bannerDetail());
        String symbol = String.valueOf(panel.rows("symbols").get(0).get("name"));
        controller.concretize(Map.of("symbol", symbol), null);
        controller.await();
        check("concretize fixes the symbol", cells("symbols").contains("fixed"), cells("symbols"));
        controller.concretize(Map.of("symbol", symbol), "0x1234");
        controller.await();
        check("a refusal is shown in the banner, not a dialog", controller.lastError() != null
            && panel.bannerDetail().contains("contradicts"), panel.bannerDetail());
        click("Continue");
        check("the chosen path runs to its return", panel.bannerTitle().startsWith("Returned"), panel.bannerTitle());

        // --- imports and hooks ---
        onEdt(() -> panel.selectTab("Imports & Hooks"));
        controller.refreshImports();
        controller.await();
        Map<String, Object> device = row("imports", "target", "mystery_device_read");
        check("imports are listed with how they are handled", panel.table("imports").getRowCount() >= 5
            && cells("imports").contains("unknown value (symbolic)") && cells("imports").contains("angr model"),
            cells("imports"));
        check("the unmodelled one is flagged", Boolean.TRUE.equals(device.get("stub")), device);

        AngrHooks.Hook hook = controller.hookFor("mystery_device_read");
        check("a template is offered for a new hook", hook != null && hook.code.contains("def hook(ctx"),
            hook == null ? null : hook.code);
        hook.code = "def hook(ctx, reg):\n    ctx.log('device', reg)\n    return 0x1234\n";
        controller.saveHook(hook);
        controller.await();
        check("saving shows it in the table and says so", cells("imports").contains("python hook: mystery_device_read")
            && panel.bannerDetail().contains("Saved hook"), panel.bannerDetail());
        shot("imports");

        AngrHooks.Hook broken = controller.hookFor("puts");
        broken.code = "def hook(ctx)\n    return 1\n";
        controller.saveHook(broken);
        controller.await();
        check("a hook that does not compile is refused with the reason",
            panel.bannerDetail().contains("does not compile") && AngrHooks.get(currentProgram, "puts") == null,
            panel.bannerDetail());

        click("Start");
        click("Continue");
        check("with the hook nothing is unknown any more", panel.bannerTitle().startsWith("Returned 0x1")
            && panel.table("paths").getRowCount() == 0 && cells("calls").contains("[python hook]"),
            panel.bannerTitle() + " | " + cells("calls"));
        check("the hook's log line is in the trace", cells("calls").contains("# device 3"), cells("calls"));
        controller.deleteHook("mystery_device_read");
        controller.await();
        check("deleting a hook removes it", AngrHooks.list(currentProgram).isEmpty(), AngrHooks.list(currentProgram));

        // --- a fault ---
        onEdt(() -> {
            panel.setFunction("deref");
            panel.setArguments("0");
        });
        click("Start");
        click("Continue");
        check("a fault is explained in the banner", panel.bannerTitle().startsWith("Fault at")
            && panel.bannerTitle().contains("deref+") && panel.bannerDetail().contains("NULL"),
            panel.bannerTitle() + " | " + panel.bannerDetail());
        shot("fault");

        // --- editing a register, watches, navigation ---
        onEdt(() -> {
            panel.setFunction("bump_counter");
            panel.setArguments("5");
        });
        click("Start");
        controller.setWatches("g_counter:4");
        controller.await();
        check("a watch is shown", cells("memory").contains("watch g_counter") && cells("memory").contains("07 00 00 00"),
            cells("memory"));
        controller.setValue(Map.of("register", "rdi"), "0x20");
        controller.await();
        check("a register can be set", "0x20".equals(row("registers", "name", "rdi").get("value")),
            row("registers", "name", "rdi"));
        click("Continue");
        check("the edit took effect (7 + 0x20)", panel.bannerTitle().startsWith("Returned 0x27"), panel.bannerTitle());
        check("the watch follows", cells("memory").contains("27 00 00 00"), cells("memory"));
        controller.goTo(String.valueOf(panel.rows("memory").get(0).get("address")));
        check("double-click targets go through the host", !navigated.isEmpty(), navigated);

        // --- pause a run that never ends ---
        onEdt(() -> {
            panel.setFunction("spin");
            panel.setArguments("1");
        });
        click("Start");
        onEdt(() -> panel.button("Continue").doClick());
        long deadline = System.currentTimeMillis() + 10_000;
        while (!panel.button("Pause").isEnabled() && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        check("while running, Pause is on and stepping is off", panel.button("Pause").isEnabled()
            && !panel.button("Step Into").isEnabled() && "Running...".equals(panel.bannerTitle()),
            panel.bannerTitle());
        Thread.sleep(600);
        onEdt(() -> panel.button("Pause").doClick());
        controller.await();
        check("Pause interrupts it and stepping works again", panel.bannerDetail().contains("Interrupted")
            && panel.button("Step Into").isEnabled(), panel.bannerTitle() + " | " + panel.bannerDetail());

        // --- mistakes ---
        onEdt(() -> panel.setFunction("no_such_function"));
        click("Start");
        check("an unknown function is explained in the banner", controller.lastError() != null
            && panel.bannerDetail().contains("no function, label or address"), panel.bannerDetail());

        // --- stop ---
        onEdt(() -> panel.button("Stop").doClick());
        controller.await();
        check("Stop ends the session", "No session".equals(panel.bannerTitle())
            && AngrDebugger.session(currentProgram) == null && "Start".equals(panel.button("Start").getText()),
            panel.bannerTitle());
    }

    // ---- helpers ----

    private void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private void click(String button) throws Exception {
        onEdt(() -> panel.button(button).doClick());
        controller.await();
    }

    private Map<String, Object> row(String table, String key, String value) {
        for (Map<String, Object> row : panel.rows(table)) {
            if (value.equals(String.valueOf(row.get(key)))) {
                return row;
            }
        }
        return Map.of();
    }

    /** Everything a table shows, as text. */
    private String cells(String name) throws Exception {
        StringBuilder sb = new StringBuilder();
        onEdt(() -> {
            JTable table = panel.table(name);
            for (int r = 0; r < table.getRowCount(); r++) {
                for (int c = 0; c < table.getColumnCount(); c++) {
                    sb.append(table.getValueAt(r, c)).append(" | ");
                }
                sb.append('\n');
            }
        });
        return sb.toString();
    }

    /** Paints the panel as it would appear, without a screen. */
    private void shot(String name) throws Exception {
        String dir = System.getenv("DFU_TEST_OUTPUT");
        if (dir == null) {
            return;
        }
        File file = new File(dir, "_angr_debugger_" + (++shots) + "_" + name + ".png");
        onEdt(() -> {
            try {
                panel.setSize(1180, 620);
                try {
                    panel.addNotify();
                }
                catch (Throwable t) {
                    // no peers without a display; lay out by hand below
                }
                layout(panel);
                layout(panel);
                BufferedImage image = new BufferedImage(panel.getWidth(), panel.getHeight(), BufferedImage.TYPE_INT_RGB);
                Graphics2D g = image.createGraphics();
                g.setColor(panel.getBackground() == null ? Color.WHITE : panel.getBackground());
                g.fillRect(0, 0, image.getWidth(), image.getHeight());
                panel.printAll(g);
                g.dispose();
                ImageIO.write(image, "png", file);
            }
            catch (Exception e) {
                println("INFO screenshot failed: " + e);
            }
        });
        check("screenshot " + name + " written", file.isFile() && file.length() > 5000, file + " " + file.length());
    }

    private static void layout(Component component) {
        synchronized (component.getTreeLock()) {
            component.doLayout();
            if (component instanceof Container container) {
                for (Component child : container.getComponents()) {
                    layout(child);
                }
            }
        }
    }
}
