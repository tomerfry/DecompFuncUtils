package decompfuncutils.angr.ui;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import decompfuncutils.angr.AngrCallSpec;
import decompfuncutils.angr.AngrDebugSession;
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.angr.AngrHooks;
import decompfuncutils.angr.AngrImage;
import decompfuncutils.angr.AngrImports;
import decompfuncutils.angr.AngrModules;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;

/**
 * Connects the debugger panel to the sessions in {@link AngrDebugger}.
 *
 * <p>Everything the user asks for runs on one background thread, so the interface never waits on
 * angr, and whatever changes - through the panel or through the MCP tool driving the same
 * session - comes back as a snapshot shown on the Swing thread. Failures are shown in the panel's
 * banner rather than in dialogs, since most of them are part of normal use ("that value
 * contradicts the path").
 *
 * <p>It depends on Ghidra's program model but not on a tool window; what needs one (moving the
 * Listing, markers) goes through {@link Host}.
 */
public class AngrDebuggerController implements AngrDebuggerPanel.Actions, AngrDebugger.Listener {

    /** What the surrounding tool window provides. */
    public interface Host {
        /** Shows an address in the Listing. */
        void goTo(Program program, Address address);

        /** Called on the Swing thread whenever the session, its position or the breakpoints changed. */
        void positionChanged(Program program, AngrDebugSession session);

        /** The interpreter set in Tool Options, or null. */
        String configuredPython();

        /**
         * Whether anyone is looking at the Ledger. Reading it asks the solver about every
         * unknown, so it is kept up to date only while it is on screen.
         */
        boolean ledgerVisible();
    }

    /** A step from the panel may run until the user pauses it. */
    private static final long RUN_BUDGET_MILLIS = 6L * 60 * 60 * 1000;
    private static final Gson GSON = new Gson();

    private final AngrDebuggerPanel panel;
    private final Host host;
    private final Supplier<Program> programSupplier;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "angr-debugger");
        t.setDaemon(true);
        return t;
    });
    private volatile Future<?> lastTask;
    private volatile String lastError;

    public AngrDebuggerController(Supplier<Program> programSupplier, Host host) {
        this(programSupplier, host, false);
    }

    /** @param detached true when the caller places the panel's views itself, as a tool window does */
    public AngrDebuggerController(Supplier<Program> programSupplier, Host host, boolean detached) {
        this.programSupplier = programSupplier;
        this.host = host;
        this.panel = new AngrDebuggerPanel(this, detached);
        AngrDebugger.addListener(this);
    }

    public AngrDebuggerPanel panel() {
        return panel;
    }

    public void dispose() {
        AngrDebugger.removeListener(this);
        executor.shutdownNow();
    }

    /** The last failure shown in the banner, or null; for tests. */
    public String lastError() {
        return lastError;
    }

    /** Blocks until everything asked for so far has finished; for tests. */
    public void await() throws Exception {
        Future<?> task = lastTask;
        if (task != null) {
            task.get();
        }
        SwingUtilities.invokeAndWait(() -> { });
    }

    // ---- plumbing ----

    /**
     * The program whose session is on screen. Usually the one the tool is showing; but when
     * that one is a library loaded into another program's session - execution crossed into it
     * and the Listing followed - it is still that other program's session being debugged.
     */
    public Program subject() {
        Program current = programSupplier.get();
        if (current == null) {
            return null;
        }
        AngrDebugSession showing = AngrDebugger.sessionShowing(current);
        return showing == null ? current : showing.program;
    }

    private interface Work {
        void run(Program program) throws Exception;
    }

    private void background(Work work) {
        Program program = subject();
        if (program == null) {
            fail("Open a program first.");
            return;
        }
        lastError = null;
        lastTask = executor.submit(() -> {
            try {
                work.run(program);
            }
            catch (Exception e) {
                AngrDebugSession session = AngrDebugger.session(program);
                // Stop kills the worker under a run in progress; that is not a failure to report.
                if (session == null && String.valueOf(e.getMessage()).contains("angr worker")) {
                    return;
                }
                fail(e.getMessage() == null ? e.toString() : e.getMessage());
            }
        });
    }

    private void fail(String message) {
        lastError = message;
        SwingUtilities.invokeLater(() -> {
            show();
            panel.showMessage(message, true);
        });
    }

    private AngrDebugSession session(Program program) {
        return AngrDebugger.require(program);
    }

    /** Puts the current program's session on screen. Safe from any thread. */
    public void refresh() {
        SwingUtilities.invokeLater(this::show);
    }

    private void show() {
        Program program = subject();
        AngrDebugSession session = program == null ? null : AngrDebugger.session(program);
        panel.showState(session == null ? null : session.snapshot(), session != null && session.isRunning());
        panel.showDestination(program == null ? null : AngrDebugger.destinationText(program));
        if (session == null) {
            panel.showLedger(null);
        }
        if (program != null) {
            host.positionChanged(program, session);
        }
    }

    @Override
    public void debuggerChanged(Program program) {
        Program subject = subject();
        // A destination or a breakpoint in a program that belongs with this one is ours to show too.
        if (program == subject || program == programSupplier.get()
                || subject != null && AngrDebugger.companions(subject).contains(program)) {
            refresh();
        }
    }

    // ---- launch ----

    /** Fills the launch bar for a function and says how Ghidra thinks it is called. */
    public void prepare(Program program, Function function) {
        if (function == null) {
            return;
        }
        panel.setFunction(function.getName(true));
        panel.setHint(function.getSignatureSource() != SourceType.DEFAULT
            ? function.getPrototypeString(false, false)
            : "Ghidra has no signature for " + function.getName() + "; arguments go where its convention puts them.");
    }

    /**
     * The argument list as the user typed it: a JSON array, or the same without the brackets -
     * {@code "hello", 5} - which is how a call is normally written.
     */
    public static List<Object> parseArguments(String text) {
        String trimmed = text == null ? "" : text.strip();
        if (trimmed.isEmpty()) {
            return List.of();
        }
        String json = quoteHexLiterals(trimmed.startsWith("[") ? trimmed : "[" + trimmed + "]");
        try {
            List<?> parsed = GSON.fromJson(json, List.class);
            return parsed == null ? List.of() : new ArrayList<Object>(parsed);
        }
        catch (JsonSyntaxException e) {
            throw new IllegalArgumentException("The arguments are not a valid list. Write them separated by "
                + "commas, with strings in double quotes: \"hello\", 5, 0x10, {\"buffer\": 64}");
        }
    }

    /** Hex literals are not JSON: quote the bare ones, so 0x10 reaches the integer parser. */
    private static String quoteHexLiterals(String json) {
        StringBuilder out = new StringBuilder();
        boolean inString = false;
        int i = 0;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (inString) {
                out.append(c);
                if (c == '\\' && i + 1 < json.length()) {
                    out.append(json.charAt(++i));
                }
                else if (c == '"') {
                    inString = false;
                }
                i++;
                continue;
            }
            if (c == '"') {
                inString = true;
                out.append(c);
                i++;
                continue;
            }
            int start = i;
            int j = c == '-' ? i + 1 : i;
            if (j + 1 < json.length() && json.charAt(j) == '0' && (json.charAt(j + 1) == 'x' || json.charAt(j + 1) == 'X')) {
                j += 2;
                int digits = j;
                while (j < json.length() && (Character.digit(json.charAt(j), 16) >= 0 || json.charAt(j) == '_')) {
                    j++;
                }
                if (j > digits) {
                    out.append('"').append(json, start, j).append('"');
                    i = j;
                    continue;
                }
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    @Override
    public void start(String function, String argumentsText, boolean symbolicImports, boolean strictMemory) {
        background(program -> {
            if (function == null || function.isBlank()) {
                throw new IllegalArgumentException("Enter the name or address of the function to debug.");
            }
            Map<String, Object> arguments = new LinkedHashMap<>();
            arguments.put("function", function);
            arguments.put("args", parseArguments(argumentsText));
            arguments.put("unmodelledImports", symbolicImports ? "symbolic" : "zero");
            arguments.put("strictMemory", strictMemory);
            SwingUtilities.invokeLater(() -> panel.showMessage("Starting angr...", false));
            AngrDebugSession session =
                AngrDebugger.start(program, host.configuredPython(), arguments, TaskMonitor.DUMMY);
            SwingUtilities.invokeLater(() -> panel.setHint(session.call.called));
            // The first session on a program is also when its imports become interesting.
            if (!panel.importsLoaded()) {
                refreshImports();
            }
        });
    }

    // ---- stepping ----

    @Override
    public void step(String kind) {
        background(program -> {
            session(program).step(kind, 1, null, RUN_BUDGET_MILLIS, TaskMonitor.DUMMY);
            ledger(program, false);
        });
    }

    // ---- the destination and the ledger ----

    /**
     * @param address the new destination, or null for none. The stub of an import means the
     *                code it stands for, in the library of the project that defines it.
     */
    public void setDestination(Program program, Address address) {
        Function function = address == null ? null : program.getFunctionManager().getFunctionAt(address);
        Function thunked = function != null && function.isThunk() ? function.getThunkedFunction(true) : null;
        if (thunked == null || !thunked.isExternal()) {
            AngrDebugger.setDestination(program, address);
            return;
        }
        // Finding the library may mean opening it: not on the Swing thread.
        lastError = null;
        lastTask = executor.submit(() -> {
            try {
                AngrModules.Location target = AngrDebugger.locate(program, AngrImage.hex(address.getOffset()),
                    null, null, TaskMonitor.DUMMY);
                if (target.program() == program) {
                    AngrDebugger.setDestination(program, target.address());
                }
                else {
                    AngrDebugger.setDestination(program, target);
                }
            }
            catch (Exception e) {
                AngrDebugger.setDestination(program, address);
            }
        });
    }

    @Override
    public void seek() {
        background(program -> {
            AngrDebugger.seek(program, List.of(), true, RUN_BUDGET_MILLIS, TaskMonitor.DUMMY);
            ledger(program, true);
        });
    }

    @Override
    public void refreshLedger() {
        background(program -> ledger(program, true));
    }

    @Override
    public String ledgerMarkdown() {
        Program program = subject();
        AngrDebugSession session = program == null ? null : AngrDebugger.session(program);
        return session == null || session.lastLedger() == null ? null
            : decompfuncutils.angr.AngrLedger.toMarkdown(session.lastLedger());
    }

    /** Reads the current path's ledger and shows it; unless forced, only while it is on screen. */
    private void ledger(Program program, boolean force) throws Exception {
        AngrDebugSession session = AngrDebugger.session(program);
        if (session == null || session.isRunning() || !(force || host.ledgerVisible())) {
            return;
        }
        Map<String, Object> ledger = session.ledger(TaskMonitor.DUMMY);
        SwingUtilities.invokeLater(() -> panel.showLedger(ledger));
    }

    /** Runs to an address once, as "Run to Cursor" does. */
    public void runTo(Address address) {
        runTo(null, address);
    }

    /** @param in the program the address is in: the one being debugged, or a library loaded with it */
    public void runTo(Program in, Address address) {
        background(program -> {
            session(program).stepUntil("continue", 1, new AngrModules.Location(in == null ? program : in, address),
                RUN_BUDGET_MILLIS, TaskMonitor.DUMMY);
            ledger(program, false);
        });
    }

    @Override
    public void pause() {
        Program program = subject();
        AngrDebugSession session = program == null ? null : AngrDebugger.session(program);
        if (session != null) {
            session.requestPause();
        }
    }

    @Override
    public void stop() {
        Program program = subject();
        if (program != null) {
            // Not queued behind a run in progress: Stop has to be able to end one.
            AngrDebugger.stop(program);
        }
    }

    public void toggleBreakpoint(Program program, Address address) {
        AngrDebugger.toggleBreakpoint(program, address);
    }

    // ---- paths, symbols, values ----

    private void edit(Map<String, Object> action) {
        background(program -> {
            session(program).edit(action, TaskMonitor.DUMMY);
            ledger(program, false);
        });
    }

    @Override
    public void selectPath(int id) {
        edit(mapOf("action", "select", "path", id));
    }

    @Override
    public void dropPath(int id) {
        edit(mapOf("action", "drop", "path", id));
    }

    @Override
    public void concretize(Map<String, Object> target, String value) {
        Map<String, Object> action = new LinkedHashMap<>(target);
        action.put("action", "concretize");
        if (value != null && !value.isBlank()) {
            action.put("value", value.strip());
        }
        edit(action);
    }

    @Override
    public void concretizeAll() {
        edit(mapOf("action", "concretize", "all", true));
    }

    @Override
    public void symbolize(String register, String name) {
        Map<String, Object> action = mapOf("action", "symbolize", "register", register);
        if (name != null && !name.isBlank()) {
            action.put("name", name.strip());
        }
        edit(action);
    }

    @Override
    public void setValue(Map<String, Object> target, String value) {
        Map<String, Object> action = new LinkedHashMap<>(target);
        action.put("action", "set");
        List<Object> parsed = parseArguments(value);
        if (parsed.size() != 1) {
            fail("Enter one value: a number, or \"text\" for a pointer to a string.");
            return;
        }
        action.put("value", parsed.get(0));
        edit(action);
    }

    @Override
    public void setWatches(String text) {
        background(program -> {
            AngrDebugSession session = session(program);
            session.setWatches(Arrays.asList(text.split(",")));
            session.refresh(TaskMonitor.DUMMY);
            SwingUtilities.invokeLater(() -> panel.selectTab("Memory"));
        });
    }

    @Override
    public void goTo(String hexAddress) {
        Program program = subject();
        if (program == null) {
            return;
        }
        // What the panel shows are addresses as the session runs them; in a library that was
        // moved they are not the library's own.
        AngrDebugSession session = AngrDebugger.session(program);
        if (session != null) {
            AngrModules.Location location = session.modules.locate(hexAddress);
            if (location != null) {
                host.goTo(location.program(), location.address());
            }
            return;
        }
        Address address = AngrCallSpec.tryAddress(program, hexAddress);
        if (address != null && program.getMemory().contains(address)) {
            host.goTo(program, address);
        }
    }

    // ---- imports and hooks ----

    @Override
    public void refreshImports() {
        background(program -> {
            List<AngrHooks.Hook> hooks = AngrHooks.list(program);
            List<Map<String, Object>> imports;
            String problem = null;
            try {
                imports = AngrImports.describe(program, host.configuredPython(), TaskMonitor.DUMMY);
            }
            catch (Exception e) {
                imports = List.of();
                problem = e.getMessage();
            }
            List<Map<String, Object>> shown = imports;
            String note = problem;
            SwingUtilities.invokeLater(() -> panel.showImports(shown, hooks, note));
        });
    }

    @Override
    public AngrHooks.Hook hookFor(String target) {
        Program program = subject();
        if (program == null) {
            return null;
        }
        for (AngrHooks.Hook hook : AngrHooks.list(program)) {
            if (hook.target.equals(target) || hook.name.equals(target)) {
                return hook;
            }
        }
        AngrHooks.Hook hook = new AngrHooks.Hook();
        hook.name = target.replaceAll("[^A-Za-z0-9_.-]", "_");
        hook.target = target;
        hook.code = AngrHooks.template(program, target);
        return hook;
    }

    @Override
    public void saveHook(AngrHooks.Hook hook) {
        background(program -> {
            // Compile before saving: a hook that cannot load would fail every later run.
            AngrImports.check(program, host.configuredPython(), hook.name, hook.code, TaskMonitor.DUMMY);
            AngrHooks.save(program, hook);
            hooksChanged(program, "Saved hook " + hook.name + ".");
        });
    }

    @Override
    public void deleteHook(String name) {
        background(program -> {
            AngrHooks.delete(program, name);
            hooksChanged(program, "Deleted hook " + name + ".");
        });
    }

    private void hooksChanged(Program program, String message) throws Exception {
        AngrDebugSession session = AngrDebugger.session(program);
        boolean applied = false;
        if (session != null && !session.isRunning()) {
            session.reloadHooks(TaskMonitor.DUMMY);
            applied = true;
        }
        List<AngrHooks.Hook> hooks = AngrHooks.list(program);
        List<Map<String, Object>> imports =
            AngrImports.describe(program, host.configuredPython(), TaskMonitor.DUMMY);
        String shown = message + (applied ? " Applied to the running session." : "");
        SwingUtilities.invokeLater(() -> {
            panel.showImports(imports, hooks, null);
            panel.showMessage(shown, false);
        });
    }

    private static Map<String, Object> mapOf(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            map.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return map;
    }

    /** "0x101b40", for code that has an Address and needs what the panel passes around. */
    static String hex(Address address) {
        return AngrImage.hex(address.getOffset());
    }
}
