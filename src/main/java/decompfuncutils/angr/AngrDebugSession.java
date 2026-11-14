package decompfuncutils.angr;

import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * One live debugging run of a function under angr.
 *
 * <p>The state lives in a worker process of its own; this class is the Java end of it. It turns
 * step requests into slices short enough to be paused, keeps the last snapshot (with Ghidra's
 * names put on the worker's addresses) for whoever wants to show it, and reports every change
 * through {@link AngrDebugger}, so the debugger panel follows a session an agent is driving over
 * MCP and the other way round.
 */
public final class AngrDebugSession {

    private static final Gson GSON = new Gson();

    /** A long run is served in slices of this length so it can be paused between them. */
    private static final long SLICE_MILLIS = 800;
    /** Time allowed for a request that is not a run (state, edits, hooks). */
    private static final long QUICK_MILLIS = 120_000;

    public final Program program;
    /** How the call was set up; kept for display and for restarting. */
    public final AngrCallSpec call;
    /** What the session was started with, so it can be started again. */
    public final Map<String, Object> launchArguments;

    private final AngrWorkers.Dedicated worker;
    private final long sessionId;
    private final List<Map<String, Object>> watches = new ArrayList<>();

    private volatile Map<String, Object> snapshot;
    private volatile boolean running;
    private volatile boolean pauseRequested;
    private volatile boolean closed;

    private AngrDebugSession(Program program, AngrCallSpec call, Map<String, Object> launchArguments,
            AngrWorkers.Dedicated worker, long sessionId) {
        this.program = program;
        this.call = call;
        this.launchArguments = launchArguments;
        this.worker = worker;
        this.sessionId = sessionId;
    }

    /** Starts a worker, loads the program into it and stops at the function's first instruction. */
    @SuppressWarnings("unchecked")
    static AngrDebugSession open(Program program, String python, Map<String, Object> arguments,
            TaskMonitor monitor) throws Exception {
        Map<String, Object> launch = new LinkedHashMap<>(arguments);
        // A debugger exists to look at what is unknown: imports nothing models return unknown
        // values unless the caller says otherwise.
        launch.putIfAbsent("unmodelledImports", "symbolic");
        AngrCallSpec call = AngrCallSpec.build(program, launch, monitor);

        AngrWorkers.Dedicated worker;
        try {
            worker = AngrWorkers.openDedicated(python, monitor);
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
        try {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("op", "dbg_open");
            request.put("imageDir", call.image.directory.toString());
            request.put("spec", call.spec);
            monitor.setMessage("Loading " + program.getName() + " into angr");
            Map<String, Object> first = GSON.fromJson(
                AngrWorkers.resultOf(worker.request(request, QUICK_MILLIS, monitor)), Map.class);
            AngrCallSpec.tidyNumbers(first);
            long id = ((Number) first.get("session")).longValue();
            AngrDebugSession session = new AngrDebugSession(program, call, launch, worker, id);
            session.accept(first);
            return session;
        }
        catch (Exception e) {
            worker.close();
            throw e;
        }
    }

    // ---- state ----

    /** The last snapshot: where execution is and everything visible there. Never null. */
    public Map<String, Object> snapshot() {
        return snapshot;
    }

    public boolean isRunning() {
        return running;
    }

    public boolean isClosed() {
        return closed;
    }

    /** "paused", "returned", "fault", "exited" or "symbolic_jump" for the current path. */
    public String status() {
        return String.valueOf(snapshot.get("status"));
    }

    /** The current instruction address, or null when it is not concrete. */
    public Address pc() {
        return address(snapshot.get("pc"));
    }

    private Address address(Object hex) {
        if (!(hex instanceof String text)) {
            return null;
        }
        Address address = AngrCallSpec.tryAddress(program, text);
        return address == null ? null : address.getNewAddress(address.getOffset() & ~thumbBit());
    }

    private long thumbBit() {
        return program.getProgramContext().getRegister("TMode") != null ? 1L : 0L;
    }

    // ---- stepping ----

    /**
     * Runs until the step is complete, a breakpoint is reached, the path ends or forks, the
     * budget is spent, or {@link #requestPause()} is called.
     *
     * @param kind  "into", "over", "out" or "continue"
     * @param runTo an extra one-time stop address, or null
     */
    public synchronized Map<String, Object> step(String kind, int count, Address runTo, long budgetMillis,
            TaskMonitor monitor) throws Exception {
        ensureOpen();
        running = true;
        pauseRequested = false;
        AngrDebugger.fire(program);
        try {
            long deadline = System.currentTimeMillis() + budgetMillis;
            String next = kind;
            while (true) {
                long slice = Math.max(50, Math.min(SLICE_MILLIS, deadline - System.currentTimeMillis()));
                Map<String, Object> request = base("dbg_step");
                request.put("kind", next);
                request.put("count", Math.max(1, count));
                request.put("timeoutMs", slice);
                List<String> stops = new ArrayList<>();
                for (Address breakpoint : AngrDebugger.breakpoints(program)) {
                    stops.add(AngrImage.hex(breakpoint.getOffset()));
                }
                request.put("breakpoints", stops);
                if (runTo != null) {
                    request.put("runTo", AngrImage.hex(runTo.getOffset()));
                }
                Map<String, Object> result = send(request, slice + QUICK_MILLIS, monitor);
                if (!"timeout".equals(result.get("stop"))) {
                    break;
                }
                if (pauseRequested) {
                    result.put("stop", "paused");
                    break;
                }
                if (System.currentTimeMillis() >= deadline) {
                    break;
                }
                next = "resume";
            }
            return snapshot;
        }
        finally {
            running = false;
            AngrDebugger.fire(program);
        }
    }

    /** Asks a run in progress to stop at the next slice boundary. */
    public void requestPause() {
        pauseRequested = true;
    }

    /** Fetches the state again, for instance after the watch list changed. */
    public synchronized Map<String, Object> refresh(TaskMonitor monitor) throws Exception {
        ensureOpen();
        send(base("dbg_state"), QUICK_MILLIS, monitor);
        AngrDebugger.fire(program);
        return snapshot;
    }

    // ---- editing ----

    /**
     * Changes the state: {@code action} is "concretize", "symbolize", "set", "select" or "drop".
     * The target is {@code register}, {@code address} (hex or a symbol name, with {@code size}),
     * {@code symbol}, or {@code path}; {@code value} takes the argument forms of a call.
     */
    public synchronized Map<String, Object> edit(Map<String, Object> action, TaskMonitor monitor)
            throws Exception {
        ensureOpen();
        Map<String, Object> request = base("dbg_edit");
        for (Map.Entry<String, Object> e : action.entrySet()) {
            Object value = e.getValue();
            if (value == null) {
                continue;
            }
            switch (e.getKey()) {
                case "address" -> request.put("address",
                    AngrImage.hex(AngrCallSpec.resolveData(program, value, "address").getOffset()));
                case "value" -> request.put("value",
                    "concretize".equals(action.get("action"))
                        ? AngrCallSpec.integerText(value, "value")
                        : AngrCallSpec.normalizeValue(value, "value"));
                case "size", "path" -> request.put(e.getKey(), AngrCallSpec.integerText(value, e.getKey()));
                default -> request.put(e.getKey(), value);
            }
        }
        if (request.get("register") != null
                && program.getLanguage().getRegister(String.valueOf(request.get("register"))) == null) {
            throw new IllegalArgumentException("Unknown register '" + request.get("register") + "'");
        }
        send(request, QUICK_MILLIS, monitor);
        AngrDebugger.fire(program);
        return snapshot;
    }

    /** Re-reads the program's saved Python hooks and installs them in the running session. */
    public synchronized Map<String, Object> reloadHooks(TaskMonitor monitor) throws Exception {
        ensureOpen();
        List<String> warnings = new ArrayList<>();
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("pyHooks", AngrHooks.toSpec(program, call.image, warnings));
        Map<String, Object> request = base("dbg_hooks");
        request.put("spec", spec);
        Map<String, Object> result = send(request, QUICK_MILLIS, monitor);
        if (!warnings.isEmpty()) {
            result.put("hookWarnings", warnings);
        }
        AngrDebugger.fire(program);
        return snapshot;
    }

    /**
     * Runs a request that has nothing to do with the session's state (listing the imports,
     * compiling a hook) on the session's own worker, which saves starting a second process just
     * to ask.
     */
    public synchronized com.google.gson.JsonObject query(Map<String, Object> request, TaskMonitor monitor)
            throws Exception {
        ensureOpen();
        return AngrWorkers.resultOf(worker.request(request, QUICK_MILLIS, monitor));
    }

    // ---- watches ----

    /**
     * Sets the memory ranges shown after every stop. Each entry is a symbol name or an address,
     * optionally followed by {@code :length} (default 64).
     */
    public synchronized void setWatches(List<String> entries) {
        List<Map<String, Object>> parsed = new ArrayList<>();
        for (String entry : entries) {
            String text = entry.strip();
            if (text.isEmpty()) {
                continue;
            }
            long length = 64;
            int colon = text.lastIndexOf(':');
            if (colon > 0 && text.substring(colon + 1).strip().matches("(0[xX][0-9a-fA-F]+|[0-9]+)")) {
                length = Long.decode(text.substring(colon + 1).strip());
                text = text.substring(0, colon).strip();
            }
            if (length < 1 || length > 4096) {
                throw new IllegalArgumentException("A watch is 1 to 4096 bytes long: " + entry);
            }
            Address address = AngrCallSpec.resolveData(program, text, "watch");
            Map<String, Object> watch = new LinkedHashMap<>();
            watch.put("addr", AngrImage.hex(address.getOffset()));
            watch.put("length", length);
            watch.put("name", text);
            parsed.add(watch);
        }
        watches.clear();
        watches.addAll(parsed);
    }

    // ---- lifetime ----

    /** Ends the session and its worker process. Safe to call more than once, and mid-run. */
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        running = false;
        worker.close();
    }

    private void ensureOpen() {
        if (closed || !worker.isAlive()) {
            closed = true;
            throw new IllegalStateException("The debug session has ended. Start a new one.");
        }
    }

    private Map<String, Object> base(String op) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("op", op);
        request.put("session", sessionId);
        if (!watches.isEmpty()) {
            request.put("readMemory", new ArrayList<>(watches));
        }
        return request;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> send(Map<String, Object> request, long timeoutMillis, TaskMonitor monitor)
            throws Exception {
        Map<String, Object> result;
        try {
            result = GSON.fromJson(AngrWorkers.resultOf(worker.request(request, timeoutMillis, monitor)),
                Map.class);
        }
        catch (Exception e) {
            if (!worker.isAlive()) {
                closed = true;
            }
            throw e;
        }
        AngrCallSpec.tidyNumbers(result);
        accept(result);
        return result;
    }

    // ---- Ghidra's names on the worker's addresses ----

    @SuppressWarnings("unchecked")
    private void accept(Map<String, Object> result) {
        result.put("function", call.title);
        result.put("called", call.called);
        if (result.get("pc") instanceof String pc) {
            String label = label(pc);
            if (label != null) {
                result.put("location", label);
            }
        }
        for (String key : List.of("registers")) {
            if (result.get(key) instanceof List<?> rows) {
                labelRows((List<Object>) rows);
            }
        }
        if (result.get("stack") instanceof Map<?, ?> stack && stack.get("words") instanceof List<?> words) {
            labelRows((List<Object>) words);
        }
        if (result.get("paths") instanceof List<?> paths) {
            for (Object o : paths) {
                if (o instanceof Map<?, ?> m) {
                    Map<String, Object> path = (Map<String, Object>) m;
                    for (String key : List.of("pc", "forkedAt")) {
                        if (path.get(key) instanceof String text) {
                            String label = label(text);
                            if (label != null) {
                                path.put(key + "Label", label);
                            }
                        }
                    }
                }
            }
        }
        if (result.get("writes") instanceof List<?> writes) {
            for (Object o : writes) {
                if (o instanceof Map<?, ?> m && m.get("address") instanceof String text
                        && "program".equals(m.get("region"))) {
                    String label = label(text);
                    if (label != null) {
                        ((Map<String, Object>) m).put("symbol", label);
                    }
                }
            }
        }
        AngrCallSpec.annotate(program, result);
        // annotate() rewrites stoppedAt/fault for the one-shot tool; a snapshot keeps pc as is.
        if (!call.warnings.isEmpty()) {
            List<Object> warnings = new ArrayList<>(call.warnings);
            if (result.get("warnings") instanceof List<?> existing) {
                warnings.addAll(existing);
            }
            result.put("warnings", warnings);
        }
        snapshot = result;
    }

    @SuppressWarnings("unchecked")
    private void labelRows(List<Object> rows) {
        for (Object o : rows) {
            if (o instanceof Map<?, ?> m && m.get("value") instanceof String text) {
                String label = label(text);
                if (label != null) {
                    ((Map<String, Object>) m).put("label", label);
                }
            }
        }
    }

    /** "check_password+0x17" for code, "g_counter" or "g_table+0x8" for data, null otherwise. */
    public String label(String hex) {
        Address address = AngrCallSpec.tryAddress(program, hex);
        if (address == null || !program.getMemory().contains(address)) {
            return null;
        }
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function != null) {
            long delta = address.subtract(function.getEntryPoint());
            return function.getName() + (delta == 0 ? "" : "+0x" + Long.toHexString(delta));
        }
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            return symbol.getName();
        }
        Data data = program.getListing().getDataContaining(address);
        if (data != null) {
            Symbol base = program.getSymbolTable().getPrimarySymbol(data.getAddress());
            if (base != null) {
                return base.getName() + "+0x" + Long.toHexString(address.subtract(data.getAddress()));
            }
        }
        return null;
    }
}
