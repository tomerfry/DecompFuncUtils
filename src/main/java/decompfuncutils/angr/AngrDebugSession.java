package decompfuncutils.angr;

import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
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
    /** The programs loaded together: this one first, then libraries whose code its imports run. */
    public final AngrModules modules;
    /** The interpreter it was started with, so it can be started again. */
    final String python;

    private final AngrWorkers.Dedicated worker;
    private final long sessionId;
    private final List<Map<String, Object>> watches = new ArrayList<>();

    private volatile Map<String, Object> snapshot;
    private volatile Map<String, Object> lastLedger;
    private AngrReach reach;
    private List<AngrModules.Location> reachFor;
    private volatile boolean running;
    private volatile boolean pauseRequested;
    private volatile boolean closed;

    private AngrDebugSession(Program program, AngrCallSpec call, Map<String, Object> launchArguments,
            AngrModules modules, String python, AngrWorkers.Dedicated worker, long sessionId) {
        this.program = program;
        this.call = call;
        this.launchArguments = launchArguments;
        this.modules = modules;
        this.python = python;
        this.worker = worker;
        this.sessionId = sessionId;
    }

    /**
     * Starts a worker, loads the program - and the libraries that go with it - into it and stops
     * at the function's first instruction.
     *
     * @param modules the program first; this session lets go of them when it closes
     */
    @SuppressWarnings("unchecked")
    static AngrDebugSession open(Program program, String python, Map<String, Object> arguments,
            AngrModules modules, TaskMonitor monitor) throws Exception {
        Map<String, Object> launch = new LinkedHashMap<>(arguments);
        // A debugger exists to look at what is unknown: imports nothing models return unknown
        // values unless the caller says otherwise.
        launch.putIfAbsent("unmodelledImports", "symbolic");
        // The same goes for what the function's caller would have decided and nobody here did:
        // an argument that was not given, a global nothing initialises, the memory behind a
        // pointer. Left at zero there is one path through the function - whichever the zeros
        // take - and no way for a search to find another.
        launch.putIfAbsent("unknownInputs", true);
        AngrCallSpec call;
        AngrWorkers.Dedicated worker;
        try {
            call = AngrCallSpec.build(program, launch, modules, monitor);
            worker = AngrWorkers.openDedicated(python, monitor);
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            modules.release();
            throw new IllegalStateException(e.getMessage());
        }
        catch (Exception e) {
            modules.release();
            throw e;
        }
        try {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("op", "dbg_open");
            request.put("imageDir", call.image.directory.toString());
            request.put("spec", call.spec);
            monitor.setMessage("Loading " + program.getName()
                + (modules.size() > 1 ? " and " + String.join(", ", modules.libraryNames()) : "") + " into angr");
            Map<String, Object> first = GSON.fromJson(
                AngrWorkers.resultOf(worker.request(request, QUICK_MILLIS, monitor)), Map.class);
            AngrCallSpec.tidyNumbers(first);
            long id = ((Number) first.get("session")).longValue();
            AngrDebugSession session = new AngrDebugSession(program, call, launch, modules, python, worker, id);
            session.accept(first);
            return session;
        }
        catch (Exception e) {
            worker.close();
            modules.release();
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

    /**
     * The current instruction when it is in this program; null when it is not concrete, or when
     * execution is in a library ({@link #where()} says which).
     */
    public Address pc() {
        AngrModules.Location location = where();
        return location == null || location.program() != program ? null : location.address();
    }

    /** The program and address execution is at, or null when the address is not concrete. */
    public AngrModules.Location where() {
        return location(snapshot.get("pc"));
    }

    /** True until the session has executed anything: starting it again loses nothing. */
    boolean pristine() {
        Object executed = snapshot.get("instructions");
        Object paths = snapshot.get("paths");
        return executed instanceof Number n && n.longValue() == 0
            && (!(paths instanceof List<?> list) || list.size() <= 1);
    }

    private AngrModules.Location location(Object hex) {
        if (!(hex instanceof String text) || !text.matches("0[xX][0-9a-fA-F]{1,16}")) {
            return null;
        }
        return modules.locate(Long.parseUnsignedLong(text.substring(2), 16) & ~thumbBit());
    }

    /** The address a place in one of the loaded programs runs at, as the worker takes it. */
    private String angr(Program in, Address address) {
        Long value = modules.toAngr(in, address);
        if (value == null) {
            throw new IllegalArgumentException(AngrModules.nameOf(in) + " is not loaded in this session.");
        }
        return AngrImage.hex(value);
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
        return stepUntil(kind, count, runTo == null ? null : new AngrModules.Location(program, runTo), budgetMillis,
            monitor);
    }

    /** The same, with the one-time stop anywhere in the loaded programs. */
    public synchronized Map<String, Object> stepUntil(String kind, int count, AngrModules.Location runTo,
            long budgetMillis, TaskMonitor monitor) throws Exception {
        ensureOpen();
        String runToAddress = runTo == null ? null : angr(runTo.program(), runTo.address());
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
                // A breakpoint in a library counts while that library is loaded.
                for (AngrModules.Module module : modules.modules()) {
                    for (Address breakpoint : AngrDebugger.breakpoints(module.program)) {
                        stops.add(AngrImage.hex(module.toAngr(breakpoint)));
                    }
                }
                request.put("breakpoints", stops);
                if (runToAddress != null) {
                    request.put("runTo", runToAddress);
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

    // ---- seeking the destination ----

    /**
     * Looks for a way from the open paths of the session (the current one first) to a
     * destination ({@link AngrDebugger#destinations} - in this program, or in a library loaded with it) and, when it finds one, makes that path
     * the current one and reads its ledger.
     *
     * <p>Unlike {@link #step}, forks do not stop it: every side of every branch on an unknown is
     * followed. With {@code guided}, Ghidra's control-flow graph tells the search which blocks
     * cannot lead to the destination, and those are tried last. A search that runs out of time
     * keeps what it has explored; calling again resumes it, and calling again after it arrived
     * looks for another way in.
     *
     * @param avoid addresses no path may pass through
     */
    public synchronized Map<String, Object> seek(List<Address> avoid, boolean guided, long budgetMillis,
            TaskMonitor monitor) throws Exception {
        ensureOpen();
        List<AngrModules.Location> destinations = destinations();
        if (destinations.isEmpty()) {
            List<String> elsewhere = new ArrayList<>();
            for (AngrModules.Location other : AngrDebugger.destinations(program)) {
                elsewhere.add(AngrModules.nameOf(other.program()));
            }
            throw new IllegalStateException(elsewhere.isEmpty()
                ? "No destination is set. Set one first: an address or a function to get to."
                : "The destination is in " + String.join(", ", elsewhere) + ", which this session did not "
                    + "load. Start the session again: it loads the libraries on the way to a destination.");
        }
        running = true;
        pauseRequested = false;
        AngrDebugger.fire(program);
        try {
            AngrReach guide = null;
            if (guided) {
                if (!destinations.equals(reachFor)) {
                    monitor.setMessage("Reading the control-flow graph towards the destination");
                    reach = AngrReach.compute(modules, call.function, destinations, monitor);
                    reachFor = destinations;
                }
                guide = reach;
            }
            List<List<String>> nonReach = new ArrayList<>();
            List<List<Object>> ranks = new ArrayList<>();
            if (guide != null) {
                for (long[] range : guide.nonReach) {
                    nonReach.add(List.of(AngrImage.hex(range[0]), AngrImage.hex(range[1])));
                }
                for (long[] range : guide.ranks) {
                    ranks.add(List.of(AngrImage.hex(range[0]), AngrImage.hex(range[1]), range[2]));
                }
            }
            List<String> avoided = new ArrayList<>();
            for (Address address : avoid) {
                avoided.add(AngrImage.hex(address.getOffset()));
            }
            List<String> targets = new ArrayList<>();
            for (AngrModules.Location destination : destinations) {
                targets.add(angr(destination.program(), destination.address()));
            }
            long deadline = System.currentTimeMillis() + budgetMillis;
            Map<String, Object> result;
            boolean first = true;
            while (true) {
                long slice = Math.max(50, Math.min(SLICE_MILLIS, deadline - System.currentTimeMillis()));
                Map<String, Object> request = base("dbg_seek");
                request.put("destinations", targets);
                request.put("avoid", avoided);
                // The guidance of a large program is long: it goes with the first slice only.
                if (first) {
                    request.put("nonReach", nonReach);
                    request.put("ranks", ranks);
                    first = false;
                }
                else {
                    request.put("sameGuide", true);
                }
                request.put("timeoutMs", slice);
                result = send(request, slice + QUICK_MILLIS, monitor);
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
            }
            if (guide != null) {
                result.put("seekGuide", guide.describe());
            }
            if ("destination".equals(result.get("stop"))) {
                result.put("ledger", fetchLedger(monitor));
            }
            return snapshot;
        }
        finally {
            running = false;
            AngrDebugger.fire(program);
        }
    }

    /** The destinations this session can get to: those in the programs it has loaded. */
    public List<AngrModules.Location> destinations() {
        List<AngrModules.Location> out = new ArrayList<>();
        for (AngrModules.Location destination : AngrDebugger.destinations(program)) {
            if (modules.contains(destination.program())) {
                out.add(destination);
            }
        }
        return out;
    }

    /** The destinations as text, "0x1019a0 (unlock)" or "libfoo.so!unlock @ 00101500"; null when there is none. */
    public String destinationText() {
        List<String> out = new ArrayList<>();
        for (AngrModules.Location destination : AngrDebugger.destinations(program)) {
            out.add(modules.contains(destination.program()) ? modules.describe(destination)
                : AngrModules.nameOf(destination.program()) + "!" + destination.address() + " (not loaded)");
        }
        return out.isEmpty() ? null : String.join(", ", out);
    }

    /**
     * The current path's ledger: every branch that depended on an unknown with the condition
     * this path took, the points where unknowns appeared and where values were fixed by hand,
     * and what all of that requires of each unknown. Addresses carry Ghidra's names.
     */
    public synchronized Map<String, Object> ledger(TaskMonitor monitor) throws Exception {
        ensureOpen();
        return fetchLedger(monitor);
    }

    /** The ledger as last read, or null. */
    public Map<String, Object> lastLedger() {
        return lastLedger;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchLedger(TaskMonitor monitor) throws Exception {
        Map<String, Object> ledger = GSON.fromJson(
            AngrWorkers.resultOf(worker.request(base("dbg_ledger"), QUICK_MILLIS, monitor)), Map.class);
        AngrCallSpec.tidyNumbers(ledger);
        ledger.put("function", call.title);
        ledger.put("program", program.getName());
        if (ledger.get("pc") instanceof String pc) {
            String label = label(pc);
            if (label != null) {
                ledger.put("location", label);
            }
        }
        String destination = destinationText();
        if (destination != null) {
            ledger.put("destination", destination);
            ledger.put("atDestination", destinations().contains(location(ledger.get("pc"))));
        }
        if (modules.size() > 1) {
            ledger.put("modules", modules.libraryNames());
        }
        if (ledger.get("entries") instanceof List<?> entries) {
            for (Object o : entries) {
                if (!(o instanceof Map<?, ?> m)) {
                    continue;
                }
                Map<String, Object> entry = (Map<String, Object>) m;
                if (entry.get("at") instanceof String at) {
                    String label = label(at);
                    entry.put("where", label == null ? at : label);
                }
                if (entry.get("to") instanceof String to) {
                    String label = label(to);
                    entry.put("toWhere", label == null ? to : label);
                }
            }
        }
        if (ledger.get("unknowns") instanceof List<?> unknowns) {
            // Memory nobody initialised is named after its address; say which global that is.
            for (Object o : unknowns) {
                if (o instanceof Map<?, ?> m && m.get("name") instanceof String name
                        && name.matches("mem_[0-9a-f]+(_b[0-9]+)?")) {
                    String label = label("0x" + name.substring(4).replaceFirst("_b[0-9]+$", ""));
                    if (label != null) {
                        ((Map<String, Object>) m).put("where", label);
                    }
                }
            }
        }
        lastLedger = ledger;
        return ledger;
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
        modules.release();
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
            // In a library, and all the more in one that was moved, the address the worker runs
            // at is not the one Ghidra shows: say which program and where in it.
            AngrModules.Location location = location(pc);
            if (location != null && location.program() != program) {
                result.put("module", AngrModules.nameOf(location.program()));
                result.put("moduleAddress", location.address().toString());
            }
        }
        if (modules.size() > 1) {
            result.put("modules", modules.libraryNames());
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
        AngrCallSpec.annotate(modules, result);
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

    /**
     * "check_password+0x17" for code, "g_counter" or "g_table+0x8" for data, with the module in
     * front ("libfoo.so!parse+0x4") outside this program; null when nothing names the address.
     */
    public String label(String hex) {
        return modules.label(hex);
    }
}
