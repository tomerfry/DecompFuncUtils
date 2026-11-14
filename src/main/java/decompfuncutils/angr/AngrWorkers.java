package decompfuncutils.angr;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Keeps angr worker processes alive between tool calls.
 *
 * <p>Importing angr takes seconds and so does building a project, which is the difference between
 * an emulator an agent can call in a loop and one it avoids. So the Python side
 * ({@code dfu_angr_worker.py}, shipped inside this jar) is a long-lived process that caches the
 * loaded image, and this class owns its lifecycle: one worker per program, so sessions working on
 * different binaries do not queue behind each other; started on first use; killed when a request
 * overruns or is cancelled; reaped after sitting idle; and destroyed with the JVM.
 */
public final class AngrWorkers {

    private static final Gson GSON = new Gson();

    /** Live workers at once; the least recently used idle one is retired beyond this. */
    private static final int MAX_WORKERS = 4;
    /** A worker nobody has called for this long is shut down to give its memory back. */
    private static final long IDLE_MILLIS = TimeUnit.MINUTES.toMillis(10);
    /** First start compiles bytecode for all of angr; later starts take a few seconds. */
    private static final long STARTUP_MILLIS = TimeUnit.MINUTES.toMillis(4);
    /** Slack past the worker's own deadline before it is presumed stuck in the solver. */
    private static final long GRACE_MILLIS = 20_000;

    private static final String SCRIPT_RESOURCE = "/decompfuncutils/angr/dfu_angr_worker.py";

    private static final Map<Long, Worker> WORKERS = new LinkedHashMap<>();
    private static final Set<Dedicated> DEDICATED = new HashSet<>();
    /** A debug session nobody has touched for this long is given up. */
    private static final long SESSION_IDLE_MILLIS = TimeUnit.HOURS.toMillis(2);
    private static volatile List<String> workingCommand;
    private static volatile String engineDescription;
    private static volatile boolean hooksInstalled;
    private static Path script;

    private AngrWorkers() {
    }

    /**
     * Runs one request on the worker that serves the given program and returns its result.
     *
     * @param programId     identifies the worker; calls for one program are serialized
     * @param configuredPython an interpreter the user configured, or null to discover one
     * @param request       the request body, without the id
     * @param budgetMillis  how long the worker itself intends to take
     * @throws AngrUnavailableException when no usable Python with angr can be started
     */
    public static JsonObject call(long programId, String configuredPython, Map<String, Object> request,
            long budgetMillis, TaskMonitor monitor) throws Exception {
        Worker worker = acquire(programId, configuredPython, monitor);
        synchronized (worker) {
            try {
                return worker.request(request, budgetMillis + GRACE_MILLIS, monitor);
            }
            finally {
                worker.lastUsed = System.currentTimeMillis();
            }
        }
    }

    /**
     * The "result" of a worker response, or an exception carrying the worker's own explanation
     * when the request failed.
     */
    public static JsonObject resultOf(JsonObject response) {
        if (response.has("ok") && response.get("ok").getAsBoolean() && response.has("result")) {
            return response.get("result").getAsJsonObject();
        }
        String error = response.has("error") ? response.get("error").getAsString() : "unknown error";
        boolean internal = response.has("kind") && "internal".equals(response.get("kind").getAsString());
        if (!internal) {
            throw new IllegalStateException(error);
        }
        // Something broke inside angr or the worker rather than in the request. The whole
        // traceback goes to the log; the message keeps to what failed and where, which is what
        // a banner can show and what a bug report needs first.
        String traceback = response.has("traceback") ? response.get("traceback").getAsString().strip() : "";
        if (!traceback.isEmpty()) {
            Msg.error(AngrWorkers.class, "angr worker failed: " + error + "\n" + traceback);
        }
        String where = innermostFrames(traceback, 3);
        throw new IllegalStateException("angr failed internally: " + error.strip()
            + (where.isEmpty() ? "" : " [" + where + "]")
            + (traceback.isEmpty() ? "" : ". The full Python traceback is in Ghidra's log (Help > Show Log)."));
    }

    private static final java.util.regex.Pattern FRAME =
        java.util.regex.Pattern.compile("File \"([^\"]+)\", line (\\d+), in (\\S+)");

    /** "loader.py:1304 _possible_idents <- loader.py:428 find_object <- ...", innermost first. */
    static String innermostFrames(String traceback, int count) {
        List<String> frames = new ArrayList<>();
        java.util.regex.Matcher matcher = FRAME.matcher(traceback);
        while (matcher.find()) {
            String file = matcher.group(1).replace('\\', '/');
            frames.add(file.substring(file.lastIndexOf('/') + 1) + ":" + matcher.group(2) + " " + matcher.group(3));
        }
        Collections.reverse(frames);
        return String.join(" <- ", frames.subList(0, Math.min(count, frames.size())));
    }

    /**
     * Starts a worker that belongs to one caller - a debug session - rather than to the pool, so
     * its state lives exactly as long as that caller keeps it and stopping it stops nothing else.
     */
    public static Dedicated openDedicated(String configuredPython, TaskMonitor monitor) throws Exception {
        installHooks();
        Dedicated dedicated = new Dedicated(start(configuredPython, monitor));
        synchronized (DEDICATED) {
            DEDICATED.add(dedicated);
        }
        return dedicated;
    }

    /** A worker process owned by one debug session. */
    public static final class Dedicated {
        private final Worker worker;

        private Dedicated(Worker worker) {
            this.worker = worker;
        }

        /** Runs one request; requests on one worker are serialized. */
        public JsonObject request(Map<String, Object> body, long timeoutMillis, TaskMonitor monitor)
                throws Exception {
            synchronized (worker) {
                try {
                    return worker.request(body, timeoutMillis + GRACE_MILLIS, monitor);
                }
                finally {
                    worker.lastUsed = System.currentTimeMillis();
                }
            }
        }

        public boolean isAlive() {
            return worker.isAlive();
        }

        /** Stops the process now, even in the middle of a request. */
        public void close() {
            synchronized (DEDICATED) {
                DEDICATED.remove(this);
            }
            worker.destroy();
        }
    }

    /** "angr 10.0.7 on Python 3.12.3", once a worker has started. */
    public static String engine() {
        return engineDescription;
    }

    /** Stops every worker; they restart on the next call. */
    public static void shutdownAll() {
        List<Worker> all;
        synchronized (WORKERS) {
            all = new ArrayList<>(WORKERS.values());
            WORKERS.clear();
        }
        for (Worker w : all) {
            w.destroy();
        }
        List<Dedicated> owned;
        synchronized (DEDICATED) {
            owned = new ArrayList<>(DEDICATED);
            DEDICATED.clear();
        }
        for (Dedicated d : owned) {
            d.worker.destroy();
        }
    }

    // ---- pool ----

    private static Worker acquire(long programId, String configuredPython, TaskMonitor monitor)
            throws Exception {
        installHooks();
        Worker retired = null;
        synchronized (WORKERS) {
            Worker existing = WORKERS.remove(programId);
            if (existing != null && existing.isAlive()) {
                WORKERS.put(programId, existing); // most recently used goes last
                return existing;
            }
            if (WORKERS.size() >= MAX_WORKERS) {
                Iterator<Map.Entry<Long, Worker>> it = WORKERS.entrySet().iterator();
                while (it.hasNext()) {
                    Worker candidate = it.next().getValue();
                    if (!candidate.busy) {
                        retired = candidate;
                        it.remove();
                        break;
                    }
                }
            }
        }
        if (retired != null) {
            retired.destroy();
        }
        Worker started = start(configuredPython, monitor);
        synchronized (WORKERS) {
            Worker raced = WORKERS.get(programId);
            if (raced != null && raced.isAlive()) {
                started.destroy();
                return raced;
            }
            WORKERS.put(programId, started);
        }
        return started;
    }

    private static synchronized void installHooks() {
        if (hooksInstalled) {
            return;
        }
        hooksInstalled = true;
        Runtime.getRuntime().addShutdownHook(new Thread(AngrWorkers::shutdownAll, "dfu-angr-shutdown"));
        ScheduledExecutorService reaper = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dfu-angr-reaper");
            t.setDaemon(true);
            return t;
        });
        reaper.scheduleWithFixedDelay(AngrWorkers::reapIdle, 1, 1, TimeUnit.MINUTES);
    }

    private static void reapIdle() {
        List<Worker> idle = new ArrayList<>();
        long now = System.currentTimeMillis();
        synchronized (WORKERS) {
            WORKERS.values().removeIf(w -> {
                boolean stale = !w.isAlive() || (!w.busy && now - w.lastUsed > IDLE_MILLIS);
                if (stale) {
                    idle.add(w);
                }
                return stale;
            });
        }
        for (Worker w : idle) {
            w.destroy();
        }
        List<Dedicated> abandoned = new ArrayList<>();
        synchronized (DEDICATED) {
            DEDICATED.removeIf(d -> {
                boolean stale = !d.worker.isAlive()
                    || (!d.worker.busy && now - d.worker.lastUsed > SESSION_IDLE_MILLIS);
                if (stale) {
                    abandoned.add(d);
                }
                return stale;
            });
        }
        for (Dedicated d : abandoned) {
            d.worker.destroy();
        }
    }

    // ---- starting a worker ----

    private static Worker start(String configuredPython, TaskMonitor monitor) throws Exception {
        Path workerScript = script();
        List<String> known = workingCommand;
        boolean explicit = configuredPython != null && !configuredPython.isBlank();
        if (known != null && !explicit) {
            try {
                return launch(known, workerScript, monitor);
            }
            catch (AngrUnavailableException e) {
                workingCommand = null; // the interpreter went away; discover again
            }
        }

        List<List<String>> candidates = explicit
            ? List.of(List.of(configuredPython.trim()))
            : AngrPython.candidates();
        List<String> failures = new ArrayList<>();
        for (List<String> candidate : candidates) {
            monitor.checkCancelled();
            try {
                Worker worker = launch(candidate, workerScript, monitor);
                if (!explicit) {
                    workingCommand = candidate;
                }
                return worker;
            }
            catch (AngrUnavailableException e) {
                failures.add(String.join(" ", candidate) + ": " + e.getMessage());
            }
        }
        throw new AngrUnavailableException(AngrPython.setupHelp(failures, explicit));
    }

    private static Worker launch(List<String> python, Path workerScript, TaskMonitor monitor)
            throws Exception {
        List<String> command = new ArrayList<>(python);
        command.add("-u");
        command.add(workerScript.toString());
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("PYTHONIOENCODING", "utf-8");
        builder.environment().put("PYTHONUNBUFFERED", "1");
        Process process;
        try {
            process = builder.start();
        }
        catch (IOException e) {
            throw new AngrUnavailableException("could not be started (" + e.getMessage() + ")");
        }
        Worker worker = new Worker(process, String.join(" ", python));
        monitor.setMessage("Starting angr (" + String.join(" ", python) + ")");
        JsonObject ready;
        try {
            ready = worker.awaitLine(STARTUP_MILLIS, monitor);
        }
        catch (CancelledException e) {
            worker.destroy();
            throw e;
        }
        catch (Exception e) {
            worker.destroy();
            throw new AngrUnavailableException(e.getMessage());
        }
        if (ready == null || !ready.has("ready") || !ready.get("ready").getAsBoolean()) {
            String error = ready != null && ready.has("error") ? ready.get("error").getAsString()
                : "did not answer the startup handshake";
            worker.destroy();
            throw new AngrUnavailableException("cannot import angr (" + error + ")");
        }
        engineDescription = "angr " + text(ready, "angr") + " on Python " + text(ready, "python");
        Msg.info(AngrWorkers.class, "Started angr worker pid " + text(ready, "pid") + ": "
            + engineDescription + " (" + text(ready, "executable") + ")");
        return worker;
    }

    private static String text(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsString() : "?";
    }

    /** The worker script, copied out of the jar next to the exported images. */
    private static synchronized Path script() throws IOException {
        if (script != null && Files.isRegularFile(script)) {
            return script;
        }
        Path target = AngrImage.root().resolve("dfu_angr_worker.py");
        try (InputStream in = AngrWorkers.class.getResourceAsStream(SCRIPT_RESOURCE)) {
            if (in == null) {
                throw new IOException("The angr worker script is missing from the extension ("
                    + SCRIPT_RESOURCE + "). Rebuild the extension.");
            }
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        script = target;
        return target;
    }

    // ---- one process ----

    private static final class Worker {
        private final Process process;
        private final String description;
        private final BufferedWriter stdin;
        private final BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        private final Deque<String> stderrTail = new ArrayDeque<>();
        private final AtomicLong nextId = new AtomicLong(1);
        volatile long lastUsed = System.currentTimeMillis();
        volatile boolean busy;

        Worker(Process process, String description) {
            this.process = process;
            this.description = description;
            this.stdin = new BufferedWriter(
                new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
            pump(process.getInputStream(), "dfu-angr-stdout", line -> lines.add(line));
            pump(process.getErrorStream(), "dfu-angr-stderr", line -> {
                synchronized (stderrTail) {
                    stderrTail.addLast(line);
                    while (stderrTail.size() > 30) {
                        stderrTail.removeFirst();
                    }
                }
            });
        }

        private static void pump(InputStream stream, String name, java.util.function.Consumer<String> sink) {
            Thread t = new Thread(() -> {
                try (BufferedReader reader =
                        new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sink.accept(line);
                    }
                }
                catch (IOException ignored) {
                    // the process is gone; whoever is waiting notices it is dead
                }
            }, name);
            t.setDaemon(true);
            t.start();
        }

        boolean isAlive() {
            return process.isAlive();
        }

        void destroy() {
            try {
                stdin.close(); // EOF is the worker's cue to exit on its own
            }
            catch (IOException ignored) {
                // already closed
            }
            process.destroy();
            try {
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            }
            catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }

        JsonObject request(Map<String, Object> body, long timeoutMillis, TaskMonitor monitor)
                throws Exception {
            busy = true;
            try {
                long id = nextId.getAndIncrement();
                Map<String, Object> message = new LinkedHashMap<>(body);
                message.put("id", id);
                lines.clear();
                try {
                    stdin.write(GSON.toJson(message));
                    stdin.write('\n');
                    stdin.flush();
                }
                catch (IOException e) {
                    destroy();
                    throw new IllegalStateException("The angr worker exited before it could be asked: "
                        + e.getMessage() + diagnostics());
                }
                long deadline = System.currentTimeMillis() + timeoutMillis;
                while (true) {
                    JsonObject response = awaitLine(Math.max(1, deadline - System.currentTimeMillis()), monitor);
                    if (response == null) {
                        continue;
                    }
                    if (response.has("id") && !response.get("id").isJsonNull()
                            && response.get("id").getAsLong() == id) {
                        return response;
                    }
                }
            }
            catch (CancelledException e) {
                destroy(); // the only way to stop a solver mid-query
                throw e;
            }
            finally {
                busy = false;
            }
        }

        /** The next protocol line, or an exception when the worker dies, stalls or is cancelled. */
        JsonObject awaitLine(long timeoutMillis, TaskMonitor monitor) throws Exception {
            long deadline = System.currentTimeMillis() + timeoutMillis;
            while (true) {
                monitor.checkCancelled();
                String line = lines.poll(200, TimeUnit.MILLISECONDS);
                if (line != null) {
                    line = line.strip();
                    if (line.startsWith("{")) {
                        try {
                            return JsonParser.parseString(line).getAsJsonObject();
                        }
                        catch (RuntimeException e) {
                            continue; // not ours; the worker never prints partial JSON
                        }
                    }
                    continue;
                }
                if (!process.isAlive() && lines.isEmpty()) {
                    throw new IllegalStateException("The angr worker (" + description + ") exited with code "
                        + process.exitValue() + "." + diagnostics());
                }
                if (System.currentTimeMillis() >= deadline) {
                    destroy();
                    throw new IllegalStateException("The angr worker did not answer within "
                        + (timeoutMillis / 1000) + " s and was stopped - most likely the constraint "
                        + "solver was still working. Lower maxSteps/maxPaths, use fewer or smaller "
                        + "symbolic inputs, or raise timeoutMs." + diagnostics());
                }
            }
        }

        private String diagnostics() {
            synchronized (stderrTail) {
                if (stderrTail.isEmpty()) {
                    return "";
                }
                List<String> tail = new ArrayList<>(stderrTail);
                int from = Math.max(0, tail.size() - 8);
                return " Last output: " + String.join(" | ", tail.subList(from, tail.size()));
            }
        }
    }

    /** No Python interpreter with a working angr could be started; the message says what to do. */
    public static final class AngrUnavailableException extends Exception {
        public AngrUnavailableException(String message) {
            super(message);
        }
    }
}
