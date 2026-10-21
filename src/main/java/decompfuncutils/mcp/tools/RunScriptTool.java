package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.*;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** Runs installed, non-interactive Ghidra scripts against the request's program. */
public class RunScriptTool implements McpTool {
    private static final ScheduledExecutorService TIMER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "MCP script timeout");
        thread.setDaemon(true);
        return thread;
    });

    public String name() { return "ghidra_run_script"; }
    public String description() {
        return "Run an existing Ghidra script by script-path name or absolute file path against the active program. " +
            "Captures script output and accepts string arguments. Use non-interactive scripts with ENABLED analysis mode. " +
            "Runs off the UI thread; timeout/cancellation is cooperative. Scripts have full Ghidra process permissions; " +
            "only active-program database edits are covered by transaction rollback, not external side effects.";
    }
    public boolean isMutating() { return true; }
    public boolean requiresEdt() { return false; }
    public Map<String, Object> inputSchema() {
        return Map.of("type", "object", "properties", Map.of(
            "script", Map.of("type", "string", "description", "Script filename in configured Ghidra script paths, or an absolute path"),
            "args", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Script arguments"),
            "address", Map.of("type", "string", "description", "Optional currentAddress for the script (hex); defaults to program minimum address"),
            "timeoutSeconds", Map.of("type", "integer", "minimum", 1, "maximum", 3600, "default", 60),
            "maxOutputChars", Map.of("type", "integer", "minimum", 1, "maximum", 1048576, "default", 65536)),
            "required", List.of("script"));
    }

    @SuppressWarnings("deprecation") // This execute overload also supports Ghidra 11.
    public Object execute(Map<String, Object> args, Program program, PluginTool tool) throws Exception {
        String name = DecompilerEditSupport.string(args, "script");
        int seconds = DecompilerEditSupport.integer(args.getOrDefault("timeoutSeconds", 60), "timeoutSeconds", 1, 3600);
        int maxOutput = DecompilerEditSupport.integer(args.getOrDefault("maxOutputChars", 65536), "maxOutputChars", 1, 1048576);
        Object values = args.getOrDefault("args", List.of());
        if (!(values instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof String))) {
            throw new IllegalArgumentException("args must be an array of strings");
        }
        var address = args.containsKey("address") ? McpUtil.parseAddress(DecompilerEditSupport.string(args, "address"), program)
            : program.getMinAddress();
        if (address == null || !program.getMemory().contains(address)) {
            throw new IllegalArgumentException("Script address must be in program memory");
        }
        File file = new File(name);
        if (!file.isAbsolute() && (name.contains("/") || name.contains("\\"))) {
            throw new IllegalArgumentException("Use a script filename or an absolute path");
        }
        // The Script Manager need not be open. Retain a runtime reference when MCP
        // initializes it, since registered source bundles are reused by later calls.
        synchronized (GhidraScriptUtil.class) {
            if (GhidraScriptUtil.getBundleHost() == null) GhidraScriptUtil.acquireBundleHostReference();
        }
        ResourceFile source = file.isAbsolute() ? new ResourceFile(file) : GhidraScriptUtil.findScriptByName(name);
        if (source == null || !source.isFile()) throw new IllegalArgumentException("Script not found: " + name);
        // Java providers compile source directories as OSGi bundles. Register an explicit
        // path's parent once, so it and sibling helper classes can be loaded normally.
        if (file.isAbsolute()) {
            var host = GhidraScriptUtil.getBundleHost();
            synchronized (host) {
                boolean registered = GhidraScriptUtil.getScriptSourceDirectories().stream()
                    .anyMatch(dir -> FileUtilities.relativizePath(dir, source) != null);
                if (!registered) host.add(source.getParentFile(), true, false);
            }
        }
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
        if (provider == null) throw new IllegalArgumentException("No installed script provider for " + source.getName());

        BoundedWriter output = new BoundedWriter(maxOutput);
        PrintWriter writer = new PrintWriter(output, true);
        TaskMonitor monitor = McpUtil.activeMonitor();
        ScheduledFuture<?> timeout = TIMER.schedule(monitor::cancel, seconds, TimeUnit.SECONDS);
        try {
            monitor.checkCancelled();
            GhidraScript script = provider.getScriptInstance(source, writer);
            if (script == null) throw new IllegalStateException("Provider did not create a script");
            if (script.getScriptAnalysisMode() != GhidraScript.AnalysisMode.ENABLED) {
                throw new IllegalArgumentException("MCP requires ENABLED script analysis mode; analysis-worker scripts cannot run inside its transaction");
            }
            script.setScriptArgs(list.toArray(String[]::new));
            GhidraState state = new GhidraState(tool, tool == null ? null : tool.getProject(), program,
                new ProgramLocation(program, address), null, null);
            script.execute(state, monitor, writer);
            monitor.checkCancelled();
            writer.flush();
            return Map.of("status", "script_completed", "script", source.getAbsolutePath(), "program", program.getName(),
                "output", output.toString(), "outputTruncated", output.truncated);
        } catch (Exception e) {
            writer.flush();
            throw new IllegalStateException("Script failed or cancelled: " + e + "\n" + output, e);
        } finally {
            timeout.cancel(false);
            writer.close();
        }
    }

    private static final class BoundedWriter extends Writer {
        private final int limit;
        private final StringBuilder text = new StringBuilder();
        private boolean truncated;
        BoundedWriter(int limit) { this.limit = limit; }
        @Override public synchronized void write(char[] chars, int offset, int count) {
            int keep = Math.min(count, limit - text.length());
            text.append(chars, offset, keep);
            truncated |= keep < count;
        }
        @Override public void flush() {}
        @Override public void close() {}
        @Override public synchronized String toString() { return text.toString(); }
    }
}
