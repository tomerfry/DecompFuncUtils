package decompfuncutils.mcp;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Thread-safe pool of DecompInterface instances, keyed per Program.
 * Allows multiple agents to decompile concurrently without contention.
 */
public class DecompInterfacePool {

    private static final int POOL_SIZE = 4;

    private final ConcurrentHashMap<Long, LinkedBlockingQueue<DecompInterface>> pools =
        new ConcurrentHashMap<>();

    /**
     * Acquire a DecompInterface for the given program.
     * Returns a pooled instance if available, otherwise creates a new one.
     */
    public DecompInterface acquire(Program program) {
        long key = program.getUniqueProgramID();
        LinkedBlockingQueue<DecompInterface> pool =
            pools.computeIfAbsent(key, k -> new LinkedBlockingQueue<>(POOL_SIZE));

        DecompInterface decomp = pool.poll();
        if (decomp != null) {
            return decomp;
        }

        decomp = new DecompInterface();
        decomp.openProgram(program);
        return decomp;
    }

    /**
     * Release a DecompInterface back to the pool.
     * If the pool is full, the instance is disposed.
     */
    public void release(Program program, DecompInterface decomp) {
        if (decomp == null) return;
        long key = program.getUniqueProgramID();
        LinkedBlockingQueue<DecompInterface> pool = pools.get(key);
        if (pool == null || !pool.offer(decomp)) {
            decomp.dispose();
        }
    }

    /**
     * Dispose all pooled instances for a specific program.
     * Call when a program is closed.
     */
    public void invalidate(Program program) {
        long key = program.getUniqueProgramID();
        LinkedBlockingQueue<DecompInterface> pool = pools.remove(key);
        if (pool != null) {
            DecompInterface decomp;
            while ((decomp = pool.poll()) != null) {
                decomp.dispose();
            }
        }
        Msg.debug(this, "Invalidated decompiler pool for program: " + program.getName());
    }

    /**
     * Dispose all pooled instances across all programs.
     * Call on server shutdown.
     */
    public void disposeAll() {
        for (var entry : pools.entrySet()) {
            DecompInterface decomp;
            while ((decomp = entry.getValue().poll()) != null) {
                decomp.dispose();
            }
        }
        pools.clear();
        Msg.debug(this, "All decompiler pools disposed");
    }
}
