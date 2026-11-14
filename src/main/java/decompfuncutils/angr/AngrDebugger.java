package decompfuncutils.angr;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The debug sessions of this Ghidra: at most one per program, plus each program's breakpoints.
 *
 * <p>This is the one place the MCP tool and the debugger panel both go through, which is what
 * lets them share a session: either can start it, step it or edit it, and the other is told.
 * Breakpoints belong to the program rather than to a session, so they can be set before one is
 * started and survive a restart.
 */
public final class AngrDebugger {

    /** Told whenever a program's session starts, stops, runs or produces a new snapshot. */
    public interface Listener {
        void debuggerChanged(Program program);
    }

    private static final Map<Program, AngrDebugSession> SESSIONS = new HashMap<>();
    private static final Map<Program, TreeSet<Address>> BREAKPOINTS = new HashMap<>();
    private static final Map<Program, Address> DESTINATIONS = new HashMap<>();
    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();

    private AngrDebugger() {
    }

    public static void addListener(Listener listener) {
        LISTENERS.add(listener);
    }

    public static void removeListener(Listener listener) {
        LISTENERS.remove(listener);
    }

    static void fire(Program program) {
        for (Listener listener : LISTENERS) {
            try {
                listener.debuggerChanged(program);
            }
            catch (RuntimeException e) {
                // one broken listener must not take the debugger down with it
            }
        }
    }

    /** The program's live session, or null. */
    public static AngrDebugSession session(Program program) {
        synchronized (SESSIONS) {
            AngrDebugSession session = SESSIONS.get(program);
            if (session != null && session.isClosed()) {
                SESSIONS.remove(program);
                return null;
            }
            return session;
        }
    }

    /** The program's live session, or an error that says how to get one. */
    public static AngrDebugSession require(Program program) {
        AngrDebugSession session = session(program);
        if (session == null) {
            throw new IllegalStateException("No debug session is running for " + program.getName()
                + ". Start one first (action 'start' with a function).");
        }
        return session;
    }

    /**
     * Starts debugging a function, replacing any session the program already has.
     *
     * @param python    an interpreter set in Tool Options, or null to discover one
     * @param arguments what {@code ghidra_angr_emulate} takes: function, args, stubs, memory, ...
     */
    public static AngrDebugSession start(Program program, String python, Map<String, Object> arguments,
            TaskMonitor monitor) throws Exception {
        stop(program);
        AngrDebugSession session = AngrDebugSession.open(program, python, arguments, monitor);
        synchronized (SESSIONS) {
            SESSIONS.put(program, session);
        }
        fire(program);
        return session;
    }

    /** Ends the program's session, if it has one. */
    public static boolean stop(Program program) {
        AngrDebugSession session;
        synchronized (SESSIONS) {
            session = SESSIONS.remove(program);
        }
        if (session == null) {
            return false;
        }
        session.close();
        fire(program);
        return true;
    }

    /** Ends everything belonging to a program that is going away. */
    public static void forget(Program program) {
        stop(program);
        synchronized (BREAKPOINTS) {
            BREAKPOINTS.remove(program);
            DESTINATIONS.remove(program);
        }
    }

    // ---- the destination ----

    /**
     * Where the program's sessions are trying to get to, or null. A breakpoint is somewhere to
     * stop if execution happens to arrive; the destination is somewhere to arrive, and
     * {@link AngrDebugSession#seek} goes looking for the way.
     */
    public static Address destination(Program program) {
        synchronized (BREAKPOINTS) {
            return DESTINATIONS.get(program);
        }
    }

    /** @param address the new destination, or null to have none */
    public static void setDestination(Program program, Address address) {
        synchronized (BREAKPOINTS) {
            if (address == null) {
                DESTINATIONS.remove(program);
            }
            else {
                DESTINATIONS.put(program, address);
            }
        }
        fire(program);
    }

    // ---- breakpoints ----

    public static List<Address> breakpoints(Program program) {
        synchronized (BREAKPOINTS) {
            TreeSet<Address> set = BREAKPOINTS.get(program);
            return set == null ? List.of() : new ArrayList<>(set);
        }
    }

    public static boolean hasBreakpoint(Program program, Address address) {
        synchronized (BREAKPOINTS) {
            TreeSet<Address> set = BREAKPOINTS.get(program);
            return set != null && set.contains(address);
        }
    }

    /** @return true when the address now has a breakpoint, false when it was just removed */
    public static boolean toggleBreakpoint(Program program, Address address) {
        boolean added;
        synchronized (BREAKPOINTS) {
            TreeSet<Address> set = BREAKPOINTS.computeIfAbsent(program, p -> new TreeSet<>());
            added = set.add(address);
            if (!added) {
                set.remove(address);
            }
        }
        fire(program);
        return added;
    }

    public static void setBreakpoint(Program program, Address address, boolean present) {
        synchronized (BREAKPOINTS) {
            TreeSet<Address> set = BREAKPOINTS.computeIfAbsent(program, p -> new TreeSet<>());
            if (present) {
                set.add(address);
            }
            else {
                set.remove(address);
            }
        }
        fire(program);
    }

    public static void clearBreakpoints(Program program) {
        synchronized (BREAKPOINTS) {
            BREAKPOINTS.remove(program);
        }
        fire(program);
    }
}
