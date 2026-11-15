package decompfuncutils.angr;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The debug sessions of this Ghidra: at most one per program, plus each program's breakpoints
 * and destination.
 *
 * <p>This is the one place the MCP tool and the debugger panel both go through, which is what
 * lets them share a session: either can start it, step it or edit it, and the other is told.
 * Breakpoints belong to the program rather than to a session, so they can be set before one is
 * started and survive a restart.
 *
 * <p>A session is not confined to its program. A destination (or a breakpoint) in a library of
 * the project counts for the sessions of the programs that use that library: the library is
 * loaded next to the program, and its code runs where the program calls into it. Which other
 * programs count for a given one is what {@link #companions} answers.
 */
public final class AngrDebugger {

    /** Told whenever a program's session starts, stops, runs or produces a new snapshot. */
    public interface Listener {
        void debuggerChanged(Program program);
    }

    /**
     * Says which other programs belong with a program: for a tool window, the programs open in
     * it. A destination set in one of them is one the program's sessions try to get to.
     */
    public interface Companions {
        Collection<Program> of(Program program);
    }

    private static final Map<Program, AngrDebugSession> SESSIONS = new HashMap<>();
    private static final Map<Program, TreeSet<Address>> BREAKPOINTS = new HashMap<>();
    private static final Map<Program, Address> DESTINATIONS = new HashMap<>();
    /** Programs a program was explicitly paired with: named over MCP, or found behind one of its imports. */
    private static final Map<Program, Set<Program>> PAIRED = new HashMap<>();
    /** Programs this class opened from the project itself, and therefore has to let go of. */
    private static final Set<Program> OPENED = Collections.newSetFromMap(new IdentityHashMap<>());
    private static final Object HOLDER = new Object();
    private static final List<Companions> COMPANIONS = new CopyOnWriteArrayList<>();
    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();

    private AngrDebugger() {
    }

    public static void addListener(Listener listener) {
        LISTENERS.add(listener);
    }

    public static void removeListener(Listener listener) {
        LISTENERS.remove(listener);
    }

    public static void addCompanions(Companions source) {
        COMPANIONS.add(source);
    }

    public static void removeCompanions(Companions source) {
        COMPANIONS.remove(source);
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

    /**
     * The session to show while {@code program} is on screen: its own, else a session of
     * another program that has this one loaded as a library - which is where the user is when
     * execution has crossed into the library and the Listing followed it.
     */
    public static AngrDebugSession sessionShowing(Program program) {
        AngrDebugSession own = session(program);
        if (own != null) {
            return own;
        }
        synchronized (SESSIONS) {
            for (AngrDebugSession session : SESSIONS.values()) {
                if (!session.isClosed() && session.modules.contains(program)) {
                    return session;
                }
            }
        }
        return null;
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
     *                  plus {@code modules}, names of project programs to load next to this one
     */
    public static AngrDebugSession start(Program program, String python, Map<String, Object> arguments,
            TaskMonitor monitor) throws Exception {
        return start(program, python, arguments, null, monitor);
    }

    /** @param tool may be null; it only helps to find the project the libraries are in */
    public static AngrDebugSession start(Program program, String python, Map<String, Object> arguments,
            PluginTool tool, TaskMonitor monitor) throws Exception {
        stop(program);
        if (arguments.get("modules") instanceof Collection<?> names) {
            for (Object name : names) {
                pair(program, String.valueOf(name), tool, monitor);
            }
        }
        AngrModules modules = plan(program, tool, monitor);
        AngrDebugSession session = AngrDebugSession.open(program, python, arguments, modules, monitor);
        synchronized (SESSIONS) {
            SESSIONS.put(program, session);
        }
        fire(program);
        return session;
    }

    /**
     * The programs a session of {@code program} should load: itself, the ones it was paired
     * with, and its companions that hold a destination when it links against them.
     */
    static AngrModules plan(Program program, PluginTool tool, TaskMonitor monitor) throws Exception {
        List<Program> required = new ArrayList<>();
        List<Program> wanted = new ArrayList<>();
        Set<Program> paired = paired(program);
        for (Program other : paired) {
            required.add(other);
        }
        for (Program other : companions(program)) {
            if (!paired.contains(other) && destination(other) != null) {
                wanted.add(other);
            }
        }
        if (required.isEmpty() && wanted.isEmpty()) {
            return AngrModules.single(program);
        }
        return AngrModules.plan(program, required, wanted, tool, monitor);
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
        List<Program> release = new ArrayList<>();
        synchronized (BREAKPOINTS) {
            BREAKPOINTS.remove(program);
            DESTINATIONS.remove(program);
            Set<Program> paired = PAIRED.remove(program);
            if (paired != null) {
                for (Program other : paired) {
                    boolean stillPaired = false;
                    for (Set<Program> others : PAIRED.values()) {
                        stillPaired |= others.contains(other);
                    }
                    if (!stillPaired && OPENED.remove(other)) {
                        DESTINATIONS.remove(other);
                        BREAKPOINTS.remove(other);
                        release.add(other);
                    }
                }
            }
        }
        for (Program other : release) {
            other.release(HOLDER);
        }
    }

    // ---- the programs that belong with a program ----

    private static Set<Program> paired(Program program) {
        synchronized (BREAKPOINTS) {
            Set<Program> out = Collections.newSetFromMap(new IdentityHashMap<>());
            Set<Program> paired = PAIRED.get(program);
            if (paired != null) {
                for (Program other : paired) {
                    if (!other.isClosed()) {
                        out.add(other);
                    }
                }
            }
            return out;
        }
    }

    /**
     * The other programs whose destinations and breakpoints count for this program's sessions:
     * those it was paired with by name, and those open next to it in a tool.
     */
    public static Set<Program> companions(Program program) {
        Set<Program> out = paired(program);
        for (Companions source : COMPANIONS) {
            try {
                for (Program other : source.of(program)) {
                    if (other != null && other != program && !other.isClosed()) {
                        out.add(other);
                    }
                }
            }
            catch (RuntimeException e) {
                // a tool that is going away has nothing to add
            }
        }
        return out;
    }

    /**
     * Pairs a program of the project with {@code program} by name, opening it when nothing has
     * it open: a session of {@code program} started after this loads it.
     *
     * @return the program of that name
     */
    public static Program pair(Program program, String name, PluginTool tool, TaskMonitor monitor)
            throws Exception {
        Set<Program> known = companions(program);
        synchronized (BREAKPOINTS) {
            known.addAll(OPENED);
        }
        Program found = AngrModules.find(program, name, known, tool, HOLDER, monitor);
        if (found == null) {
            throw new IllegalArgumentException("There is no program named '" + name.strip() + "' in the project. "
                + "Import the library into the project " + program.getName() + " is in.");
        }
        if (found == program) {
            if (!known.contains(found)) {
                found.release(HOLDER);
            }
            return found;
        }
        return pair(program, found, !known.contains(found));
    }

    /** @param opened true when {@code other} was just opened for this and is held by {@link #HOLDER} */
    private static Program pair(Program program, Program other, boolean opened) {
        synchronized (BREAKPOINTS) {
            if (opened) {
                OPENED.add(other);
            }
            PAIRED.computeIfAbsent(program, p -> Collections.newSetFromMap(new IdentityHashMap<>())).add(other);
        }
        return other;
    }

    /**
     * Where a name or address the user gave is, looking past the program itself: the name of an
     * import is taken to mean the code in the library that defines it, {@code library!name} a
     * name in that library. The library is paired with the program.
     *
     * @param library the program the text is to be looked up in, or null
     */
    public static AngrModules.Location locate(Program program, String text, String library, PluginTool tool,
            TaskMonitor monitor) throws Exception {
        String what = text.strip();
        String in = library == null || library.isBlank() ? null : library.strip();
        int bang = what.indexOf('!');
        if (in == null && bang > 0) {
            in = what.substring(0, bang).strip();
            what = what.substring(bang + 1).strip();
        }
        if (in != null && !in.equals(AngrModules.nameOf(program)) && !in.equals(program.getName())) {
            Program other = pair(program, in, tool, monitor);
            if (other != program) {
                return new AngrModules.Location(other, AngrCallSpec.resolveCode(other, what, "address"));
            }
        }

        Function external = null;
        Address address = null;
        try {
            address = AngrCallSpec.resolveCode(program, what, "address");
            Function function = program.getFunctionManager().getFunctionAt(address);
            Function thunked = function != null && function.isThunk() ? function.getThunkedFunction(true) : null;
            if (thunked != null && thunked.isExternal()) {
                external = thunked;
            }
        }
        catch (IllegalArgumentException e) {
            for (Symbol symbol : program.getSymbolTable().getSymbols(what)) {
                if (symbol.isExternal() && symbol.getObject() instanceof Function function) {
                    external = function;
                }
            }
            if (external == null) {
                throw e;
            }
        }
        if (external == null) {
            return new AngrModules.Location(program, address);
        }

        // An import: the place meant is the code behind it, which is in another program.
        Set<Program> known = companions(program);
        synchronized (BREAKPOINTS) {
            known.addAll(OPENED);
        }
        AngrModules.Location target = AngrModules.followImport(program, external, known, tool, HOLDER, monitor);
        if (target == null) {
            if (address != null) {
                return new AngrModules.Location(program, address); // the stub, as before
            }
            throw new IllegalArgumentException("'" + what + "' is an import of " + program.getName()
                + ", and no program in the project defines it. Import the library that does, or name the "
                + "place as library!name.");
        }
        pair(program, target.program(), !known.contains(target.program()));
        return target;
    }

    // ---- the destination ----

    /**
     * Where sessions are trying to get to in this program, or null. A breakpoint is somewhere
     * to stop if execution happens to arrive; the destination is somewhere to arrive, and
     * {@link #seek} goes looking for the way.
     */
    public static Address destination(Program program) {
        synchronized (BREAKPOINTS) {
            return DESTINATIONS.get(program);
        }
    }

    /**
     * Every destination a session of {@code program} is after: its own, then the ones set in
     * the programs that belong with it.
     */
    public static List<AngrModules.Location> destinations(Program program) {
        List<AngrModules.Location> out = new ArrayList<>();
        Address own = destination(program);
        if (own != null) {
            out.add(new AngrModules.Location(program, own));
        }
        for (Program other : companions(program)) {
            Address address = destination(other);
            if (address != null) {
                out.add(new AngrModules.Location(other, address));
            }
        }
        return out;
    }

    /** The destinations of the program's sessions as text for a person; null when there is none. */
    public static String destinationText(Program program) {
        AngrDebugSession session = session(program);
        if (session != null) {
            return session.destinationText();
        }
        List<String> out = new ArrayList<>();
        for (AngrModules.Location destination : destinations(program)) {
            String hex = AngrImage.hex(destination.address().getOffset());
            if (destination.program() == program) {
                out.add(AngrCallSpec.codeLabel(program, hex));
                continue;
            }
            String label = AngrModules.localLabel(destination.program(), destination.address());
            out.add(AngrModules.nameOf(destination.program()) + "!"
                + (label == null ? destination.address().toString() : label + " @ " + destination.address()));
        }
        return out.isEmpty() ? null : String.join(", ", out);
    }

    /** @param address the new destination in this program, or null to have none in it */
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

    /**
     * Makes {@code target} the one destination of {@code program}'s sessions, wherever it is:
     * in the program or in a program paired with it. Null clears it.
     */
    public static void setDestination(Program program, AngrModules.Location target) {
        Set<Program> touched = Collections.newSetFromMap(new IdentityHashMap<>());
        touched.add(program);
        touched.addAll(paired(program));
        synchronized (BREAKPOINTS) {
            for (Program other : touched) {
                DESTINATIONS.remove(other);
            }
            if (target != null) {
                DESTINATIONS.put(target.program(), target.address());
            }
        }
        if (target != null) {
            touched.add(target.program());
        }
        for (Program other : touched) {
            fire(other);
        }
        fire(program);
    }

    /**
     * Looks for a way from the program's current path to a destination; see
     * {@link AngrDebugSession#seek}. When a destination is in a library the session has not
     * loaded and the session has not moved yet, it is started again with the library in it.
     */
    public static AngrDebugSession seek(Program program, List<Address> avoid, boolean guided, long budgetMillis,
            TaskMonitor monitor) throws Exception {
        AngrDebugSession session = require(program);
        boolean missing = false;
        for (AngrModules.Location destination : destinations(program)) {
            missing |= !session.modules.contains(destination.program());
        }
        String restarted = null;
        if (missing && !session.isRunning()) {
            AngrModules trial = plan(program, null, monitor);
            List<String> more = new ArrayList<>();
            try {
                for (AngrModules.Module module : trial.modules()) {
                    if (!session.modules.contains(module.program)) {
                        more.add(module.name);
                    }
                }
            }
            finally {
                trial.release();
            }
            if (!more.isEmpty()) {
                if (!session.pristine()) {
                    throw new IllegalStateException("The destination is in " + String.join(", ", more)
                        + ", which this session did not load: the destination was set after it had started "
                        + "running. Start the session again and seek from the beginning.");
                }
                session = start(program, session.python, session.launchArguments, monitor);
                restarted = "The session was started again to load " + String.join(", ", more) + ".";
            }
        }
        session.seek(avoid, guided, budgetMillis, monitor);
        if (restarted != null) {
            session.snapshot().put("reloaded", restarted);
        }
        return session;
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
