package decompfuncutils.angr;

import decompfuncutils.crossmodule.CrossModuleLinker;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * The programs that run together in one angr address space: the one being debugged, and the
 * libraries of the project whose code its imports should really run.
 *
 * <p>Each program keeps the addresses Ghidra shows for it as long as nothing else is in the
 * way. Shared objects are usually all loaded at the same image base in Ghidra, so a library
 * that would land on top of an earlier module is moved: every address of it is shifted by the
 * module's {@link Module#delta}, and {@link AngrImage} shifts the pointers stored in it to match.
 * The program being debugged is always first and is never moved.
 *
 * <p>This class is where an address of the shared space is turned back into "this address of
 * that program", which is what names, markers and the Listing need.
 */
public final class AngrModules {

    /** How far a search for the libraries between two programs may go. */
    private static final int MAX_OPENED = 48;
    /** Where moved modules go: a round base well clear of whatever came before. */
    private static final long ALIGN = 0x1000000L;
    private static final long PAGE = 0x1000L;

    /** An address in one particular program. */
    public record Location(Program program, Address address) {
    }

    /** One program of the set. */
    public static final class Module {
        public final Program program;
        /** The name it is shown under: its file name in the project. */
        public final String name;
        /** First and last address Ghidra has memory for, in the program's own terms. */
        final long min;
        final long max;
        long delta;

        Module(Program program) {
            this.program = program;
            DomainFile file = program.getDomainFile();
            this.name = file != null && file.getName() != null ? file.getName() : program.getName();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            long lo = Long.MAX_VALUE;
            long hi = Long.MIN_VALUE;
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!exported(block, space)) {
                    continue;
                }
                lo = Math.min(lo, block.getStart().getOffset());
                hi = Math.max(hi, block.getEnd().getOffset());
            }
            this.min = lo;
            this.max = hi;
        }

        /** What is added to one of the program's addresses to get the address it runs at. */
        public long delta() {
            return delta;
        }

        public boolean moved() {
            return delta != 0;
        }

        /** Whether the value, read as one of the program's own addresses, lies in its memory. */
        boolean covers(long offset) {
            return offset >= min && offset <= max;
        }

        public long toAngr(Address address) {
            return address.getOffset() + delta;
        }
    }

    /** An import of one module that another module of the set defines. */
    public static final class Link {
        public final Module importer;
        public final String name;
        /** The importer's external function, or null when the import is a variable. */
        public final Function external;
        /** For a variable: the stand-in address Ghidra gave it in the importer's EXTERNAL block. */
        public final Address slot;
        public final Module target;
        /** Where the target module defines it, in that program's own terms. */
        public final Address address;

        Link(Module importer, String name, Function external, Address slot, Module target, Address address) {
            this.importer = importer;
            this.name = name;
            this.external = external;
            this.slot = slot;
            this.target = target;
            this.address = address;
        }

        public long angrAddress() {
            return target.toAngr(address);
        }
    }

    private final List<Module> modules = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();
    private List<Link> links;
    private boolean released;

    private AngrModules(Program main) {
        modules.add(new Module(main));
    }

    /** The memory blocks that take part: the flat address space, loaded, plus the EXTERNAL stand-ins. */
    static boolean exported(MemoryBlock block, AddressSpace space) {
        if (block.isOverlay() || !block.getStart().getAddressSpace().equals(space)) {
            return false;
        }
        return block.isLoaded() || block.isExternalBlock();
    }

    // ---- building the set ----

    /** The program by itself, as every session ran before libraries could be loaded with it. */
    public static AngrModules single(Program main) {
        return new AngrModules(main);
    }

    /**
     * The program with other programs of the project next to it.
     *
     * @param required loaded whatever the link structure says: the caller asked for them by name
     * @param wanted   loaded when the program reaches them through its libraries, together with
     *                 whatever libraries lie in between; left out (with a note) otherwise
     * @param tool     may be null; only used to find the project
     */
    public static AngrModules plan(Program main, Collection<Program> required, Collection<Program> wanted,
            PluginTool tool, TaskMonitor monitor) throws Exception {
        AngrModules set = new AngrModules(main);
        try {
            for (Program program : required) {
                set.add(program);
            }
            ProjectData data = CrossModuleLinker.projectDataFor(main, tool);
            for (Program program : wanted) {
                if (set.moduleOf(program) != null || program.isClosed()) {
                    continue;
                }
                if (!set.addLinked(program, data, monitor)) {
                    set.notes.add(nameOf(program) + " was not loaded: nothing " + nameOf(main)
                        + " links against leads to it.");
                }
            }
            set.place();
            return set;
        }
        catch (Exception e) {
            set.release();
            throw e;
        }
    }

    private void add(Program program) {
        if (program == null || program.isClosed() || moduleOf(program) != null) {
            return;
        }
        Program main = main();
        if (!program.getLanguage().getProcessor().equals(main.getLanguage().getProcessor())
                || program.getDefaultPointerSize() != main.getDefaultPointerSize()
                || program.getLanguage().isBigEndian() != main.getLanguage().isBigEndian()) {
            throw new IllegalArgumentException(nameOf(program) + " is built for "
                + program.getLanguage().getLanguageID() + ", " + nameOf(main) + " for "
                + main.getLanguage().getLanguageID() + "; they cannot run together.");
        }
        if (!program.addConsumer(this)) {
            return;
        }
        Module module = new Module(program);
        if (module.min > module.max) {
            program.release(this);
            return;
        }
        modules.add(module);
        links = null;
    }

    /**
     * Adds {@code target} together with the libraries that lead to it from the modules already
     * in the set. Libraries are looked up the way the cross-module linker does: by the project
     * path stored for the library, else by name.
     *
     * @return false when nothing links them, in which case nothing was added
     */
    private boolean addLinked(Program target, ProjectData data, TaskMonitor monitor) throws Exception {
        Map<Program, Program> parent = new IdentityHashMap<>();
        List<Program> opened = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Deque<Program> queue = new ArrayDeque<>();
        // Programs opened only to read their library lists are held by this, not by the set.
        Object search = new Object();
        for (Module module : modules) {
            queue.add(module.program);
            parent.put(module.program, null);
        }
        try {
            while (!queue.isEmpty()) {
                monitor.checkCancelled();
                Program program = queue.removeFirst();
                for (String library : program.getExternalManager().getExternalLibraryNames()) {
                    if (Library.UNKNOWN.equals(library)) {
                        continue;
                    }
                    if (isLibrary(program, library, target)) {
                        List<Program> chain = new ArrayList<>(List.of(target));
                        for (Program step = program; step != null && moduleOf(step) == null; step = parent.get(step)) {
                            chain.add(0, step);
                        }
                        for (Program step : chain) {
                            add(step);
                        }
                        return true;
                    }
                    DomainFile file = libraryFile(program, library, data, monitor);
                    if (file == null || !seen.add(file.getPathname()) || opened.size() >= MAX_OPENED) {
                        continue;
                    }
                    Program next = open(file, search, monitor);
                    if (next == null) {
                        continue;
                    }
                    opened.add(next);
                    if (!parent.containsKey(next)) {
                        parent.put(next, program);
                        queue.add(next);
                    }
                }
            }
            return false;
        }
        finally {
            for (Program program : opened) {
                program.release(search);
            }
        }
    }

    /** Whether {@code library}, a library name of {@code importer}, is the program {@code candidate}. */
    static boolean isLibrary(Program importer, String library, Program candidate) {
        DomainFile file = candidate.getDomainFile();
        String path = importer.getExternalManager().getExternalLibraryPath(library);
        if (path != null && file != null && path.equals(file.getPathname())) {
            return true;
        }
        String name = file != null && file.getName() != null ? file.getName() : candidate.getName();
        return name.equals(library) || name.startsWith(library) || candidate.getName().equals(library);
    }

    /** The project file of one of a program's libraries, or null. */
    static DomainFile libraryFile(Program importer, String library, ProjectData data, TaskMonitor monitor)
            throws Exception {
        if (data == null) {
            return null;
        }
        String path = importer.getExternalManager().getExternalLibraryPath(library);
        if (path != null) {
            DomainFile file = data.getFile(path);
            if (file != null) {
                return file;
            }
        }
        DomainFile own = importer.getDomainFile();
        DomainFolder preferred = own != null && own.getParent() != null ? own.getParent() : data.getRootFolder();
        return CrossModuleLinker.findLibraryFile(data, preferred, library, monitor);
    }

    /**
     * Opens a program of the project, sharing the instance a tool already has open.
     *
     * @return the program, held by {@code consumer}; null when the file is not a program that
     *         can be opened as it is (it needs an upgrade, say)
     */
    public static Program open(DomainFile file, Object consumer, TaskMonitor monitor) {
        try {
            Object object = file.getDomainObject(consumer, false, false, monitor);
            if (object instanceof Program program) {
                return program;
            }
            if (object instanceof ghidra.framework.model.DomainObject other) {
                other.release(consumer);
            }
        }
        catch (Exception e) {
            // fall through: not openable as it is
        }
        return null;
    }

    /** Gives every module after the first a place that is clear of the ones before it. */
    private void place() {
        List<long[]> taken = new ArrayList<>();
        Module main = modules.get(0);
        taken.add(new long[] { main.min, main.max });
        int bits = main.program.getDefaultPointerSize() * 8;
        long limit = bits >= 63 ? 0x400000000000L : (1L << bits) - 0x10000000L;
        for (Module module : modules.subList(1, modules.size())) {
            long delta = 0;
            if (overlaps(taken, module.min, module.max)) {
                long top = 0;
                for (long[] range : taken) {
                    top = Math.max(top, range[1]);
                }
                long base = (top + ALIGN + ALIGN - 1) / ALIGN * ALIGN;
                delta = base - (module.min & ~(PAGE - 1));
                if (module.max + delta >= limit) {
                    throw new IllegalStateException("There is no room in the address space to load "
                        + module.name + " next to " + main.name + ".");
                }
                if (module.program.getRelocationTable().getSize() == 0) {
                    notes.add(module.name + " shares addresses with another module and was moved, but Ghidra "
                        + "has no relocations for it: absolute addresses stored in it still point at the old place.");
                }
            }
            module.delta = delta;
            taken.add(new long[] { module.min + delta, module.max + delta });
        }
    }

    private static boolean overlaps(List<long[]> taken, long lo, long hi) {
        for (long[] range : taken) {
            // A page of clearance, so two modules never share one.
            if (lo - PAGE <= range[1] && range[0] <= hi + PAGE) {
                return true;
            }
        }
        return false;
    }

    /** Lets go of the libraries this set holds open. Safe to call more than once. */
    public synchronized void release() {
        if (released) {
            return;
        }
        released = true;
        for (Module module : modules.subList(1, modules.size())) {
            module.program.release(this);
        }
    }

    // ---- what is in it ----

    public Program main() {
        return modules.get(0).program;
    }

    public List<Module> modules() {
        return Collections.unmodifiableList(modules);
    }

    public int size() {
        return modules.size();
    }

    /** Things worth telling the user about how the set came out. */
    public List<String> notes() {
        return Collections.unmodifiableList(notes);
    }

    /** The names of the modules after the first, for messages. */
    public List<String> libraryNames() {
        List<String> names = new ArrayList<>();
        for (Module module : modules.subList(1, modules.size())) {
            names.add(module.name);
        }
        return names;
    }

    public Module moduleOf(Program program) {
        for (Module module : modules) {
            if (module.program == program) {
                return module;
            }
        }
        return null;
    }

    public boolean contains(Program program) {
        return moduleOf(program) != null;
    }

    /** Identifies this exact arrangement of these exact program versions. */
    public String key() {
        StringBuilder key = new StringBuilder();
        for (Module module : modules) {
            if (key.length() > 0) {
                key.append('_');
            }
            key.append(Long.toHexString(module.program.getUniqueProgramID())).append('-')
               .append(module.program.getModificationNumber()).append('-').append(Long.toHexString(module.delta));
        }
        return key.toString();
    }

    // ---- addresses ----

    /** The module an address of the shared space belongs to, or null. */
    public Module moduleAt(long angr) {
        for (Module module : modules) {
            if (module.covers(angr - module.delta)) {
                return module;
            }
        }
        return null;
    }

    /** The program and address behind an address of the shared space, or null. */
    public Location locate(long angr) {
        Module module = moduleAt(angr);
        if (module == null) {
            return null;
        }
        try {
            Address address = module.program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(angr - module.delta);
            return module.program.getMemory().contains(address) ? new Location(module.program, address) : null;
        }
        catch (Exception e) {
            return null;
        }
    }

    public Location locate(String hex) {
        Long value = parse(hex);
        return value == null ? null : locate(value);
    }

    /** Where an address of one of the programs runs, or null when the program is not loaded. */
    public Long toAngr(Program program, Address address) {
        Module module = moduleOf(program);
        return module == null ? null : module.toAngr(address);
    }

    public Long toAngr(Location location) {
        return toAngr(location.program(), location.address());
    }

    private static Long parse(String hex) {
        if (hex == null) {
            return null;
        }
        String cleaned = hex.replaceFirst("^0[xX]", "");
        if (!cleaned.matches("[0-9a-fA-F]{1,16}")) {
            return null;
        }
        return Long.parseUnsignedLong(cleaned, 16);
    }

    // ---- names ----

    /**
     * "check_password+0x17" for code and "g_counter" or "g_table+0x8" for data in the program
     * being debugged; the same with the module in front - "libfoo.so!parse+0x4" - anywhere
     * else. Null when the address is in no module or has no name.
     */
    public String label(String hex) {
        Location location = locate(hex);
        return location == null ? null : label(location);
    }

    public String label(Location location) {
        String local = localLabel(location.program(), location.address());
        if (local == null) {
            return null;
        }
        return location.program() == main() ? local : nameOf(location.program()) + "!" + local;
    }

    /** "0x101b00 (deref+0x10)", or just the address when nothing names it. */
    public String codeLabel(String hex) {
        Location location = locate(hex);
        if (location == null) {
            return hex;
        }
        Function function = location.program().getFunctionManager().getFunctionContaining(location.address());
        if (function == null) {
            return hex;
        }
        return hex + " (" + label(location) + ownAddress(location) + ")";
    }

    /** How a place reads to a person: "unlock", or "libfoo.so!unlock @ 00101500" in a library. */
    public String describe(Location location) {
        String label = label(location);
        if (location.program() == main()) {
            String hex = AngrImage.hex(location.address().getOffset());
            return label == null ? hex : hex + " (" + label + ")";
        }
        return (label == null ? nameOf(location.program()) + "!" + location.address() : label + ownAddress(location));
    }

    /** A moved module's code is not at the address Ghidra shows for it; say which that is. */
    private String ownAddress(Location location) {
        Module module = moduleOf(location.program());
        return module != null && module.moved() ? " @ " + location.address() : "";
    }

    /** The function that starts at the address, named as {@link #label} names things; null when none does. */
    public String functionAt(String hex) {
        Location location = locate(hex);
        if (location == null) {
            return null;
        }
        Function function = location.program().getFunctionManager().getFunctionAt(location.address());
        if (function == null) {
            return null;
        }
        return location.program() == main() ? function.getName()
            : nameOf(location.program()) + "!" + function.getName();
    }

    /** The symbol a data address belongs to, with its offset inside the data item; null when unnamed. */
    public String dataLabel(String hex) {
        Location location = locate(hex);
        if (location == null) {
            return null;
        }
        String label = AngrCallSpec.dataLabel(location.program(), AngrImage.hex(location.address().getOffset()));
        return label == null || location.program() == main() ? label : nameOf(location.program()) + "!" + label;
    }

    static String localLabel(Program program, Address address) {
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

    public static String nameOf(Program program) {
        DomainFile file = program.getDomainFile();
        return file != null && file.getName() != null ? file.getName() : program.getName();
    }

    // ---- imports that another module defines ----

    /**
     * Every import of a module that another module of the set defines: functions, whose calls
     * then run the real code, and variables, whose users are pointed at the real storage.
     */
    public synchronized List<Link> links() {
        if (links != null) {
            return links;
        }
        List<Link> out = new ArrayList<>();
        if (modules.size() > 1) {
            for (Module importer : modules) {
                collectFunctionLinks(importer, out);
                collectDataLinks(importer, out);
            }
        }
        links = out;
        return out;
    }

    /** The imports, in any module, that end up at this function. */
    public List<Link> importersOf(Program program, Address entry) {
        List<Link> out = new ArrayList<>();
        for (Link link : links()) {
            if (link.external != null && link.target.program == program && link.address.equals(entry)) {
                out.add(link);
            }
        }
        return out;
    }

    private void collectFunctionLinks(Module importer, List<Link> out) {
        Program program = importer.program;
        Set<String> done = new HashSet<>();
        for (Function external : program.getFunctionManager().getExternalFunctions()) {
            ExternalLocation location = external.getExternalLocation();
            String name = location != null ? CrossModuleLinker.importedName(location) : external.getName();
            if (name == null || !done.add(name)) {
                continue;
            }
            Module target = null;
            Address address = null;
            // The library Ghidra attributes the import to, when it is one of ours...
            if (location != null && location.getLibraryName() != null
                    && !Library.UNKNOWN.equals(location.getLibraryName())) {
                for (Module candidate : modules) {
                    if (candidate != importer && isLibrary(program, location.getLibraryName(), candidate.program)) {
                        address = CrossModuleLinker.resolveTarget(candidate.program, location);
                        target = address == null ? null : candidate;
                        break;
                    }
                }
            }
            // ...else whichever module exports the name, first loaded first, as a loader would.
            if (target == null) {
                for (Module candidate : modules) {
                    if (candidate == importer) {
                        continue;
                    }
                    address = CrossModuleLinker.exportedAddress(candidate.program, name);
                    if (address != null) {
                        target = candidate;
                        break;
                    }
                }
            }
            if (target == null || !target.program.getMemory().contains(address)) {
                continue;
            }
            Function defined = target.program.getFunctionManager().getFunctionAt(address);
            if (defined != null && defined.isThunk()) {
                Function thunked = defined.getThunkedFunction(true);
                if (thunked == null || thunked.isExternal()) {
                    continue; // the "library" only passes the import on
                }
                address = thunked.getEntryPoint();
            }
            MemoryBlock block = target.program.getMemory().getBlock(address);
            if (block == null || block.isExternalBlock() || !block.isInitialized()) {
                continue;
            }
            out.add(new Link(importer, name, external, null, target, address));
        }
    }

    private void collectDataLinks(Module importer, List<Link> out) {
        Program program = importer.program;
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isExternalBlock() || !block.getStart().getAddressSpace().equals(space)) {
                continue;
            }
            SymbolIterator symbols = program.getSymbolTable().getSymbolIterator(block.getStart(), true);
            int looked = 0;
            while (symbols.hasNext() && looked++ < 65536) {
                Symbol symbol = symbols.next();
                Address slot = symbol.getAddress();
                if (!block.contains(slot)) {
                    break;
                }
                if (!symbol.isPrimary() || program.getFunctionManager().getFunctionAt(slot) != null) {
                    continue;
                }
                for (Module candidate : modules) {
                    if (candidate == importer) {
                        continue;
                    }
                    Address address = exportedData(candidate.program, symbol.getName());
                    if (address != null) {
                        out.add(new Link(importer, symbol.getName(), null, slot, candidate, address));
                        break;
                    }
                }
            }
        }
    }

    /** Where a program defines a variable other programs can import, or null. */
    private static Address exportedData(Program program, String name) {
        Address fallback = null;
        for (Symbol symbol : program.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
            Address address = symbol.getAddress();
            if (symbol.isExternal() || symbol.getSymbolType() == SymbolType.FUNCTION || !address.isMemoryAddress()) {
                continue;
            }
            MemoryBlock block = program.getMemory().getBlock(address);
            if (block == null || block.isExternalBlock()) {
                continue;
            }
            if (symbol.isExternalEntryPoint()) {
                return address;
            }
            // Ghidra does not mark every exported object as an entry point; a global name that
            // came from the file's own symbol table is as good.
            if (fallback == null && symbol.isGlobal() && symbol.getSource() == SourceType.IMPORTED) {
                fallback = address;
            }
        }
        return fallback;
    }

    // ---- finding a program by what the user called it ----

    /**
     * A program of the project by name: one of {@code known} when a name matches, else the
     * project file of that name, opened and held by {@code consumer}.
     *
     * @return the program, or null when there is none of that name
     */
    public static Program find(Program main, String name, Collection<Program> known, PluginTool tool,
            Object consumer, TaskMonitor monitor) throws Exception {
        String wanted = name.strip();
        for (Program program : known) {
            if (!program.isClosed() && (nameOf(program).equals(wanted) || program.getName().equals(wanted))) {
                return program;
            }
        }
        ProjectData data = CrossModuleLinker.projectDataFor(main, tool);
        if (data == null) {
            return null;
        }
        DomainFile file = wanted.startsWith("/") ? data.getFile(wanted) : null;
        if (file == null) {
            DomainFile own = main.getDomainFile();
            DomainFolder preferred = own != null && own.getParent() != null ? own.getParent() : data.getRootFolder();
            file = CrossModuleLinker.findLibraryFile(data, preferred, wanted, monitor);
        }
        return file == null ? null : open(file, consumer, monitor);
    }

    /**
     * The code an import of {@code main} stands for, in whichever program of the project
     * defines it; null when none does.
     *
     * @param consumer holds the library open when it had to be opened
     */
    public static Location followImport(Program main, Function external, Collection<Program> known,
            PluginTool tool, Object consumer, TaskMonitor monitor) throws Exception {
        ExternalLocation location = external.getExternalLocation();
        String name = location != null ? CrossModuleLinker.importedName(location) : external.getName();
        String library = location == null ? null : location.getLibraryName();
        List<Program> candidates = new ArrayList<>();
        if (library != null && !Library.UNKNOWN.equals(library)) {
            for (Program program : known) {
                if (!program.isClosed() && isLibrary(main, library, program)) {
                    candidates.add(program);
                }
            }
            if (candidates.isEmpty()) {
                DomainFile file = libraryFile(main, library, CrossModuleLinker.projectDataFor(main, tool), monitor);
                Program opened = file == null ? null : open(file, consumer, monitor);
                if (opened != null) {
                    candidates.add(opened);
                }
            }
        }
        for (Program program : known) {
            if (!program.isClosed() && !candidates.contains(program) && program != main) {
                candidates.add(program);
            }
        }
        for (Program program : candidates) {
            Address address = location != null ? CrossModuleLinker.resolveTarget(program, location)
                : CrossModuleLinker.exportedAddress(program, name);
            if (address != null && program.getMemory().contains(address)) {
                return new Location(program, address);
            }
        }
        return null;
    }
}
