package decompfuncutils.angr;

import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * A Ghidra program exported for the angr worker: its memory as Ghidra holds it ({@code image.bin})
 * and a manifest saying where each block goes, which addresses are imports, and what architecture
 * to lift it as ({@code image.json}).
 *
 * <p>Exporting what Ghidra has in memory, instead of pointing angr at the original file, is what
 * keeps the two tools talking about the same thing: every address in a result is the address
 * Ghidra shows, relocations and patches applied in Ghidra are in effect, and formats only Ghidra
 * can load (firmware, raw blobs, memory dumps) work without teaching angr about them.
 *
 * <p>An export is keyed on the program's modification number, so it is reused until the program
 * changes and replaced when it does.
 *
 * <p>An image can hold several programs ({@link AngrModules}): the one being debugged and
 * libraries of the project next to it, in one address space. A library that would overlap is
 * moved, and the pointers stored in it - found through Ghidra's relocation table - are moved
 * with it. Imports that another module defines are marked as such, so a call runs the real code,
 * and pointers to imported variables are pointed at the real storage.
 */
public final class AngrImage {

    /** Refuse to copy more than this much initialized memory; nobody emulates a 1 GiB image by accident. */
    private static final long MAX_IMAGE_BYTES = 1L << 30;

    /**
     * What image.bin starts with. A program loaded at its image base begins with its own file
     * header, so the raw memory would start with "\\x7fELF" or "MZ" - and CLE, even when told
     * the file is a blob, sniffs the format to work out the object's name and parses it as that
     * executable. A memory image is not laid out like the file, so that parse fails deep inside
     * the ELF reader (an AssertionError on any binary with a dynamic section the layout
     * disturbs). With this in front the file is recognisably nothing but ours.
     */
    static final byte[] IMAGE_HEADER = "DFU-ANGR-IMAGE\0\0".getBytes(StandardCharsets.US_ASCII);

    private static final Gson GSON = new Gson();
    private static final Map<Long, AngrImage> CACHE = new ConcurrentHashMap<>();
    /** Images of several programs together, most recently used last. */
    private static final LinkedHashMap<String, AngrImage> COMPOSITES = new LinkedHashMap<>(8, 0.75f, true);
    private static final int MAX_COMPOSITES = 4;
    private static volatile Path root;

    /** Directory holding image.bin and image.json. */
    public final Path directory;
    /** Identifies this exact export to the worker's project cache. */
    public final String key;
    /** Names of the imports that have at least one hookable address. */
    public final Set<String> externalNames;
    /** Imports that run another module's code, by name, with the module they run in. */
    public final Map<String, String> linkedImports;
    /** Things about the export the user should know (a module moved without relocations, say). */
    public final List<String> notes;

    private final long modificationNumber;

    private AngrImage(Path directory, String key, long modificationNumber, Set<String> externalNames,
            Map<String, String> linkedImports, List<String> notes) {
        this.directory = directory;
        this.key = key;
        this.modificationNumber = modificationNumber;
        this.externalNames = externalNames;
        this.linkedImports = linkedImports;
        this.notes = notes;
    }

    /** The export for the program as it is now, creating or refreshing it as needed. */
    public static AngrImage of(Program program, TaskMonitor monitor) throws Exception {
        long id = program.getUniqueProgramID();
        long modification = program.getModificationNumber();
        synchronized (lockFor(id)) {
            AngrImage cached = CACHE.get(id);
            if (cached != null && cached.modificationNumber == modification
                    && Files.isRegularFile(cached.directory.resolve("image.json"))) {
                return cached;
            }
            if (cached != null) {
                deleteTree(cached.directory);
            }
            String key = Long.toHexString(id) + "-" + modification;
            Path dir = root().resolve(safeName(program.getName()) + "-" + key);
            AngrImage fresh = export(AngrModules.single(program), dir, key, modification, monitor);
            CACHE.put(id, fresh);
            return fresh;
        }
    }

    /** The export of several programs in one address space; of the first alone when it is alone. */
    public static AngrImage of(AngrModules modules, TaskMonitor monitor) throws Exception {
        if (modules.size() == 1) {
            return of(modules.main(), monitor);
        }
        String key = modules.key();
        synchronized (COMPOSITES) {
            AngrImage cached = COMPOSITES.get(key);
            if (cached != null && Files.isRegularFile(cached.directory.resolve("image.json"))) {
                return cached;
            }
            Path dir = root().resolve(safeName(modules.main().getName()) + "-with-"
                + (modules.size() - 1) + "-" + Integer.toHexString(key.hashCode()));
            deleteTree(dir);
            AngrImage fresh = export(modules, dir, key, 0, monitor);
            COMPOSITES.put(key, fresh);
            Iterator<Map.Entry<String, AngrImage>> oldest = COMPOSITES.entrySet().iterator();
            while (COMPOSITES.size() > MAX_COMPOSITES && oldest.hasNext()) {
                AngrImage old = oldest.next().getValue();
                if (old != fresh) {
                    oldest.remove();
                    deleteTree(old.directory);
                }
            }
            return fresh;
        }
    }

    private static final Map<Long, Object> LOCKS = new ConcurrentHashMap<>();

    private static Object lockFor(long id) {
        return LOCKS.computeIfAbsent(id, k -> new Object());
    }

    // ---- export ----

    @SuppressWarnings("unchecked")
    private static AngrImage export(AngrModules modules, Path dir, String key, long modification,
            TaskMonitor monitor) throws Exception {
        Files.createDirectories(dir);
        Program program = modules.main();

        // What another module defines: variables by the stand-in address the importer uses for
        // them, functions by name.
        Map<AngrModules.Module, Map<Long, Long>> variables = new IdentityHashMap<>();
        Map<String, AngrModules.Link> functions = new LinkedHashMap<>();
        for (AngrModules.Link link : modules.links()) {
            if (link.external != null) {
                functions.putIfAbsent(link.name, link);
            }
            else {
                variables.computeIfAbsent(link.importer, m -> new HashMap<>())
                    .put(link.slot.getOffset(), link.angrAddress());
            }
        }

        List<Map<String, Object>> segments = new ArrayList<>();
        List<Map<String, Object>> zero = new ArrayList<>();
        List<Map<String, Object>> loaded = new ArrayList<>();
        Map<String, Map<String, Object>> externals = new LinkedHashMap<>();
        List<Map<String, Object>> externalData = new ArrayList<>();
        List<Map<String, Object>> stdio = new ArrayList<>();
        List<String> notes = new ArrayList<>(modules.notes());
        long offset = IMAGE_HEADER.length;

        monitor.setMessage("Exporting memory image for angr");
        try (OutputStream out = Files.newOutputStream(dir.resolve("image.bin"))) {
            out.write(IMAGE_HEADER);
            byte[] buffer = new byte[1 << 16];
            for (AngrModules.Module module : modules.modules()) {
                Program source = module.program;
                AddressSpace space = source.getAddressFactory().getDefaultAddressSpace();
                boolean first = source == program;
                long delta = module.delta();
                Map<Long, Long> imported = variables.getOrDefault(module, Map.of());
                Patches patches = Patches.of(module, imported, monitor);
                int blocks = 0;

                for (MemoryBlock block : source.getMemory().getBlocks()) {
                    monitor.checkCancelled();
                    // Overlays and other spaces are not part of the flat address space the code runs in.
                    if (!AngrModules.exported(block, space)) {
                        continue;
                    }
                    // The EXTERNAL block is Ghidra's stand-in for imports. Functions in it are hooked;
                    // imported variables in it are plain storage, so it goes out as zero memory and a
                    // read of 'stdout' or a missing library's global does not fault.
                    boolean external = block.isExternalBlock();
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("name", first ? block.getName() : module.name + ":" + block.getName());
                    entry.put("addr", hex(block.getStart().getOffset() + delta));
                    entry.put("size", block.getSize());
                    entry.put("perm", (block.isRead() ? "r" : "") + (block.isWrite() ? "w" : "")
                        + (block.isExecute() ? "x" : ""));

                    if (!block.isInitialized() || external) {
                        zero.add(entry);
                        continue;
                    }
                    if (offset + block.getSize() > MAX_IMAGE_BYTES) {
                        throw new IllegalStateException("There is more than " + (MAX_IMAGE_BYTES >> 20)
                            + " MiB of initialized memory to load, which is more than this tool will copy "
                            + "out for angr.");
                    }
                    entry.put("offset", offset);
                    long written = 0;
                    try (InputStream in = block.getData()) {
                        int n;
                        while ((n = in.read(buffer)) > 0) {
                            if (patches != null) {
                                patches.apply(buffer, n, block.getStart().getOffset() + written);
                            }
                            out.write(buffer, 0, n);
                            written += n;
                        }
                    }
                    if (written != block.getSize()) {
                        // A mapped block whose source is not fully backed: keep what could be read.
                        entry.put("size", written);
                    }
                    if (written > 0) {
                        segments.add(entry);
                        offset += written;
                        blocks++;
                    }
                }

                for (Map<String, Object> ext : externalsOf(source, space, delta)) {
                    Map<String, Object> known = externals.get(ext.get("name"));
                    if (known == null) {
                        externals.put((String) ext.get("name"), ext);
                        continue;
                    }
                    // The same import in two modules is one import: a stub or a hook covers both.
                    merge(known, "addrs", new LinkedHashSet<>((List<String>) ext.get("addrs")));
                    merge(known, "slots", new LinkedHashSet<>((List<String>) ext.get("slots")));
                    if (((Number) known.get("params")).intValue() < 0) {
                        known.put("params", ext.get("params"));
                    }
                }
                for (Map<String, Object> item : externalDataOf(source, space, delta)) {
                    // Pointed at the defining module's storage instead; see Patches.
                    if (!imported.containsKey(Long.decode((String) item.get("addr")) - delta)) {
                        externalData.add(item);
                    }
                }
                stdio.addAll(stdioOf(source, space, delta));

                Map<String, Object> described = new LinkedHashMap<>();
                described.put("name", module.name);
                described.put("delta", hex(delta));
                described.put("addr", hex(module.min + delta));
                described.put("end", hex(module.max + delta));
                described.put("blocks", blocks);
                described.put("pointersMoved", patches == null ? 0 : patches.moved);
                described.put("pointersLinked", patches == null ? 0 : patches.linked);
                loaded.add(described);
            }
        }

        Map<String, String> linkedImports = new LinkedHashMap<>();
        for (AngrModules.Link link : functions.values()) {
            Map<String, Object> ext = externals.get(link.name);
            if (ext == null) {
                continue; // nothing reaches the import, so there is nothing to redirect
            }
            ext.put("target", hex(link.angrAddress()));
            ext.put("module", link.target.name);
            linkedImports.put(link.name, link.target.name);
        }

        Language language = program.getLanguage();
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("version", 1);
        manifest.put("program", program.getName());
        manifest.put("language", language.getLanguageID().getIdAsString());
        manifest.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        manifest.put("format", program.getExecutableFormat());
        manifest.put("arch", archOf(language));
        manifest.put("pointerSize", program.getDefaultPointerSize());
        manifest.put("image", "image.bin");
        manifest.put("segments", segments);
        manifest.put("zero", zero);
        manifest.put("modules", loaded);
        manifest.put("externals", new ArrayList<>(externals.values()));
        manifest.put("externalData", externalData);
        manifest.put("stdio", stdio);

        Files.writeString(dir.resolve("image.json"), GSON.toJson(manifest), StandardCharsets.UTF_8);

        Msg.info(AngrImage.class, "Exported " + program.getName()
            + (modules.size() > 1 ? " with " + String.join(", ", modules.libraryNames()) : "")
            + " for angr: " + segments.size() + " initialized block(s), " + (offset >> 10) + " KiB, "
            + externals.size() + " import(s), " + linkedImports.size() + " linked -> " + dir);
        return new AngrImage(dir, key, modification, new HashSet<>(externals.keySet()),
            Collections.unmodifiableMap(linkedImports), Collections.unmodifiableList(notes));
    }

    /**
     * The pointers of one module that have to hold something other than what Ghidra's memory
     * holds: those into the module itself when it was moved, and those to an imported variable
     * that another module defines. Ghidra's relocation table says where the pointers are.
     */
    private static final class Patches {
        final long[] at;
        final long[] value;
        final int width;
        final boolean bigEndian;
        final int moved;
        final int linked;

        private Patches(TreeMap<Long, Long> found, int width, boolean bigEndian, int moved, int linked) {
            this.at = new long[found.size()];
            this.value = new long[found.size()];
            int i = 0;
            for (Map.Entry<Long, Long> e : found.entrySet()) {
                at[i] = e.getKey();
                value[i++] = e.getValue();
            }
            this.width = width;
            this.bigEndian = bigEndian;
            this.moved = moved;
            this.linked = linked;
        }

        static Patches of(AngrModules.Module module, Map<Long, Long> imported, TaskMonitor monitor)
                throws Exception {
            long delta = module.delta();
            if (delta == 0 && imported.isEmpty()) {
                return null;
            }
            Program program = module.program;
            int width = program.getDefaultPointerSize();
            if (width != 2 && width != 4 && width != 8) {
                return null;
            }
            boolean bigEndian = program.getLanguage().isBigEndian();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Memory memory = program.getMemory();
            TreeMap<Long, Long> found = new TreeMap<>();
            byte[] word = new byte[width];
            int moved = 0;
            int linked = 0;
            Iterator<Relocation> relocations = program.getRelocationTable().getRelocations();
            while (relocations.hasNext()) {
                monitor.checkCancelled();
                Address address = relocations.next().getAddress();
                if (address == null || !address.getAddressSpace().equals(space)) {
                    continue;
                }
                try {
                    if (memory.getBytes(address, word) != width) {
                        continue;
                    }
                }
                catch (Exception e) {
                    continue; // nothing stored there
                }
                long stored = 0;
                for (int i = 0; i < width; i++) {
                    stored = (stored << 8) | (word[bigEndian ? i : width - 1 - i] & 0xffL);
                }
                Long target = imported.get(stored);
                if (target != null) {
                    found.put(address.getOffset(), target);
                    linked++;
                }
                else if (delta != 0 && stored != 0 && module.covers(stored)) {
                    // A pointer into the module itself: it moves with the module.
                    found.put(address.getOffset(), stored + delta);
                    moved++;
                }
            }
            return new Patches(found, width, bigEndian, moved, linked);
        }

        /** Rewrites the pointers that fall in {@code buffer}, which holds memory from {@code start}. */
        void apply(byte[] buffer, int length, long start) {
            int i = Arrays.binarySearch(at, start - width + 1);
            if (i < 0) {
                i = -i - 1;
            }
            for (; i < at.length && at[i] < start + length; i++) {
                for (int k = 0; k < width; k++) {
                    long index = at[i] + k - start;
                    if (index < 0 || index >= length) {
                        continue;
                    }
                    int shift = 8 * (bigEndian ? width - 1 - k : k);
                    buffer[(int) index] = (byte) (value[i] >>> shift);
                }
            }
        }
    }

    /** What angr should lift the program as. The worker falls back to archinfo's own lookup by name. */
    static Map<String, Object> archOf(Language language) {
        LanguageDescription description = language.getLanguageDescription();
        String processor = language.getProcessor().toString();
        int size = description.getSize();
        String variant = String.valueOf(description.getVariant());

        String name;
        switch (processor.toLowerCase(Locale.ROOT)) {
            case "x86":
                name = size == 64 ? "AMD64" : size == 32 ? "X86" : "x86_" + size;
                break;
            case "arm":
                name = variant.toLowerCase(Locale.ROOT).contains("cortex") ? "ARMCortexM" : "ARMEL";
                break;
            case "aarch64":
                name = "AARCH64";
                break;
            case "mips":
                name = size == 64 ? "MIPS64" : "MIPS32";
                break;
            case "powerpc":
                name = size == 64 ? "PPC64" : "PPC32";
                break;
            case "riscv":
                name = size == 64 ? "riscv64" : "riscv32";
                break;
            default:
                name = processor.toLowerCase(Locale.ROOT);
        }
        Map<String, Object> arch = new LinkedHashMap<>();
        arch.put("name", name);
        arch.put("bits", size);
        arch.put("endian", language.isBigEndian() ? "big" : "little");
        arch.put("processor", processor);
        arch.put("language", language.getLanguageID().getIdAsString());
        return arch;
    }

    /**
     * Every imported function with the addresses that reach it. A call gets to an import through
     * a thunk (a PLT stub, or the slot Ghidra gives it in the EXTERNAL block, which is also where
     * relocated GOT entries point), so hooking the thunk entry points covers direct and indirect
     * calls alike. Where the loader leaves a pointer slot unresolved instead - a PE import table -
     * the slot is listed so the worker can point it at a hook of its own.
     */
    private static List<Map<String, Object>> externalsOf(Program program, AddressSpace space, long delta) {
        Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
        ReferenceManager references = program.getReferenceManager();
        Listing listing = program.getListing();

        for (Function ext : program.getFunctionManager().getExternalFunctions()) {
            ExternalLocation location = ext.getExternalLocation();
            String name = ext.getName();
            if (location != null && location.getOriginalImportedName() != null) {
                name = location.getOriginalImportedName();
            }

            Set<String> addrs = new LinkedHashSet<>();
            Address[] thunks = ext.getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address thunk : thunks) {
                    if (thunk.getAddressSpace().equals(space)) {
                        addrs.add(hex(thunk.getOffset() + delta));
                    }
                }
            }
            Set<String> slots = new LinkedHashSet<>();
            for (Reference ref : references.getReferencesTo(ext.getEntryPoint())) {
                Address from = ref.getFromAddress();
                if (from != null && from.getAddressSpace().equals(space)
                        && listing.getInstructionContaining(from) == null
                        && program.getMemory().contains(from)) {
                    slots.add(hex(from.getOffset() + delta));
                }
            }
            if (addrs.isEmpty() && slots.isEmpty()) {
                continue;
            }

            Map<String, Object> entry = byName.get(name);
            if (entry == null) {
                entry = new LinkedHashMap<>();
                entry.put("name", name);
                if (location != null && location.getLibraryName() != null) {
                    entry.put("library", location.getLibraryName());
                }
                entry.put("addrs", new ArrayList<String>());
                entry.put("slots", new ArrayList<String>());
                // -1: Ghidra has no signature, so the argument count is unknown.
                entry.put("params", ext.getSignatureSource() == SourceType.DEFAULT ? -1 : ext.getParameterCount());
                entry.put("noreturn", ext.hasNoReturn());
                byName.put(name, entry);
            }
            merge(entry, "addrs", addrs);
            merge(entry, "slots", slots);
        }
        return new ArrayList<>(byName.values());
    }

    /**
     * The program's stdin, stdout and stderr variables, wherever the linker put them: in the
     * EXTERNAL block when reached through the GOT, or copied into the program's own .bss. The
     * worker points each at a FILE object, so stdio calls on them work.
     */
    private static List<Map<String, Object>> stdioOf(Program program, AddressSpace space, long delta) {
        List<Map<String, Object>> out = new ArrayList<>();
        String[] names = { "stdin", "stdout", "stderr" };
        for (int fd = 0; fd < names.length; fd++) {
            for (ghidra.program.model.symbol.Symbol symbol : program.getSymbolTable().getSymbols(names[fd])) {
                Address address = symbol.getAddress();
                if (symbol.isExternal() || !address.getAddressSpace().equals(space)
                        || !program.getMemory().contains(address)
                        || program.getFunctionManager().getFunctionAt(address) != null) {
                    continue;
                }
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", names[fd]);
                entry.put("addr", hex(address.getOffset() + delta));
                entry.put("fd", fd);
                out.add(entry);
            }
        }
        return out;
    }

    /**
     * Imported variables: labels in the EXTERNAL block that are not functions. With unknown
     * imports symbolic, the worker makes these unknown as well.
     */
    private static List<Map<String, Object>> externalDataOf(Program program, AddressSpace space, long delta) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isExternalBlock() || !block.getStart().getAddressSpace().equals(space)) {
                continue;
            }
            ghidra.program.model.symbol.SymbolIterator symbols = program.getSymbolTable()
                .getSymbolIterator(block.getStart(), true);
            while (symbols.hasNext() && out.size() < 4096) {
                ghidra.program.model.symbol.Symbol symbol = symbols.next();
                Address address = symbol.getAddress();
                if (!block.contains(address)) {
                    break;
                }
                if (!symbol.isPrimary() || program.getFunctionManager().getFunctionAt(address) != null) {
                    continue;
                }
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", symbol.getName());
                entry.put("addr", hex(address.getOffset() + delta));
                out.add(entry);
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void merge(Map<String, Object> entry, String field, Set<String> values) {
        List<String> list = (List<String>) entry.get(field);
        for (String value : values) {
            if (!list.contains(value)) {
                list.add(value);
            }
        }
    }

    // ---- files ----

    /** Where exports and the extracted worker script live; removed when the JVM exits. */
    static Path root() throws IOException {
        Path r = root;
        if (r != null) {
            return r;
        }
        synchronized (AngrImage.class) {
            if (root == null) {
                String override = System.getProperty("dfu.angr.tmp", System.getenv("DFU_ANGR_TMP"));
                Path base = override != null && !override.isBlank()
                    ? Path.of(override) : Path.of(System.getProperty("java.io.tmpdir"));
                Files.createDirectories(base);
                Path created = Files.createTempDirectory(base, "dfu-angr-");
                Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteTree(created), "dfu-angr-cleanup"));
                root = created;
            }
            return root;
        }
    }

    static void deleteTree(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                }
                catch (IOException ignored) {
                    // best effort: a file the worker still holds open goes with the temp dir
                }
            });
        }
        catch (IOException ignored) {
            // best effort
        }
    }

    private static String safeName(String name) {
        String cleaned = name.replaceAll("[^A-Za-z0-9._-]", "_");
        return cleaned.length() > 40 ? cleaned.substring(0, 40) : cleaned;
    }

    public static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
