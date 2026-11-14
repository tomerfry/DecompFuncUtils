package decompfuncutils.angr;

import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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
 */
public final class AngrImage {

    /** Refuse to copy more than this much initialized memory; nobody emulates a 1 GiB image by accident. */
    private static final long MAX_IMAGE_BYTES = 1L << 30;

    private static final Gson GSON = new Gson();
    private static final Map<Long, AngrImage> CACHE = new ConcurrentHashMap<>();
    private static volatile Path root;

    /** Directory holding image.bin and image.json. */
    public final Path directory;
    /** Identifies this exact export to the worker's project cache. */
    public final String key;
    /** Names of the imports that have at least one hookable address. */
    public final Set<String> externalNames;

    private final long modificationNumber;

    private AngrImage(Path directory, String key, long modificationNumber, Set<String> externalNames) {
        this.directory = directory;
        this.key = key;
        this.modificationNumber = modificationNumber;
        this.externalNames = externalNames;
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
            AngrImage fresh = export(program, id, modification, monitor);
            CACHE.put(id, fresh);
            return fresh;
        }
    }

    private static final Map<Long, Object> LOCKS = new ConcurrentHashMap<>();

    private static Object lockFor(long id) {
        return LOCKS.computeIfAbsent(id, k -> new Object());
    }

    // ---- export ----

    private static AngrImage export(Program program, long id, long modification, TaskMonitor monitor)
            throws Exception {
        String key = Long.toHexString(id) + "-" + modification;
        Path dir = root().resolve(safeName(program.getName()) + "-" + key);
        Files.createDirectories(dir);

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        List<Map<String, Object>> segments = new ArrayList<>();
        List<Map<String, Object>> zero = new ArrayList<>();
        long offset = 0;

        monitor.setMessage("Exporting memory image for angr");
        try (OutputStream out = Files.newOutputStream(dir.resolve("image.bin"))) {
            byte[] buffer = new byte[1 << 16];
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                monitor.checkCancelled();
                // Overlays and other spaces are not part of the flat address space the code runs in.
                if (block.isOverlay() || !block.getStart().getAddressSpace().equals(space)) {
                    continue;
                }
                // The EXTERNAL block is Ghidra's stand-in for imports. Functions in it are hooked;
                // imported variables in it are plain storage, so it goes out as zero memory and a
                // read of 'stdout' or a missing library's global does not fault.
                boolean external = block.isExternalBlock();
                if (!block.isLoaded() && !external) {
                    continue;
                }
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", block.getName());
                entry.put("addr", hex(block.getStart().getOffset()));
                entry.put("size", block.getSize());
                entry.put("perm", (block.isRead() ? "r" : "") + (block.isWrite() ? "w" : "")
                    + (block.isExecute() ? "x" : ""));

                if (!block.isInitialized() || external) {
                    zero.add(entry);
                    continue;
                }
                if (offset + block.getSize() > MAX_IMAGE_BYTES) {
                    throw new IllegalStateException("The program has more than "
                        + (MAX_IMAGE_BYTES >> 20) + " MiB of initialized memory, which is more than "
                        + "this tool will copy out for angr.");
                }
                entry.put("offset", offset);
                long written = 0;
                try (InputStream in = block.getData()) {
                    int n;
                    while ((n = in.read(buffer)) > 0) {
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
                }
            }
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
        List<Map<String, Object>> externals = externalsOf(program, space);
        manifest.put("externals", externals);
        manifest.put("externalData", externalDataOf(program, space));

        Files.writeString(dir.resolve("image.json"), GSON.toJson(manifest), StandardCharsets.UTF_8);

        Set<String> names = new HashSet<>();
        for (Map<String, Object> ext : externals) {
            names.add((String) ext.get("name"));
        }
        Msg.info(AngrImage.class, "Exported " + program.getName() + " for angr: " + segments.size()
            + " initialized block(s), " + (offset >> 10) + " KiB, " + externals.size() + " import(s) -> " + dir);
        return new AngrImage(dir, key, modification, names);
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
    private static List<Map<String, Object>> externalsOf(Program program, AddressSpace space) {
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
                        addrs.add(hex(thunk.getOffset()));
                    }
                }
            }
            Set<String> slots = new LinkedHashSet<>();
            for (Reference ref : references.getReferencesTo(ext.getEntryPoint())) {
                Address from = ref.getFromAddress();
                if (from != null && from.getAddressSpace().equals(space)
                        && listing.getInstructionContaining(from) == null
                        && program.getMemory().contains(from)) {
                    slots.add(hex(from.getOffset()));
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
     * Imported variables: labels in the EXTERNAL block that are not functions. With unknown
     * imports symbolic, the worker makes these unknown as well.
     */
    private static List<Map<String, Object>> externalDataOf(Program program, AddressSpace space) {
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
                entry.put("addr", hex(address.getOffset()));
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
