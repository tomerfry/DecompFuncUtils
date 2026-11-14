package decompfuncutils.angr;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The Python replacements a user (or an agent, through {@code ghidra_angr_hook}) has written for
 * functions of a program.
 *
 * <p>Each hook is one ordinary {@code .py} file under
 * {@code ~/.decompfuncutils/angr-hooks/<program>/}, so it can be written in any editor, kept in
 * version control and copied between machines. The first line carries what the hook is attached
 * to:
 *
 * <pre>
 * # dfu-hook: target=mystery_device_read kind=replace enabled=true
 * def hook(ctx, reg):
 *     return 0x1234 if reg == 3 else 0
 * </pre>
 *
 * <p>{@code target} is an import name, a function name or an address. {@code kind=replace} runs
 * the hook instead of the function and returns to the caller with its result;
 * {@code kind=inline} runs it when execution reaches the address and then carries on (skipping
 * {@code skip} bytes of the original code). Enabled hooks apply to every angr run of the program:
 * the emulator and the debugger alike.
 */
public final class AngrHooks {

    public static final String KIND_REPLACE = "replace";
    public static final String KIND_INLINE = "inline";

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private static final Pattern HEADER =
        Pattern.compile("^#\\s*dfu-hook:\\s*(.*)$");
    private static final Pattern FIELD = Pattern.compile("(\\w+)=(\\S+)");

    private AngrHooks() {
    }

    /** One saved hook. */
    public static final class Hook {
        public String name;
        public String target;
        public String kind = KIND_REPLACE;
        public int skip = 0;
        public boolean enabled = true;
        /** The Python source, without the header line. */
        public String code = "";

        public Map<String, Object> describe(boolean withCode) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            out.put("target", target);
            out.put("kind", kind);
            if (KIND_INLINE.equals(kind)) {
                out.put("skip", skip);
            }
            out.put("enabled", enabled);
            if (withCode) {
                out.put("code", code);
            }
            return out;
        }
    }

    // ---- where they live ----

    /** The folder holding every program's hooks. */
    public static Path root() {
        String override = System.getProperty("dfu.angr.hooks", System.getenv("DFU_ANGR_HOOKS"));
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return Path.of(System.getProperty("user.home"), ".decompfuncutils", "angr-hooks");
    }

    /** The folder holding one program's hooks. */
    public static Path directory(Program program) {
        return root().resolve(program.getName().replaceAll("[^A-Za-z0-9._-]", "_"));
    }

    // ---- reading and writing ----

    public static List<Hook> list(Program program) {
        List<Hook> hooks = new ArrayList<>();
        Path dir = directory(program);
        if (!Files.isDirectory(dir)) {
            return hooks;
        }
        try (Stream<Path> files = Files.list(dir)) {
            for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".py")).sorted().toList()) {
                Hook hook = read(file);
                if (hook != null) {
                    hooks.add(hook);
                }
            }
        }
        catch (IOException e) {
            // an unreadable folder is the same as no hooks
        }
        return hooks;
    }

    public static Hook get(Program program, String name) {
        Path file = directory(program).resolve(checkName(name) + ".py");
        return Files.isRegularFile(file) ? read(file) : null;
    }

    private static Hook read(Path file) {
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
            if (text.startsWith("﻿")) {
                text = text.substring(1);
            }
            Hook hook = new Hook();
            String fileName = file.getFileName().toString();
            hook.name = fileName.substring(0, fileName.length() - 3);
            int newline = text.indexOf('\n');
            String first = newline < 0 ? text : text.substring(0, newline);
            Matcher header = HEADER.matcher(first.strip());
            if (header.matches()) {
                Matcher field = FIELD.matcher(header.group(1));
                while (field.find()) {
                    String value = field.group(2);
                    switch (field.group(1)) {
                        case "target" -> hook.target = value;
                        case "kind" -> hook.kind = KIND_INLINE.equals(value) ? KIND_INLINE : KIND_REPLACE;
                        case "skip" -> hook.skip = parseInt(value);
                        case "enabled" -> hook.enabled = !"false".equalsIgnoreCase(value);
                        default -> { }
                    }
                }
                hook.code = newline < 0 ? "" : text.substring(newline + 1);
            }
            else {
                // A file written by hand without the header: attached to what it is named after.
                hook.code = text;
            }
            if (hook.target == null || hook.target.isBlank()) {
                hook.target = hook.name;
            }
            return hook;
        }
        catch (IOException e) {
            return null;
        }
    }

    public static void save(Program program, Hook hook) throws IOException {
        checkName(hook.name);
        if (hook.target == null || hook.target.isBlank()) {
            hook.target = hook.name;
        }
        if (hook.target.matches(".*\\s.*")) {
            throw new IllegalArgumentException("A hook target is one import name, function name or address");
        }
        if (!KIND_REPLACE.equals(hook.kind) && !KIND_INLINE.equals(hook.kind)) {
            throw new IllegalArgumentException("kind must be '" + KIND_REPLACE + "' or '" + KIND_INLINE + "'");
        }
        if (hook.code == null || !hook.code.contains("def hook")) {
            throw new IllegalArgumentException("The code must define the entry point: def hook(ctx, ...):");
        }
        Path dir = directory(program);
        Files.createDirectories(dir);
        StringBuilder text = new StringBuilder("# dfu-hook: target=").append(hook.target)
            .append(" kind=").append(hook.kind);
        if (KIND_INLINE.equals(hook.kind)) {
            text.append(" skip=").append(hook.skip);
        }
        text.append(" enabled=").append(hook.enabled).append('\n');
        text.append(hook.code.replace("\r\n", "\n"));
        if (!hook.code.endsWith("\n")) {
            text.append('\n');
        }
        Files.writeString(dir.resolve(hook.name + ".py"), text.toString(), StandardCharsets.UTF_8);
    }

    public static boolean delete(Program program, String name) throws IOException {
        return Files.deleteIfExists(directory(program).resolve(checkName(name) + ".py"));
    }

    private static String checkName(String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("A hook name is 1-64 letters, digits, '_', '-' or '.' "
                + "(it becomes a file name): " + name);
        }
        return name;
    }

    private static int parseInt(String text) {
        try {
            return Integer.decode(text);
        }
        catch (NumberFormatException e) {
            return 0;
        }
    }

    // ---- into a worker request ----

    /**
     * The program's enabled hooks in the form the worker installs. A hook whose target no longer
     * resolves is left out with a warning rather than failing the run.
     */
    public static List<Map<String, Object>> toSpec(Program program, AngrImage image, List<String> warnings) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Hook hook : list(program)) {
            if (!hook.enabled) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", hook.name);
            entry.put("kind", hook.kind);
            entry.put("skip", hook.skip);
            entry.put("code", hook.code);
            try {
                String external = externalName(program, image, hook.target);
                if (external != null && KIND_REPLACE.equals(hook.kind)) {
                    entry.put("external", external);
                }
                else {
                    Address address = AngrCallSpec.resolveCode(program, hook.target, "hook " + hook.name);
                    entry.put("addrs", List.of(AngrImage.hex(address.getOffset())));
                }
            }
            catch (IllegalArgumentException e) {
                warnings.add("Python hook '" + hook.name + "' was not applied: " + e.getMessage());
                continue;
            }
            out.add(entry);
        }
        return out;
    }

    /** The import a target names, directly or through its thunk; null when it is not an import. */
    public static String externalName(Program program, AngrImage image, String target) {
        if (image.externalNames.contains(target)) {
            return target;
        }
        try {
            Address address = AngrCallSpec.resolveCode(program, target, "hook");
            Function f = program.getFunctionManager().getFunctionAt(address);
            if (f != null && f.isThunk()) {
                Function thunked = f.getThunkedFunction(true);
                if (thunked != null && thunked.isExternal() && image.externalNames.contains(thunked.getName())) {
                    return thunked.getName();
                }
            }
        }
        catch (IllegalArgumentException e) {
            // not resolvable as code either; the caller reports it
        }
        return null;
    }

    // ---- a starting point ----

    /** A hook body to start from, with the target's parameters named when Ghidra knows them. */
    public static String template(Program program, String target) {
        List<String> names = new ArrayList<>();
        String signature = null;
        Function function = null;
        for (Function f : program.getFunctionManager().getExternalFunctions()) {
            if (f.getName().equals(target)) {
                function = f;
                break;
            }
        }
        if (function == null) {
            try {
                function = program.getFunctionManager()
                    .getFunctionAt(AngrCallSpec.resolveCode(program, target, "hook"));
            }
            catch (IllegalArgumentException e) {
                function = null;
            }
        }
        if (function != null && function.getSignatureSource() != SourceType.DEFAULT) {
            signature = function.getPrototypeString(false, false);
            for (Parameter p : function.getParameters()) {
                String name = p.getName().replaceAll("[^A-Za-z0-9_]", "_");
                names.add(name.isEmpty() || Character.isDigit(name.charAt(0)) ? "a" + names.size() : name);
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# Runs instead of ").append(target).append(" and returns to the caller.\n");
        if (signature != null) {
            sb.append("# Ghidra: ").append(signature).append('\n');
        }
        else {
            sb.append("# Ghidra has no signature for it: add a parameter after ctx for each argument you need.\n");
        }
        sb.append("#\n")
          .append("# ctx.arg(i)  ctx.string(ptr)  ctx.read(ptr, n)  ctx.read_int(ptr, size)\n")
          .append("# ctx.write(ptr, bytes_or_str)  ctx.write_int(ptr, value, size)  ctx.alloc(n)\n")
          .append("# ctx.reg(name)  ctx.set_reg(name, value)  ctx.log(...)\n")
          .append("# ctx.symbolic(name)  -> an unknown value, to return or store\n")
          .append("# ctx.state is the angr SimState; angr and claripy are imported.\n")
          .append("def hook(ctx").append(names.isEmpty() ? "" : ", " + String.join(", ", names)).append("):\n")
          .append("    ctx.log(\"").append(target).append("\"")
          .append(names.isEmpty() ? "" : ", " + String.join(", ", names)).append(")\n")
          .append("    return 0\n");
        return sb.toString();
    }
}
