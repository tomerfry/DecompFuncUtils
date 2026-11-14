package decompfuncutils.angr;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * What happens when the program calls each of its imports under angr - the answer to "can I
 * analyze this binary without its shared objects?".
 *
 * <p>A library that is missing from the project is not an obstacle: no import is ever followed
 * into a library. Each one is handled in place, by the first of these that applies: a Python hook
 * the user wrote, angr's own model of the function, or a stub that returns an unknown value (the
 * debugger's default) or zero (the emulator's default).
 */
public final class AngrImports {

    public static final String HANDLED_BY_HOOK = "python hook";
    public static final String HANDLED_BY_MODEL = "angr model";
    public static final String HANDLED_BY_STUB = "stub";

    private AngrImports() {
    }

    /**
     * One row per import: name, library, whether that library is in the project, and how a call
     * to it is handled.
     *
     * @param python an interpreter set in Tool Options, or null to discover one
     */
    public static List<Map<String, Object>> describe(Program program, String python, TaskMonitor monitor)
            throws Exception {
        AngrImage image = AngrImage.of(program, monitor);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("op", "imports");
        request.put("imageDir", image.directory.toString());
        request.put("imageKey", image.key);
        JsonObject response;
        try {
            response = AngrWorkers.resultOf(
                AngrWorkers.call(program.getUniqueProgramID(), python, request, 60_000, monitor));
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
        Map<String, String> models = new HashMap<>();
        JsonArray rows = response.getAsJsonArray("imports");
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject();
            if (row.has("model") && !row.get("model").isJsonNull()) {
                models.put(row.get("name").getAsString(), row.get("model").getAsString());
            }
        }

        Map<String, AngrHooks.Hook> hooks = new HashMap<>();
        for (AngrHooks.Hook hook : AngrHooks.list(program)) {
            if (!hook.enabled || !AngrHooks.KIND_REPLACE.equals(hook.kind)) {
                continue;
            }
            String external = AngrHooks.externalName(program, image, hook.target);
            if (external != null) {
                hooks.put(external, hook);
            }
        }

        Map<String, Map<String, Object>> byName = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Function ext : program.getFunctionManager().getExternalFunctions()) {
            ExternalLocation location = ext.getExternalLocation();
            String name = location != null && location.getOriginalImportedName() != null
                ? location.getOriginalImportedName() : ext.getName();
            if (!image.externalNames.contains(name) || byName.containsKey(name)) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", name);
            String libraryName = location == null ? null : location.getLibraryName();
            boolean known = libraryName != null && !Library.UNKNOWN.equals(libraryName);
            entry.put("library", known ? libraryName : null);
            String path = known ? program.getExternalManager().getExternalLibraryPath(libraryName) : null;
            entry.put("libraryInProject", path != null);

            AngrHooks.Hook hook = hooks.get(name);
            if (hook != null) {
                entry.put("handledBy", HANDLED_BY_HOOK);
                entry.put("hook", hook.name);
            }
            else if (models.containsKey(name)) {
                entry.put("handledBy", HANDLED_BY_MODEL);
                entry.put("model", models.get(name));
            }
            else {
                entry.put("handledBy", HANDLED_BY_STUB);
            }
            byName.put(name, entry);
        }
        return new ArrayList<>(byName.values());
    }

    /** Compiles hook code in the worker without running it; throws with the Python error. */
    public static void check(Program program, String python, String name, String code, TaskMonitor monitor)
            throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("op", "check_hook");
        request.put("name", name);
        request.put("code", code);
        try {
            AngrWorkers.resultOf(
                AngrWorkers.call(program.getUniqueProgramID(), python, request, 60_000, monitor));
        }
        catch (AngrWorkers.AngrUnavailableException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
