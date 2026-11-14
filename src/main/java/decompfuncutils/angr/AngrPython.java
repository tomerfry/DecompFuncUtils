package decompfuncutils.angr;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Finds the Python interpreter the angr worker runs under.
 *
 * <p>angr pins exact versions of a large dependency tree, so it rarely survives in a shared
 * interpreter. The supported setup is therefore a private virtual environment created by
 * {@code tools/setup-angr.ps1} / {@code tools/setup-angr.sh}, which records the interpreter it
 * made in a one-line pointer file. Discovery order, first working one wins:
 * <ol>
 * <li>{@code -Ddfu.angr.python} or the {@code DFU_ANGR_PYTHON} environment variable</li>
 * <li>the pointer file {@code ~/.decompfuncutils/angr-python}</li>
 * <li>the default environment {@code ~/.decompfuncutils/angr-venv}</li>
 * <li>{@code python3}, {@code python} and (Windows) {@code py -3} on the PATH</li>
 * </ol>
 * An interpreter set in Tool Options is used on its own, with no fallback, so a wrong setting is
 * reported rather than silently papered over.
 */
public final class AngrPython {

    private static final Path HOME = Path.of(System.getProperty("user.home"), ".decompfuncutils");
    /** Written by the setup scripts: the interpreter of the environment they created. */
    public static final Path POINTER_FILE = HOME.resolve("angr-python");
    private static final Path DEFAULT_VENV = HOME.resolve("angr-venv");

    private AngrPython() {
    }

    static List<List<String>> candidates() {
        List<List<String>> out = new ArrayList<>();
        String configured = System.getProperty("dfu.angr.python", System.getenv("DFU_ANGR_PYTHON"));
        if (configured != null && !configured.isBlank()) {
            out.add(List.of(configured.trim()));
        }
        try {
            if (Files.isRegularFile(POINTER_FILE)) {
                String pointed = Files.readString(POINTER_FILE, StandardCharsets.UTF_8).strip();
                // PowerShell 5 writes a byte-order mark in front of UTF-8 text.
                if (pointed.startsWith("﻿")) {
                    pointed = pointed.substring(1).strip();
                }
                if (!pointed.isEmpty() && Files.isRegularFile(Path.of(pointed))) {
                    out.add(List.of(pointed));
                }
            }
        }
        catch (Exception ignored) {
            // an unreadable pointer file is the same as none
        }
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        Path venvPython = windows
            ? DEFAULT_VENV.resolve("Scripts").resolve("python.exe")
            : DEFAULT_VENV.resolve("bin").resolve("python3");
        if (Files.isRegularFile(venvPython)) {
            out.add(List.of(venvPython.toString()));
        }
        out.add(List.of("python3"));
        out.add(List.of("python"));
        if (windows) {
            out.add(List.of("py", "-3"));
        }
        return out;
    }

    static String setupHelp(List<String> failures, boolean explicit) {
        StringBuilder sb = new StringBuilder();
        sb.append("angr is not available, so this tool cannot run. ");
        if (explicit) {
            sb.append("The interpreter set in Tool Options > MCP Server > 'angr Python Interpreter' ")
              .append("does not work: ");
        }
        else {
            sb.append("Tried: ");
        }
        sb.append(String.join("; ", failures)).append(". ");
        sb.append("To fix it, run tools/setup-angr.ps1 (Windows) or tools/setup-angr.sh from the ")
          .append("DecompFuncUtils repository once: it creates a private Python environment with angr ")
          .append("and records it in ").append(POINTER_FILE).append(". Alternatively point the ")
          .append("DFU_ANGR_PYTHON environment variable, or Tool Options > MCP Server > 'angr Python ")
          .append("Interpreter', at any Python that can 'import angr'. No Ghidra restart is needed.");
        return sb.toString();
    }
}
