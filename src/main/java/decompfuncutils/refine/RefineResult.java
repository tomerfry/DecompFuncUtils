package decompfuncutils.refine;

import decompfuncutils.refine.ast.CFunction;
import decompfuncutils.refine.ast.CPrinter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Outcome of refining one function. */
public final class RefineResult {
    public CFunction function;
    /** The decompiler's own output, for comparison. */
    public String original = "";
    /** The refined code, with where everything landed. */
    public CPrinter.Printed printed;
    /** Every rewrite applied, and every one refuted, in the order they were tried. */
    public final List<Rewrite> log = new ArrayList<>();
    /** Things worth telling the user that are not rewrites: rule syntax errors, skipped checks. */
    public final List<String> messages = new ArrayList<>();
    /** Outcome of running the machine code and the refined code side by side; null when not run. */
    public Validation validation;
    public int rounds;
    public long elapsedMs;
    public int solverQueries, proofs, tests;

    /** Whole-function check against the emulator. */
    public static final class Validation {
        public enum Outcome { AGREES, DIFFERS, NOT_CHECKED }

        public Outcome outcome = Outcome.NOT_CHECKED;
        public int trials, agreed;
        /** The differing trial, or why the check could not run. */
        public String detail = "";

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome.name().toLowerCase());
            m.put("trials", trials);
            m.put("agreed", agreed);
            if (!detail.isEmpty()) m.put("detail", detail);
            return m;
        }
    }

    public String text() { return printed == null ? "" : printed.text; }

    public int count(Rewrite.Status status) {
        int n = 0;
        for (Rewrite r : log) if (r.status == status) n++;
        return n;
    }

    public int applied() { return log.size() - count(Rewrite.Status.REFUTED); }

    /** One-line account for a status bar. */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append(applied()).append(" rewrite").append(applied() == 1 ? "" : "s");
        if (applied() > 0) {
            sb.append(" (").append(count(Rewrite.Status.PROVEN)).append(" proved, ").append(count(Rewrite.Status.TESTED)).append(" tested");
            if (count(Rewrite.Status.STRUCTURAL) > 0) sb.append(", ").append(count(Rewrite.Status.STRUCTURAL)).append(" structural");
            if (count(Rewrite.Status.ASSUMED) > 0) sb.append(", ").append(count(Rewrite.Status.ASSUMED)).append(" unchecked");
            sb.append(')');
        }
        if (count(Rewrite.Status.REFUTED) > 0) sb.append(", ").append(count(Rewrite.Status.REFUTED)).append(" refused");
        if (validation != null) {
            switch (validation.outcome) {
                case AGREES -> sb.append("; emulator agrees on ").append(validation.agreed).append(" runs");
                case DIFFERS -> sb.append("; EMULATOR DISAGREES: ").append(validation.detail);
                default -> sb.append("; emulator check skipped: ").append(validation.detail);
            }
        }
        sb.append("; ").append(elapsedMs).append(" ms");
        return sb.toString();
    }

    public Map<String, Object> toMap(boolean includeOriginal) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (function != null && function.function != null) {
            m.put("function", function.function.getName());
            m.put("address", function.function.getEntryPoint().toString());
        }
        m.put("refined", text());
        if (includeOriginal) m.put("original", original);
        m.put("summary", summary());
        List<Map<String, Object>> rewrites = new ArrayList<>();
        for (Rewrite r : log) rewrites.add(r.toMap());
        m.put("rewrites", rewrites);
        if (validation != null) m.put("validation", validation.toMap());
        if (!messages.isEmpty()) m.put("messages", messages);
        m.put("rounds", rounds);
        m.put("elapsedMs", elapsedMs);
        return m;
    }
}
