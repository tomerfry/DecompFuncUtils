package decompfuncutils.refine;

import ghidra.program.model.address.Address;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One change the engine made, and how far it can be trusted. Attached to the AST node it produced
 * (so a view can highlight and explain it) and collected in the result's log.
 */
public final class Rewrite {
    public enum Status {
        /** Z3 proved the replacement equal to the original for every input. */
        PROVEN,
        /** Original and replacement agreed on every concrete trial; the solver could not decide. */
        TESTED,
        /** Meaning-preserving by the shape of the code (liveness, control flow); nothing to compute. */
        STRUCTURAL,
        /** Applied without a check: verification was off, or neither check could model the code. */
        ASSUMED,
        /** A check found an input where they differ. Never applied; kept in the log as a warning. */
        REFUTED
    }

    public final String pass;
    public final String rule;
    public final String before;
    public final String after;
    public final Status status;
    /** Counterexample, the reason a check could not run, or other supporting detail. */
    public final String detail;
    public final Address address;
    /** Instructions the rewritten code was decompiled from, for the reader to compare against. */
    public String evidence;

    public Rewrite(String pass, String rule, String before, String after, Status status, String detail, Address address) {
        this.pass = pass;
        this.rule = rule;
        this.before = before;
        this.after = after;
        this.status = status;
        this.detail = detail == null ? "" : detail;
        this.address = address;
    }

    public boolean applied() { return status != Status.REFUTED; }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pass", pass);
        m.put("rule", rule);
        m.put("status", status.name().toLowerCase());
        if (address != null) m.put("address", address.toString());
        m.put("before", before);
        m.put("after", after);
        if (!detail.isEmpty()) m.put("detail", detail);
        if (evidence != null && !evidence.isEmpty()) m.put("disassembly", evidence);
        return m;
    }

    @Override public String toString() {
        return "[" + status + "] " + pass + "/" + rule + ": " + before + "  =>  " + after + (detail.isEmpty() ? "" : "  (" + detail + ")");
    }
}
