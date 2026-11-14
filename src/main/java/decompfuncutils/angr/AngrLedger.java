package decompfuncutils.angr;

import java.util.List;
import java.util.Map;

/**
 * Writes a path's ledger out as a document a person can keep: what happened on the way to where
 * execution is, in order, and what that requires of every unknown.
 *
 * <p>The ledger itself is data (see {@link AngrDebugSession#ledger}); this is its Markdown form,
 * used by "Copy" and "Save" in the debugger's Ledger window and by the MCP tool's
 * {@code format: "markdown"}.
 */
public final class AngrLedger {

    private AngrLedger() {
    }

    @SuppressWarnings("unchecked")
    public static String toMarkdown(Map<String, Object> ledger) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Path ledger: ").append(text(ledger.get("function")));
        if (ledger.get("program") != null) {
            sb.append(" (").append(ledger.get("program")).append(')');
        }
        sb.append("\n\n");
        sb.append("Path ").append(text(ledger.get("path"))).append(", ").append(text(ledger.get("status")));
        if (ledger.get("pc") != null) {
            sb.append(" at `").append(ledger.get("pc")).append('`');
            if (ledger.get("location") != null) {
                sb.append(" (").append(ledger.get("location")).append(')');
            }
        }
        sb.append(". ").append(text(ledger.get("decisions"))).append(" decision(s) on unknown values over ")
          .append(text(ledger.get("steps"))).append(" step(s).\n");
        if (ledger.get("destination") != null) {
            sb.append("\nDestination: `").append(ledger.get("destination")).append("`")
              .append(Boolean.TRUE.equals(ledger.get("atDestination")) ? " - reached.\n" : " - not reached on this path.\n");
        }

        List<Map<String, Object>> entries = ledger.get("entries") instanceof List<?> l
            ? (List<Map<String, Object>>) l : List.of();
        sb.append("\n## On the way\n\n");
        if (entries.isEmpty()) {
            sb.append("Nothing on this path depended on an unknown value.\n");
        }
        else {
            if (ledger.get("entriesOmitted") != null) {
                sb.append("(the first ").append(ledger.get("entriesOmitted")).append(" entries are left out)\n\n");
            }
            sb.append("| # | Where | What | Condition |\n|---|---|---|---|\n");
            for (Map<String, Object> entry : entries) {
                sb.append("| ").append(text(entry.get("n"))).append(" | ").append(cell(where(entry)))
                  .append(" | ").append(cell(what(entry))).append(" | ");
                if (entry.get("condition") != null) {
                    sb.append('`').append(cell(text(entry.get("condition")))).append('`');
                }
                sb.append(" |\n");
            }
        }

        List<Map<String, Object>> unknowns = ledger.get("unknowns") instanceof List<?> l
            ? (List<Map<String, Object>>) l : List.of();
        if (!unknowns.isEmpty()) {
            sb.append("\n## What the path requires of each unknown\n\n");
            sb.append("The values are one assignment that satisfies the whole path together.\n\n");
            for (Map<String, Object> unknown : unknowns) {
                sb.append("- `").append(unknown.get("name")).append("` (").append(text(unknown.get("bits")))
                  .append("-bit").append(unknown.get("from") != null ? ", from " + unknown.get("from") : "")
                  .append(")\n");
                if (unknown.get("requires") instanceof List<?> requires) {
                    for (Object condition : requires) {
                        sb.append("  - requires `").append(condition).append("`\n");
                    }
                    if (unknown.get("requiresOmitted") != null) {
                        sb.append("  - ... and ").append(unknown.get("requiresOmitted")).append(" more\n");
                    }
                }
                else {
                    sb.append("  - free: nothing on this path depends on it\n");
                }
                if (unknown.get("value") != null) {
                    sb.append("  - a value that works: `").append(unknown.get("value")).append('`');
                    if (unknown.get("string") != null) {
                        sb.append(" (\"").append(unknown.get("string")).append("\")");
                    }
                    if (Boolean.TRUE.equals(unknown.get("unique"))) {
                        sb.append(" - the only one");
                    }
                    sb.append('\n');
                }
            }
        }

        List<Object> constraints = ledger.get("constraints") instanceof List<?> l ? (List<Object>) l : List.of();
        sb.append("\n## All constraints (").append(text(ledger.get("constraintCount"))).append(")\n\n");
        if (constraints.isEmpty()) {
            sb.append("None.\n");
        }
        for (Object constraint : constraints) {
            sb.append("- `").append(constraint).append("`\n");
        }
        return sb.toString();
    }

    /** "gate+0x17" when Ghidra has a name for the address, else the address. */
    public static String where(Map<String, Object> entry) {
        if (entry.get("where") != null) {
            return text(entry.get("where"));
        }
        return text(entry.get("at"));
    }

    /** What an entry records, in a few words. */
    public static String what(Map<String, Object> entry) {
        String kind = text(entry.get("kind"));
        switch (kind) {
            case "branch":
                return "branch" + (entry.get("toWhere") != null ? " to " + entry.get("toWhere")
                    : entry.get("to") != null ? " to " + entry.get("to") : "");
            case "unknown":
            case "symbolize":
                return text(entry.get("text")) + (entry.get("symbol") != null ? ": " + entry.get("symbol") : "");
            default:
                return text(entry.get("text")).isEmpty() ? kind : text(entry.get("text"));
        }
    }

    private static String cell(String value) {
        return value.replace("|", "\\|").replace("\n", " ");
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
