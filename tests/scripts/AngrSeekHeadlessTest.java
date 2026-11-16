// Headless regression test for seeking a destination from a session started the way the angr
// Debugger panel starts one: a function name and nothing else.
//
// What nobody gave a value has to be unknown for a search to have anything to solve for - the
// arguments, the registers, globals with no initial contents, the memory behind pointers. With
// those at zero (as they once were) every seek here ends "unreachable" after following the one
// path the zeros take. The second half checks the order of the search: loops that fork on every
// iteration, and a loop in a helper the destination is not in.
//
// Driven by tests/run_angr_test.ps1 -Script AngrSeekHeadlessTest.java over tests/angr/libangrseek.so.
//@category Test
import decompfuncutils.angr.AngrDebugger;
import decompfuncutils.mcp.tools.AngrDebugTool;
import ghidra.app.script.GhidraScript;

import java.util.*;

public class AngrSeekHeadlessTest extends GhidraScript {

    private final AngrDebugTool debug = new AngrDebugTool();
    private int failures = 0;

    private void check(String label, boolean ok, Object detail) {
        String text = detail == null ? "" : String.valueOf(detail).replace("\n", "\\n");
        println("CHECK " + label + ": " + (ok ? "PASS" : "FAIL")
            + (text.isEmpty() ? "" : "  (" + (text.length() > 700 ? text.substring(0, 700) + "..." : text) + ")"));
        if (!ok) {
            failures++;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> dbg(String action, Object... pairs) throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            request.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        request.put("action", action);
        return (Map<String, Object>) debug.execute(request, currentProgram, null);
    }

    private static long num(Object value) {
        return value instanceof Number n ? n.longValue() : Long.MIN_VALUE;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(Object value) {
        return value instanceof List<?> l ? (List<Map<String, Object>>) l : List.of();
    }

    /** Starts a function with no arguments (unless some are among the extra pairs) and seeks. */
    private Map<String, Object> seek(String function, Object... startPairs) throws Exception {
        Object[] pairs = new Object[startPairs.length + 4];
        pairs[0] = "function";
        pairs[1] = function;
        pairs[2] = "args";
        pairs[3] = List.of();
        System.arraycopy(startPairs, 0, pairs, 4, startPairs.length);
        dbg("start", pairs);
        return dbg("seek", "timeoutMs", 60000.0);
    }

    private boolean arrived(Map<String, Object> s) {
        return "destination".equals(s.get("stop")) && "reached".equals(s.get("location"))
            && "reached".equals(map(s.get("seek")).get("result"));
    }

    /** The row of the ledger's unknowns with this name, or an empty map. */
    private static Map<String, Object> unknown(Map<String, Object> s, String name) {
        for (Map<String, Object> row : rows(map(s.get("ledger")).get("unknowns"))) {
            if (name.equals(row.get("name"))) {
                return row;
            }
        }
        return Map.of();
    }

    /** What the memory behind an unknown pointer has to hold, or an empty map. */
    private static Map<String, Object> behind(Map<String, Object> s, String pointer) {
        for (Map<String, Object> row : rows(map(s.get("ledger")).get("pointers"))) {
            if (pointer.equals(row.get("pointer"))) {
                return row;
            }
        }
        return Map.of();
    }

    @Override
    public void run() throws Exception {
        if (!"libangrseek.so".equals(currentProgram.getName())) {
            println(getClass().getSimpleName() + ": skipping " + currentProgram.getName());
            return;
        }
        try {
            dbg("set_destination", "address", "reached");
            unknownInputs();
            afterAFork();
            searchOrder();
        }
        finally {
            AngrDebugger.forget(currentProgram);
        }
        println("HEADLESS_TEST_SUMMARY failures=" + failures);
        println("HEADLESS_TEST_RESULT " + (failures == 0 ? "PASS" : "FAIL"));
    }

    /** Every kind of thing a function's way can depend on, none of it given a value. */
    private void unknownInputs() throws Exception {
        // An argument.
        Map<String, Object> s = seek("seek_int");
        Map<String, Object> key = unknown(s, "arg0");
        check("an argument nobody gave is solved for", arrived(s) && "0x1337".equals(key.get("value")),
            s.get("stop") + " " + map(s.get("ledger")).get("unknowns"));
        check("and says where it came from", "not set at entry".equals(key.get("from")), key);

        // A structure behind a pointer argument, and a string behind a pointer in it.
        s = seek("seek_struct");
        check("a structure behind an unknown pointer needs no setting up", arrived(s), s);
        check("its fields are unknowns of their own size, named after the pointer",
            "0x3".equals(unknown(s, "arg0_at_0").get("value")) && num(unknown(s, "arg0_at_0").get("bits")) == 32
                && String.valueOf(unknown(s, "arg0_at_4").get("requires")).contains(">=s 0x10")
                && "memory behind arg0".equals(unknown(s, "arg0_at_0").get("from")),
            map(s.get("ledger")).get("unknowns"));
        check("a pointer inside it is followed in turn", "AZ".equals(behind(s, "arg0_at_8").get("string")),
            map(s.get("ledger")).get("pointers"));
        String entries = String.valueOf(map(s.get("ledger")).get("entries"));
        check("the ledger notes each pointer that was given somewhere to point",
            entries.contains("kind=pointer") && entries.contains("arg0 is an unknown pointer and was followed"),
            entries);

        // A string compared by a libc model.
        s = seek("seek_string");
        check("a string behind an unknown pointer is solved through strcmp",
            arrived(s) && "open sesame".equals(behind(s, "arg0").get("string")),
            s.get("stop") + " " + map(s.get("ledger")).get("pointers"));

        // Globals nothing initialises.
        s = seek("seek_global");
        String globals = String.valueOf(map(s.get("ledger")).get("unknowns"));
        check("a global with no initial contents is unknown, under Ghidra's name for it",
            arrived(s) && globals.contains("where=g_mode") && globals.contains("== 0x5")
                && globals.contains("where=g_limits") && num(unknown(s, "mem_104544").get("bits")) == 32,
            s.get("stop") + " " + globals);

        // Loops, call chains, a jump table, a list.
        s = seek("seek_checksum");
        check("a loop over unknown bytes with an unknown count", arrived(s)
            && "0x6".equals(unknown(s, "arg1").get("value")), s.get("stop") + " " + unknown(s, "arg1"));
        s = seek("seek_after_work");
        check("a long loop that decides nothing is run through", arrived(s), s.get("seek"));
        s = seek("seek_chain");
        check("through helpers and past error exits",
            arrived(s) && String.valueOf(behind(s, "arg0").get("bytes")).startsWith("7f44"),
            s.get("stop") + " " + map(s.get("ledger")).get("pointers"));
        s = seek("seek_switch");
        check("through a jump table", arrived(s) && "0x6".equals(unknown(s, "arg0").get("value")),
            s.get("stop") + " " + unknown(s, "arg0"));
        s = seek("seek_list");
        check("a linked list of unknown nodes", arrived(s), s.get("seek"));

        // Input through libc rather than through arguments.
        s = seek("seek_read");
        check("input read from a descriptor nobody gave", arrived(s), s.get("seek"));
        s = seek("seek_read", "args", List.of(0.0));
        check("unknown standard input, and what it has to be",
            arrived(s) && String.valueOf(map(map(s.get("ledger")).get("stdin")).get("hex")).startsWith("474f"),
            s.get("stop") + " " + map(s.get("ledger")).get("stdin"));
        s = seek("seek_main");
        check("argc and argv", arrived(s) && "0x3".equals(unknown(s, "arg0").get("value"))
            && "unlock".equals(behind(s, "arg1_at_8").get("string")),
            s.get("stop") + " " + map(s.get("ledger")).get("pointers"));

        // A write through an address that depends on an unknown (local[key & 3] = key) must not
        // quietly fix the unknown to one of the places it can be.
        s = seek("seek_out");
        check("a write at an unknown index keeps every place it can go", arrived(s), s.get("seek"));

        // Still a verdict when there is no way.
        s = seek("seek_never");
        check("a destination no input reaches is still reported unreachable",
            "seek_exhausted".equals(s.get("stop")) && "unreachable".equals(map(s.get("seek")).get("result"))
                && num(map(s.get("seek")).get("forks")) > 0, s.get("seek"));

        // What was given a value stays what it was given...
        s = seek("seek_int", "args", List.of(5.0));
        check("an argument that was given is fixed: no fork, and the hint says why",
            "seek_exhausted".equals(s.get("stop")) && num(map(s.get("seek")).get("forks")) == 0
                && String.valueOf(s.get("hint")).contains("No branch on the way depended on an unknown"), s);
        s = seek("seek_int", "args", List.of((double) 0x1337));
        check("and the right value walks in without solving anything",
            arrived(s) && num(map(s.get("seek")).get("forks")) == 0, s.get("seek"));

        // ... and the old behaviour is still there to ask for.
        s = seek("seek_int", "unknownInputs", false);
        check("unknownInputs:false goes back to zeros", "seek_exhausted".equals(s.get("stop"))
            && num(map(s.get("seek")).get("forks")) == 0, s.get("seek"));
        dbg("start", "function", "seek_struct", "args", List.of(), "unknownInputs", false);
        s = dbg("continue");
        check("where a NULL pointer faults as before", "fault".equals(s.get("status")), s.get("fault"));

        // Stepping by hand sees the same unknowns: a fork at the first decision.
        dbg("start", "function", "seek_int", "args", List.of());
        s = dbg("continue");
        check("stepping forks on an argument nobody gave", "fork".equals(s.get("stop"))
            && String.valueOf(s.get("symbols")).contains("name=arg0"), s);
        s = dbg("concretize", "symbol", "arg0");
        check("an unknown at entry can be concretized by name",
            String.valueOf(s.get("symbols")).contains("pinned=true")
                && !String.valueOf(s.get("symbols")).contains("example"), s.get("symbols"));
    }

    /**
     * Continue stops at a branch on an unknown and stays on one side of it, with the other side
     * parked as a path of its own. The way to the destination is as likely to be the parked side
     * as the current one, so a seek from there has to look down both.
     */
    private void afterAFork() throws Exception {
        dbg("start", "function", "seek_int", "args", List.of());
        Map<String, Object> s = dbg("continue");
        List<Map<String, Object>> paths = rows(s.get("paths"));
        check("continue stops at the fork with both sides kept", "fork".equals(s.get("stop")) && paths.size() == 2, s);
        for (Map<String, Object> path : paths) {
            long id = num(path.get("id"));
            dbg("start", "function", "seek_int", "args", List.of());
            dbg("continue");
            dbg("select_path", "path", (double) id);
            s = dbg("seek", "timeoutMs", 60000.0);
            check("seek arrives after a fork, with path " + id + " (" + path.get("guard") + ") current",
                arrived(s) && "0x1337".equals(unknown(s, "arg0").get("value")),
                s.get("stop") + " " + s.get("seek") + " " + s.get("hint"));
        }

        // Several forks deep, wherever stepping happened to leave the current path.
        dbg("start", "function", "seek_chain", "args", List.of());
        int forks = 0;
        for (int i = 0; i < 3; i++) {
            s = dbg("continue");
            if (!"fork".equals(s.get("stop"))) {
                break;
            }
            forks++;
        }
        s = dbg("seek", "timeoutMs", 60000.0);
        check("seek arrives after " + forks + " forks taken by hand", forks > 0 && arrived(s),
            s.get("stop") + " " + s.get("seek") + " " + s.get("paths"));
        check("and says how many paths it started from and which one the way carries on from",
            num(map(s.get("seek")).get("startedFrom")) == forks + 1 && map(s.get("seek")).get("through") != null,
            s.get("seek"));

        // No way from any side is still a verdict, and not the "nothing was unknown" one.
        dbg("start", "function", "seek_never", "args", List.of());
        s = dbg("continue");
        s = dbg("seek", "timeoutMs", 60000.0);
        check("no way from either side of a fork is still unreachable",
            "seek_exhausted".equals(s.get("stop")) && "unreachable".equals(map(s.get("seek")).get("result"))
                && !String.valueOf(s.get("hint")).contains("No branch on the way depended"),
            s.get("seek") + " " + s.get("hint"));

        // A path that has finished is no place to search from, but its open siblings are.
        dbg("start", "function", "seek_int", "args", List.of());
        s = dbg("continue");
        long wrong = -1;
        long right = -1;
        for (Map<String, Object> path : rows(s.get("paths"))) {
            if (String.valueOf(path.get("guard")).contains("!=")) {
                wrong = num(path.get("id"));
            }
            else {
                right = num(path.get("id"));
            }
        }
        dbg("select_path", "path", (double) wrong);
        s = dbg("continue");
        check("the side that misses runs to its end", "returned".equals(s.get("stop")), s.get("stop"));
        s = dbg("seek", "timeoutMs", 60000.0);
        check("seek from a path that has returned searches the side still open",
            arrived(s) && num(map(s.get("seek")).get("through")) == right
                && String.valueOf(s.get("hint")).contains("down path " + right),
            s.get("stop") + " " + s.get("seek") + " " + s.get("hint"));
    }

    /** Which open path goes next decides whether a search that could arrive does. */
    private void searchOrder() throws Exception {
        Map<String, Object> s = seek("seek_diamonds");
        Map<String, Object> seek = map(s.get("seek"));
        check("a loop that forks on every iteration is crossed by one path, not by all abreast",
            arrived(s) && num(seek.get("blocks")) < 5000 && map(seek.get("ended")).get("dropped") == null
                && Boolean.TRUE.equals(seek.get("directed")), seek);

        s = seek("seek_after_spaces");
        seek = map(s.get("seek"));
        // Inside a helper the graph has no distances; what tells the way out of its loop from
        // another turn of it is that the turn has been taken before.
        check("a loop in a helper the destination is not in is left, not gone round for ever",
            arrived(s) && num(seek.get("blocks")) < 500
                && String.valueOf(behind(s, "arg0").get("string")).contains("go"),
            seek + " " + map(s.get("ledger")).get("pointers"));

        // Breadth first, as it is without the graph, still arrives where the paths are few.
        dbg("start", "function", "seek_chain", "args", List.of());
        s = dbg("seek", "guided", false, "timeoutMs", 60000.0);
        check("without the graph the search is breadth first and still arrives",
            arrived(s) && Boolean.FALSE.equals(map(s.get("seek")).get("directed")), s.get("seek"));
    }
}
