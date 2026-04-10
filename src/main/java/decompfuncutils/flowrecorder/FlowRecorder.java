package decompfuncutils.flowrecorder;

import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.FunctionChangeRecord.FunctionChangeType;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Listens to Ghidra program change events and emits FlowSteps in the same
 * shape the MCP tool layer would accept. Records at the semantic level:
 * one user action -> one step, even when that action fires several low-level
 * change records.
 *
 * Event type matching is done by string rather than by importing the
 * ProgramEvent enum so the recorder stays compatible across Ghidra versions
 * where event names evolve but the underlying strings stay stable.
 */
public class FlowRecorder implements DomainObjectListener {

    private volatile boolean recording = false;
    private Program program;
    private final List<FlowStep> steps = new ArrayList<>();
    private final FlowTemplatizer templatizer = new FlowTemplatizer();

    public synchronized void start(Program program) {
        if (recording) return;
        if (program == null) {
            Msg.warn(this, "FlowRecorder: cannot start, no program");
            return;
        }
        this.program = program;
        program.addListener(this);
        recording = true;
        Msg.info(this, "FlowRecorder started on " + program.getName());
    }

    public synchronized void stop() {
        if (!recording) return;
        if (program != null) program.removeListener(this);
        recording = false;
        Msg.info(this, "FlowRecorder stopped with " + steps.size() + " steps");
    }

    public synchronized void reset() {
        steps.clear();
    }

    public boolean isRecording() { return recording; }
    public synchronized List<FlowStep> getSteps() { return new ArrayList<>(steps); }
    public FlowTemplatizer getTemplatizer() { return templatizer; }
    public Program getProgram() { return program; }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (!recording) return;

        // Group the event's records so we can emit ONE logical step per user
        // action even when the underlying transaction fired several low-level
        // change records. Tracked per-event:
        //   - consumed: indices already turned into a step
        //   - renamedFuncs: function entry addresses that produced a rename
        //     step, so a tagalong FUNCTION_CHANGED in the same event doesn't
        //     re-emit a signature step
        //   - signatureFuncs: function entry addresses that already produced
        //     a signature-change step (params + return in one edit arrive as
        //     two records but are one user action)
        Set<Integer> consumed = new HashSet<>();
        Set<String> renamedFuncs = new HashSet<>();
        Set<String> signatureFuncs = new HashSet<>();

        int n = ev.numRecords();

        // Pass 1: process renames and non-function events first so the
        // renamedFuncs set is populated before we look at FUNCTION_CHANGED.
        for (int i = 0; i < n; i++) {
            if (consumed.contains(i)) continue;
            DomainObjectChangeRecord rec = ev.getChangeRecord(i);
            String type = String.valueOf(rec.getEventType());
            try {
                if (type.contains("SYMBOL_RENAMED")) {
                    String entry = handleSymbolRenamed(rec);
                    if (entry != null) {
                        consumed.add(i);
                        if (!entry.isEmpty()) renamedFuncs.add(entry);
                    }
                } else if (type.contains("COMMENT_CHANGED")) {
                    if (handleCommentChanged(rec, type)) consumed.add(i);
                } else if (type.contains("DATA_TYPE_ADDED")) {
                    if (handleDataTypeAdded(rec)) consumed.add(i);
                } else if (type.contains("SYMBOL_ADDED")) {
                    if (handleSymbolAdded(rec)) consumed.add(i);
                }
            } catch (Exception e) {
                Msg.debug(this, "FlowRecorder: ignoring record " + type + ": " + e.getMessage());
            }
        }

        // Pass 2: function signature changes. A FunctionChangeRecord whose
        // isFunctionSignatureChange() is true represents return-type or
        // parameter edits — exactly what ghidra_set_function_signature
        // accepts. Skip functions already captured as renames in pass 1 and
        // dedup multiple signature records per function within this event.
        for (int i = 0; i < n; i++) {
            if (consumed.contains(i)) continue;
            DomainObjectChangeRecord rec = ev.getChangeRecord(i);
            if (!(rec instanceof FunctionChangeRecord)) continue;
            FunctionChangeRecord fcr = (FunctionChangeRecord) rec;
            try {
                if (!fcr.isFunctionSignatureChange()) continue;
                Function func = fcr.getFunction();
                if (func == null) continue;
                String entry = func.getEntryPoint().toString();
                if (renamedFuncs.contains(entry)) { consumed.add(i); continue; }
                if (signatureFuncs.contains(entry)) { consumed.add(i); continue; }
                if (handleSignatureChanged(func, fcr.getSpecificChangeType())) {
                    signatureFuncs.add(entry);
                    consumed.add(i);
                }
            } catch (Exception e) {
                Msg.debug(this, "FlowRecorder: ignoring function record: " + e.getMessage());
            }
        }
    }

    // --- handlers ----------------------------------------------------------

    /**
     * @return null if the record was not consumed; an empty string if it
     *         was consumed but did not touch a function's entry point; or
     *         the function entry address string if a function rename was
     *         emitted (so pass 2 can skip tagalong FUNCTION_CHANGED records
     *         that belong to the same user action).
     */
    private String handleSymbolRenamed(DomainObjectChangeRecord rec) {
        Object obj = rec.getNewValue();
        Object oldVal = rec.getOldValue();
        Symbol symbol = null;

        if (rec instanceof ProgramChangeRecord) {
            Object subject = ((ProgramChangeRecord) rec).getObject();
            if (subject instanceof Symbol) symbol = (Symbol) subject;
        }
        if (symbol == null && obj instanceof Symbol) symbol = (Symbol) obj;
        if (symbol == null) return null;

        String oldName = oldVal instanceof String ? (String) oldVal : null;
        String newName = symbol.getName();
        if (oldName == null || oldName.equals(newName)) return null;

        SymbolType st = symbol.getSymbolType();
        if (st == SymbolType.FUNCTION) {
            String addr = symbol.getAddress().toString();
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("address", addr);
            args.put("newName", newName);
            emit("ghidra_rename_function", args,
                 "Rename function " + oldName + " -> " + newName);
            templatizer.describe("addr", addr, "function at " + addr + " (was " + oldName + ")");
            return addr;
        }
        if (st == SymbolType.LOCAL_VAR || st == SymbolType.PARAMETER) {
            Function parent = findContainingFunction(symbol);
            if (parent == null) return null;
            String faddr = parent.getEntryPoint().toString();
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("functionAddress", faddr);
            args.put("oldName", oldName);
            args.put("newName", newName);
            emit("ghidra_rename_variable", args,
                 "Rename " + (st == SymbolType.PARAMETER ? "parameter " : "var ")
                     + oldName + " -> " + newName + " in " + parent.getName());
            templatizer.describe("addr", faddr, "containing function " + parent.getName());
            templatizer.describe("var", oldName, "variable in " + parent.getName());
            return "";
        }
        if (st == SymbolType.LABEL) {
            String addr = symbol.getAddress().toString();
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("address", addr);
            args.put("oldName", oldName);
            args.put("newName", newName);
            emit("ghidra_rename_label", args,
                 "Rename label " + oldName + " -> " + newName + " at " + addr);
            templatizer.describe("addr", addr, "label site (was " + oldName + ")");
            return "";
        }
        return null;
    }

    private boolean handleSignatureChanged(Function func, FunctionChangeType changeType) {
        String addr = func.getEntryPoint().toString();
        String signature = func.getPrototypeString(true, false);
        if (signature == null || signature.isEmpty()) return false;

        Map<String, Object> args = new LinkedHashMap<>();
        args.put("address", addr);
        args.put("signature", signature);

        String reason;
        if (changeType == FunctionChangeType.RETURN_TYPE_CHANGED) reason = "return type";
        else if (changeType == FunctionChangeType.PARAMETERS_CHANGED) reason = "parameters";
        else reason = "signature";

        emit("ghidra_set_function_signature", args,
             "Set " + reason + " of " + func.getName() + " -> " + signature);
        templatizer.describe("addr", addr, "function " + func.getName());
        return true;
    }

    private boolean handleCommentChanged(DomainObjectChangeRecord rec, String type) {
        if (!(rec instanceof ProgramChangeRecord)) return false;
        ProgramChangeRecord pcr = (ProgramChangeRecord) rec;
        Object newVal = pcr.getNewValue();
        if (!(newVal instanceof String)) return false;
        String comment = (String) newVal;
        if (comment.isEmpty()) return false;

        String commentKind = "EOL";
        if (type.contains("PRE_COMMENT")) commentKind = "PRE";
        else if (type.contains("POST_COMMENT")) commentKind = "POST";
        else if (type.contains("PLATE_COMMENT")) commentKind = "PLATE";
        else if (type.contains("REPEATABLE_COMMENT")) commentKind = "REPEATABLE";

        String addr = pcr.getStart() != null ? pcr.getStart().toString() : null;
        if (addr == null) return false;

        Map<String, Object> args = new LinkedHashMap<>();
        args.put("address", addr);
        args.put("comment", comment);
        args.put("type", commentKind);
        emit("ghidra_set_comment", args,
             "Set " + commentKind + " comment at " + addr);
        templatizer.describe("addr", addr, commentKind + " comment site");
        return true;
    }

    private boolean handleDataTypeAdded(DomainObjectChangeRecord rec) {
        Object obj = rec.getNewValue();
        if (!(obj instanceof DataType)) {
            if (rec instanceof ProgramChangeRecord) {
                obj = ((ProgramChangeRecord) rec).getObject();
            }
        }
        if (!(obj instanceof DataType)) return false;
        DataType dt = (DataType) obj;

        // Only record structures for now — other types are usually byproducts.
        if (!(dt instanceof Structure)) return false;
        Structure struct = (Structure) dt;

        Map<String, Object> args = new LinkedHashMap<>();
        args.put("name", struct.getName());
        String cat = struct.getCategoryPath() != null ? struct.getCategoryPath().getPath() : "/";
        args.put("category", cat);
        List<Map<String, Object>> fields = new ArrayList<>();
        for (DataTypeComponent c : struct.getDefinedComponents()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("name", c.getFieldName() != null ? c.getFieldName() : "field_" + c.getOffset());
            f.put("type", c.getDataType().getDisplayName());
            f.put("size", c.getLength());
            fields.add(f);
        }
        args.put("fields", fields);

        emit("ghidra_create_struct", args, "Create struct " + struct.getName());
        return true;
    }

    private boolean handleSymbolAdded(DomainObjectChangeRecord rec) {
        Object obj = rec.getNewValue();
        Symbol symbol = null;
        if (obj instanceof Symbol) symbol = (Symbol) obj;
        else if (rec instanceof ProgramChangeRecord) {
            Object subject = ((ProgramChangeRecord) rec).getObject();
            if (subject instanceof Symbol) symbol = (Symbol) subject;
        }
        if (symbol == null) return false;

        if (symbol.getSymbolType() == SymbolType.CLASS) {
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("name", symbol.getName());
            String parent = symbol.getParentNamespace() != null
                ? symbol.getParentNamespace().getName() : null;
            if (parent != null && !"Global".equalsIgnoreCase(parent)) {
                args.put("namespace", parent);
            }
            emit("ghidra_create_class", args, "Create class " + symbol.getName());
            return true;
        }
        return false;
    }

    // --- helpers -----------------------------------------------------------

    private Function findContainingFunction(Symbol symbol) {
        if (symbol == null || program == null) return null;
        return program.getFunctionManager()
            .getFunctionContaining(symbol.getAddress());
    }

    private void emit(String toolName, Map<String, Object> args, String summary) {
        FlowStep step = new FlowStep(toolName, args, summary);
        step.setTemplatedArgs(templatizer.templatize(toolName, args));
        synchronized (this) {
            steps.add(step);
        }
        Msg.debug(this, "FlowRecorder: recorded " + toolName + " — " + summary);
    }
}
