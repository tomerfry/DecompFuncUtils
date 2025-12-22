/*
 * IP: GHIDRA - VTable Handler
 * Creates/updates a struct at a vtable DATA reference in the Decompiler popup.
 */
package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import javax.swing.JOptionPane;
import java.util.*;

/**
 * Create/update a vtable structure from a label token (preferred) or a DATA ref
 * in a ctor.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "VTable Handler",
    description = "Create or update a vtable structure from a function-pointer table."
)
//@formatter:on
public class VTableHandlerPlugin extends ProgramPlugin {

    private DockingAction createVTableAction;

    public VTableHandlerPlugin(PluginTool tool) {
        super(tool);
        setupActions();
    }

    private void setupActions() {
        createVTableAction = new DockingAction("Create/Update VTable Structure", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext dac) {
                    handleVTableCreation(dac);
                }
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                if (!(context instanceof DecompilerActionContext dac))
                    return false;
                ClangToken tok = dac.getTokenAtCursor();
                if (tok == null)
                    return false;
                return mightBeVtableContext(tok, dac);
            }

            @Override
            public boolean isAddToPopup(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }
        };

        createVTableAction.setPopupMenuData(
                new MenuData(new String[] { "Create/Update VTable Structure" }, null, "Decompile"));
        createVTableAction.setEnabled(true);
        createVTableAction.setDescription("Create or update vtable structure from function pointer table");
        tool.addAction(createVTableAction);
    }

    /**
     * Heuristic: allow if token has a recognizable label OR instruction has a DATA
     * ref.
     */
    private boolean mightBeVtableContext(ClangToken token, DecompilerActionContext ctx) {
        Address byLabel = resolveByTokenLabel(ctx.getProgram(), token);
        if (byLabel != null)
            return true;

        // fallback: instruction DATA ref (less precise)
        Address a = token.getMinAddress();
        if (a == null)
            return false;
        Instruction ins = ctx.getProgram().getListing().getInstructionAt(a);
        if (ins == null)
            return false;
        for (Reference r : ins.getReferencesFrom()) {
            if (r.getReferenceType().isData())
                return true;
        }
        return false;
    }

    /**
     * Preferred resolution: use the token text as a symbol/label to get the data
     * address.
     */
    private Address resolveByTokenLabel(Program program, ClangToken token) {
        String text = token.getText();
        if (text == null || text.isEmpty())
            return null;

        SymbolTable st = program.getSymbolTable();

        // Try exact-name lookup across all namespaces
        SymbolIterator it = st.getSymbols(text);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (isUsableDataSymbol(program, s)) {
                return s.getAddress();
            }
        }

        // Fallback: if the token looks like an address literal, try parsing it
        try {
            Address a = program.getAddressFactory().getAddress(text);
            if (a != null && a.isMemoryAddress() && program.getMemory().contains(a)) {
                return a;
            }
        } catch (Exception ignore) {
        }

        return null;
    }

    private boolean isUsableDataSymbol(Program p, Symbol s) {
        if (s == null)
            return false;
        Address a = s.getAddress();
        if (a == null || !a.isMemoryAddress())
            return false;
        if (!p.getMemory().contains(a))
            return false;

        // Vtables are typically plain LABELs (not FUNCTION/CODE/EXTERNAL).
        return s.getSymbolType() == SymbolType.LABEL;
    }

    private void handleVTableCreation(DecompilerActionContext ctx) {
        Program program = ctx.getProgram();
        ClangToken token = ctx.getTokenAtCursor();
        if (token == null)
            return;

        // 1) Prefer label-based resolution (user asked for this)
        Address vtableAddr = resolveByTokenLabel(program, token);

        // 2) Fallback to instruction's DATA ref if we didn't get a label address
        if (vtableAddr == null) {
            Address ea = token.getMinAddress();
            if (ea != null) {
                Instruction ins = program.getListing().getInstructionAt(ea);
                if (ins != null) {
                    for (Reference r : ins.getReferencesFrom()) {
                        if (r.getReferenceType().isData()) {
                            vtableAddr = r.getToAddress();
                            break;
                        }
                    }
                }
            }
        }

        if (vtableAddr == null) {
            tool.setStatusInfo("Could not resolve a vtable address from token or data-reference.");
            return;
        }

        Data existing = program.getListing().getDataAt(vtableAddr);
        if (existing != null && existing.getDataType() instanceof Structure s) {
            updateVTableStructure(program, vtableAddr, s);
        } else {
            createVTableStructure(program, vtableAddr);
        }
    }

    // -------- create / update ----------

    private void createVTableStructure(Program program, Address vtableAddr) {
        int tx = program.startTransaction("Create VTable Structure");
        boolean ok = false;
        try {
            List<Address> entries = scanForVTablePointers(program, vtableAddr);
            if (entries.isEmpty()) {
                tool.setStatusInfo("No function pointers at " + vtableAddr);
                return;
            }

            String defaultName = "vtable_" + vtableAddr.toString().replace(":", "_");
            String vtableName = JOptionPane.showInputDialog(tool.getToolFrame(),
                    "Enter name for vtable structure:", defaultName);
            if (vtableName == null || vtableName.trim().isEmpty())
                return;
            vtableName = vtableName.trim();

            StructureDataType sdt = buildVTableStruct(program, vtableName, entries);
            Structure added = (Structure) program.getDataTypeManager().addDataType(
                    sdt, DataTypeConflictHandler.REPLACE_HANDLER);

            Address end = vtableAddr.add(added.getLength() - 1);
            clearAllDataInRange(program, vtableAddr, end);
            program.getListing().clearCodeUnits(vtableAddr, end, false); // extra sweep
            program.getListing().createData(vtableAddr, added);

            Symbol sym = program.getSymbolTable().getPrimarySymbol(vtableAddr);
            if (sym == null || sym.getSource() == SourceType.DEFAULT) {
                program.getSymbolTable().createLabel(vtableAddr, vtableName, SourceType.USER_DEFINED);
            }
            ok = true;
            tool.setStatusInfo("Created " + vtableName + " (" + entries.size() + " ptrs) at " + vtableAddr);
        } catch (Exception ex) {
            tool.setStatusInfo("Create vtable failed: " + ex.getMessage());
            Msg.error(this, "Create vtable failed", ex);
        } finally {
            program.endTransaction(tx, ok);
        }
    }

    private void updateVTableStructure(Program program, Address vtableAddr, Structure existing) {
        int tx = program.startTransaction("Update VTable Structure");
        boolean ok = false;
        try {
            List<Address> entries = scanForVTablePointers(program, vtableAddr);
            if (entries.isEmpty()) {
                tool.setStatusInfo("No function pointers at " + vtableAddr);
                return;
            }

            int choice = JOptionPane.showConfirmDialog(
                    tool.getToolFrame(),
                    "Update vtable '" + existing.getName() + "' field names and size to match pointers?",
                    "Update VTable Structure",
                    JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (choice != JOptionPane.YES_OPTION)
                return;

            StructureDataType sdt = buildVTableStruct(program, existing.getName(), entries);
            sdt.setCategoryPath(existing.getCategoryPath());

            Structure updated = (Structure) program.getDataTypeManager().addDataType(
                    sdt, DataTypeConflictHandler.REPLACE_HANDLER);

            Address end = vtableAddr.add(updated.getLength() - 1);
            clearAllDataInRange(program, vtableAddr, end);
            program.getListing().clearCodeUnits(vtableAddr, end, false); // extra sweep
            program.getListing().createData(vtableAddr, updated);

            ok = true;
            tool.setStatusInfo("Updated vtable '" + existing.getName() + "' (" + entries.size() + " ptrs)");
        } catch (Exception ex) {
            tool.setStatusInfo("Update vtable failed: " + ex.getMessage());
            Msg.error(this, "Update vtable failed", ex);
        } finally {
            program.endTransaction(tx, ok);
        }
    }

    // -------- helpers ----------

    /**
     * EXACT function names as field names; explicit pointer size + packing to avoid
     * overlay errors.
     */
    private StructureDataType buildVTableStruct(Program program, String name, List<Address> entries) {
        StructureDataType sdt = new StructureDataType(new CategoryPath("/vtables"), name, 0);

        int ptrSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
        Pointer ptrT = new PointerDataType(VoidDataType.dataType, ptrSize, program.getDataTypeManager());

        try {
            sdt.setPackingEnabled(true);
            sdt.setToDefaultPacking();
            sdt.setExplicitMinimumAlignment(ptrSize);
        } catch (Throwable ignore) {
        }

        Map<String, Integer> used = new HashMap<>();
        for (int i = 0; i < entries.size(); i++) {
            Function f = program.getFunctionManager().getFunctionAt(entries.get(i));
            String base = (f != null) ? f.getName() : ("ptr_" + i);
            String field = base;
            Integer seen = used.get(base);
            if (seen != null) {
                seen = seen + 1;
                used.put(base, seen);
                field = base + "_" + seen;
            } else {
                used.put(base, 1);
            }
            sdt.add(ptrT, ptrSize, field, null); // explicit size
        }
        return sdt;
    }

    /**
     * Scan a table of pointers starting at {@code start}.
     * - Works for 32/64-bit
     * - Stops on null
     * - Accepts: Function, Instruction, or any pointer into an executable block
     * - Tolerates a few non-code entries before stopping
     */
    private List<Address> scanForVTablePointers(Program program, Address start) {
        List<Address> out = new ArrayList<>();
        int ptrSize = program.getDefaultPointerSize();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address cur = start;

        int max = 1024;
        int badStreak = 0, badLimit = 6;

        for (int i = 0; i < max; i++) {
            try {
                if (!program.getMemory().contains(cur) ||
                        !program.getMemory().contains(cur.add(ptrSize - 1)))
                    break;

                long raw;
                if (ptrSize == 8)
                    raw = program.getMemory().getLong(cur);
                else if (ptrSize == 4)
                    raw = program.getMemory().getInt(cur) & 0xffffffffL;
                else
                    break;

                if (raw == 0)
                    break; // null terminator

                Address tgt = space.getAddress(raw);
                if (tgt == null || !program.getMemory().contains(tgt)) {
                    badStreak++;
                } else {
                    boolean ok = program.getFunctionManager().getFunctionAt(tgt) != null ||
                            program.getListing().getInstructionAt(tgt) != null ||
                            (program.getMemory().getBlock(tgt) != null
                                    && program.getMemory().getBlock(tgt).isExecute());
                    if (ok) {
                        out.add(tgt);
                        badStreak = 0;
                    } else {
                        badStreak++;
                    }
                }

                if (badStreak > badLimit)
                    break;
                cur = cur.add(ptrSize);
            } catch (MemoryAccessException e) {
                break;
            }
        }
        return out;
    }

    /**
     * Delete all defined Data overlapping [start, end], then a final sweep to be
     * sure.
     */
    private void clearAllDataInRange(Program program, Address start, Address end) throws Exception {
        Listing listing = program.getListing();
        Address cur = start;

        while (cur.compareTo(end) <= 0) {
            Data d = listing.getDefinedDataContaining(cur);
            if (d == null) {
                Data next = listing.getDefinedDataAfter(cur);
                if (next == null || next.getMinAddress().compareTo(end) > 0)
                    break;
                cur = next.getMinAddress();
                continue;
            }
            Address ds = d.getMinAddress(), de = d.getMaxAddress();
            listing.clearCodeUnits(ds, de, false);
            cur = de.add(1);
        }
        listing.clearCodeUnits(start, end, false);
    }

    @Override
    protected void dispose() {
        if (createVTableAction != null)
            tool.removeAction(createVTableAction);
        super.dispose();
    }
}
