/*
 * LibAFLFuzzerGeneratorPlugin
 *
 * Generates a complete Rust LibAFL QEMU-based fuzzing project from
 * the current Ghidra analysis context.
 *
 * Features:
 *   - Architecture auto-detection (ARM, AArch64, x86, x64, MIPS)
 *   - External/imported function detection with interactive stub config
 *   - Global state detection with initialization setup
 *   - Memory map extraction
 *   - String/dictionary extraction for seed corpus
 *   - Decompiled code embedded as reference
 *   - Windows/WSL/Docker support with cross-platform scripts
 *
 * Licensed under the Apache License 2.0.
 */

package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "LibAFL Fuzzer Generator",
    description = "Generates a complete Rust LibAFL QEMU-based fuzzing project "
                + "from the current binary and function context."
)
//@formatter:on
public class LibAFLFuzzerGeneratorPlugin extends ProgramPlugin {

    private DockingAction generateAction;
    private DockingAction generateFromFuncAction;

    public LibAFLFuzzerGeneratorPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    // ===================================================================
    // Actions
    // ===================================================================

    private void createActions() {
        generateAction = new DockingAction("Generate LibAFL Fuzzer", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) { generateFuzzer(null); }
            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return currentProgram != null;
            }
            @Override
            public boolean isAddToPopup(ActionContext ctx) { return false; }
        };
        generateAction.setMenuBarData(
                new MenuData(new String[] { "Tools", "Generate LibAFL Fuzzer..." }));
        generateAction.setKeyBindingData(
                new KeyBindingData(KeyEvent.VK_F,
                        InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK));
        generateAction.setDescription(
                "Generate a LibAFL QEMU fuzzing project for the current binary");
        tool.addAction(generateAction);

        generateFromFuncAction = new DockingAction(
                "Generate LibAFL Fuzzer for Function", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                Function func = findFunctionFromContext(ctx);
                generateFuzzer(func);
            }
            @Override
            public boolean isEnabledForContext(ActionContext ctx) {
                return currentProgram != null;
            }
            @Override
            public boolean isAddToPopup(ActionContext ctx) {
                return ctx instanceof DecompilerActionContext;
            }
        };
        generateFromFuncAction.setPopupMenuData(
                new MenuData(new String[] { "Generate LibAFL Fuzzer for Function" },
                        null, "Decompile"));
        tool.addAction(generateFromFuncAction);
    }

    private Function findFunctionFromContext(ActionContext ctx) {
        if (currentProgram == null) return null;
        try {
            if (ctx instanceof DecompilerActionContext dac) {
                Address addr = dac.getAddress();
                if (addr != null)
                    return currentProgram.getFunctionManager().getFunctionContaining(addr);
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ===================================================================
    // Data structures
    // ===================================================================

    enum TargetArch {
        ARM("arm"), AARCH64("aarch64"), X86("i386"), X86_64("x86_64"),
        MIPS("mips"), MIPSEL("mipsel"), PPC("ppc"), UNKNOWN("x86_64");
        final String qemuName;
        TargetArch(String qemuName) { this.qemuName = qemuName; }
    }

    enum ExternAction {
        STUB_RETURN("Stub (return 0)"),
        STUB_PASSTHROUGH("Passthrough (nop)"),
        HOOK_CUSTOM("Custom hook"),
        SKIP("Skip (don't touch)");
        final String label;
        ExternAction(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    static class ExternFuncInfo {
        String name;
        Address address;      // thunk or PLT address
        String library;       // originating library if known
        ExternAction action = ExternAction.SKIP;
        String customHookCode = "";  // Rust code for HOOK_CUSTOM

        ExternFuncInfo(String name, Address address, String library) {
            this.name = name;
            this.address = address;
            this.library = library != null ? library : "unknown";
        }
    }

    static class GlobalRef {
        String name;
        Address address;
        long size;
        String dataTypeName;
        boolean initialize = false;
        String initValue = "0";   // hex or literal

        GlobalRef(String name, Address address, long size, String dataTypeName) {
            this.name = name;
            this.address = address;
            this.size = size;
            this.dataTypeName = dataTypeName;
        }
    }

    static class MemRegion {
        String name;
        long start;
        long end;
        boolean read, write, execute;

        MemRegion(String name, long start, long end, boolean r, boolean w, boolean x) {
            this.name = name; this.start = start; this.end = end;
            this.read = r; this.write = w; this.execute = x;
        }
    }

    // --- Input mapping: how fuzz data reaches the target function ---

    enum InputRole {
        FUZZ_PTR("Fuzz buffer pointer",
            "This parameter receives a pointer to the fuzz input data"),
        FUZZ_LEN("Fuzz buffer length",
            "This parameter receives the length of the fuzz input"),
        FUZZ_VALUE("Fuzz scalar value",
            "This parameter is directly fuzzed (raw bytes cast to its type)"),
        FIXED("Fixed / constant value",
            "This parameter gets a fixed value every iteration"),
        IGNORE("Ignore / leave default",
            "This parameter is left at its default (zero or whatever is in registers)");

        final String label;
        final String tooltip;
        InputRole(String label, String tooltip) {
            this.label = label; this.tooltip = tooltip;
        }
        @Override public String toString() { return label; }
    }

    static class FuncParamConfig {
        String name;          // parameter name from Ghidra
        String dataType;      // type string, e.g. "char *", "int", "size_t"
        int index;            // 0-based parameter index
        boolean isPointer;    // is it a pointer type?
        InputRole role = InputRole.IGNORE;
        String fixedValue = "0";  // used when role == FIXED (hex literal)
        int fuzzValueSize = 4;    // byte width for FUZZ_VALUE

        FuncParamConfig(String name, String dataType, int index, boolean isPointer) {
            this.name = name;
            this.dataType = dataType;
            this.index = index;
            this.isPointer = isPointer;
        }
    }

    static class GlobalInputConfig {
        String name;
        long address;
        long size;
        String dataType;
        boolean writeFuzzData = false;  // write fuzz input to this global each iteration
        boolean initialize = false;      // initialize to a fixed value at setup
        String initValue = "0";

        GlobalInputConfig(String name, long address, long size, String dataType) {
            this.name = name;
            this.address = address;
            this.size = size;
            this.dataType = dataType;
        }
    }

    static class FuzzerConfig {
        String projectName;
        String targetBinaryPath;
        TargetArch arch;
        Function targetFunction;
        long entryAddress;
        long exitAddress;
        long mainAddress;    // Address of main() for initialization
        long imageBase;
        long elfEntryPoint;
        boolean useSnapshots = true;
        boolean useCmpLog = true;
        boolean generateDictionary = true;
        int maxInputSize = 4096;
        List<MemRegion> memoryMap = new ArrayList<>();
        String decompiledCode;
        List<String> seedStrings = new ArrayList<>();
        List<ExternFuncInfo> externalFunctions = new ArrayList<>();
        List<GlobalRef> globals = new ArrayList<>();

        // Input mapping — how fuzz data reaches the target
        List<FuncParamConfig> paramConfigs = new ArrayList<>();
        List<GlobalInputConfig> globalInputs = new ArrayList<>();
    }

    // ===================================================================
    // Main generation flow
    // ===================================================================

    private void generateFuzzer(Function targetFunc) {
        if (currentProgram == null) {
            Msg.showError(this, null, "Error", "No program loaded.");
            return;
        }

        // --- Step 1: Choose output directory ---
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select output directory for LibAFL project");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setApproveButtonText("Generate Here");
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        File outputDir = chooser.getSelectedFile();

        // --- Step 2: Build config from analysis ---
        FuzzerConfig config = buildInitialConfig(targetFunc);

        // --- Step 3: Detect externals & globals ---
        if (targetFunc != null) {
            config.externalFunctions = detectExternalCalls(targetFunc);
            config.globals = detectReferencedGlobals(targetFunc);
        } else {
            config.externalFunctions = detectAllExternalFunctions();
            config.globals = new ArrayList<>();
        }

        // --- Step 4: Show interactive config wizard ---
        if (!showConfigWizard(config)) return; // user cancelled

        // --- Step 5: Generate project ---
        try {
            Path projectDir = outputDir.toPath().resolve(config.projectName);
            generateProject(projectDir, config);
            Msg.showInfo(this, null, "LibAFL Fuzzer Generated",
                    "Project generated at:\n" + projectDir.toAbsolutePath()
                    + "\n\nSee README.md for build and run instructions.");
        } catch (Exception ex) {
            Msg.showError(this, null, "Generation Error",
                    "Failed to generate fuzzer: " + ex.getMessage(), ex);
        }
    }

    private FuzzerConfig buildInitialConfig(Function targetFunc) {
        FuzzerConfig config = new FuzzerConfig();
        config.projectName = sanitizeName(currentProgram.getName()) + "_fuzzer";
        config.arch = detectArch();
        config.targetFunction = targetFunc;
        config.memoryMap = extractMemoryMap();
        config.seedStrings = extractInterestingStrings(50);
        config.targetBinaryPath = currentProgram.getExecutablePath();

        // Get Ghidra's image base (e.g. 0x100000 for PIE, 0x400000 for non-PIE x86_64)
        config.imageBase = currentProgram.getImageBase().getOffset();

        // Get the raw ELF entry point from the binary header.
        // For PIE binaries this is a small offset like 0x1060.
        // We compute it as: elfEntry = ghidraEntry - ghidraBase
        // where ghidraEntry is what Ghidra shows for _start.
        Address ghidraEntry = null;
        Symbol startSym = findSymbol("_start");
        if (startSym != null) {
            ghidraEntry = startSym.getAddress();
        } else {
            // Fallback: use the minimum address or program's declared entry
            ghidraEntry = currentProgram.getMinAddress();
        }
        // The raw ELF entry = ghidra entry - ghidra image base
        config.elfEntryPoint = ghidraEntry.getOffset() - config.imageBase;

        // Find main() address for initialization phase
        Symbol mainSym = findSymbol("main");
        if (mainSym != null) {
            config.mainAddress = mainSym.getAddress().getOffset();
        } else {
            config.mainAddress = 0; // will skip main initialization phase
        }

        if (targetFunc != null) {
            config.entryAddress = targetFunc.getEntryPoint().getOffset();
            config.exitAddress = findFunctionExitAddress(targetFunc);
            config.decompiledCode = decompileFunction(targetFunc);

            // Extract function parameters for input mapping
            Parameter[] params = targetFunc.getParameters();
            for (int i = 0; i < params.length; i++) {
                Parameter p = params[i];
                DataType dt = p.getDataType();
                String typeName = dt.getDisplayName();
                boolean isPtr = typeName.contains("*") || typeName.contains("[]")
                    || dt instanceof ghidra.program.model.data.Pointer;
                FuncParamConfig pc = new FuncParamConfig(
                    p.getName(), typeName, i, isPtr);

                // Smart defaults: try to guess roles from names and types
                String nameLower = p.getName().toLowerCase();
                if (isPtr && (nameLower.contains("buf") || nameLower.contains("data")
                        || nameLower.contains("input") || nameLower.contains("src")
                        || nameLower.contains("str") || nameLower.contains("msg")
                        || nameLower.contains("payload") || nameLower.contains("pkt")
                        || nameLower.contains("ptr") || nameLower.contains("mem"))) {
                    pc.role = InputRole.FUZZ_PTR;
                } else if (!isPtr && (nameLower.contains("len") || nameLower.contains("size")
                        || nameLower.contains("count") || nameLower.contains("nbytes")
                        || nameLower.contains("sz") || nameLower.contains("length"))) {
                    pc.role = InputRole.FUZZ_LEN;
                } else if (isPtr && i == 0 && params.length >= 2) {
                    // First pointer arg with a second arg → likely (buf, len)
                    pc.role = InputRole.FUZZ_PTR;
                } else if (!isPtr && i == 1 && params.length >= 2
                        && config.paramConfigs.size() > 0
                        && config.paramConfigs.get(0).role == InputRole.FUZZ_PTR) {
                    // Second non-pointer arg after a FUZZ_PTR → likely length
                    pc.role = InputRole.FUZZ_LEN;
                }
                config.paramConfigs.add(pc);
            }

            // If no params were marked as FUZZ_PTR, mark the first pointer as FUZZ_PTR
            // and the first integer after it as FUZZ_LEN
            boolean hasFuzzPtr = config.paramConfigs.stream()
                .anyMatch(p -> p.role == InputRole.FUZZ_PTR);
            if (!hasFuzzPtr) {
                for (FuncParamConfig pc : config.paramConfigs) {
                    if (pc.isPointer) { pc.role = InputRole.FUZZ_PTR; break; }
                }
                // Now find a length candidate after the ptr
                boolean afterPtr = false;
                for (FuncParamConfig pc : config.paramConfigs) {
                    if (pc.role == InputRole.FUZZ_PTR) { afterPtr = true; continue; }
                    if (afterPtr && !pc.isPointer && pc.role == InputRole.IGNORE) {
                        pc.role = InputRole.FUZZ_LEN; break;
                    }
                }
            }
        } else {
            Address entry = currentProgram.getMinAddress();
            Symbol sym = findSymbol("main");
            if (sym == null) sym = findSymbol("_start");
            if (sym != null) entry = sym.getAddress();
            config.entryAddress = entry.getOffset();
            config.exitAddress = 0;
        }
        return config;
    }

    // ===================================================================
    // External function detection
    // ===================================================================

    private List<ExternFuncInfo> detectExternalCalls(Function targetFunc) {
        List<ExternFuncInfo> externs = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        if (targetFunc == null) return externs;

        // Walk all called functions from the target
        Set<Function> called = targetFunc.getCalledFunctions(TaskMonitor.DUMMY);
        for (Function callee : called) {
            if (seen.contains(callee.getName())) continue;
            seen.add(callee.getName());

            if (callee.isExternal() || callee.isThunk()) {
                String lib = "unknown";
                if (callee.isExternal()) {
                    ExternalLocation extLoc = callee.getExternalLocation();
                    if (extLoc != null && extLoc.getLibraryName() != null) {
                        lib = extLoc.getLibraryName();
                    }
                } else if (callee.isThunk()) {
                    Function thunked = callee.getThunkedFunction(true);
                    if (thunked != null && thunked.isExternal()) {
                        ExternalLocation extLoc = thunked.getExternalLocation();
                        if (extLoc != null && extLoc.getLibraryName() != null) {
                            lib = extLoc.getLibraryName();
                        }
                    }
                }

                ExternFuncInfo info = new ExternFuncInfo(
                        callee.getName(), callee.getEntryPoint(), lib);

                // Auto-suggest action based on function name
                String name = callee.getName().toLowerCase(Locale.ROOT);
                if (name.contains("malloc") || name.contains("calloc")
                        || name.contains("realloc") || name.contains("free")
                        || name.contains("memcpy") || name.contains("memset")
                        || name.contains("strlen") || name.contains("strcmp")
                        || name.contains("printf") || name.contains("puts")
                        || name.contains("fprintf") || name.contains("sprintf")) {
                    info.action = ExternAction.SKIP; // libc functions handled by QEMU
                } else {
                    info.action = ExternAction.STUB_RETURN;
                }

                externs.add(info);
            }
        }
        return externs;
    }

    private List<ExternFuncInfo> detectAllExternalFunctions() {
        List<ExternFuncInfo> externs = new ArrayList<>();
        if (currentProgram == null) return externs;
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator iter = symTable.getExternalSymbols();
        int count = 0;
        while (iter.hasNext() && count < 500) {
            Symbol sym = iter.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                String lib = "unknown";
                try {
                    ExternalLocation ext = currentProgram.getExternalManager()
                            .getExternalLocation(sym);
                    if (ext != null && ext.getLibraryName() != null)
                        lib = ext.getLibraryName();
                } catch (Exception ignored) {}

                externs.add(new ExternFuncInfo(sym.getName(), sym.getAddress(), lib));
                count++;
            }
        }
        return externs;
    }

    // ===================================================================
    // Global state detection
    // ===================================================================

    private List<GlobalRef> detectReferencedGlobals(Function func) {
        List<GlobalRef> globals = new ArrayList<>();
        if (func == null || currentProgram == null) return globals;

        Set<Address> seen = new LinkedHashSet<>();
        Listing listing = currentProgram.getListing();

        // Walk instructions in function and find data references
        AddressSetView body = func.getBody();
        InstructionIterator instrIter = listing.getInstructions(body, true);

        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                if (ref.getReferenceType().isData()) {
                    Address target = ref.getToAddress();
                    if (seen.contains(target)) continue;
                    seen.add(target);

                    // Check if it's a global data reference
                    Data data = listing.getDefinedDataAt(target);
                    if (data != null) {
                        String name = null;
                        Symbol sym = currentProgram.getSymbolTable()
                                .getPrimarySymbol(target);
                        if (sym != null) name = sym.getName();
                        if (name == null) name = "DAT_" + target.toString();

                        DataType dt = data.getDataType();
                        long size = data.getLength();
                        globals.add(new GlobalRef(name, target, size,
                                dt != null ? dt.getName() : "undefined"));
                    }
                }
            }
        }
        return globals;
    }

    // ===================================================================
    // Config wizard (multi-tab dialog)
    // ===================================================================

    private boolean showConfigWizard(FuzzerConfig config) {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setPreferredSize(new Dimension(800, 550));

        // --- Tab 1: General ---
        JPanel generalTab = createGeneralTab(config);
        tabs.addTab("General", generalTab);

        // --- Tab 2: Input Mapping (always shown when targeting a function) ---
        if (config.targetFunction != null) {
            JPanel inputTab = createInputMappingTab(config);
            int paramCount = config.paramConfigs.size();
            String tabTitle = paramCount > 0
                ? "★ Input Mapping (" + paramCount + " params)"
                : "★ Input Mapping (no params detected — add manually)";
            tabs.addTab(tabTitle, inputTab);
            tabs.setSelectedIndex(1); // Focus on input mapping by default
        }

        // --- Tab 3: External Functions ---
        JPanel externsTab = createExternsTab(config);
        tabs.addTab("External Functions (" + config.externalFunctions.size() + ")",
                externsTab);

        // --- Tab 4: Global State ---
        JPanel globalsTab = createGlobalsTab(config);
        tabs.addTab("Globals (" + config.globals.size() + ")", globalsTab);

        // --- Tab 5: Platform ---
        JPanel platformTab = createPlatformTab(config);
        tabs.addTab("Platform / Build", platformTab);

        int result = JOptionPane.showConfirmDialog(null, tabs,
                "LibAFL Fuzzer Configuration",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        return result == JOptionPane.OK_OPTION;
    }

    // --- General tab ---

    private JPanel createGeneralTab(FuzzerConfig config) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        JTextField nameField = addLabeledField(panel, gbc, row++,
                "Project name:", config.projectName);
        JTextField binaryField = addLabeledField(panel, gbc, row++,
                "Target binary:", config.targetBinaryPath);
        JLabel archLabel = addLabeledInfo(panel, gbc, row++,
                "Architecture:", config.arch.qemuName);
        JLabel funcLabel = addLabeledInfo(panel, gbc, row++,
                "Target:",
                config.targetFunction != null
                        ? config.targetFunction.getName() + " @ 0x"
                            + Long.toHexString(config.entryAddress)
                        : "Whole binary (from entry/main)");
        JTextField entryField = addLabeledField(panel, gbc, row++,
                "Entry address:", String.format("0x%x", config.entryAddress));
        JTextField exitField = addLabeledField(panel, gbc, row++,
                "Exit address:",
                config.exitAddress != 0
                        ? String.format("0x%x", config.exitAddress) : "auto");
        JTextField maxSizeField = addLabeledField(panel, gbc, row++,
                "Max input size:", String.valueOf(config.maxInputSize));

        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 2;
        panel.add(Box.createVerticalStrut(8), gbc);

        JCheckBox snapshotCheck = new JCheckBox("Use snapshots (fast state reset)",
                config.useSnapshots);
        gbc.gridy = row++;
        panel.add(snapshotCheck, gbc);

        JCheckBox cmplogCheck = new JCheckBox("Enable CmpLog (comparison coverage)",
                config.useCmpLog);
        gbc.gridy = row++;
        panel.add(cmplogCheck, gbc);

        JCheckBox dictCheck = new JCheckBox("Generate dictionary from binary strings",
                config.generateDictionary);
        gbc.gridy = row++;
        panel.add(dictCheck, gbc);

        // Fill remaining space
        gbc.gridy = row; gbc.weighty = 1.0;
        panel.add(Box.createGlue(), gbc);

        // Wire values back on OK (we read them when dialog closes)
        // Store references so we can read them later
        panel.putClientProperty("nameField", nameField);
        panel.putClientProperty("binaryField", binaryField);
        panel.putClientProperty("entryField", entryField);
        panel.putClientProperty("exitField", exitField);
        panel.putClientProperty("maxSizeField", maxSizeField);
        panel.putClientProperty("snapshotCheck", snapshotCheck);
        panel.putClientProperty("cmplogCheck", cmplogCheck);
        panel.putClientProperty("dictCheck", dictCheck);
        panel.putClientProperty("config", config);

        // Read values when the panel's parent dialog closes
        panel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                    && !panel.isShowing()) {
                // Dialog closing — read values back into config
                config.projectName = nameField.getText().trim();
                config.targetBinaryPath = binaryField.getText().trim();
                try { config.entryAddress = Long.decode(entryField.getText().trim()); }
                catch (Exception ignored) {}
                String exitText = exitField.getText().trim();
                if (!"auto".equalsIgnoreCase(exitText) && !exitText.isEmpty()) {
                    try { config.exitAddress = Long.decode(exitText); }
                    catch (Exception ignored) {}
                }
                try { config.maxInputSize = Integer.parseInt(maxSizeField.getText().trim()); }
                catch (Exception ignored) {}
                config.useSnapshots = snapshotCheck.isSelected();
                config.useCmpLog = cmplogCheck.isSelected();
                config.generateDictionary = dictCheck.isSelected();
            }
        });

        return panel;
    }

    private JTextField addLabeledField(JPanel panel, GridBagConstraints gbc,
                                       int row, String label, String value) {
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        JTextField field = new JTextField(value, 35);
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(field, gbc);
        return field;
    }

    private JLabel addLabeledInfo(JPanel panel, GridBagConstraints gbc,
                                  int row, String label, String value) {
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        JLabel info = new JLabel(value);
        info.setFont(info.getFont().deriveFont(Font.BOLD));
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(info, gbc);
        return info;
    }

    // --- Input Mapping tab ---

    private JPanel createInputMappingTab(FuzzerConfig config) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Top: function signature display
        JPanel sigPanel = new JPanel(new BorderLayout());
        sigPanel.setBorder(BorderFactory.createTitledBorder("Target Function"));
        String sig = buildFuncSignature(config);
        JTextArea sigArea = new JTextArea(sig);
        sigArea.setEditable(false);
        sigArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        sigArea.setRows(3);
        sigArea.setBackground(new Color(245, 245, 245));
        sigPanel.add(new JScrollPane(sigArea), BorderLayout.CENTER);
        panel.add(sigPanel, BorderLayout.NORTH);

        // Center: parameter table
        JPanel centerPanel = new JPanel(new BorderLayout(4, 4));
        centerPanel.setBorder(BorderFactory.createTitledBorder(
            "Parameter → Input Mapping (configure how fuzz data reaches each parameter)"));

        String[] colNames = {"#", "Name", "Type", "Role", "Fixed Value"};
        Object[][] tableData = new Object[config.paramConfigs.size()][5];
        for (int i = 0; i < config.paramConfigs.size(); i++) {
            FuncParamConfig p = config.paramConfigs.get(i);
            tableData[i] = new Object[]{
                p.index, p.name, p.dataType, p.role, p.fixedValue
            };
        }

        javax.swing.table.DefaultTableModel model = new javax.swing.table.DefaultTableModel(
                tableData, colNames) {
            @Override public boolean isCellEditable(int row, int col) {
                return col == 3 || col == 4; // only role and fixed value
            }
            @Override public Class<?> getColumnClass(int col) {
                if (col == 3) return InputRole.class;
                return String.class;
            }
        };
        JTable table = new JTable(model);
        table.setRowHeight(26);
        table.getColumnModel().getColumn(0).setPreferredWidth(30);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(120);
        table.getColumnModel().getColumn(3).setPreferredWidth(180);
        table.getColumnModel().getColumn(4).setPreferredWidth(120);

        // Role column: combo box editor
        JComboBox<InputRole> roleCombo = new JComboBox<>(InputRole.values());
        table.getColumnModel().getColumn(3).setCellEditor(
                new DefaultCellEditor(roleCombo));

        centerPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Help text
        JTextArea helpText = new JTextArea(
            "Roles:\n" +
            "  • Fuzz buffer pointer — receives pointer to the mmap'd fuzz input buffer\n" +
            "  • Fuzz buffer length — receives the current fuzz input length\n" +
            "  • Fuzz scalar value — parameter itself is fuzzed (e.g. int flags)\n" +
            "  • Fixed / constant — always set to the value in 'Fixed Value' column (hex)\n" +
            "  • Ignore — left at default (zero)\n\n" +
            "Typical pattern: func(char* buf, size_t len) → buf=Fuzz ptr, len=Fuzz len"
        );
        helpText.setEditable(false);
        helpText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        helpText.setRows(6);
        helpText.setBackground(panel.getBackground());
        centerPanel.add(helpText, BorderLayout.SOUTH);

        panel.add(centerPanel, BorderLayout.CENTER);

        // Wire values back on close
        panel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                    && !panel.isShowing()) {
                // Stop any active editing
                if (table.isEditing()) table.getCellEditor().stopCellEditing();
                for (int i = 0; i < config.paramConfigs.size(); i++) {
                    Object roleVal = model.getValueAt(i, 3);
                    if (roleVal instanceof InputRole) {
                        config.paramConfigs.get(i).role = (InputRole) roleVal;
                    }
                    Object fixVal = model.getValueAt(i, 4);
                    if (fixVal != null) {
                        config.paramConfigs.get(i).fixedValue = fixVal.toString();
                    }
                }
            }
        });

        return panel;
    }

    private String buildFuncSignature(FuzzerConfig config) {
        if (config.targetFunction == null) return "(no function selected)";
        StringBuilder sb = new StringBuilder();
        // Show decompiled prototype
        String retType = config.targetFunction.getReturnType().getDisplayName();
        sb.append(retType).append(" ").append(config.targetFunction.getName()).append("(");
        for (int i = 0; i < config.paramConfigs.size(); i++) {
            if (i > 0) sb.append(", ");
            FuncParamConfig p = config.paramConfigs.get(i);
            sb.append(p.dataType).append(" ").append(p.name);
        }
        sb.append(")");
        sb.append("\n@ 0x").append(Long.toHexString(config.entryAddress));
        if (config.decompiledCode != null) {
            // Show first few lines of decompiled code
            String[] lines = config.decompiledCode.split("\n");
            sb.append("\n\n");
            for (int i = 0; i < Math.min(lines.length, 5); i++) {
                sb.append(lines[i]).append("\n");
            }
            if (lines.length > 5) sb.append("  ...");
        }
        return sb.toString();
    }

    // --- External Functions tab ---

    private JPanel createExternsTab(FuzzerConfig config) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        if (config.externalFunctions.isEmpty()) {
            panel.add(new JLabel(
                    "<html><i>No external function calls detected in the target.</i></html>"),
                    BorderLayout.CENTER);
            return panel;
        }

        JLabel desc = new JLabel("<html>External functions called by the target. "
                + "Choose how each should be handled during fuzzing:<br>"
                + "<b>Stub</b> = replace with return 0, "
                + "<b>Skip</b> = let QEMU handle it (libc etc.), "
                + "<b>Hook</b> = custom Rust code.</html>");
        desc.setBorder(new EmptyBorder(0, 0, 8, 0));
        panel.add(desc, BorderLayout.NORTH);

        // Table model
        String[] columns = { "Function", "Library", "Address", "Action" };
        AbstractTableModel model = new AbstractTableModel() {
            @Override public int getRowCount() { return config.externalFunctions.size(); }
            @Override public int getColumnCount() { return 4; }
            @Override public String getColumnName(int col) { return columns[col]; }
            @Override public Object getValueAt(int row, int col) {
                ExternFuncInfo info = config.externalFunctions.get(row);
                return switch (col) {
                    case 0 -> info.name;
                    case 1 -> info.library;
                    case 2 -> info.address != null ? info.address.toString() : "N/A";
                    case 3 -> info.action;
                    default -> "";
                };
            }
            @Override public boolean isCellEditable(int row, int col) { return col == 3; }
            @Override public void setValueAt(Object val, int row, int col) {
                if (col == 3 && val instanceof ExternAction ea) {
                    config.externalFunctions.get(row).action = ea;
                }
            }
            @Override public Class<?> getColumnClass(int col) {
                return col == 3 ? ExternAction.class : String.class;
            }
        };

        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(180);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);

        // Combo box editor for Action column
        JComboBox<ExternAction> combo = new JComboBox<>(ExternAction.values());
        table.getColumnModel().getColumn(3).setCellEditor(
                new DefaultCellEditor(combo));

        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Bulk action buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton stubAll = new JButton("Stub All Non-libc");
        stubAll.addActionListener(e -> {
            for (ExternFuncInfo info : config.externalFunctions) {
                String n = info.name.toLowerCase(Locale.ROOT);
                boolean isLibc = n.contains("malloc") || n.contains("free")
                        || n.contains("memcpy") || n.contains("memset")
                        || n.contains("printf") || n.contains("puts")
                        || n.contains("strlen") || n.contains("strcmp")
                        || n.contains("calloc") || n.contains("realloc");
                info.action = isLibc ? ExternAction.SKIP : ExternAction.STUB_RETURN;
            }
            model.fireTableDataChanged();
        });
        JButton skipAll = new JButton("Skip All");
        skipAll.addActionListener(e -> {
            for (ExternFuncInfo info : config.externalFunctions)
                info.action = ExternAction.SKIP;
            model.fireTableDataChanged();
        });
        buttons.add(stubAll);
        buttons.add(skipAll);
        panel.add(buttons, BorderLayout.SOUTH);

        return panel;
    }

    // --- Globals tab ---

    private JPanel createGlobalsTab(FuzzerConfig config) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        if (config.globals.isEmpty()) {
            panel.add(new JLabel(
                    "<html><i>No global data references detected in the target function."
                    + "<br>If the function uses global state, you may need to set it up "
                    + "manually in harness.rs.</i></html>"),
                    BorderLayout.CENTER);
            return panel;
        }

        JLabel desc = new JLabel("<html>Global variables referenced by the target function. "
                + "Check <b>Init</b> to write an initial value before each fuzz iteration. "
                + "Values in hex (e.g. 0x41414141) or decimal.</html>");
        desc.setBorder(new EmptyBorder(0, 0, 8, 0));
        panel.add(desc, BorderLayout.NORTH);

        String[] columns = { "Init?", "Name", "Address", "Type", "Size", "Init Value" };
        AbstractTableModel model = new AbstractTableModel() {
            @Override public int getRowCount() { return config.globals.size(); }
            @Override public int getColumnCount() { return 6; }
            @Override public String getColumnName(int col) { return columns[col]; }
            @Override public Object getValueAt(int row, int col) {
                GlobalRef g = config.globals.get(row);
                return switch (col) {
                    case 0 -> g.initialize;
                    case 1 -> g.name;
                    case 2 -> g.address.toString();
                    case 3 -> g.dataTypeName;
                    case 4 -> g.size;
                    case 5 -> g.initValue;
                    default -> "";
                };
            }
            @Override public boolean isCellEditable(int row, int col) {
                return col == 0 || col == 5;
            }
            @Override public void setValueAt(Object val, int row, int col) {
                GlobalRef g = config.globals.get(row);
                if (col == 0) g.initialize = (Boolean) val;
                else if (col == 5) g.initValue = val.toString();
            }
            @Override public Class<?> getColumnClass(int col) {
                if (col == 0) return Boolean.class;
                if (col == 4) return Long.class;
                return String.class;
            }
        };

        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(90);
        table.getColumnModel().getColumn(4).setPreferredWidth(50);
        table.getColumnModel().getColumn(5).setPreferredWidth(120);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        return panel;
    }

    // --- Platform tab ---

    private JPanel createPlatformTab(FuzzerConfig config) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel info = new JLabel("<html><b>Platform Notes</b><br><br>"
                + "LibAFL's QEMU usermode backend requires <b>Linux</b>. "
                + "The generated project includes support for:<br><br>"
                + "• <b>Native Linux</b> — build and run directly<br>"
                + "• <b>WSL2 on Windows</b> — run.sh works inside WSL<br>"
                + "• <b>Docker</b> — Dockerfile included for any platform<br><br>"
                + "The generated <code>Dockerfile</code> and <code>docker-run.sh</code> "
                + "handle all dependencies automatically.</html>");
        info.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(info);
        panel.add(Box.createVerticalStrut(16));

        JCheckBox dockerCheck = new JCheckBox("Generate Dockerfile + docker-run scripts",
                true);
        dockerCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(dockerCheck);

        JCheckBox wslCheck = new JCheckBox("Generate WSL launch script (for Windows)",
                true);
        wslCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(wslCheck);

        panel.add(Box.createVerticalGlue());

        // Store for later
        panel.putClientProperty("dockerCheck", dockerCheck);
        panel.putClientProperty("wslCheck", wslCheck);

        return panel;
    }

    // ===================================================================
    // Project generation
    // ===================================================================

    private void generateProject(Path projectDir, FuzzerConfig config)
            throws IOException {
        Files.createDirectories(projectDir);
        Files.createDirectories(projectDir.resolve("src"));
        Files.createDirectories(projectDir.resolve("corpus"));
        Files.createDirectories(projectDir.resolve("crashes"));

        writeFile(projectDir.resolve("Cargo.toml"), genCargoToml(config));
        writeFile(projectDir.resolve("src/main.rs"), genMainRs(config));
        writeFile(projectDir.resolve("src/harness.rs"), genHarnessRs(config));
        writeFile(projectDir.resolve("src/externals.rs"), genExternalsRs(config));
        writeFile(projectDir.resolve("src/globals.rs"), genGlobalsRs(config));
        writeFile(projectDir.resolve("run.ps1"), genRunPs1(config));
        writeFile(projectDir.resolve("run.sh"), genRunSh(config));
        writeFile(projectDir.resolve("Dockerfile"), genDockerfile(config));
        writeFile(projectDir.resolve(".dockerignore"), genDockerIgnore(config));
        writeFile(projectDir.resolve("README.md"), genReadme(config));

        generateSeedCorpus(projectDir.resolve("corpus"), config);
        if (config.generateDictionary) {
            writeFile(projectDir.resolve("dictionary.txt"), genDictionary(config));
        }

        try { projectDir.resolve("run.sh").toFile().setExecutable(true); } catch (Exception ignored) {}
    }

    // ===================================================================
    // Cargo.toml
    // ===================================================================

    private String genCargoToml(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("[package]\n");
        s.append("name = \"").append(config.projectName).append("\"\n");
        s.append("version = \"0.1.0\"\n");
        s.append("edition = \"2021\"\n");
        s.append("publish = false\n\n");
        s.append("# Auto-generated by Ghidra LibAFL Fuzzer Generator\n");
        s.append("# Target: ").append(config.targetBinaryPath).append("\n");
        s.append("# Arch: ").append(config.arch.qemuName).append("\n\n");
        s.append("[dependencies]\n");
        s.append("libafl = { version = \"0.15\", features = [\"std\", \"derive\", \"llmp_compression\"] }\n");
        s.append("libafl_bolts = { version = \"0.15\", features = [\"std\"] }\n");
        s.append("libafl_qemu = { version = \"0.15\", features = [\"usermode\"] }\n");
        s.append("libafl_qemu_sys = { version = \"0.15\" }\n");
        s.append("libafl_targets = { version = \"0.15\", features = [\"std\", \"pointer_maps\"] }\n");
        s.append("log = \"0.4\"\n");
        s.append("env_logger = \"0.11\"\n");
        s.append("goblin = \"0.10\"\n\n");
        s.append("[profile.release]\n");
        s.append("opt-level = 3\n");
        s.append("lto = \"thin\"\n");
        s.append("codegen-units = 1\n");
        s.append("debug = true\n");
        return s.toString();
    }

    // ===================================================================
    // src/main.rs
    // ===================================================================

    private String genMainRs(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("//! LibAFL QEMU fuzzer — auto-generated from Ghidra.\n");
        s.append("#![allow(dead_code, unused_variables)]\n");
        s.append("//! Target: ").append(config.targetBinaryPath).append("\n");
        if (config.targetFunction != null) {
            s.append("//! Function: ").append(config.targetFunction.getName())
             .append(" @ 0x").append(Long.toHexString(config.entryAddress)).append("\n");
        }
        s.append("//! Arch: ").append(config.arch.qemuName).append("\n\n");

        s.append("use std::{env, path::PathBuf, process, time::Duration};\n\n");
        s.append("use std::num::NonZeroUsize;\n");
        s.append("use libafl::{\n");
        s.append("    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},\n");
        s.append("    events::SimpleEventManager,\n");
        s.append("    executors::ExitKind,\n");
        s.append("    feedbacks::{CrashFeedback, MaxMapFeedback},\n");
        s.append("    fuzzer::{Fuzzer, StdFuzzer},\n");
        s.append("    generators::RandBytesGenerator,\n");
        s.append("    inputs::BytesInput,\n");
        s.append("    monitors::SimpleMonitor,\n");
        s.append("    mutators::{havoc_mutations, scheduled::HavocScheduledMutator, Tokens},\n");
        s.append("    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},\n");
        s.append("    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},\n");
        s.append("    stages::StdMutationalStage,\n");
        s.append("    state::{HasCorpus, StdState},\n");
        s.append("    HasMetadata,\n");
        s.append("};\n");
        s.append("use libafl_bolts::{current_nanos, ownedref::OwnedMutSlice, rands::StdRand, tuples::tuple_list};\n");
        s.append("use libafl_targets;\n");
        s.append("use libafl_qemu::{\n");
        s.append("    emu::Emulator, executor::QemuExecutor,\n");
        s.append("    modules::edges::StdEdgeCoverageModule,\n");
        s.append("    GuestAddr, GuestReg, MmapPerms, Qemu, Regs,\n");
        s.append("};\n\n");
        s.append("mod harness;\n");
        s.append("mod externals;\n");
        s.append("mod globals;\n\n");

        s.append("/// Ghidra addresses (with Ghidra's image base)\n");
        s.append("const GHIDRA_ENTRY: GuestAddr = 0x")
         .append(Long.toHexString(config.entryAddress)).append(";\n");
        s.append("const GHIDRA_BASE: GuestAddr = 0x")
         .append(Long.toHexString(config.imageBase)).append(";\n");
        if (config.exitAddress != 0) {
            s.append("const GHIDRA_EXIT: GuestAddr = 0x")
             .append(Long.toHexString(config.exitAddress)).append(";\n");
        }
        if (config.mainAddress != 0) {
            s.append("const GHIDRA_MAIN: GuestAddr = 0x")
             .append(Long.toHexString(config.mainAddress)).append(";\n");
        }
        s.append("const MAX_INPUT_SIZE: usize = ").append(config.maxInputSize).append(";\n");
        s.append("\n");

        s.append("/// Resolve a Ghidra address to a runtime QEMU address.\n");
        s.append("/// For PIE binaries, Ghidra uses an image base (e.g. 0x100000) that differs\n");
        s.append("/// from QEMU's actual load address. This function computes the file offset\n");
        s.append("/// and adds it to the actual QEMU load base.\n");
        s.append("fn resolve_addr(load_base: GuestAddr, ghidra_addr: GuestAddr) -> GuestAddr {\n");
        s.append("    let file_offset = ghidra_addr - GHIDRA_BASE;\n");
        s.append("    let resolved = load_base + file_offset;\n");
        s.append("    log::info!(\"Resolved {:#x} (Ghidra) -> {:#x} (QEMU) [base={:#x}, offset={:#x}]\",\n");
        s.append("        ghidra_addr, resolved, load_base, file_offset);\n");
        s.append("    resolved\n");
        s.append("}\n\n");

        s.append("/// Determine the PIE load base from QEMU's internal state.\n");
        s.append("/// After Emulator::build(), QEMU has loaded the binary into guest memory.\n");
        s.append("/// We use multiple strategies to discover where it was loaded.\n");
        s.append("/// Returns (load_base, is_pie).\n");
        s.append("fn find_load_base(qemu: &Qemu) -> (GuestAddr, bool) {\n");
        s.append("    let args: Vec<String> = std::env::args().collect();\n");
        s.append("    let binary_path = args.iter().rev()\n");
        s.append("        .find(|a| !a.starts_with('-') && *a != \"--\")\n");
        s.append("        .expect(\"Could not find binary path in args\");\n");
        s.append("    \n");
        s.append("    log::info!(\"Parsing ELF: {}\", binary_path);\n");
        s.append("    let binary_data = std::fs::read(binary_path).expect(\"Failed to read binary\");\n");
        s.append("    let elf = goblin::elf::Elf::parse(&binary_data).expect(\"Failed to parse ELF\");\n");
        s.append("    let elf_entry = elf.entry;\n");
        s.append("    let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;\n");
        s.append("    log::info!(\"ELF entry={:#x}, PIE={}\", elf_entry, is_pie);\n");
        s.append("    \n");
        s.append("    if !is_pie {\n");
        s.append("        log::info!(\"Non-PIE binary, load_base = 0\");\n");
        s.append("        return (0, false);\n");
        s.append("    }\n\n");

        s.append("    let first_load_vaddr: u64 = elf.program_headers.iter()\n");
        s.append("        .find(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)\n");
        s.append("        .map(|ph| ph.p_vaddr)\n");
        s.append("        .unwrap_or(0);\n");
        s.append("    let mut load_base: Option<GuestAddr> = None;\n\n");

        // Strategy 1: Parse /proc/self/maps — match ANY mapping of the binary
        s.append("    // Strategy 1: Parse /proc/self/maps.\n");
        s.append("    // In QEMU usermode, the guest binary is mmap'd into the host process.\n");
        s.append("    // Note: QEMU TCG doesn't mark guest code as r-xp (executable) — it loads\n");
        s.append("    // segments as r--p/rw-p since TCG translates at runtime. So we match ANY\n");
        s.append("    // mapping that contains the binary path.\n");
        s.append("    // The load base = mapping_start - file_offset (from the maps line).\n");
        s.append("    let binary_name = std::path::Path::new(binary_path)\n");
        s.append("        .file_name().unwrap().to_str().unwrap();\n");
        s.append("    log::info!(\"Searching /proc/self/maps for '{}'\", binary_name);\n");
        s.append("    if let Ok(maps) = std::fs::read_to_string(\"/proc/self/maps\") {\n");
        s.append("        for line in maps.lines() {\n");
        s.append("            // Match any mapping that contains the binary name\n");
        s.append("            if line.contains(binary_name) {\n");
        s.append("                // Parse: addr_start-addr_end perms file_offset dev inode pathname\n");
        s.append("                let parts: Vec<&str> = line.split_whitespace().collect();\n");
        s.append("                if parts.len() >= 3 {\n");
        s.append("                    let addr_str = parts[0].split('-').next().unwrap_or(\"\");\n");
        s.append("                    let offset_str = parts[2];\n");
        s.append("                    if let (Ok(map_addr), Ok(file_off)) = (\n");
        s.append("                        u64::from_str_radix(addr_str, 16),\n");
        s.append("                        u64::from_str_radix(offset_str, 16),\n");
        s.append("                    ) {\n");
        s.append("                        // load_base = mapping_addr - file_offset\n");
        s.append("                        let base = map_addr - file_off;\n");
        s.append("                        log::info!(\"Found binary mapping: {}\", line.trim());\n");
        s.append("                        log::info!(\"  map_addr={:#x}, file_offset={:#x}, base={:#x}\",\n");
        s.append("                            map_addr, file_off, base);\n");
        s.append("                        load_base = Some(base);\n");
        s.append("                        break;\n");
        s.append("                    }\n");
        s.append("                }\n");
        s.append("            }\n");
        s.append("        }\n");
        s.append("        if load_base.is_none() {\n");
        s.append("            log::warn!(\"Binary not found in /proc/self/maps. Dumping all mappings:\");\n");
        s.append("            for line in maps.lines() {\n");
        s.append("                log::warn!(\"  {}\", line);\n");
        s.append("            }\n");
        s.append("        }\n");
        s.append("    } else {\n");
        s.append("        log::warn!(\"/proc/self/maps not readable\");\n");
        s.append("    }\n\n");

        // Strategy 2: Multi-probe breakpoints at main (not _start, since QEMU may have passed _start)
        s.append("    // Strategy 2: Probe by setting breakpoints at main() with candidate bases.\n");
        s.append("    // Note: By the time Emulator::build() returns, QEMU may have already\n");
        s.append("    // executed past _start. So we probe main() instead.\n");
        s.append("    if load_base.is_none() {\n");

        // Use mainAddress if available, otherwise fall back to entry
        long probeAddr = config.mainAddress != 0 ? config.mainAddress : config.entryAddress;
        long ghidraBase = config.imageBase;
        long probeOffset = probeAddr - ghidraBase;

        s.append("        let probe_offset: u64 = 0x")
         .append(Long.toHexString(probeOffset)).append("; // file offset of probe target\n");
        s.append("        log::info!(\"Probing with offset {:#x} from candidate bases...\", probe_offset);\n");
        s.append("        let candidates: Vec<GuestAddr> = vec![\n");
        s.append("            0x555555554000, 0x4000000000, 0x10000, 0x400000,\n");
        s.append("            0x8000000, 0x100000, 0x0,\n");
        s.append("        ];\n");
        s.append("        for &cand in &candidates {\n");
        s.append("            let addr = cand + probe_offset;\n");
        s.append("            log::info!(\"  Setting BP at {:#x} (base={:#x})\", addr, cand);\n");
        s.append("            qemu.set_breakpoint(addr);\n");
        s.append("        }\n");
        s.append("        unsafe { let _ = qemu.run(); }\n");
        s.append("        let pc: u64 = qemu.read_reg(Regs::Pc).expect(\"read PC\");\n");
        s.append("        log::info!(\"Stopped at PC={:#x}\", pc);\n");
        s.append("        for &cand in &candidates {\n");
        s.append("            qemu.remove_breakpoint(cand + probe_offset);\n");
        s.append("        }\n");
        s.append("        load_base = Some(pc - probe_offset);\n");
        s.append("    }\n\n");

        s.append("    let base = load_base.unwrap();\n");
        s.append("    log::info!(\"Resolved load base = {:#x}\", base);\n");
        s.append("    (base, is_pie)\n");
        s.append("}\n\n");

        s.append("fn main() {\n");
        s.append("    env_logger::init();\n\n");
        s.append("    let args: Vec<String> = env::args().collect();\n");
        s.append("    let qemu_args: Vec<String> = if let Some(pos) = args.iter().position(|a| a == \"--\") {\n");
        s.append("        let mut qa = vec![\"qemu\".to_string()];\n");
        s.append("        qa.extend_from_slice(&args[pos + 1..]);\n");
        s.append("        qa\n");
        s.append("    } else {\n");
        s.append("        eprintln!(\"Usage: {} -- <target_binary> [args]\", args[0]);\n");
        s.append("        process::exit(1);\n");
        s.append("    };\n\n");

        // Create the edges observer FIRST (before emulator, because the module needs it)
        s.append("    // Coverage observer — connected to StdEdgeCoverageModule\n");
        s.append("    let mut edges_observer = unsafe {\n");
        s.append("        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(\n");
        s.append("            \"edges\",\n");
        s.append("            OwnedMutSlice::from_raw_parts_mut(\n");
        s.append("                libafl_targets::edges_map_mut_ptr(),\n");
        s.append("                libafl_targets::EDGES_MAP_DEFAULT_SIZE,\n");
        s.append("            ),\n");
        s.append("            std::ptr::addr_of_mut!(libafl_targets::MAX_EDGES_FOUND),\n");
        s.append("        ))\n");
        s.append("        .track_indices()\n");
        s.append("    };\n\n");

        s.append("    let emu = Emulator::builder()\n");
        s.append("        .qemu_parameters(qemu_args)\n");
        s.append("        .modules(tuple_list!(\n");
        s.append("            StdEdgeCoverageModule::builder()\n");
        s.append("                .map_observer(edges_observer.as_mut())\n");
        s.append("                .build()\n");
        s.append("                .expect(\"Failed to build edge coverage module\")\n");
        s.append("        ))\n");
        s.append("        .build()\n");
        s.append("        .expect(\"Failed to initialize QEMU\");\n");
        s.append("    let qemu = emu.qemu();\n\n");

        s.append("    // === Phase 1: Determine PIE load base ===\n");
        s.append("    let (load_base, _is_pie) = find_load_base(&qemu);\n");
        s.append("    // Note: After find_load_base, QEMU state may be at _start or still\n");
        s.append("    // at initial state depending on which strategy succeeded.\n\n");

        // Phase 2: Run to main() for libc initialization (if main is known)
        if (config.mainAddress != 0) {
            s.append("    // === Phase 2: Run to main() so libc/ld fully initializes ===\n");
            s.append("    let main_addr = resolve_addr(load_base, GHIDRA_MAIN);\n");
            s.append("    log::info!(\"Running to main() at {:#x}\", main_addr);\n");
            s.append("    qemu.set_breakpoint(main_addr);\n");
            s.append("    unsafe { let _ = qemu.run(); }\n");
            s.append("    let pc: u64 = qemu.read_reg(Regs::Pc).unwrap_or(0);\n");
            s.append("    log::info!(\"Stopped at PC={:#x} (expected main={:#x})\", pc, main_addr);\n");
            s.append("    qemu.remove_breakpoint(main_addr);\n\n");
        } else {
            s.append("    // No main() symbol found, staying at _start.\n");
            s.append("    // Note: libc may not be fully initialized.\n\n");
        }

        s.append("    // === Phase 3: Set up fuzzing harness at target function ===\n");
        s.append("    let target_entry = resolve_addr(load_base, GHIDRA_ENTRY);\n");
        s.append("    log::info!(\"Target function at {:#x}\", target_entry);\n\n");

        s.append("    // Map input buffer in guest memory\n");
        s.append("    let input_addr = qemu.map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)\n");
        s.append("        .expect(\"Failed to mmap input buffer\");\n\n");

        s.append("    // Set PC directly to the target function (don't rely on program calling it)\n");
        s.append("    log::info!(\"Jumping PC to target function {:#x}\", target_entry);\n");

        switch (config.arch) {
            case X86_64:
                // For x86_64: set RIP to target, push a fake return address for the exit BP
                s.append("    // Push a return address on the stack for the exit breakpoint\n");
                s.append("    let sp: u64 = qemu.read_reg(Regs::Rsp).unwrap();\n");
                s.append("    let sp = sp - 8; // make room for return address\n");
                break;
            case X86:
                s.append("    let sp: u64 = qemu.read_reg(Regs::Esp).unwrap();\n");
                s.append("    let sp = sp - 4;\n");
                break;
            default:
                break;
        }

        s.append("    \n");

        // Set up exit breakpoint
        // We allocate a "ret-sled" page: a page of NOP/INT3 that the target returns to
        s.append("    // Allocate a return-sled page for the exit breakpoint\n");
        s.append("    let ret_sled = qemu.map_private(0, 4096, MmapPerms::ReadWriteExecute)\n");
        s.append("        .expect(\"Failed to mmap ret-sled\");\n");
        s.append("    // Fill with NOP (0x90) — the breakpoint fires before executing.\n");
        s.append("    // Using NOP instead of INT3 avoids a crash if the BP mechanism\n");
        s.append("    // doesn't fire before instruction execution.\n");
        s.append("    let sled_data = vec![0x90u8; 4096];\n");
        s.append("    let _ = qemu.write_mem(ret_sled, &sled_data);\n");
        s.append("    log::info!(\"Return sled at {:#x}\", ret_sled);\n\n");

        // Push ret_sled as return address and set PC
        switch (config.arch) {
            case X86_64:
                s.append("    // Write ret_sled as return address on stack, set PC\n");
                s.append("    let _ = qemu.write_mem(sp, &ret_sled.to_le_bytes());\n");
                s.append("    let _ = qemu.write_reg(Regs::Rsp, sp);\n");
                s.append("    let _ = qemu.write_reg(Regs::Rip, target_entry);\n");
                break;
            case X86:
                s.append("    let _ = qemu.write_mem(sp, &(ret_sled as u32).to_le_bytes());\n");
                s.append("    let _ = qemu.write_reg(Regs::Esp, sp);\n");
                s.append("    let _ = qemu.write_reg(Regs::Eip, target_entry);\n");
                break;
            case ARM: case AARCH64:
                s.append("    // Set LR to ret_sled, PC to target\n");
                s.append("    let _ = qemu.write_reg(Regs::Lr, ret_sled);\n");
                s.append("    let _ = qemu.write_reg(Regs::Pc, target_entry);\n");
                break;
            case MIPS: case MIPSEL:
                s.append("    let _ = qemu.write_reg(Regs::Ra, ret_sled);\n");
                s.append("    let _ = qemu.write_reg(Regs::Pc, target_entry);\n");
                break;
            default:
                s.append("    // TODO: set PC and return address for your architecture\n");
        }
        s.append("    \n");

        s.append("    // Set breakpoint at the return sled (this is our \"exit\" for the harness)\n");
        s.append("    qemu.set_breakpoint(ret_sled);\n\n");

        s.append("    // Install external function hooks/stubs\n");
        s.append("    externals::install_hooks(&qemu);\n\n");

        s.append("    // Setup target state (registers, args, globals)\n");
        s.append("    harness::setup_target_state(&qemu, input_addr, MAX_INPUT_SIZE);\n");
        s.append("    globals::initialize_globals(&qemu);\n");
        s.append("    // Save the initial state (PC, SP) for restoring each fuzzing iteration\n");
        s.append("    harness::save_state(&qemu);\n\n");

        // Feedback & objective (observer was created above, before emulator)
        s.append("    let time_observer = TimeObserver::new(\"time\");\n");
        s.append("    let mut feedback = MaxMapFeedback::new(&edges_observer);\n");
        s.append("    let mut objective = CrashFeedback::new();\n\n");

        s.append("    let mut state = StdState::new(\n");
        s.append("        StdRand::with_seed(current_nanos()),\n");
        s.append("        InMemoryCorpus::new(),\n");
        s.append("        OnDiskCorpus::new(PathBuf::from(\"./crashes\")).unwrap(),\n");
        s.append("        &mut feedback, &mut objective,\n");
        s.append("    ).unwrap();\n\n");

        if (config.generateDictionary) {
            s.append("    // Load dictionary\n");
            s.append("    if let Ok(data) = std::fs::read_to_string(\"dictionary.txt\") {\n");
            s.append("        let mut tokens = Tokens::new();\n");
            s.append("        for line in data.lines() {\n");
            s.append("            let t = line.trim();\n");
            s.append("            if !t.is_empty() && !t.starts_with('#') {\n");
            s.append("                tokens.add_token(&t.trim_matches('\"').as_bytes().to_vec());\n");
            s.append("            }\n");
            s.append("        }\n");
            s.append("        if !tokens.is_empty() { state.add_metadata(tokens); }\n");
            s.append("    }\n\n");
        }

        s.append("    let monitor = SimpleMonitor::new(|s| println!(\"{s}\"));\n");
        s.append("    let mut mgr = SimpleEventManager::new(monitor);\n");
        s.append("    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());\n");
        s.append("    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);\n\n");

        s.append("    let qemu_ref = qemu.clone();\n");
        s.append("    let mut harness_fn = move |_emu_ref: &mut _, _state: &mut _, input: &BytesInput| -> ExitKind {\n");
        s.append("        harness::run_target(&qemu_ref, input)\n");
        s.append("    };\n");
        s.append("    let mut executor = QemuExecutor::new(\n");
        s.append("        emu, &mut harness_fn,\n");
        s.append("        tuple_list!(edges_observer, time_observer),\n");
        s.append("        &mut fuzzer, &mut state, &mut mgr,\n");
        s.append("        Duration::from_secs(5),\n");
        s.append("    ).expect(\"Failed to create executor\");\n\n");

        s.append("    let corpus_dir = PathBuf::from(\"./corpus\");\n");
        s.append("    if corpus_dir.exists() {\n");
        s.append("        let _ = state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir]);\n");
        s.append("    }\n");
        s.append("    if state.corpus().count() == 0 {\n");
        s.append("        let mut gen = RandBytesGenerator::new(NonZeroUsize::new(MAX_INPUT_SIZE).unwrap());\n");
        s.append("        state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut gen, &mut mgr, 256)\n");
        s.append("            .expect(\"Failed to generate seeds\");\n");
        s.append("    }\n\n");

        s.append("    let mutator = HavocScheduledMutator::new(havoc_mutations());\n");
        s.append("    let mut stages = tuple_list!(StdMutationalStage::new(mutator));\n\n");

        s.append("    println!(\"[*] Starting fuzzing...\");\n");
        s.append("    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)\n");
        s.append("        .expect(\"Fuzz loop failed\");\n");
        s.append("}\n");

        return s.toString();
    }

    // ===================================================================
    // src/harness.rs
    // ===================================================================

    private String genHarnessRs(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("//! Target-specific harness. Auto-generated from Ghidra.\n\n");
        s.append("use libafl::executors::ExitKind;\n");
        s.append("use libafl::inputs::{BytesInput, HasTargetBytes};\n");
        s.append("use libafl_qemu::{GuestAddr, GuestReg, Qemu, QemuExitReason, Regs};\n");
        s.append("use libafl_bolts::AsSlice;\n\n");

        s.append("static mut INPUT_ADDR: GuestAddr = 0;\n");
        s.append("static mut INPUT_MAX_SIZE: usize = 0;\n");
        s.append("static mut SAVED_PC: GuestAddr = 0;\n");
        s.append("static mut SAVED_SP: GuestAddr = 0;\n\n");

        s.append("/// Save the initial harness state (PC, SP) so we can restore each iteration.\n");
        s.append("pub fn save_state(qemu: &Qemu) {\n");
        switch (config.arch) {
            case X86_64:
                s.append("    unsafe {\n");
                s.append("        SAVED_PC = qemu.read_reg(Regs::Rip).unwrap();\n");
                s.append("        SAVED_SP = qemu.read_reg(Regs::Rsp).unwrap();\n");
                s.append("    }\n");
                break;
            case X86:
                s.append("    unsafe {\n");
                s.append("        SAVED_PC = qemu.read_reg(Regs::Eip).unwrap();\n");
                s.append("        SAVED_SP = qemu.read_reg(Regs::Esp).unwrap();\n");
                s.append("    }\n");
                break;
            case ARM: case AARCH64:
                s.append("    unsafe {\n");
                s.append("        SAVED_PC = qemu.read_reg(Regs::Pc).unwrap();\n");
                s.append("        SAVED_SP = qemu.read_reg(Regs::Sp).unwrap();\n");
                s.append("    }\n");
                break;
            default:
                s.append("    unsafe {\n");
                s.append("        SAVED_PC = qemu.read_reg(Regs::Pc).unwrap();\n");
                s.append("        SAVED_SP = 0; // TODO\n");
                s.append("    }\n");
        }
        s.append("    log::info!(\"Saved state: PC={:#x}, SP={:#x}\", unsafe { SAVED_PC }, unsafe { SAVED_SP });\n");
        s.append("}\n\n");

        // Decompiled code as reference
        if (config.decompiledCode != null && !config.decompiledCode.isEmpty()) {
            s.append("/*\n * Decompiled target (from Ghidra):\n");
            for (String line : config.decompiledCode.split("\n")) {
                s.append(" * ").append(line).append("\n");
            }
            s.append(" */\n\n");
        }

        // Memory map reference
        s.append("// Memory map:\n");
        for (MemRegion r : config.memoryMap) {
            s.append(String.format("//   %-20s 0x%08x - 0x%08x %s%s%s\n",
                    r.name, r.start, r.end,
                    r.read ? "R" : "-", r.write ? "W" : "-", r.execute ? "X" : "-"));
        }
        s.append("\n");

        // setup_target_state — initial setup of function arguments
        s.append("pub fn setup_target_state(qemu: &Qemu, input_addr: GuestAddr, max_size: usize) {\n");
        s.append("    unsafe { INPUT_ADDR = input_addr; INPUT_MAX_SIZE = max_size; }\n\n");
        s.append("    // Set function arguments per input mapping from Ghidra config.\n");
        for (FuncParamConfig p : config.paramConfigs) {
            String comment = String.format("    // param[%d] %s %s → %s\n",
                p.index, p.dataType, p.name, p.role.label);
            s.append(comment);
            switch (p.role) {
                case FUZZ_PTR:
                    genSetArg(s, config.arch, p.index, "input_addr");
                    break;
                case FUZZ_LEN:
                    genSetArg(s, config.arch, p.index, "max_size as GuestReg");
                    break;
                case FUZZ_VALUE:
                    genSetArg(s, config.arch, p.index, "0 as GuestReg"); // initial 0, overwritten per-iteration
                    break;
                case FIXED:
                    genSetArg(s, config.arch, p.index, p.fixedValue + " as GuestReg");
                    break;
                case IGNORE:
                    // leave default
                    break;
            }
        }
        s.append("}\n\n");

        // find_exit_address (kept for compatibility but unused with ret-sled approach)
        s.append("pub fn find_exit_address(qemu: &Qemu, _entry: GuestAddr) -> GuestAddr {\n");
        switch (config.arch) {
            case ARM: case AARCH64:
                s.append("    let lr: GuestAddr = qemu.read_reg(Regs::Lr).unwrap();\n");
                s.append("    log::info!(\"Exit address (LR): {:#x}\", lr);\n    lr\n");
                break;
            case X86:
                s.append("    let sp: GuestAddr = qemu.read_reg(Regs::Esp).unwrap();\n");
                s.append("    let mut buf = [0u8; 4];\n");
                s.append("    let _ = qemu.read_mem(sp, &mut buf);\n");
                s.append("    let ret = u32::from_le_bytes(buf) as GuestAddr;\n");
                s.append("    log::info!(\"Exit address (ret): {:#x}\", ret);\n    ret\n");
                break;
            case X86_64:
                s.append("    let sp: GuestAddr = qemu.read_reg(Regs::Rsp).unwrap();\n");
                s.append("    let mut buf = [0u8; 8];\n");
                s.append("    let _ = qemu.read_mem(sp, &mut buf);\n");
                s.append("    let ret = u64::from_le_bytes(buf) as GuestAddr;\n");
                s.append("    log::info!(\"Exit address (ret): {:#x}\", ret);\n    ret\n");
                break;
            default:
                s.append("    log::warn!(\"Cannot auto-detect exit; using entry+0x1000\");\n");
                s.append("    _entry + 0x1000\n");
        }
        s.append("}\n\n");

        // run_target — called from the closure in main.rs
        s.append("/// Per-iteration target execution. Called from the harness closure.\n");
        s.append("pub fn run_target(qemu: &Qemu, input: &BytesInput) -> ExitKind {\n");
        s.append("    let target = input.target_bytes();\n");
        s.append("    let bytes = target.as_slice();\n");
        s.append("    let len = bytes.len().min(unsafe { INPUT_MAX_SIZE });\n");
        s.append("    if len == 0 { return ExitKind::Ok; }\n\n");

        // Restore PC and SP to the saved state (start of target function)
        s.append("    // Restore PC/SP to target function entry\n");
        switch (config.arch) {
            case X86_64:
                s.append("    let _ = qemu.write_reg(Regs::Rip, unsafe { SAVED_PC });\n");
                s.append("    let _ = qemu.write_reg(Regs::Rsp, unsafe { SAVED_SP });\n");
                break;
            case X86:
                s.append("    let _ = qemu.write_reg(Regs::Eip, unsafe { SAVED_PC });\n");
                s.append("    let _ = qemu.write_reg(Regs::Esp, unsafe { SAVED_SP });\n");
                break;
            case ARM: case AARCH64:
                s.append("    let _ = qemu.write_reg(Regs::Pc, unsafe { SAVED_PC });\n");
                s.append("    let _ = qemu.write_reg(Regs::Sp, unsafe { SAVED_SP });\n");
                break;
            default:
                s.append("    let _ = qemu.write_reg(Regs::Pc, unsafe { SAVED_PC });\n");
        }
        s.append("\n");

        s.append("    // Write fuzz data to the input buffer\n");
        s.append("    let _ = qemu.write_mem(unsafe { INPUT_ADDR }, &bytes[..len]);\n\n");

        // Set arguments per iteration based on paramConfigs
        s.append("    // Set arguments per input mapping\n");

        // Track offset into fuzz input for FUZZ_VALUE params
        boolean hasFuzzValue = config.paramConfigs.stream()
            .anyMatch(p -> p.role == InputRole.FUZZ_VALUE);
        if (hasFuzzValue) {
            s.append("    let mut fuzz_offset = 0usize;\n");
        }

        for (FuncParamConfig p : config.paramConfigs) {
            switch (p.role) {
                case FUZZ_PTR:
                    s.append("    // ").append(p.name).append(" → fuzz buffer ptr\n");
                    genSetArg(s, config.arch, p.index, "unsafe { INPUT_ADDR }");
                    break;
                case FUZZ_LEN:
                    s.append("    // ").append(p.name).append(" → fuzz length\n");
                    genSetArg(s, config.arch, p.index, "len as GuestReg");
                    break;
                case FUZZ_VALUE:
                    s.append("    // ").append(p.name).append(" → fuzzed scalar (")
                     .append(p.fuzzValueSize).append(" bytes from input)\n");
                    s.append("    {\n");
                    s.append("        let vsize = ").append(p.fuzzValueSize).append(";\n");
                    s.append("        let mut vbuf = [0u8; 8];\n");
                    s.append("        let end = (fuzz_offset + vsize).min(len);\n");
                    s.append("        if fuzz_offset < len {\n");
                    s.append("            vbuf[..end-fuzz_offset].copy_from_slice(&bytes[fuzz_offset..end]);\n");
                    s.append("        }\n");
                    s.append("        let val = u64::from_le_bytes(vbuf);\n");
                    genSetArg(s, config.arch, p.index, "val as GuestReg");
                    s.append("        fuzz_offset += vsize;\n");
                    s.append("    }\n");
                    break;
                case FIXED:
                    s.append("    // ").append(p.name).append(" → fixed: ")
                     .append(p.fixedValue).append("\n");
                    genSetArg(s, config.arch, p.index, p.fixedValue + " as GuestReg");
                    break;
                case IGNORE:
                    // nothing
                    break;
            }
        }

        s.append("\n    // Initialize globals before each iteration\n");
        s.append("    crate::globals::initialize_globals(qemu);\n\n");
        s.append("    unsafe {\n");
        s.append("        match qemu.run() {\n");
        s.append("            Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,\n");
        s.append("            Ok(QemuExitReason::End(_)) => ExitKind::Ok,\n");
        s.append("            Err(_) => ExitKind::Crash,\n");
        s.append("            _ => ExitKind::Ok,\n");
        s.append("        }\n    }\n}\n");
        return s.toString();
    }

    // ===================================================================
    // Helper: generate code to set a function argument by index
    // ===================================================================

    /**
     * Generates Rust code to write a value to function argument [argIndex]
     * using the appropriate calling convention for the target architecture.
     */
    private void genSetArg(StringBuilder s, TargetArch arch, int argIndex, String valueExpr) {
        switch (arch) {
            case X86_64: {
                // System V AMD64: RDI, RSI, RDX, RCX, R8, R9, then stack
                String[] regs = {"Rdi", "Rsi", "Rdx", "Rcx", "R8", "R9"};
                if (argIndex < regs.length) {
                    s.append("    let _ = qemu.write_reg(Regs::").append(regs[argIndex])
                     .append(", ").append(valueExpr).append(");\n");
                } else {
                    int stackOff = (argIndex - 6) * 8 + 8; // +8 for return address
                    s.append("    { let sp: u64 = qemu.read_reg(Regs::Rsp).unwrap();\n");
                    s.append("      let _ = qemu.write_mem(sp + ").append(stackOff)
                     .append(", &(").append(valueExpr).append(" as u64).to_le_bytes()); }\n");
                }
                break;
            }
            case X86: {
                // cdecl: all args on stack  [esp+4], [esp+8], ...
                int stackOff = (argIndex + 1) * 4; // +4 for return address
                s.append("    { let sp: u64 = qemu.read_reg(Regs::Esp).unwrap();\n");
                s.append("      let _ = qemu.write_mem(sp + ").append(stackOff)
                 .append(", &(").append(valueExpr).append(" as u32).to_le_bytes()); }\n");
                break;
            }
            case ARM: {
                // ARM EABI: R0-R3, then stack
                String[] regs = {"R0", "R1", "R2", "R3"};
                if (argIndex < regs.length) {
                    s.append("    let _ = qemu.write_reg(Regs::").append(regs[argIndex])
                     .append(", ").append(valueExpr).append(");\n");
                } else {
                    int stackOff = (argIndex - 4) * 4;
                    s.append("    { let sp: u64 = qemu.read_reg(Regs::Sp).unwrap();\n");
                    s.append("      let _ = qemu.write_mem(sp + ").append(stackOff)
                     .append(", &(").append(valueExpr).append(" as u32).to_le_bytes()); }\n");
                }
                break;
            }
            case AARCH64: {
                // AAPCS64: X0-X7, then stack
                String[] regs = {"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"};
                if (argIndex < regs.length) {
                    s.append("    let _ = qemu.write_reg(Regs::").append(regs[argIndex])
                     .append(", ").append(valueExpr).append(");\n");
                } else {
                    int stackOff = (argIndex - 8) * 8;
                    s.append("    { let sp: u64 = qemu.read_reg(Regs::Sp).unwrap();\n");
                    s.append("      let _ = qemu.write_mem(sp + ").append(stackOff)
                     .append(", &(").append(valueExpr).append(" as u64).to_le_bytes()); }\n");
                }
                break;
            }
            case MIPS: case MIPSEL: {
                // MIPS O32: $a0-$a3, then stack
                String[] regs = {"A0", "A1", "A2", "A3"};
                if (argIndex < regs.length) {
                    s.append("    let _ = qemu.write_reg(Regs::").append(regs[argIndex])
                     .append(", ").append(valueExpr).append(");\n");
                } else {
                    int stackOff = argIndex * 4; // MIPS always reserves stack space for a0-a3
                    s.append("    { let sp: u64 = qemu.read_reg(Regs::Sp).unwrap();\n");
                    s.append("      let _ = qemu.write_mem(sp + ").append(stackOff)
                     .append(", &(").append(valueExpr).append(" as u32).to_le_bytes()); }\n");
                }
                break;
            }
            default:
                s.append("    // TODO: set arg[").append(argIndex).append("] = ")
                 .append(valueExpr).append("\n");
        }
    }

    // ===================================================================
    // src/externals.rs — external function stubs/hooks
    // ===================================================================

    private String genExternalsRs(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("//! External function stubs and hooks.\n");
        s.append("//! Auto-generated from Ghidra import analysis.\n\n");
        s.append("use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};\n\n");

        s.append("pub fn install_hooks(qemu: &Qemu) {\n");

        boolean hasStubs = false;
        for (ExternFuncInfo ext : config.externalFunctions) {
            if (ext.action == ExternAction.SKIP) continue;
            hasStubs = true;

            String addrStr = ext.address != null
                    ? "0x" + Long.toHexString(ext.address.getOffset())
                    : "0 /* FIXME: unknown address */";

            s.append("\n    // ").append(ext.name)
             .append(" (").append(ext.library).append(")\n");

            switch (ext.action) {
                case STUB_RETURN:
                    s.append("    // Stub: set return value to 0 and skip\n");
                    s.append("    qemu.set_breakpoint(").append(addrStr).append(");\n");
                    s.append("    // When hit, the hook handler should:\n");
                    s.append("    //   1. Set return register to 0\n");
                    s.append("    //   2. Set PC to return address\n");
                    s.append("    log::info!(\"Stub installed for ").append(ext.name)
                     .append(" @ {:#x}\", ").append(addrStr).append(");\n");
                    break;
                case STUB_PASSTHROUGH:
                    s.append("    // Passthrough: function executes normally in QEMU\n");
                    s.append("    log::info!(\"Passthrough for ").append(ext.name).append("\");\n");
                    break;
                case HOOK_CUSTOM:
                    s.append("    // Custom hook — implement your logic here\n");
                    s.append("    qemu.set_breakpoint(").append(addrStr).append(");\n");
                    if (!ext.customHookCode.isEmpty()) {
                        s.append("    ").append(ext.customHookCode).append("\n");
                    } else {
                        s.append("    // TODO: Add custom hook code for ").append(ext.name).append("\n");
                    }
                    break;
                default:
                    break;
            }
        }

        if (!hasStubs) {
            s.append("    // No stubs configured — all externals handled by QEMU's libc\n");
            s.append("    log::info!(\"No external function hooks installed\");\n");
        }

        s.append("}\n\n");

        // Document all externals
        s.append("// All detected external functions:\n");
        for (ExternFuncInfo ext : config.externalFunctions) {
            s.append(String.format("//   %-30s %-15s %s  [%s]\n",
                    ext.name, ext.library,
                    ext.address != null ? ext.address.toString() : "N/A",
                    ext.action.label));
        }

        return s.toString();
    }

    // ===================================================================
    // src/globals.rs — global state initialization
    // ===================================================================

    private String genGlobalsRs(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("//! Global state initialization.\n");
        s.append("//! Auto-generated from Ghidra data reference analysis.\n\n");
        s.append("use libafl_qemu::{GuestAddr, Qemu};\n\n");

        s.append("/// Initialize global variables before each fuzz iteration.\n");
        s.append("/// This ensures deterministic state for reproducibility.\n");
        s.append("pub fn initialize_globals(qemu: &Qemu) {\n");

        boolean hasInits = false;
        for (GlobalRef g : config.globals) {
            if (!g.initialize) continue;
            hasInits = true;

            s.append("\n    // ").append(g.name)
             .append(" (").append(g.dataTypeName)
             .append(", ").append(g.size).append(" bytes)\n");
            s.append("    {\n");
            s.append("        let addr: GuestAddr = 0x")
             .append(Long.toHexString(g.address.getOffset())).append(";\n");

            // Parse init value
            String val = g.initValue.trim();
            if (g.size <= 8) {
                s.append("        let value: u64 = ").append(val).append(";\n");
                s.append("        let bytes = value.to_le_bytes();\n");
                s.append("        let _ = qemu.write_mem(addr, &bytes[..").append(g.size).append("]);\n");
            } else {
                s.append("        // Zero-fill ").append(g.size).append(" bytes\n");
                s.append("        let zeros = vec![0u8; ").append(g.size).append("];\n");
                s.append("        let _ = qemu.write_mem(addr, &zeros);\n");
            }
            s.append("    }\n");
        }

        if (!hasInits) {
            s.append("    // No globals configured for initialization.\n");
            s.append("    // Use the Globals tab in the generator to select variables.\n");
            s.append("    let _ = qemu; // suppress unused warning\n");
        }

        s.append("}\n\n");

        // Document all detected globals
        s.append("// All detected global references:\n");
        for (GlobalRef g : config.globals) {
            s.append(String.format("//   %-25s @ %-12s  %-15s  %d bytes  %s\n",
                    g.name, g.address, g.dataTypeName, g.size,
                    g.initialize ? "[INIT=" + g.initValue + "]" : ""));
        }

        return s.toString();
    }

    // ===================================================================
    // Dockerfile
    // ===================================================================

    private String genDockerfile(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("# ").append(config.projectName).append(" — LibAFL QEMU Fuzzer\n");
        s.append("# Multi-stage build: compiles QEMU + fuzzer, produces slim runtime image.\n\n");

        s.append("FROM debian:bookworm AS builder\n\n");

        s.append("# Install system build dependencies\n");
        s.append("RUN apt-get update && apt-get install -y --no-install-recommends \\\n");
        s.append("    build-essential cmake ninja-build pkg-config curl ca-certificates git \\\n");
        s.append("    python3 python3-venv python3-pip python3-setuptools \\\n");
        s.append("    libglib2.0-dev libpixman-1-dev libslirp-dev \\\n");
        s.append("    lsb-release wget software-properties-common gnupg \\\n");
        s.append("    && rm -rf /var/lib/apt/lists/*\n\n");

        s.append("# Install LLVM 20 (required by libafl_qemu — must match rustc's LLVM version)\n");
        s.append("RUN wget -qO- https://apt.llvm.org/llvm.sh | bash -s -- 20 \\\n");
        s.append("    && apt-get install -y --no-install-recommends llvm-20-dev libclang-20-dev \\\n");
        s.append("    && ln -sf /usr/bin/llvm-config-20 /usr/bin/llvm-config \\\n");
        s.append("    && rm -rf /var/lib/apt/lists/*\n\n");

        s.append("# Install Rust via rustup (gets latest stable, currently 1.87+)\n");
        s.append("RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n");
        s.append("ENV PATH=\"/root/.cargo/bin:${PATH}\"\n\n");

        s.append("WORKDIR /fuzzer\n");
        s.append("COPY Cargo.toml .\n");
        s.append("COPY src/ src/\n\n");

        s.append("# Build — show full output so errors are visible\n");
        s.append("RUN cargo build --release && \\\n");
        s.append("    ls -la /fuzzer/target/release/ | head -20\n\n");

        s.append("# --- Runtime stage ---\n");
        s.append("FROM debian:bookworm-slim\n\n");
        s.append("RUN apt-get update && apt-get install -y --no-install-recommends \\\n");
        s.append("    libglib2.0-0 libpixman-1-0 libslirp0 \\\n");
        s.append("    && rm -rf /var/lib/apt/lists/*\n\n");
        s.append("WORKDIR /fuzzer\n");
        s.append("COPY --from=builder /fuzzer/target/release/").append(config.projectName).append(" .\n");
        s.append("COPY corpus/ corpus/\n");
        s.append("COPY crashes/ crashes/\n");
        if (config.generateDictionary) {
            s.append("COPY dictionary.txt .\n");
        }
        s.append("\n# Mount your target binary at runtime:\n");
        s.append("#   docker run -v /path/to/binary:/fuzzer/target_binary ...\n");
        s.append("ENV RUST_LOG=info\n");
        s.append("ENTRYPOINT [\"./").append(config.projectName).append("\"]\n");
        s.append("CMD [\"--\", \"./target_binary\"]\n");
        return s.toString();
    }

    // ===================================================================
    // Scripts
    // ===================================================================

    private String genRunSh(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("#!/bin/bash\n");
        s.append("# ").append(config.projectName).append(" — LibAFL QEMU Fuzzer\n");
        s.append("# Works on native Linux and WSL2.\n");
        s.append("set -e\n\n");

        // Detect WSL and warn about /mnt/c performance
        s.append("# --- Warn if building on Windows filesystem (slow) ---\n");
        s.append("if [[ \"$(pwd)\" == /mnt/c/* ]] || [[ \"$(pwd)\" == /mnt/d/* ]]; then\n");
        s.append("    echo \"\"\n");
        s.append("    echo \"[!] WARNING: You are building on the Windows filesystem (/mnt/c/...).\"\n");
        s.append("    echo \"    This is ~10x slower than building on the WSL native filesystem.\"\n");
        s.append("    echo \"    Recommended: cp -r $(pwd) ~/").append(config.projectName).append(" && cd ~/").append(config.projectName).append("\"\n");
        s.append("    echo \"\"\n");
        s.append("fi\n\n");

        // Dependency check
        s.append("# --- Check dependencies ---\n");
        s.append("MISSING=\"\"\n");
        s.append("command -v cargo  >/dev/null 2>&1 || MISSING=\"$MISSING rust/cargo\"\n");
        s.append("command -v cmake  >/dev/null 2>&1 || MISSING=\"$MISSING cmake\"\n");
        s.append("command -v ninja  >/dev/null 2>&1 || MISSING=\"$MISSING ninja-build\"\n");
        s.append("command -v python3 >/dev/null 2>&1 || MISSING=\"$MISSING python3\"\n");
        s.append("command -v pkg-config >/dev/null 2>&1 || MISSING=\"$MISSING pkg-config\"\n");
        s.append("python3 -c 'import ensurepip' 2>/dev/null || MISSING=\"$MISSING python3-venv\"\n\n");

        // Check libraries
        s.append("pkg-config --exists glib-2.0 2>/dev/null || MISSING=\"$MISSING libglib2.0-dev\"\n");
        s.append("pkg-config --exists pixman-1 2>/dev/null || MISSING=\"$MISSING libpixman-1-dev\"\n\n");

        s.append("if [ -n \"$MISSING\" ]; then\n");
        s.append("    echo \"\"\n");
        s.append("    echo \"[!] Missing dependencies:$MISSING\"\n");
        s.append("    echo \"\"\n");
        s.append("    echo \"    Install them with:\"\n");
        s.append("    echo \"    sudo apt update && sudo apt install -y \\\\\"\n");
        s.append("    echo \"        build-essential cmake ninja-build python3 python3-venv \\\\\"\n");
        s.append("    echo \"        python3-pip libglib2.0-dev libpixman-1-dev libslirp-dev pkg-config\"\n");
        s.append("    echo \"\"\n");
        s.append("    if command -v apt >/dev/null 2>&1; then\n");
        s.append("        read -p \"    Install now? [Y/n] \" -n 1 -r\n");
        s.append("        echo\n");
        s.append("        if [[ ! $REPLY =~ ^[Nn]$ ]]; then\n");
        s.append("            sudo apt update\n");
        s.append("            sudo apt install -y build-essential cmake ninja-build python3 python3-venv \\\n");
        s.append("                python3-pip libglib2.0-dev libpixman-1-dev libslirp-dev pkg-config\n");
        s.append("        else\n");
        s.append("            exit 1\n");
        s.append("        fi\n");
        s.append("    else\n");
        s.append("        exit 1\n");
        s.append("    fi\n");
        s.append("fi\n\n");

        // Check Rust
        s.append("if ! command -v cargo >/dev/null 2>&1; then\n");
        s.append("    echo \"[!] Rust not found. Installing via rustup...\"\n");
        s.append("    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n");
        s.append("    source \"$HOME/.cargo/env\"\n");
        s.append("fi\n\n");

        // Build
        s.append("echo \"[*] Building (first build compiles QEMU — this takes 10-20 min)...\"\n");
        s.append("cargo build --release\n\n");

        // Run
        s.append("echo \"\"\n");
        s.append("echo \"[*] Starting fuzzer\"\n");
        s.append("echo \"    Arch:   ").append(config.arch.qemuName).append("\"\n");
        s.append("echo \"    Entry:  0x").append(Long.toHexString(config.entryAddress)).append("\"\n");
        s.append("echo \"\"\n");
        s.append("RUST_LOG=info ./target/release/").append(config.projectName);
        s.append(" -- \"${1:-").append(config.targetBinaryPath).append("}\" \"${@:2}\"\n");

        return s.toString();
    }

    private String genRunBat(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("@echo off\n");
        s.append("REM ").append(config.projectName).append(" - LibAFL QEMU Fuzzer\n");
        s.append("REM LibAFL QEMU requires Linux. This script launches via WSL or Docker.\n");
        s.append("REM For best results, copy the project into WSL and run run.sh directly.\n\n");

        s.append("where wsl >nul 2>nul\n");
        s.append("if %errorlevel% equ 0 (\n");
        s.append("    echo [*] Launching via WSL...\n");
        s.append("    echo     NOTE: Building on /mnt/c is slow. For faster builds:\n");
        s.append("    echo       wsl cp -r \"%~dp0\" ~/").append(config.projectName).append("\n");
        s.append("    echo       wsl bash -c \"cd ~/").append(config.projectName).append(" ^&^& bash run.sh\"\n");
        s.append("    echo.\n");
        s.append("    wsl bash -lc \"cd '$(wslpath '%~dp0')' && bash run.sh %*\"\n");
        s.append(") else (\n");
        s.append("    where docker >nul 2>nul\n");
        s.append("    if %errorlevel% equ 0 (\n");
        s.append("        echo [*] WSL not found. Using Docker...\n");
        s.append("        docker build -t ").append(config.projectName).append(" \"%~dp0\"\n");
        s.append("        docker run --rm -it -v \"%cd%\\corpus:/fuzzer/corpus\" ");
        s.append("-v \"%cd%\\crashes:/fuzzer/crashes\" ");
        s.append(config.projectName).append(" -- %*\n");
        s.append("    ) else (\n");
        s.append("        echo [!] Neither WSL nor Docker found.\n");
        s.append("        echo     LibAFL QEMU requires Linux. Please install one of:\n");
        s.append("        echo       - WSL2: wsl --install\n");
        s.append("        echo       - Docker Desktop: https://docker.com/products/docker-desktop/\n");
        s.append("        exit /b 1\n");
        s.append("    )\n");
        s.append(")\n");
        return s.toString();
    }

    private String genDockerIgnore(FuzzerConfig config) {
        return "target/\ncrashes/*\n*.exe\n*.pdb\n.git/\n";
    }

    /**
     * PowerShell script — native Windows entry point.
     * Uses Docker under the hood (no WSL needed).
     */
    private String genRunPs1(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("# ").append(config.projectName).append(" - LibAFL QEMU Fuzzer\n");
        s.append("# Usage: .\\run.ps1 -TargetBinary <path> [-Rebuild] [-Shell]\n");
        s.append("#\n");
        s.append("# LibAFL QEMU requires Linux. This script uses Docker transparently.\n");
        s.append("# Prerequisite: Docker Desktop (https://docker.com/products/docker-desktop/)\n\n");

        s.append("param(\n");
        s.append("    [Parameter(Mandatory=$true)]\n");
        s.append("    [string]$TargetBinary,\n");
        s.append("    [switch]$Rebuild,\n");
        s.append("    [switch]$Shell\n");
        s.append(")\n\n");

        s.append("$ErrorActionPreference = \"Stop\"\n");
        s.append("$ImageName = \"").append(config.projectName).append("\"\n");
        s.append("$ProjectDir = $PSScriptRoot\n\n");

        // Docker check
        s.append("# --- Check Docker ---\n");
        s.append("if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {\n");
        s.append("    Write-Host \"`n[!] Docker not found.\" -ForegroundColor Red\n");
        s.append("    Write-Host \"    Install Docker Desktop: https://docker.com/products/docker-desktop/\"\n");
        s.append("    Write-Host \"    Or use WSL: wsl bash run.sh`n\"\n");
        s.append("    exit 1\n");
        s.append("}\n");
        s.append("$null = docker info 2>&1\n");
        s.append("if ($LASTEXITCODE -ne 0) {\n");
        s.append("    Write-Host \"`n[!] Docker daemon not running. Start Docker Desktop first.`n\" -ForegroundColor Red\n");
        s.append("    exit 1\n");
        s.append("}\n\n");

        // Build image
        s.append("# --- Build image (cached after first run) ---\n");
        s.append("$imageExists = docker images -q $ImageName 2>$null\n");
        s.append("if ($Rebuild -or -not $imageExists) {\n");
        s.append("    Write-Host \"`n[*] Building Docker image (first time takes ~15 min)...\" -ForegroundColor Cyan\n");
        s.append("    docker build -t $ImageName $ProjectDir\n");
        s.append("    if ($LASTEXITCODE -ne 0) { Write-Host \"[!] Build failed.\" -ForegroundColor Red; exit 1 }\n");
        s.append("    Write-Host \"[+] Image ready.`n\" -ForegroundColor Green\n");
        s.append("} else {\n");
        s.append("    Write-Host \"[*] Using cached image (use -Rebuild to force rebuild)\" -ForegroundColor DarkGray\n");
        s.append("}\n\n");

        // Resolve binary
        s.append("# --- Resolve target binary ---\n");
        s.append("$resolved = Resolve-Path $TargetBinary\n");
        s.append("$binaryName = Split-Path $resolved -Leaf\n");
        s.append("$binaryDir  = Split-Path $resolved -Parent\n\n");

        // Ensure corpus/crashes dirs
        s.append("$corpusDir = Join-Path $ProjectDir \"corpus\"\n");
        s.append("$crashDir  = Join-Path $ProjectDir \"crashes\"\n");
        s.append("if (-not (Test-Path $corpusDir)) { $null = New-Item -ItemType Directory $corpusDir }\n");
        s.append("if (-not (Test-Path $crashDir))  { $null = New-Item -ItemType Directory $crashDir }\n\n");

        // Run
        s.append("# --- Run ---\n");
        s.append("$dockerArgs = @(\n");
        s.append("    \"run\", \"--rm\", \"-it\",\n");
        s.append("    \"-v\", \"${binaryDir}:/target:ro\",\n");
        s.append("    \"-v\", \"${corpusDir}:/fuzzer/corpus\",\n");
        s.append("    \"-v\", \"${crashDir}:/fuzzer/crashes\"\n");
        s.append(")\n\n");

        s.append("if ($Shell) {\n");
        s.append("    Write-Host \"[*] Opening shell in container...\" -ForegroundColor Cyan\n");
        s.append("    & docker @dockerArgs --entrypoint /bin/bash $ImageName\n");
        s.append("} else {\n");
        s.append("    Write-Host \"[*] Starting fuzzer\" -ForegroundColor Green\n");
        s.append("    Write-Host \"    Binary: $resolved\"\n");
        s.append("    Write-Host \"    Arch:   ").append(config.arch.qemuName).append("\"\n");
        s.append("    Write-Host \"    Entry:  0x").append(Long.toHexString(config.entryAddress)).append("`n\"\n");
        s.append("    & docker @dockerArgs $ImageName \"--\" \"/target/$binaryName\"\n");
        s.append("}\n");

        return s.toString();
    }

    // ===================================================================
    // Dictionary + Corpus
    // ===================================================================

    private String genDictionary(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("# Dictionary from Ghidra string analysis\n\n");
        for (String str : config.seedStrings) {
            String escaped = str.replace("\\", "\\\\").replace("\"", "\\\"");
            if (escaped.length() <= 64) s.append("\"").append(escaped).append("\"\n");
        }
        s.append("\n# Common edge-case tokens\n");
        s.append("\"\\x00\\x00\\x00\\x00\"\n");
        s.append("\"\\xff\\xff\\xff\\xff\"\n");
        s.append("\"\\x7f\\xff\\xff\\xff\"\n");
        s.append("\"\\x80\\x00\\x00\\x00\"\n");
        return s.toString();
    }

    private void generateSeedCorpus(Path corpusDir, FuzzerConfig config)
            throws IOException {
        Files.write(corpusDir.resolve("seed_zeros"), new byte[64]);
        byte[] inc = new byte[256];
        for (int i = 0; i < 256; i++) inc[i] = (byte) i;
        Files.write(corpusDir.resolve("seed_incremental"), inc);
        int n = 3;
        for (int i = 0; i < Math.min(config.seedStrings.size(), 10); i++) {
            String str = config.seedStrings.get(i);
            if (str.length() >= 4) {
                Files.writeString(corpusDir.resolve("seed_str_" + n++), str);
            }
        }
        byte[] ints = new byte[32];
        putInt(ints, 0, 0); putInt(ints, 4, 1); putInt(ints, 8, -1);
        putInt(ints, 12, Integer.MAX_VALUE); putInt(ints, 16, Integer.MIN_VALUE);
        putInt(ints, 20, 0x41414141); putInt(ints, 24, 0xdeadbeef);
        Files.write(corpusDir.resolve("seed_ints"), ints);
    }

    private void putInt(byte[] buf, int off, int val) {
        buf[off] = (byte)(val); buf[off+1] = (byte)(val>>8);
        buf[off+2] = (byte)(val>>16); buf[off+3] = (byte)(val>>24);
    }

    // ===================================================================
    // README
    // ===================================================================

    private String genReadme(FuzzerConfig config) {
        StringBuilder s = new StringBuilder();
        s.append("# ").append(config.projectName).append("\n\n");
        s.append("Auto-generated LibAFL QEMU fuzzer.\n\n");
        s.append("## Target\n\n");
        s.append("| | |\n|---|---|\n");
        s.append("| Binary | `").append(config.targetBinaryPath).append("` |\n");
        s.append("| Architecture | ").append(config.arch.qemuName).append(" |\n");
        s.append("| Entry | `0x").append(Long.toHexString(config.entryAddress)).append("` |\n");
        if (config.targetFunction != null) {
            s.append("| Function | `").append(config.targetFunction.getName()).append("` |\n");
        }
        s.append("\n");

        s.append("## Quick Start\n\n");
        s.append("> LibAFL QEMU requires a Linux environment. Choose the option that fits your setup.\n\n");

        // Windows PowerShell (Docker)
        s.append("### Windows — PowerShell + Docker (easiest)\n\n");
        s.append("Requires: [Docker Desktop](https://docker.com/products/docker-desktop/)\n\n");
        s.append("```powershell\n");
        s.append(".\\run.ps1 -TargetBinary .\\path\\to\\binary\n\n");
        s.append("# First run builds the Docker image (~15 min), then cached.\n");
        s.append("# Use -Rebuild to force rebuild, -Shell to get a bash shell inside.\n");
        s.append("```\n\n");

        // Windows CMD (WSL fallback)
        s.append("### Windows — CMD/bat via WSL\n\n");
        s.append("```cmd\n");
        s.append("run.bat path\\to\\binary\n");
        s.append("```\n\n");

        // WSL direct
        s.append("### WSL2 (fastest builds)\n\n");
        s.append("```bash\n");
        s.append("# Copy project to WSL filesystem for 10x faster builds:\n");
        s.append("cp -r /mnt/c/.../").append(config.projectName).append(" ~/").append(config.projectName).append("\n");
        s.append("cd ~/").append(config.projectName).append("\n\n");
        s.append("# run.sh auto-checks and offers to install missing deps\n");
        s.append("bash run.sh ./target_binary\n");
        s.append("```\n\n");

        // Native Linux
        s.append("### Native Linux\n\n");
        s.append("```bash\n");
        s.append("# run.sh handles dependency checks automatically\n");
        s.append("bash run.sh ./target_binary\n\n");
        s.append("# Or manually:\n");
        s.append("sudo apt install build-essential cmake ninja-build python3 python3-venv \\\n");
        s.append("    libglib2.0-dev libpixman-1-dev libslirp-dev pkg-config\n");
        s.append("cargo build --release\n");
        s.append("RUST_LOG=info ./target/release/").append(config.projectName);
        s.append(" -- ./target_binary\n");
        s.append("```\n\n");

        s.append("## Project Files\n\n");
        s.append("| File | Purpose |\n|---|---|\n");
        s.append("| `run.ps1` | **Windows entry point** — PowerShell + Docker |\n");
        s.append("| `run.bat` | CMD wrapper — uses WSL or Docker |\n");
        s.append("| `run.sh` | **Linux/WSL entry point** — auto-installs deps |\n");
        s.append("| `Dockerfile` | Self-contained Linux build environment |\n");
        s.append("| `src/harness.rs` | Target-specific harness (**edit this**) |\n");
        s.append("| `src/externals.rs` | External function stubs/hooks |\n");
        s.append("| `src/globals.rs` | Global variable initialization |\n");
        s.append("| `dictionary.txt` | Token dictionary for mutations |\n");
        s.append("| `corpus/` | Seed inputs |\n");
        s.append("| `crashes/` | Crash-triggering inputs (output) |\n\n");

        if (!config.externalFunctions.isEmpty()) {
            s.append("## External Functions\n\n");
            s.append("| Function | Library | Action |\n|---|---|---|\n");
            for (ExternFuncInfo ext : config.externalFunctions) {
                s.append("| `").append(ext.name).append("` | ")
                 .append(ext.library).append(" | ")
                 .append(ext.action.label).append(" |\n");
            }
            s.append("\n");
        }

        if (!config.globals.isEmpty()) {
            s.append("## Referenced Globals\n\n");
            s.append("| Name | Address | Type | Init? |\n|---|---|---|---|\n");
            for (GlobalRef g : config.globals) {
                s.append("| `").append(g.name).append("` | `")
                 .append(g.address).append("` | ").append(g.dataTypeName)
                 .append(" | ").append(g.initialize ? "Yes (" + g.initValue + ")" : "No")
                 .append(" |\n");
            }
            s.append("\n");
        }

        s.append("## Troubleshooting\n\n");
        s.append("| Problem | Solution |\n|---|---|\n");
        s.append("| `cmake not found` | `sudo apt install cmake ninja-build` |\n");
        s.append("| `ensurepip not found` | `sudo apt install python3-venv` |\n");
        s.append("| `cargo not found` in WSL | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \\| sh` |\n");
        s.append("| Build very slow | Don't build on `/mnt/c/` — copy to `~/` in WSL |\n");
        s.append("| Docker build fails | Ensure Docker Desktop is running with Linux containers |\n");
        s.append("| No new coverage | Review `src/harness.rs` — input may not reach target code |\n");

        return s.toString();
    }

    // ===================================================================
    // Analysis helpers
    // ===================================================================

    private TargetArch detectArch() {
        if (currentProgram == null) return TargetArch.UNKNOWN;
        Language lang = currentProgram.getLanguage();
        String proc = lang.getProcessor().toString().toLowerCase(Locale.ROOT);
        int ptr = currentProgram.getDefaultPointerSize();
        if (proc.contains("aarch64")) return TargetArch.AARCH64;
        if (proc.contains("arm")) return ptr >= 8 ? TargetArch.AARCH64 : TargetArch.ARM;
        if (proc.contains("x86")) return ptr >= 8 ? TargetArch.X86_64 : TargetArch.X86;
        if (proc.contains("mips")) return lang.isBigEndian() ? TargetArch.MIPS : TargetArch.MIPSEL;
        if (proc.contains("ppc")) return TargetArch.PPC;
        return ptr >= 8 ? TargetArch.X86_64 : TargetArch.X86;
    }

    private List<MemRegion> extractMemoryMap() {
        List<MemRegion> regions = new ArrayList<>();
        if (currentProgram == null) return regions;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() && !block.isMapped()) continue;
            regions.add(new MemRegion(block.getName(),
                    block.getStart().getOffset(), block.getEnd().getOffset(),
                    block.isRead(), block.isWrite(), block.isExecute()));
        }
        return regions;
    }

    private List<String> extractInterestingStrings(int limit) {
        List<String> strings = new ArrayList<>();
        if (currentProgram == null) return strings;
        DataIterator iter = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        while (iter.hasNext() && count < limit) {
            Data data = iter.next();
            if (data.hasStringValue()) {
                try {
                    Object val = data.getValue();
                    if (val instanceof String sv && sv.length() >= 3 && sv.length() <= 128) {
                        strings.add(sv);
                        count++;
                    }
                } catch (Exception ignored) {}
            }
        }
        return strings;
    }

    private long findFunctionExitAddress(Function func) {
        if (func == null) return 0;
        try {
            AddressSetView body = func.getBody();
            Address max = body.getMaxAddress();
            if (max != null) {
                Instruction instr = currentProgram.getListing().getInstructionAt(max);
                if (instr != null) return instr.getAddress().getOffset();
                return max.getOffset();
            }
        } catch (Exception ignored) {}
        return 0;
    }

    private String decompileFunction(Function func) {
        if (func == null) return null;
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
            String code = results.decompileCompleted()
                    ? results.getDecompiledFunction().getC() : null;
            decomp.dispose();
            return code;
        } catch (Exception e) {
            Msg.warn(this, "Decompilation failed: " + e.getMessage());
            return null;
        }
    }

    private Symbol findSymbol(String name) {
        if (currentProgram == null) return null;
        SymbolIterator iter = currentProgram.getSymbolTable().getSymbols(name);
        return iter.hasNext() ? iter.next() : null;
    }

    private String sanitizeName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_]", "_").replaceAll("_+", "_")
                   .toLowerCase(Locale.ROOT);
    }

    private void writeFile(Path path, String content) throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(path.toFile()))) {
            pw.print(content);
        }
    }

    @Override
    protected void dispose() {
        if (generateAction != null) tool.removeAction(generateAction);
        if (generateFromFuncAction != null) tool.removeAction(generateFromFuncAction);
        super.dispose();
    }
}