package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import javax.swing.JOptionPane;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Create struct from memory selection",
    description = "Creates a struct from selected memory with automatic field naming based on references"
)
//@formatter:on
public class MemoryToStructPlugin extends ProgramPlugin {

    public MemoryToStructPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        DockingAction action = new DockingAction("Create Struct from Memory Selection", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    createStructFromSelection(context);
                } catch (Exception e) {
                    Msg.showError(this, null, "Error", "Failed: " + e.getMessage(), e);
                }
            }

            @Override
            public boolean isValidContext(ActionContext context) {
                if (currentProgram == null) {
                    return false;
                }
                
                if (context instanceof ListingActionContext) {
                    ListingActionContext listingContext = (ListingActionContext) context;
                    // Check if there's a selection
                    if (listingContext.hasSelection()) {
                        AddressSetView selection = listingContext.getSelection();
                        return selection != null && !selection.isEmpty();
                    }
                }
                
                return false;
            }
            
            @Override
            public boolean isAddToPopup(ActionContext context) {
                return isValidContext(context);
            }
        };

        action.setPopupMenuData(new MenuData(new String[] { "Create Struct from Selection" }));
        tool.addAction(action);
    }
    
    private void createStructFromSelection(ActionContext context) throws Exception {
        if (!(context instanceof ListingActionContext)) {
            return;
        }
        
        ListingActionContext listingContext = (ListingActionContext) context;
        AddressSetView selection = listingContext.getSelection();
        
        if (selection == null || selection.isEmpty()) {
            Msg.showWarn(this, null, "No Selection", "Please select a memory region first");
            return;
        }
        
        // Get the selection bounds
        Address startAddr = selection.getMinAddress();
        Address endAddr = selection.getMaxAddress();
        long size = endAddr.subtract(startAddr) + 1;
        
        if (size <= 0 || size > 100000) {
            Msg.showWarn(this, null, "Invalid Size", 
                "Selection size must be between 1 and 100000 bytes. Selected: " + size);
            return;
        }
        
        // Ask for struct name
        String structName = JOptionPane.showInputDialog(null, 
            "Enter name for the new struct:", 
            "Struct Name", 
            JOptionPane.QUESTION_MESSAGE);
        
        if (structName == null || structName.trim().isEmpty()) {
            return;
        }
        
        structName = structName.trim();
        
        // Create the struct
        int transaction = currentProgram.startTransaction("Create Struct from Memory");
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            StructureDataType newStruct = new StructureDataType(structName, 0);
            newStruct.setPackingEnabled(false);
            
            int pointerSize = currentProgram.getDefaultPointerSize();
            Memory memory = currentProgram.getMemory();
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            
            // Iterate through the selection, pointer-size at a time
            Address currentAddr = startAddr;
            int fieldIndex = 0;
            
            while (currentAddr.compareTo(endAddr) <= 0) {
                long remaining = endAddr.subtract(currentAddr) + 1;
                
                if (remaining >= pointerSize) {
                    // Read pointer value
                    long pointerValue = 0;
                    try {
                        if (pointerSize == 8) {
                            pointerValue = memory.getLong(currentAddr);
                        } else if (pointerSize == 4) {
                            pointerValue = memory.getInt(currentAddr) & 0xFFFFFFFFL;
                        }
                        
                        // Check if this looks like a valid address
                        Address targetAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                        
                        // Get field name based on what this pointer references
                        String fieldName = getFieldNameForPointer(currentAddr, targetAddr, symbolTable, refMgr);
                        
                        // Add pointer field
                        newStruct.add(new PointerDataType(), pointerSize, fieldName, null);
                        
                        currentAddr = currentAddr.add(pointerSize);
                        fieldIndex++;
                    } catch (Exception e) {
                        // If we can't read or it's invalid, add undefined pointer
                        newStruct.add(new PointerDataType(), pointerSize, "field_" + fieldIndex, null);
                        currentAddr = currentAddr.add(pointerSize);
                        fieldIndex++;
                    }
                } else {
                    // Remaining bytes - add as byte array or individual bytes
                    for (int i = 0; i < remaining; i++) {
                        newStruct.add(ByteDataType.dataType, 1, "padding_" + i, null);
                    }
                    break;
                }
            }
            
            // Add the struct to the data type manager
            DataType addedStruct = dtm.addDataType(newStruct, null);
            
            // Apply the struct at the selection start address
            Listing listing = currentProgram.getListing();
            Data data = listing.getDataAt(startAddr);
            if (data != null) {
                listing.clearCodeUnits(startAddr, endAddr, false);
            }
            listing.createData(startAddr, addedStruct);
            
            currentProgram.endTransaction(transaction, true);
            
            Msg.showInfo(this, null, "Success", 
                "Created struct '" + structName + "' with " + fieldIndex + " fields\n" +
                "Applied at address " + startAddr);
        } catch (Exception e) {
            currentProgram.endTransaction(transaction, false);
            throw e;
        }
    }
    
    private String getFieldNameForPointer(Address pointerAddr, Address targetAddr, 
                                         SymbolTable symbolTable, ReferenceManager refMgr) {
        try {
            // Check if target address is valid
            if (targetAddr == null || !currentProgram.getMemory().contains(targetAddr)) {
                return "ptr_" + pointerAddr.getOffset();
            }
            
            // Check for references from this pointer location
            Reference[] refsFrom = refMgr.getReferencesFrom(pointerAddr);
            if (refsFrom != null && refsFrom.length > 0) {
                // Use the first reference's target
                Address refTarget = refsFrom[0].getToAddress();
                
                // Get symbol at target
                Symbol symbol = symbolTable.getPrimarySymbol(refTarget);
                if (symbol != null) {
                    return sanitizeFieldName(symbol.getName());
                }
            }
            
            // Check for symbols at the target address directly
            Symbol symbol = symbolTable.getPrimarySymbol(targetAddr);
            if (symbol != null) {
                return sanitizeFieldName(symbol.getName());
            }
            
            // Check if target is a function
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            Function func = funcMgr.getFunctionAt(targetAddr);
            if (func != null) {
                return sanitizeFieldName(func.getName());
            }
            
            // Check for any symbol nearby (within 16 bytes)
            SymbolIterator symbols = symbolTable.getSymbolIterator(targetAddr, true);
            if (symbols.hasNext()) {
                Symbol nearbySymbol = symbols.next();
                if (nearbySymbol.getAddress().subtract(targetAddr) < 16) {
                    return sanitizeFieldName(nearbySymbol.getName());
                }
            }
            
            // Default: use target address
            return "ptr_" + targetAddr.toString().replace(":", "_");
            
        } catch (Exception e) {
            return "field_" + pointerAddr.getOffset();
        }
    }
    
    private String sanitizeFieldName(String name) {
        if (name == null || name.isEmpty()) {
            return "field";
        }
        
        // Remove invalid characters and replace with underscore
        String sanitized = name.replaceAll("[^a-zA-Z0-9_]", "_");
        
        // Ensure it starts with a letter or underscore
        if (!sanitized.matches("^[a-zA-Z_].*")) {
            sanitized = "_" + sanitized;
        }
        
        // Limit length
        if (sanitized.length() > 64) {
            sanitized = sanitized.substring(0, 64);
        }
        
        return sanitized;
    }
}
