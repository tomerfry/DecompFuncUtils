package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData; // [Added Import]
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.decompiler.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.awt.event.InputEvent; // [Added Import]
import java.awt.event.KeyEvent;   // [Added Import]

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DecompFuncUtils",
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Navigate to struct field targets",
    description = "Enables navigation to functions/labels by clicking struct field names in decompiler"
)
//@formatter:on
public class StructFieldNavigationPlugin extends ProgramPlugin {

    public StructFieldNavigationPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        // Action with dynamic menu name
        DockingAction navigateAction = new DockingAction("Navigate to Field Target", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    navigateToFieldTarget(context);
                } catch (Exception e) {
                    Msg.showError(this, null, "Navigation Error", 
                        "Failed to navigate: " + e.getMessage(), e);
                }
            }

            @Override
            public boolean isValidContext(ActionContext context) {
                if (currentProgram == null || !(context instanceof DecompilerActionContext)) {
                    return false;
                }
                
                DecompilerActionContext decompContext = (DecompilerActionContext) context;
                ClangToken token = decompContext.getTokenAtCursor();
                
                if (token == null) {
                    return false;
                }
                
                // Check if this is a field token
                if (token instanceof ClangFieldToken) {
                    String fieldName = token.getText();
                    // Check if a symbol exists with this name
                    return findSymbolByName(fieldName) != null;
                }
                
                return false;
            }
            
            @Override
            public boolean isAddToPopup(ActionContext context) {
                if (!isValidContext(context)) {
                    return false;
                }
                
                // Update menu text dynamically
                DecompilerActionContext decompContext = (DecompilerActionContext) context;
                ClangToken token = decompContext.getTokenAtCursor();
                if (token != null) {
                    String fieldName = token.getText();
                    setPopupMenuData(
                        new MenuData(new String[] { "Go to '" + fieldName + "'" }, "Navigation")
                    );
                }
                
                return true;
            }
        };
        
        // Set default menu data
        navigateAction.setPopupMenuData(
            new MenuData(new String[] { "Go to Field Target" }, "Navigation")
        );

        // [Added] Set Key Binding to Ctrl+G
        navigateAction.setKeyBindingData(
            new KeyBindingData(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK)
        );
        
        tool.addAction(navigateAction);
    }
    
    private void navigateToFieldTarget(ActionContext context) throws Exception {
        if (!(context instanceof DecompilerActionContext)) {
            return;
        }
        
        DecompilerActionContext decompContext = (DecompilerActionContext) context;
        ClangToken token = decompContext.getTokenAtCursor();
        
        if (token == null) {
            Msg.showWarn(this, null, "No Token", "No token at cursor");
            return;
        }
        
        String fieldName = token.getText();
        
        // Find symbol with this name
        Symbol symbol = findSymbolByName(fieldName);
        
        if (symbol == null) {
            Msg.showInfo(this, null, "Not Found", 
                "No function or label named '" + fieldName + "' found");
            return;
        }
        
        // Navigate to the symbol's address
        Address targetAddr = symbol.getAddress();
        
        if (targetAddr == null) {
            Msg.showWarn(this, null, "No Address", 
                "Symbol '" + fieldName + "' has no address");
            return;
        }
        
        // Navigate using the parent class's goTo method
        goTo(targetAddr);
        
        tool.setStatusInfo("Navigated to '" + fieldName + "' at " + targetAddr);
    }
    
    private Symbol findSymbolByName(String name) {
        if (currentProgram == null || name == null || name.isEmpty()) {
            return null;
        }
        
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Try to find as function first by iterating through all functions
        for (Function func : funcMgr.getFunctions(true)) {
            if (func.getName().equals(name)) {
                return func.getSymbol();
            }
        }
        
        // Search for symbol by name
        SymbolIterator symbols = symbolTable.getSymbols(name);
        
        // Prefer functions and labels
        Symbol bestMatch = null;
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            
            // Prioritize functions
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                return sym;
            }
            
            // Then labels
            if (sym.getSymbolType() == SymbolType.LABEL) {
                bestMatch = sym;
            }
            
            // Keep any match as fallback
            if (bestMatch == null) {
                bestMatch = sym;
            }
        }
        
        return bestMatch;
    }
}