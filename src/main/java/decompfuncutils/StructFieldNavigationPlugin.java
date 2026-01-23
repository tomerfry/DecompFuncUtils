package decompfuncutils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.awt.AWTEvent;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger; // [Added Import]

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

    private AWTEventListener globalMouseListener;

    public StructFieldNavigationPlugin(PluginTool tool) {
        super(tool);
        createActions();
        setupGlobalMouseListener();
    }

    private void setupGlobalMouseListener() {
        globalMouseListener = new AWTEventListener() {
            @Override
            public void eventDispatched(AWTEvent event) {
                if (event.getID() == MouseEvent.MOUSE_CLICKED) {
                    MouseEvent mouseEvent = (MouseEvent) event;
                    if (mouseEvent.getClickCount() == 2 && mouseEvent.getButton() == MouseEvent.BUTTON1) {
                        checkForDecompilerNavigation(mouseEvent);
                    }
                }
            }
        };

        Toolkit.getDefaultToolkit().addAWTEventListener(globalMouseListener, AWTEvent.MOUSE_EVENT_MASK);
    }

    private void checkForDecompilerNavigation(MouseEvent e) {
        Component clickedComponent = (Component) e.getSource();
        DecompilerPanel panel = findDecompilerPanel(clickedComponent);

        if (panel != null) {
            // Since the double click places the cursor, we can just get the token at the cursor
            ClangToken token = getTokenAtCursor(panel);
            
            if (token != null) {
                handleNavigation(token, null);
            }
        }
    }

    private DecompilerPanel findDecompilerPanel(Component c) {
        while (c != null) {
            if (c instanceof DecompilerPanel) {
                return (DecompilerPanel) c;
            }
            c = c.getParent();
        }
        return null;
    }

    /**
     * Retrieves the token at the current cursor position in the DecompilerPanel.
     */
    private ClangToken getTokenAtCursor(DecompilerPanel panel) {
        FieldPanel fieldPanel = panel.getFieldPanel();
        
        // Get current cursor location
        FieldLocation loc = fieldPanel.getCursorLocation();
        
        if (loc == null) {
            return null;
        }

        // Retrieve the Layout using the BigInteger index
        Layout layout = fieldPanel.getLayoutModel().getLayout(loc.getIndex());
        
        if (layout == null) {
            return null;
        }

        // Get the specific field within the layout
        docking.widgets.fieldpanel.field.Field field = layout.getField(loc.getFieldNum());
        
        if (field instanceof ClangTextField) {
            ClangTextField clangField = (ClangTextField) field;
            return clangField.getToken(loc);
        }
        return null;
    }

    @Override
    protected void dispose() {
        if (globalMouseListener != null) {
            Toolkit.getDefaultToolkit().removeAWTEventListener(globalMouseListener);
            globalMouseListener = null;
        }
        super.dispose();
    }

    private void createActions() {
        DockingAction navigateAction = new DockingAction("Navigate to Field Target", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (context instanceof DecompilerActionContext) {
                    DecompilerActionContext decompContext = (DecompilerActionContext) context;
                    handleNavigation(decompContext.getTokenAtCursor(), null);
                }
            }

            @Override
            public boolean isValidContext(ActionContext context) {
                if (currentProgram == null || !(context instanceof DecompilerActionContext)) {
                    return false;
                }
                DecompilerActionContext decompContext = (DecompilerActionContext) context;
                ClangToken token = decompContext.getTokenAtCursor();
                return getTargetSymbol(token) != null;
            }
            
            @Override
            public boolean isAddToPopup(ActionContext context) {
                if (!isValidContext(context)) return false;
                
                DecompilerActionContext decompContext = (DecompilerActionContext) context;
                ClangToken token = decompContext.getTokenAtCursor();
                if (token != null) {
                    setPopupMenuData(
                        new MenuData(new String[] { "Go to '" + token.getText() + "'" }, "Navigation")
                    );
                }
                return true;
            }
        };
        
        navigateAction.setPopupMenuData(new MenuData(new String[] { "Go to Field Target" }, "Navigation"));
        navigateAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK));
        
        tool.addAction(navigateAction);
    }

    private void handleNavigation(ClangToken token, Component sourceComponent) {
        Symbol symbol = getTargetSymbol(token);
        
        if (symbol == null) {
            if (sourceComponent != null) { 
                Msg.showWarn(this, null, "Navigation Failed", "Could not find target symbol.");
            }
            return;
        }

        Address targetAddr = symbol.getAddress();
        if (targetAddr != null) {
            goTo(targetAddr);
            tool.setStatusInfo("Navigated to '" + symbol.getName() + "' at " + targetAddr);
        }
    }

    private Symbol getTargetSymbol(ClangToken token) {
        if (token == null || !(token instanceof ClangFieldToken)) {
            return null;
        }
        return findSymbolByName(token.getText());
    }
    
    private Symbol findSymbolByName(String name) {
        if (currentProgram == null || name == null || name.isEmpty()) {
            return null;
        }
        
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        for (Function func : funcMgr.getFunctions(true)) {
            if (func.getName().equals(name)) {
                return func.getSymbol();
            }
        }
        
        SymbolIterator symbols = symbolTable.getSymbols(name);
        Symbol bestMatch = null;
        
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) return sym;
            if (sym.getSymbolType() == SymbolType.LABEL) bestMatch = sym;
            if (bestMatch == null) bestMatch = sym;
        }
        
        return bestMatch;
    }
}