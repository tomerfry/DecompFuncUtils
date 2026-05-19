package decompfuncutils.mcp.tools;

import decompfuncutils.mcp.McpImageContent;
import decompfuncutils.mcp.McpTool;
import docking.ComponentProvider;
import docking.DockingWindowManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import javax.imageio.ImageIO;
import javax.swing.JComponent;
import javax.swing.JFrame;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.*;

/**
 * Captures a screenshot of the Ghidra GUI — the operator's point of view.
 *
 * <p>Rather than grabbing raw screen pixels (which break under window occlusion),
 * this renders a specific Swing component to a {@link BufferedImage}. It can target
 * a named dockable panel (the decompiler, the listing, ...), whichever panel the
 * operator currently has focused, or the whole tool window, and optionally crop to
 * a sub-region.
 */
public class ScreenshotTool implements McpTool {

    @Override
    public String name() { return "ghidra_screenshot"; }

    @Override
    public String description() {
        return "Capture a screenshot of the Ghidra GUI as a PNG image — the operator's point of view. "
             + "Renders a specific dockable panel ('decompiler', 'listing', ...), the focused panel "
             + "('active'), or the whole tool window ('window'). Optionally crop to a [x,y,w,h] region. "
             + "Captures the live component even if it is occluded by other windows.";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        Map<String, Object> props = new LinkedHashMap<>();

        Map<String, Object> target = new LinkedHashMap<>();
        target.put("type", "string");
        target.put("description", "What to capture: 'decompiler', 'listing', 'symbol tree', 'data types', "
            + "'active' (the currently focused panel), 'window' (the whole Ghidra tool window), or the "
            + "exact display name of any other dockable provider. Defaults to 'active'.");
        props.put("target", target);

        Map<String, Object> region = new LinkedHashMap<>();
        region.put("type", "array");
        region.put("description", "Optional crop region [x, y, width, height] in pixels, relative to the "
            + "captured component's top-left corner. Out-of-bounds values are clamped.");
        Map<String, Object> items = new LinkedHashMap<>();
        items.put("type", "integer");
        region.put("items", items);
        region.put("minItems", 4);
        region.put("maxItems", 4);
        props.put("region", region);

        schema.put("properties", props);
        return schema;
    }

    @Override
    public boolean requiresEdt() {
        return true; // Swing rendering must happen on the Event Dispatch Thread.
    }

    @Override
    public Object execute(Map<String, Object> arguments, Program program, PluginTool tool) throws Exception {
        if (tool == null) {
            throw new RuntimeException("No Ghidra tool available to capture.");
        }

        String target = arguments.get("target") != null
            ? String.valueOf(arguments.get("target")).trim()
            : "active";

        Component component;
        String label;

        switch (target.toLowerCase()) {
            case "window":
            case "main":
            case "tool": {
                JFrame frame = tool.getToolFrame();
                if (frame == null) {
                    throw new RuntimeException("Tool window is not available.");
                }
                component = frame.getRootPane();
                label = "Ghidra tool window";
                break;
            }
            case "active":
            case "focused": {
                DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
                ComponentProvider provider = dwm != null ? dwm.getActiveComponentProvider() : null;
                if (provider == null) {
                    throw new RuntimeException("No panel is currently focused; specify an explicit target.");
                }
                component = bringUp(tool, provider);
                label = "Active panel: " + provider.getName();
                break;
            }
            default: {
                String name = resolveProviderName(target);
                ComponentProvider provider = tool.getComponentProvider(name);
                if (provider == null) {
                    throw new RuntimeException("No dockable panel named '" + name + "' found. "
                        + "Try 'decompiler', 'listing', 'active', or 'window'.");
                }
                component = bringUp(tool, provider);
                label = "Panel: " + provider.getName();
            }
        }

        BufferedImage image = render(component);

        int[] crop = parseRegion(arguments.get("region"));
        if (crop != null) {
            image = cropImage(image, crop);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (!ImageIO.write(image, "png", baos)) {
            throw new RuntimeException("Failed to encode screenshot as PNG.");
        }
        String base64 = Base64.getEncoder().encodeToString(baos.toByteArray());

        String caption = label + " — " + image.getWidth() + "x" + image.getHeight() + " px";
        return new McpImageContent(base64, "image/png", caption);
    }

    /** Maps friendly aliases to Ghidra's canonical provider display names. */
    private static String resolveProviderName(String target) {
        switch (target.toLowerCase()) {
            case "decompiler":   return "Decompiler";
            case "listing":      return "Listing";
            case "symboltree":
            case "symbol tree":  return "Symbol Tree";
            case "functions":    return "Functions";
            case "datatypes":
            case "data types":   return "Data Type Manager";
            default:             return target;
        }
    }

    /** Resolves a provider's component, surfacing it first if it is not currently shown. */
    private static Component bringUp(PluginTool tool, ComponentProvider provider) {
        JComponent comp = provider.getComponent();
        if (comp == null) {
            throw new RuntimeException("Panel '" + provider.getName() + "' has no renderable component.");
        }
        if (!comp.isShowing()) {
            tool.showComponentProvider(provider, true);
        }
        return comp;
    }

    /** Renders a (possibly occluded) component into an off-screen image. */
    private static BufferedImage render(Component component) {
        int w = component.getWidth();
        int h = component.getHeight();
        if (w <= 0 || h <= 0) {
            Dimension pref = component.getPreferredSize();
            w = Math.max(pref.width, 1);
            h = Math.max(pref.height, 1);
            component.setSize(w, h);
            component.doLayout();
        }
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            // printAll() forces a synchronous paint of the component and all its
            // children, independent of dirty-region tracking or on-screen visibility.
            component.printAll(g);
        } finally {
            g.dispose();
        }
        return image;
    }

    private static int[] parseRegion(Object raw) {
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof List)) {
            throw new RuntimeException("'region' must be an array [x, y, width, height].");
        }
        List<?> list = (List<?>) raw;
        if (list.size() != 4) {
            throw new RuntimeException("'region' must have exactly 4 elements [x, y, width, height].");
        }
        int[] r = new int[4];
        for (int i = 0; i < 4; i++) {
            if (!(list.get(i) instanceof Number)) {
                throw new RuntimeException("'region' elements must be integers.");
            }
            r[i] = ((Number) list.get(i)).intValue();
        }
        return r;
    }

    private static BufferedImage cropImage(BufferedImage image, int[] r) {
        int x = Math.max(0, Math.min(r[0], image.getWidth() - 1));
        int y = Math.max(0, Math.min(r[1], image.getHeight() - 1));
        int w = Math.max(1, Math.min(r[2], image.getWidth() - x));
        int h = Math.max(1, Math.min(r[3], image.getHeight() - y));
        return image.getSubimage(x, y, w, h);
    }
}
