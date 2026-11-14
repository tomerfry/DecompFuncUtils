package decompfuncutils.refine.ui;

import decompfuncutils.refine.RefineResult;
import decompfuncutils.refine.Rewrite;
import decompfuncutils.refine.ast.CPrinter;
import generic.theme.Gui;
import ghidra.program.model.address.Address;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JTextPane;
import javax.swing.ToolTipManager;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * The text of the Refined Decompiler view: refined C coloured like the decompiler's own output,
 * with every rewritten stretch tinted by how it was justified and explained in a tooltip.
 */
public final class RefinedCodeView extends JTextPane {
    private List<CPrinter.Span> spans = List.of();
    private List<Address> lineAddress = List.of();
    private int currentLine = -1;
    private Consumer<Address> onNavigate = a -> { };
    private boolean tint = true;

    public RefinedCodeView() {
        setEditable(false);
        setFont(codeFont());
        setBackground(color("color.bg.decompiler", Color.WHITE, new Color(0x2b2b2b)));
        setForeground(color("color.fg.decompiler", Color.BLACK, new Color(0xd0d0d0)));
        ToolTipManager.sharedInstance().registerComponent(this);
        addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getButton() != MouseEvent.BUTTON1) return;
                Address a = addressAt(viewToModel2D(e.getPoint()));
                if (a != null) onNavigate.accept(a);
            }
        });
    }

    /** Code does not wrap: the pane scrolls sideways once a line is wider than the view. */
    @Override public boolean getScrollableTracksViewportWidth() {
        return getParent() == null || getUI().getPreferredSize(this).width <= getParent().getSize().width;
    }

    /** Called with the machine address of a line the user clicked. */
    public void onNavigate(Consumer<Address> listener) { onNavigate = listener; }

    /** Whether rewritten code is tinted by verification status. */
    public void setTint(boolean on) { tint = on; }

    // ------------------------------------------------------------------ theme

    static Font codeFont() {
        try {
            if (Gui.hasFont("font.decompiler")) return Gui.getFont("font.decompiler");
        } catch (RuntimeException e) {
            // no theme (tests): fall through
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 13);
    }

    static boolean dark() {
        try {
            return Gui.isDarkTheme();
        } catch (RuntimeException | Error e) {
            return false;
        }
    }

    static Color color(String id, Color light, Color darkColor) {
        try {
            if (Gui.hasColor(id)) {
                Color c = Gui.getColor(id);
                return new Color(c.getRGB(), true);
            }
        } catch (RuntimeException | Error e) {
            // no theme (tests): fall through
        }
        return dark() ? darkColor : light;
    }

    private Color syntax(String kind) {
        return switch (kind) {
            case "keyword" -> color("color.fg.decompiler.keyword", new Color(0x0000c0), new Color(0x6fa8ff));
            case "type" -> color("color.fg.decompiler.type", new Color(0x0000c0), new Color(0x6fa8ff));
            case "function" -> color("color.fg.decompiler.function.name", new Color(0x0000ff), new Color(0x79b8ff));
            case "parameter" -> color("color.fg.decompiler.parameter", new Color(0x800080), new Color(0xd19ad1));
            case "global" -> color("color.fg.decompiler.global", new Color(0x008b8b), new Color(0x56c8c8));
            case "constant" -> color("color.fg.decompiler.constant", new Color(0x008000), new Color(0x8fce8f));
            case "comment" -> color("color.fg.decompiler.comment", new Color(0x8a2be2), new Color(0xb294e8));
            case "variable" -> color("color.fg.decompiler.variable", new Color(0x808000), new Color(0xc8c86e));
            default -> null;
        };
    }

    /** Background for a rewrite, a wash of the status colour over the pane's own background. */
    static Color tint(Rewrite.Status status, Color background) {
        Color accent = switch (status) {
            case PROVEN -> new Color(0x2e9f4d);
            case TESTED -> new Color(0x2f7fd0);
            case STRUCTURAL -> new Color(0x8a8a8a);
            case ASSUMED -> new Color(0xe09a1a);
            default -> new Color(0xd04040);
        };
        float k = 0.24f;
        return new Color(
            Math.round(background.getRed() * (1 - k) + accent.getRed() * k),
            Math.round(background.getGreen() * (1 - k) + accent.getGreen() * k),
            Math.round(background.getBlue() * (1 - k) + accent.getBlue() * k));
    }

    // ------------------------------------------------------------------ content

    /** Show a refinement result. */
    public void show(RefineResult result) {
        show(result.printed.text, result.printed.spans, result.printed.lineAddress);
    }

    /** Show plain text with no markup (an error, or the decompiler's own output for comparison). */
    public void showPlain(String text) { show(text, List.of(), List.of()); }

    private void show(String text, List<CPrinter.Span> newSpans, List<Address> addresses) {
        spans = new ArrayList<>(newSpans);
        lineAddress = new ArrayList<>(addresses);
        currentLine = -1;
        setText(text);
        StyledDocument doc = getStyledDocument();
        SimpleAttributeSet plain = new SimpleAttributeSet();
        StyleConstants.setForeground(plain, getForeground());
        doc.setCharacterAttributes(0, doc.getLength(), plain, true);
        for (CPrinter.Span s : spans) {
            if (s.kind.equals("rewrite")) continue;
            Color c = syntax(s.kind);
            if (c == null) continue;
            SimpleAttributeSet a = new SimpleAttributeSet();
            StyleConstants.setForeground(a, c);
            doc.setCharacterAttributes(s.start, s.end - s.start, a, false);
        }
        if (tint) {
            // Outer rewrites first, so the innermost (most specific) one decides the colour.
            List<CPrinter.Span> marked = new ArrayList<>();
            for (CPrinter.Span s : spans) if (s.kind.equals("rewrite") && s.note instanceof Rewrite) marked.add(s);
            marked.sort((x, y) -> Integer.compare(y.end - y.start, x.end - x.start));
            for (CPrinter.Span s : marked) {
                SimpleAttributeSet a = new SimpleAttributeSet();
                StyleConstants.setBackground(a, tint(((Rewrite) s.note).status, getBackground()));
                doc.setCharacterAttributes(s.start, s.end - s.start, a, false);
            }
        }
        setCaretPosition(0);
    }

    public List<CPrinter.Span> spans() { return spans; }

    /** The innermost rewrite covering a text offset, or null. */
    public Rewrite rewriteAt(int offset) {
        CPrinter.Span best = null;
        for (CPrinter.Span s : spans) {
            if (!s.kind.equals("rewrite") || !(s.note instanceof Rewrite) || offset < s.start || offset >= s.end) continue;
            if (best == null || s.end - s.start < best.end - best.start) best = s;
        }
        return best == null ? null : (Rewrite) best.note;
    }

    /** Select and scroll to the code a rewrite produced. Returns false when it left no code behind. */
    public boolean reveal(Rewrite rewrite) {
        for (CPrinter.Span s : spans) {
            if (s.note != rewrite) continue;
            select(s.start, s.end);
            try {
                java.awt.geom.Rectangle2D at = modelToView2D(s.start);
                if (at != null) {
                    Rectangle r = at.getBounds();
                    r.height *= 3;
                    scrollRectToVisible(r);
                }
            } catch (BadLocationException e) {
                // stale span; nothing to scroll to
            }
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ lines and addresses

    private int lineOf(int offset) {
        Element root = getDocument().getDefaultRootElement();
        return root.getElementIndex(Math.max(0, Math.min(offset, getDocument().getLength())));
    }

    /** Machine address of the line holding a text offset; null for lines that have none. */
    public Address addressAt(int offset) {
        int line = lineOf(offset);
        return line >= 0 && line < lineAddress.size() ? lineAddress.get(line) : null;
    }

    /**
     * Mark the line that best corresponds to a listing address: the line with the greatest
     * address not above it. Returns false when no line qualifies.
     */
    public boolean highlightAddress(Address address) {
        int best = -1;
        if (address != null) {
            for (int i = 0; i < lineAddress.size(); i++) {
                Address a = lineAddress.get(i);
                if (a == null || !a.getAddressSpace().equals(address.getAddressSpace()) || a.compareTo(address) > 0) continue;
                if (best < 0 || a.compareTo(lineAddress.get(best)) > 0) best = i;
            }
        }
        if (best == currentLine) return best >= 0;
        currentLine = best;
        repaint();
        if (best >= 0) {
            try {
                Element line = getDocument().getDefaultRootElement().getElement(best);
                java.awt.geom.Rectangle2D at = line == null ? null : modelToView2D(line.getStartOffset());
                if (at != null) scrollRectToVisible(at.getBounds());
            } catch (BadLocationException e) {
                // document changed underneath; the next result repaints
            }
        }
        return best >= 0;
    }

    @Override protected void paintComponent(Graphics g) {
        if (currentLine >= 0 && isOpaque()) {
            // Paint the background ourselves so the current-line band sits under the text.
            g.setColor(getBackground());
            g.fillRect(0, 0, getWidth(), getHeight());
            try {
                Element line = getDocument().getDefaultRootElement().getElement(currentLine);
                java.awt.geom.Rectangle2D at = line == null ? null : modelToView2D(line.getStartOffset());
                if (at != null) {
                    Rectangle r = at.getBounds();
                    g.setColor(color("color.bg.currentline", new Color(0xe8f2fe), new Color(0x3a3d41)));
                    g.fillRect(0, r.y, getWidth(), r.height);
                }
            } catch (BadLocationException e) {
                // nothing to mark
            }
            setOpaque(false);
            try {
                super.paintComponent(g);
            } finally {
                setOpaque(true);
            }
            return;
        }
        super.paintComponent(g);
    }

    // ------------------------------------------------------------------ tooltips

    @Override public String getToolTipText(MouseEvent event) {
        Rewrite rw = rewriteAt(viewToModel2D(event.getPoint()));
        return rw == null ? null : describe(rw);
    }

    /** HTML account of one rewrite: what it replaced, how it was justified, and the instructions behind it. */
    public static String describe(Rewrite rw) {
        StringBuilder sb = new StringBuilder("<html><body style='width:520px'>");
        sb.append("<b>").append(esc(rw.rule)).append("</b> &nbsp;<i>").append(esc(rw.pass)).append("</i> &nbsp; ")
            .append(statusWords(rw.status)).append("<br>");
        sb.append("<table cellpadding='2'><tr><td valign='top'>was</td><td><code>").append(esc(clip(rw.before, 420))).append("</code></td></tr>");
        sb.append("<tr><td valign='top'>now</td><td><code>").append(esc(clip(rw.after, 420))).append("</code></td></tr></table>");
        if (!rw.detail.isEmpty()) sb.append(esc(clip(rw.detail, 300))).append("<br>");
        if (rw.evidence != null && !rw.evidence.isBlank()) {
            sb.append("<pre>").append(esc(clip(rw.evidence, 700))).append("</pre>");
        }
        return sb.append("</body></html>").toString();
    }

    static String statusWords(Rewrite.Status status) {
        return switch (status) {
            case PROVEN -> "proved for all inputs";
            case TESTED -> "tested on concrete runs";
            case STRUCTURAL -> "follows from the code's structure";
            case ASSUMED -> "applied without a check";
            default -> "refuted; not applied";
        };
    }

    private static String clip(String s, int max) { return s.length() <= max ? s : s.substring(0, max) + " ..."; }

    private static String esc(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }
}
