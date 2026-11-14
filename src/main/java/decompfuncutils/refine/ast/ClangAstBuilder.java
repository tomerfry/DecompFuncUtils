package decompfuncutils.refine.ast;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a {@link CFunction} from the decompiler's token markup. The prototype and the
 * declarations are taken from the markup's own groups; the body is flattened to tokens and handed
 * to {@link CParser}.
 */
public final class ClangAstBuilder {
    private final Program program;
    private final List<ClangToken> flat = new ArrayList<>();

    public ClangAstBuilder(Program program) { this.program = program; }

    public CFunction build(DecompileResults results) {
        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup == null) throw new IllegalStateException("Decompiler produced no markup");
        HighFunction high = results.getHighFunction();
        CFunction f = new CFunction();
        f.program = program;
        f.high = high;
        f.function = results.getFunction();
        f.name = f.function != null ? f.function.getName() : "?";
        f.pointerBits = program.getDefaultPointerSize() * 8;
        f.bigEndian = program.getLanguage().isBigEndian();
        if (f.function != null) f.returnType = CType.of(f.function.getReturnType(), f.pointerBits);

        // Top level: [comments] prototype { declarations... statements... }
        List<ClangNode> top = new ArrayList<>();
        for (int i = 0; i < markup.numChildren(); i++) top.add(markup.Child(i));
        int i = 0;
        StringBuilder headerComment = new StringBuilder();
        for (; i < top.size(); i++) {
            ClangNode n = top.get(i);
            if (n instanceof ClangFuncProto proto) {
                f.prototype = text(proto).strip();
                collectParams(proto, f);
                if (high != null && high.getFunctionPrototype() != null && high.getFunctionPrototype().getReturnType() != null) {
                    f.returnType = CType.of(high.getFunctionPrototype().getReturnType(), f.pointerBits);
                }
                i++;
                break;
            }
            if (n instanceof ClangCommentToken c) headerComment.append(c.getText());
            else if (n instanceof ClangBreak) flushComment(headerComment, f.header);
            else if (n instanceof ClangToken t && headerComment.length() > 0 && t.getText() != null) headerComment.append(t.getText());
        }
        flushComment(headerComment, f.header);
        for (; i < top.size(); i++) {
            ClangNode n = top.get(i);
            if (n instanceof ClangSyntaxToken s && s.getText().equals("{")) { i++; break; }
        }
        List<ClangNode> bodyNodes = new ArrayList<>();
        int end = top.size();
        for (int k = top.size() - 1; k >= i; k--) {
            if (top.get(k) instanceof ClangSyntaxToken s && s.getText().equals("}")) { end = k; break; }
        }
        for (; i < end; i++) {
            ClangNode n = top.get(i);
            if (n instanceof ClangVariableDecl decl) {
                declare(decl, f, false);
                continue;
            }
            bodyNodes.add(n);
        }
        List<ClangNode> nodes = new ArrayList<>();
        for (ClangNode n : bodyNodes) n.flatten(nodes);
        for (ClangNode n : nodes) if (n instanceof ClangToken t) flat.add(t);
        List<Tok> toks = new ArrayList<>();
        for (int k = 0; k < flat.size(); k++) {
            if (flat.get(k) instanceof ClangCommentToken) {
                // A comment arrives as one token per word; put it back together.
                int from = k;
                StringBuilder text = new StringBuilder();
                while (k < flat.size() && !(flat.get(k) instanceof ClangBreak)
                        && (flat.get(k) instanceof ClangCommentToken || flat.get(k).getText() == null || flat.get(k).getText().isBlank())) {
                    if (flat.get(k).getText() != null) text.append(flat.get(k).getText());
                    k++;
                }
                k--;
                Tok c = new Tok(Tok.Kind.COMMENT, text.toString().strip(), flat.get(from), null);
                c.pos = from;
                toks.add(c);
                continue;
            }
            Tok t = adapt(flat.get(k));
            if (t == null) continue;
            // The ';' that ends a declaration stays behind in the body stream; drop strays.
            if (t.is(";") && (toks.isEmpty() || toks.get(toks.size() - 1).is(";") || toks.get(toks.size() - 1).is("{")
                    || toks.get(toks.size() - 1).is("}"))) continue;
            t.pos = k;
            toks.add(t);
        }
        toks = joinQualifiedNames(toks);
        CParser.Scope scope = new CParser.Scope() {
            @Override public CType typeOf(String name) { return f.typeOf(name); }
            @Override public Function functionAt(Address a) {
                Function fn = program.getFunctionManager().getFunctionAt(a);
                // A call through a PLT stub is a call to what the stub jumps to, when that is in this program.
                if (fn != null && fn.isThunk()) {
                    Function real = fn.getThunkedFunction(true);
                    if (real != null && !real.isExternal()) return real;
                }
                return fn;
            }
        };
        CParser parser = new CParser(toks, scope, f.pointerBits, this::quote);
        f.body = parser.parseBlockBody();
        f.rawStatements = countRaw(f.body);
        AstUtil.walk(f.body, s -> {
            if (s instanceof Stmt.Goto || s instanceof Stmt.Label || s instanceof Stmt.Raw) f.unstructured = true;
        });
        f.frameEscapes = f.rawStatements > 0 || AstUtil.any(f.body, e -> {
            if (e instanceof Expr.Raw) return true;
            if (e instanceof Expr.Id id && id.kind != Expr.Id.Kind.FUNC && id.kind != Expr.Id.Kind.GLOBAL && id.type.isAggregate()) return true;
            if (!(e instanceof Expr.Un u) || !u.o.equals("&")) return false;
            Expr root = u.e;
            while (root instanceof Expr.Member || root instanceof Expr.Index || root instanceof Expr.Cast) root = root.kid(0);
            return root instanceof Expr.Id id && id.kind != Expr.Id.Kind.GLOBAL && id.kind != Expr.Id.Kind.FUNC;
        });
        return f;
    }

    /**
     * "ns :: Class :: ~Class" arrives as separate tokens. Fold each run into one name carrying
     * the last component's kind and decompiler token, which is the one with the p-code behind it.
     */
    private static List<Tok> joinQualifiedNames(List<Tok> in) {
        List<Tok> out = new ArrayList<>(in.size());
        for (int i = 0; i < in.size(); i++) {
            Tok t = in.get(i);
            if (!isName(t) || i + 1 >= in.size() || !in.get(i + 1).is("::")) { out.add(t); continue; }
            StringBuilder name = new StringBuilder(t.text);
            Tok last = t;
            int k = i;
            while (k + 2 < in.size() && in.get(k + 1).is("::")) {
                int nameAt = k + 2;
                String prefix = "";
                if (in.get(nameAt).is("~") && nameAt + 1 < in.size()) { prefix = "~"; nameAt++; }
                if (!isName(in.get(nameAt))) break;
                name.append("::").append(prefix).append(in.get(nameAt).text);
                last = in.get(nameAt);
                k = nameAt;
            }
            if (k == i) { out.add(t); continue; }
            Tok joined = new Tok(last.kind, name.toString(), last.src, last.dataType);
            joined.pos = t.pos;
            out.add(joined);
            i = k;
        }
        return out;
    }

    private static boolean isWordChar(char c) { return Character.isLetterOrDigit(c) || c == '_'; }

    private static boolean isName(Tok t) {
        return t.kind == Tok.Kind.ID || t.kind == Tok.Kind.FUNC || t.kind == Tok.Kind.TYPE || t.kind == Tok.Kind.FIELD;
    }

    private static void flushComment(StringBuilder sb, List<String> into) {
        if (!sb.toString().isBlank()) into.add(sb.toString().strip());
        sb.setLength(0);
    }

    private static int countRaw(Stmt s) {
        int n = s instanceof Stmt.Raw ? 1 : 0;
        if (s instanceof Stmt.Block b) for (Stmt c : b.body) n += countRaw(c);
        for (Stmt.Block b : s.blocks()) n += countRaw(b);
        return n;
    }

    private void collectParams(ClangFuncProto proto, CFunction f) {
        for (int i = 0; i < proto.numChildren(); i++) {
            if (proto.Child(i) instanceof ClangVariableDecl decl) declare(decl, f, true);
        }
    }

    private void declare(ClangVariableDecl decl, CFunction f, boolean param) {
        String name = null;
        for (int i = 0; i < decl.numChildren(); i++) {
            if (decl.Child(i) instanceof ClangVariableToken v) name = v.getText();
        }
        if (name == null) return;
        HighSymbol symbol = decl.getHighSymbol();
        CType type = CType.of(decl.getDataType(), f.pointerBits);
        if (symbol != null && symbol.getDataType() != null) type = CType.of(symbol.getDataType(), f.pointerBits);
        CFunction.Var v = new CFunction.Var(name, type, text(decl).strip(), symbol, param);
        (param ? f.params : f.locals).add(v);
        f.vars.put(name, v);
    }

    private static String text(ClangNode node) {
        List<ClangNode> list = new ArrayList<>();
        node.flatten(list);
        StringBuilder sb = new StringBuilder();
        for (ClangNode n : list) {
            if (n instanceof ClangBreak) continue;
            if (!(n instanceof ClangToken t) || t.getText() == null || t.getText().isEmpty()) continue;
            String piece = t instanceof ClangTypeToken ? typeName(t.getText()) : t.getText();
            // Two words with no separator token between them ("__thiscall" "std") still need a space.
            if (sb.length() > 0 && isWordChar(sb.charAt(sb.length() - 1)) && isWordChar(piece.charAt(0))) sb.append(' ');
            sb.append(piece);
        }
        return sb.toString();
    }

    /** Original text between two body tokens, one string per printed line, indentation removed. */
    private List<String> quote(Tok first, Tok last) {
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        for (int i = Math.max(0, first.pos); i <= last.pos && i < flat.size(); i++) {
            ClangToken t = flat.get(i);
            if (t instanceof ClangBreak) {
                if (!line.toString().isBlank()) lines.add(line.toString().strip());
                line.setLength(0);
            } else if (t.getText() != null) line.append(t.getText());
        }
        if (!line.toString().isBlank()) lines.add(line.toString().strip());
        return lines;
    }

    /** The decompiler prints multi-word type names with underscores ("unsigned_long"). */
    private static String typeName(String text) { return text.strip().replace(' ', '_'); }

    private static Tok adapt(ClangToken t) {
        if (t instanceof ClangBreak) return null;
        String text = t.getText();
        if (text == null || text.isBlank()) return null;
        if (t instanceof ClangCommentToken) return new Tok(Tok.Kind.COMMENT, text, t, null);
        if (t instanceof ClangTypeToken type) return new Tok(Tok.Kind.TYPE, typeName(text), t, type.getDataType());
        if (t instanceof ClangFuncNameToken) return new Tok(Tok.Kind.FUNC, text, t, null);
        if (t instanceof ClangFieldToken) return new Tok(Tok.Kind.FIELD, text, t, null);
        if (t instanceof ClangLabelToken) return new Tok(Tok.Kind.LABEL, text, t, null);
        if (t instanceof ClangCaseToken) return new Tok(Tok.Kind.NUM, text, t, null);
        if (t instanceof ClangVariableToken) {
            char c = text.charAt(0);
            if (c == '"' || (text.length() > 1 && text.charAt(1) == '"')) return new Tok(Tok.Kind.STR, text, t, null);
            if (text.equals("true") || text.equals("false")) return new Tok(Tok.Kind.NUM, text, t, null);
            boolean literal = Character.isDigit(c) || c == '\''
                || (c == '-' && text.length() > 1 && Character.isDigit(text.charAt(1)))
                || (text.length() > 1 && text.charAt(1) == '\'');
            // A named constant (enum member, #define-style equate) prints as a name but is a value.
            boolean named = !literal && t.getScalar() != null
                && (t.getHighVariable() == null || t.getHighVariable() instanceof ghidra.program.model.pcode.HighConstant);
            return new Tok(literal || named ? Tok.Kind.NUM : Tok.Kind.ID, text, t, null);
        }
        // Operator and syntax tokens: keywords, punctuation, or the name of a pseudo-function
        // such as CONCAT44 / SUB41 / ZEXT48.
        if (Character.isLetter(text.charAt(0)) || text.charAt(0) == '_') {
            if (text.equals("true") || text.equals("false")) return new Tok(Tok.Kind.NUM, text, t, null);
            if (CLexer.KEYWORDS.contains(text)) return new Tok(Tok.Kind.KEYWORD, text, t, null);
            return new Tok(Tok.Kind.FUNC, text, t, null);
        }
        // Array subscripts are printed as bare tokens with nothing behind them.
        if (Character.isDigit(text.charAt(0)) || text.charAt(0) == '\'') return new Tok(Tok.Kind.NUM, text, t, null);
        if (text.charAt(0) == '"') return new Tok(Tok.Kind.STR, text, t, null);
        return new Tok(Tok.Kind.PUNCT, text, t, null);
    }
}
