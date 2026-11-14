package decompfuncutils.refine.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Lexer for the C-like text of rewrite rules: C expressions plus {@code $metavariables}. */
public final class CLexer {
    private static final String[] PUNCT = {
        ">>=", "<<=", "=>", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "=", "?", ":", ",", ";",
        "(", ")", "[", "]", "{", "}", "."
    };
    static final Set<String> KEYWORDS = Set.of("if", "else", "while", "do", "for", "switch", "case",
        "default", "return", "break", "continue", "goto");
    private static final Set<String> TYPES = Set.of("void", "bool", "char", "uchar", "byte", "sbyte",
        "short", "ushort", "word", "int", "uint", "dword", "long", "ulong", "qword", "longlong", "ulonglong",
        "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
        "size_t", "ssize_t", "float", "double", "code", "_");

    private CLexer() {}

    public static boolean isTypeName(String s) { return TYPES.contains(s); }

    public static List<Tok> lex(String s) {
        List<Tok> out = new ArrayList<>();
        int i = 0, n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) { i++; continue; }
            if (c == '/' && i + 1 < n && s.charAt(i + 1) == '*') {
                int end = s.indexOf("*/", i + 2);
                if (end < 0) throw new IllegalArgumentException("Unterminated comment");
                i = end + 2;
                continue;
            }
            if (c == '$') {
                int j = i + 1;
                while (j < n && (Character.isLetterOrDigit(s.charAt(j)) || s.charAt(j) == '_')) j++;
                if (j == i + 1) throw new IllegalArgumentException("Expected a name after '$' at column " + (i + 1));
                // $name:kind -- the kind is one identifier, glued on so "? $a : $b" still lexes.
                int k = j;
                if (k + 1 < n && s.charAt(k) == ':' && Character.isLetter(s.charAt(k + 1))) {
                    int e = k + 1;
                    while (e < n && Character.isLetter(s.charAt(e))) e++;
                    String kind = s.substring(k + 1, e);
                    if (kind.equals("const") || kind.equals("var") || kind.equals("expr")) k = e;
                }
                out.add(new Tok(Tok.Kind.META, s.substring(i, k)));
                i = k;
                continue;
            }
            if (Character.isLetter(c) || c == '_') {
                int j = i;
                while (j < n && (Character.isLetterOrDigit(s.charAt(j)) || s.charAt(j) == '_')) j++;
                String word = s.substring(i, j);
                Tok.Kind kind = KEYWORDS.contains(word) ? Tok.Kind.KEYWORD
                    : TYPES.contains(word) ? Tok.Kind.TYPE : Tok.Kind.ID;
                out.add(new Tok(kind, word));
                i = j;
                continue;
            }
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && (Character.isLetterOrDigit(s.charAt(j)) || s.charAt(j) == '.')) j++;
                out.add(new Tok(Tok.Kind.NUM, s.substring(i, j)));
                i = j;
                continue;
            }
            if (c == '\'' || c == '"') {
                int j = i + 1;
                while (j < n && s.charAt(j) != c) j += s.charAt(j) == '\\' ? 2 : 1;
                if (j >= n) throw new IllegalArgumentException("Unterminated literal at column " + (i + 1));
                out.add(new Tok(c == '"' ? Tok.Kind.STR : Tok.Kind.NUM, s.substring(i, j + 1)));
                i = j + 1;
                continue;
            }
            String match = null;
            for (String p : PUNCT) {
                if (s.startsWith(p, i)) { match = p; break; }
            }
            if (match == null) throw new IllegalArgumentException("Unexpected character '" + c + "' at column " + (i + 1));
            out.add(new Tok(Tok.Kind.PUNCT, match));
            i += match.length();
        }
        return out;
    }
}
