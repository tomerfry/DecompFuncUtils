package decompfuncutils.refine.ast;

import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.data.DataType;

/** One lexical token, from the decompiler's markup or from rule text. */
public final class Tok {
    public enum Kind { ID, FUNC, FIELD, NUM, STR, TYPE, KEYWORD, PUNCT, LABEL, COMMENT, META, EOF }

    public final Kind kind;
    public final String text;
    /** Decompiler token this came from; null for rule text. */
    public final ClangToken src;
    /** Data type of a {@link Kind#TYPE} token, when the decompiler supplied one. */
    public final DataType dataType;
    /** Index of this token in the decompiler's flattened markup, or -1. Used to quote source verbatim. */
    public int pos = -1;

    public Tok(Kind kind, String text, ClangToken src, DataType dataType) {
        this.kind = kind;
        this.text = text;
        this.src = src;
        this.dataType = dataType;
    }

    public Tok(Kind kind, String text) { this(kind, text, null, null); }

    public boolean is(String s) { return (kind == Kind.PUNCT || kind == Kind.KEYWORD) && text.equals(s); }

    @Override public String toString() { return kind + ":" + text; }
}
