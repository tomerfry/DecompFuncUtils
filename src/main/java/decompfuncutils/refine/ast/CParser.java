package decompfuncutils.refine.ast;

import decompfuncutils.refine.ast.Expr.*;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recursive-descent parser for the C the decompiler prints and for the C-like text of rewrite
 * rules. Both arrive as {@link Tok}s; tokens from the decompiler also carry the p-code operation,
 * varnode and data type behind them, which is where node types come from.
 *
 * <p>A statement that does not parse is not an error: it becomes a {@link Stmt.Raw} holding the
 * original text, so refinement never loses code it does not understand.
 */
public final class CParser {
    /** What the parser needs to know about names it meets. */
    public interface Scope {
        /** Declared type of a local or parameter, or null. */
        CType typeOf(String name);
        /** Function at an address, or null. */
        Function functionAt(Address a);
    }

    public static final class ParseError extends RuntimeException {
        public ParseError(String message) { super(message); }
    }

    private static final Map<String, Integer> PREC = Map.ofEntries(
        Map.entry("||", 1), Map.entry("&&", 2), Map.entry("|", 3), Map.entry("^", 4), Map.entry("&", 5),
        Map.entry("==", 6), Map.entry("!=", 6), Map.entry("<", 7), Map.entry(">", 7), Map.entry("<=", 7),
        Map.entry(">=", 7), Map.entry("<<", 8), Map.entry(">>", 8), Map.entry("+", 9), Map.entry("-", 9),
        Map.entry("*", 10), Map.entry("/", 10), Map.entry("%", 10));
    private static final java.util.Set<String> ASSIGN = java.util.Set.of(
        "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=");
    private static final Pattern NUMBER = Pattern.compile("(-?)(0[xX][0-9a-fA-F]+|[0-9]+)([uUlL]*)");
    private static final Pattern PIECE_FIELD = Pattern.compile("_(\\d+)_(\\d+)_");

    private final List<Tok> toks;
    private final Scope scope;
    private final Typer typer;
    private final int pointerBits;
    /** Quotes the original text between two tokens, one entry per line. */
    private final BiFunction<Tok, Tok, List<String>> quote;
    private int p;
    private static final Tok EOF = new Tok(Tok.Kind.EOF, "<end>");

    public CParser(List<Tok> toks, Scope scope, int pointerBits, BiFunction<Tok, Tok, List<String>> quote) {
        this.toks = toks;
        this.scope = scope;
        this.pointerBits = pointerBits;
        this.typer = new Typer(pointerBits);
        this.quote = quote;
    }

    /** Parser for rule text: no declarations, no decompiler tokens. */
    public static CParser forText(String text, int pointerBits) {
        return new CParser(CLexer.lex(text), null, pointerBits, null);
    }

    public boolean atEnd() { return p >= toks.size(); }
    public Tok peek() { return p < toks.size() ? toks.get(p) : EOF; }
    private Tok peek(int ahead) { return p + ahead < toks.size() ? toks.get(p + ahead) : EOF; }
    private Tok next() { Tok t = peek(); p++; return t; }
    private boolean at(String s) { return peek().is(s); }
    private boolean accept(String s) { if (at(s)) { p++; return true; } return false; }
    private void expect(String s) {
        if (!accept(s)) throw new ParseError("Expected '" + s + "' but found '" + peek().text + "'");
    }

    // ------------------------------------------------------------------ statements

    /** Parse statements up to the closing brace of the enclosing block (not consumed) or the end. */
    public Stmt.Block parseBlockBody() {
        Stmt.Block block = new Stmt.Block();
        while (!atEnd() && !at("}")) block.body.add(parseStatementSafe());
        return block;
    }

    private Stmt parseStatementSafe() {
        int start = p;
        try {
            Stmt s = parseStatement();
            span(s, start, p);
            return s;
        } catch (ParseError | IndexOutOfBoundsException e) {
            p = start;
            skipStatement();
            if (p == start) p++;
            Tok first = toks.get(start), last = toks.get(Math.min(p, toks.size()) - 1);
            List<String> lines = quote != null ? quote.apply(first, last) : List.of(join(start, p));
            Stmt.Raw raw = new Stmt.Raw(lines);
            raw.reason = String.valueOf(e.getMessage());
            span(raw, start, p);
            return raw;
        }
    }

    private String join(int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to && i < toks.size(); i++) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(toks.get(i).text);
        }
        return sb.toString();
    }

    /** Skip one statement's worth of tokens without understanding it. */
    private void skipStatement() {
        int paren = 0, brace = 0;
        boolean isDo = at("do");
        while (!atEnd()) {
            Tok t = next();
            if (t.is("(") || t.is("[")) paren++;
            else if (t.is(")") || t.is("]")) paren--;
            else if (t.is("{")) brace++;
            else if (t.is("}")) {
                brace--;
                if (brace < 0) { p--; return; }
                if (brace == 0 && paren <= 0) {
                    if (at("else")) continue;
                    if (isDo && at("while")) { isDo = false; continue; }
                    return;
                }
            } else if (t.is(";") && paren <= 0 && brace == 0) return;
        }
    }

    private void span(Stmt s, int from, int to) {
        Address lo = null, hi = null;
        for (int i = from; i < to && i < toks.size(); i++) {
            ClangToken src = toks.get(i).src;
            if (src == null) continue;
            Address a = src.getMinAddress(), b = src.getMaxAddress();
            if (a != null && (lo == null || a.compareTo(lo) < 0)) lo = a;
            if (b != null && (hi == null || b.compareTo(hi) > 0)) hi = b;
        }
        s.span(lo, hi);
    }

    private Stmt.Block parseBlock() {
        if (accept("{")) {
            Stmt.Block b = parseBlockBody();
            expect("}");
            return b;
        }
        Stmt.Block b = new Stmt.Block();
        b.body.add(parseStatementSafe());
        return b;
    }

    public Stmt parseStatement() {
        Tok t = peek();
        if (t.kind == Tok.Kind.COMMENT) { p++; return new Stmt.Comment(t.text); }
        if (t.kind == Tok.Kind.LABEL) {
            p++;
            accept(":");
            return new Stmt.Label(stripColon(t.text));
        }
        if (t.is("{")) return parseBlock();
        if (t.kind == Tok.Kind.KEYWORD) {
            switch (t.text) {
                case "if": {
                    p++;
                    expect("(");
                    Expr c = parseExpr();
                    expect(")");
                    Stmt.Block then = parseBlock();
                    Stmt.Block otherwise = null;
                    if (accept("else")) {
                        if (at("if")) {
                            otherwise = new Stmt.Block();
                            otherwise.body.add(parseStatementSafe());
                        } else otherwise = parseBlock();
                    }
                    return new Stmt.If(c, then, otherwise);
                }
                case "while": {
                    p++;
                    expect("(");
                    Expr c = parseExpr();
                    expect(")");
                    return new Stmt.While(c, parseBlock());
                }
                case "do": {
                    p++;
                    Stmt.Block body = parseBlock();
                    expect("while");
                    expect("(");
                    Expr c = parseExpr();
                    expect(")");
                    accept(";");
                    return new Stmt.DoWhile(body, c);
                }
                case "for": {
                    p++;
                    expect("(");
                    Expr init = at(";") ? null : parseExpr();
                    expect(";");
                    Expr cond = at(";") ? null : parseExpr();
                    expect(";");
                    Expr step = at(")") ? null : parseExpr();
                    expect(")");
                    return new Stmt.For(init, cond, step, parseBlock());
                }
                case "switch": {
                    p++;
                    expect("(");
                    Expr e = parseExpr();
                    expect(")");
                    return new Stmt.Switch(e, parseBlock());
                }
                case "case": {
                    p++;
                    Expr v = parseCond();
                    expect(":");
                    return new Stmt.CaseLabel(v);
                }
                case "default":
                    p++;
                    expect(":");
                    return new Stmt.CaseLabel(null);
                case "return": {
                    p++;
                    Expr e = at(";") ? null : parseExpr();
                    expect(";");
                    return new Stmt.Return(e);
                }
                case "break": p++; expect(";"); return new Stmt.Break();
                case "continue": p++; expect(";"); return new Stmt.Continue();
                case "goto": {
                    p++;
                    Tok label = next();
                    expect(";");
                    return new Stmt.Goto(stripColon(label.text));
                }
                default: throw new ParseError("Unexpected keyword '" + t.text + "'");
            }
        }
        // "name:" in rule text is a label.
        if (t.kind == Tok.Kind.ID && t.src == null && peek(1).is(":")) {
            p += 2;
            return new Stmt.Label(t.text);
        }
        Expr e = parseExpr();
        expect(";");
        return new Stmt.ExprStmt(e);
    }

    private static String stripColon(String s) { return s.endsWith(":") ? s.substring(0, s.length() - 1) : s; }

    // ------------------------------------------------------------------ expressions

    /** Full expression, including the comma operator. */
    public Expr parseExpr() {
        Expr e = parseAssign();
        while (at(",")) {
            p++;
            Expr r = parseAssign();
            Bin b = new Bin(",", e, r);
            b.type = r.type;
            e = b;
        }
        return e;
    }

    public Expr parseAssign() {
        Expr l = parseCond();
        Tok t = peek();
        if (t.kind == Tok.Kind.PUNCT && ASSIGN.contains(t.text)) {
            p++;
            Expr r = parseAssign();
            Assign a = new Assign(t.text, l, r);
            a.op = opOf(t);
            a.addr = addrOf(a.op);
            a.type = l.type;
            typer.retype(a);
            return a;
        }
        return l;
    }

    public Expr parseCond() {
        Expr c = parseBinary(1);
        if (at("?")) {
            p++;
            Expr a = parseExpr();
            expect(":");
            Expr b = parseCond();
            Cond n = new Cond(c, a, b);
            typer.retype(n);
            return n;
        }
        return c;
    }

    private Expr parseBinary(int minPrec) {
        Expr l = parseUnary();
        while (true) {
            Tok t = peek();
            Integer prec = t.kind == Tok.Kind.PUNCT ? PREC.get(t.text) : null;
            if (prec == null || prec < minPrec) return l;
            p++;
            Expr r = parseBinary(prec + 1);
            l = binary(t, l, r);
        }
    }

    private Expr binary(Tok t, Expr l, Expr r) {
        Bin b = new Bin(t.text, l, r);
        typer.retype(b);
        PcodeOp op = opOf(t);
        if (op == null) return b;
        b.op = op;
        b.addr = addrOf(op);
        switch (op.getOpcode()) {
            case PcodeOp.INT_SDIV, PcodeOp.INT_SREM, PcodeOp.INT_SRIGHT, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL -> b.sgn = true;
            case PcodeOp.INT_DIV, PcodeOp.INT_REM, PcodeOp.INT_RIGHT, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL -> b.sgn = false;
            default -> { }
        }
        if (isFloatOp(op.getOpcode())) {
            if (!Typer.COMPARE.contains(b.o)) b.type = CType.floating(op.getOutput() == null ? 64 : op.getOutput().getSize() * 8, "double");
            return b;
        }
        if (Typer.COMPARE.contains(b.o) || Typer.LOGICAL.contains(b.o)) return b;
        CType fromOp = typeOfOutput(op);
        if (fromOp != null && fromOp.isScalarInt()) b.type = fromOp.isBool() ? CType.integer(fromOp.bits, false) : fromOp;
        if (b.o.equals("+") || b.o.equals("-")) {
            // Pointer scaling is whatever the machine operation did, not what the operand types
            // would imply: PTRADD multiplies, a plain INT_ADD on a pointer does not.
            b.scale = 0;
            if (op.getOpcode() == PcodeOp.PTRADD && op.getNumInputs() > 2 && op.getInput(2).isConstant()) {
                long s = op.getInput(2).getOffset();
                b.scale = s > 1 && s <= Integer.MAX_VALUE ? (int) s : 0;
            }
        }
        return b;
    }

    private static boolean isFloatOp(int opcode) {
        return opcode >= PcodeOp.FLOAT_EQUAL && opcode <= PcodeOp.FLOAT_ROUND;
    }

    private Expr parseUnary() {
        Tok t = peek();
        if (t.kind == Tok.Kind.PUNCT) {
            switch (t.text) {
                case "-", "~", "!", "*", "&", "+": {
                    p++;
                    Expr e = parseUnary();
                    if (t.text.equals("+")) return e;
                    return unary(t, e);
                }
                case "++", "--": {
                    p++;
                    Expr e = parseUnary();
                    Un u = new Un(t.text, e);
                    u.type = e.type;
                    return u;
                }
                case "(":
                    if (peek(1).kind == Tok.Kind.TYPE) return parseCast();
                    break;
                default:
                    break;
            }
        }
        return parsePostfix();
    }

    private Expr unary(Tok t, Expr e) {
        Un u = new Un(t.text, e);
        PcodeOp op = opOf(t);
        u.op = op;
        u.addr = addrOf(op);
        if (t.text.equals("*")) {
            CType pointee = e.type.pointee;
            int opBytes = 0;
            if (op != null && op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null) opBytes = op.getOutput().getSize();
            else if (op != null && op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2) opBytes = op.getInput(2).getSize();
            if (pointee != null && pointee.isKnown() && (opBytes == 0 || pointee.byteSize() == opBytes)) u.type = pointee;
            else if (opBytes > 0) u.type = CType.integer(opBytes * 8, false);
            else u.type = CType.UNKNOWN;
            return u;
        }
        if (op != null && !t.text.equals("!")) {
            CType fromOp = typeOfOutput(op);
            if (fromOp != null && fromOp.isKnown() && (t.text.equals("&") == fromOp.isPointer())) u.type = fromOp;
        }
        typer.retype(u);
        return u;
    }

    private Expr parseCast() {
        expect("(");
        StringBuilder text = new StringBuilder();
        DataType dt = null;
        String last = null;
        while (peek().kind == Tok.Kind.TYPE) {
            Tok t = next();
            if (text.length() > 0) text.append(' ');
            text.append(t.text);
            if (t.dataType != null) dt = t.dataType;
            last = t.text;
        }
        int depth = 0;
        while (at("*")) { p++; depth++; }
        expect(")");
        Expr e = parseUnary();
        CType base = dt != null ? CType.of(dt, pointerBits) : namedType(last);
        CType type = base;
        for (int i = 0; i < depth; i++) type = CType.pointerTo(type, pointerBits);
        if (depth > 0) text.append(' ').append("*".repeat(depth));
        return new Cast(type, text.toString(), e);
    }

    /** Type named in rule text. Sizes are the LP64 ones the decompiler uses for ELF. */
    public static CType namedType(String name) {
        if (name == null) return CType.UNKNOWN;
        return switch (name) {
            case "void" -> CType.VOID;
            case "bool" -> CType.BOOL;
            case "char", "sbyte", "int8_t" -> CType.integer(8, true, name);
            case "uchar", "byte", "undefined", "undefined1", "uint8_t" -> CType.integer(8, false, name);
            case "short", "int16_t" -> CType.integer(16, true, name);
            case "ushort", "word", "undefined2", "uint16_t" -> CType.integer(16, false, name);
            case "int", "int32_t" -> CType.integer(32, true, name);
            case "uint", "dword", "undefined4", "uint32_t" -> CType.integer(32, false, name);
            case "long", "longlong", "int64_t", "ssize_t" -> CType.integer(64, true, name);
            case "ulong", "ulonglong", "qword", "undefined8", "uint64_t", "size_t" -> CType.integer(64, false, name);
            case "float" -> CType.floating(32, name);
            case "double" -> CType.floating(64, name);
            default -> CType.UNKNOWN;
        };
    }

    private Expr parsePostfix() {
        Expr e = parsePrimary();
        while (true) {
            Tok t = peek();
            if (t.is("(")) {
                p++;
                List<Expr> args = new ArrayList<>();
                if (!at(")")) {
                    do args.add(parseAssign()); while (accept(","));
                }
                expect(")");
                Call c = new Call(e, args);
                c.op = e.op;
                c.addr = e.addr;
                c.type = e instanceof Id id && id.kind == Id.Kind.FUNC ? id.type : CType.UNKNOWN;
                if (c.op != null) {
                    CType out = typeOfOutput(c.op);
                    if (out != null) c.type = out;
                    else if (c.op.getOpcode() == PcodeOp.CALL || c.op.getOpcode() == PcodeOp.CALLIND) c.type = CType.VOID;
                }
                e = c;
            } else if (t.is("[")) {
                p++;
                Expr idx = parseExpr();
                expect("]");
                Index ix = new Index(e, idx);
                typer.retype(ix);
                e = ix;
            } else if (t.is(".") || t.is("->")) {
                p++;
                Tok f = next();
                if (f.kind != Tok.Kind.FIELD && f.kind != Tok.Kind.ID && f.kind != Tok.Kind.FUNC) throw new ParseError("Expected a field name");
                e = member(e, f, t.text.equals("->"));
            } else if (t.is("++") || t.is("--")) {
                p++;
                Un u = new Un(t.text, e, true);
                u.type = e.type;
                e = u;
            } else return e;
        }
    }

    private Expr member(Expr base, Tok f, boolean arrow) {
        Member m = new Member(base, f.text, arrow);
        Matcher piece = PIECE_FIELD.matcher(f.text);
        if (piece.matches()) {
            // Decompiler notation for "size bytes at offset" of a wider value: x._4_2_
            m.offset = Integer.parseInt(piece.group(1));
            m.type = CType.integer(Integer.parseInt(piece.group(2)) * 8, false);
            return m;
        }
        if (f.src instanceof ClangFieldToken ft) {
            DataType dt = ft.getDataType();
            while (dt instanceof TypeDef td) dt = td.getBaseDataType();
            m.offset = ft.getOffset();
            if (dt instanceof Composite comp && m.offset >= 0) {
                DataTypeComponent c = comp instanceof Structure s ? s.getComponentContaining(m.offset) : null;
                if (c == null) {
                    for (DataTypeComponent cand : comp.getComponents()) {
                        if (f.text.equals(cand.getFieldName())) { c = cand; break; }
                    }
                }
                if (c != null) m.type = CType.of(c.getDataType(), pointerBits);
            }
        }
        return m;
    }

    private Expr parsePrimary() {
        Tok t = next();
        switch (t.kind) {
            case META: {
                String body = t.text.substring(1);
                int colon = body.indexOf(':');
                Id id = new Id(colon < 0 ? body : body.substring(0, colon), Id.Kind.META);
                id.metaKind = colon < 0 ? null : body.substring(colon + 1);
                return id;
            }
            case ID, FUNC, FIELD:
                return identifier(t);
            case NUM:
                return literal(t);
            case STR: {
                Lit s = new Lit(Lit.Kind.STRING, null, t.text, CType.pointerTo(CType.integer(8, true, "char"), pointerBits));
                // The token for a string the program contains carries that string's address.
                Varnode where = t.src == null ? null : t.src.getVarnode();
                if (where != null && where.isConstant()) s.value = BigInteger.valueOf(where.getOffset()).mod(BigInteger.ONE.shiftLeft(pointerBits));
                return s;
            }
            case PUNCT:
                if (t.text.equals("(")) {
                    Expr e = parseExpr();
                    expect(")");
                    return e;
                }
                break;
            default:
                break;
        }
        throw new ParseError("Unexpected '" + t.text + "'");
    }

    private Expr identifier(Tok t) {
        ClangToken src = t.src;
        boolean callee = peek().is("(");
        Id id = new Id(t.text, t.kind == Tok.Kind.FUNC || (callee && src == null) ? Id.Kind.FUNC : Id.Kind.VAR);
        if (src == null) {
            CType declared = scope == null ? null : scope.typeOf(t.text);
            if (declared != null) id.type = declared;
            return id;
        }
        if (src instanceof ClangFuncNameToken || t.kind == Tok.Kind.FUNC) {
            id.kind = Id.Kind.FUNC;
            PcodeOp op = src.getPcodeOp();
            id.op = op;
            id.addr = addrOf(op);
            if (op != null && op.getOpcode() == PcodeOp.CALL && scope != null) {
                id.function = scope.functionAt(op.getInput(0).getAddress());
                if (id.function != null) id.type = CType.of(id.function.getReturnType(), pointerBits);
            }
            return id;
        }
        HighVariable high = src.getHighVariable();
        id.high = high;
        if (high instanceof HighParam) id.kind = Id.Kind.PARAM;
        else if (high instanceof HighGlobal) {
            id.kind = Id.Kind.GLOBAL;
            HighSymbol sym = high.getSymbol();
            if (sym != null && sym.getStorage() != null && sym.getStorage().isMemoryStorage()) id.storage = sym.getStorage().getMinAddress();
        }
        CType declared = scope == null ? null : scope.typeOf(t.text);
        if (declared != null) id.type = declared;
        else if (high != null && high.getDataType() != null) id.type = CType.of(high.getDataType(), pointerBits);
        else if (src.getVarnode() != null) id.type = CType.integer(src.getVarnode().getSize() * 8, false);
        return id;
    }

    private Expr literal(Tok t) {
        String text = t.text;
        ClangToken src = t.src;
        int bits = 0;
        Boolean signed = null;
        CType highType = null;
        BigInteger fallback = null;
        if (src != null) {
            Varnode vn = src.getVarnode();
            if (vn != null && vn.isConstant()) {
                bits = vn.getSize() * 8;
                fallback = BigInteger.valueOf(vn.getOffset());
            }
            if (src.getScalar() != null) {
                if (bits == 0) bits = src.getScalar().bitLength();
                if (fallback == null) fallback = src.getScalar().getBigInteger();
            }
            HighVariable high = src.getHighVariable();
            if (high != null && high.getDataType() != null) {
                highType = CType.of(high.getDataType(), pointerBits);
                if (highType.isScalarInt()) signed = highType.signed;
                if (bits == 0 && highType.isScalarInt()) bits = highType.bits;
            }
        }
        if (text.equals("true") || text.equals("false")) {
            return new Lit(Lit.Kind.INT, text.equals("true") ? BigInteger.ONE : BigInteger.ZERO, text, CType.BOOL);
        }
        int quote = text.indexOf('\'');
        if (quote >= 0 && quote <= 1) {
            int w = bits != 0 ? bits : quote == 1 ? 16 : 8;
            BigInteger v = BigInteger.valueOf(charValue(text.substring(quote + 1, text.length() - 1))).mod(BigInteger.ONE.shiftLeft(w));
            return new Lit(Lit.Kind.CHAR, v, text, CType.integer(w, signed == null ? w == 8 : signed));
        }
        Matcher m = NUMBER.matcher(text);
        if (m.matches()) {
            String digits = m.group(2);
            BigInteger v = digits.startsWith("0x") || digits.startsWith("0X")
                ? new BigInteger(digits.substring(2), 16) : new BigInteger(digits, 10);
            boolean negative = !m.group(1).isEmpty();
            if (negative) v = v.negate();
            if (bits == 0) {
                // Rule text: the literal's width is decided by what it is combined with.
                Lit l = new Lit(Lit.Kind.INT, v, src != null ? text : null, CType.UNKNOWN);
                l.flexible = true;
                return l;
            }
            boolean unsignedSuffix = m.group(3).toLowerCase().contains("u");
            boolean isSigned = negative || (signed != null && signed && !unsignedSuffix);
            v = v.mod(BigInteger.ONE.shiftLeft(bits));
            CType type = highType != null && highType.isPointer() && highType.bits == bits ? highType : CType.integer(bits, isSigned);
            return new Lit(Lit.Kind.INT, v, text, type);
        }
        if (text.matches("-?[0-9]*\\.[0-9]*([eE][-+]?[0-9]+)?[fFlL]?") || text.matches("-?[0-9]+[eE][-+]?[0-9]+")) {
            return new Lit(Lit.Kind.FLOAT, null, text, CType.floating(bits == 0 ? 64 : bits, "double"));
        }
        // A named constant (an enum member, say): keep the name, use the value behind it.
        if (fallback != null && bits > 0) {
            return new Lit(Lit.Kind.INT, fallback.mod(BigInteger.ONE.shiftLeft(bits)), text,
                highType != null && highType.isScalarInt() && highType.bits == bits ? highType : CType.integer(bits, false));
        }
        throw new ParseError("Unrecognized literal '" + text + "'");
    }

    private static long charValue(String body) {
        if (body.isEmpty()) return 0;
        if (body.charAt(0) != '\\') return body.codePointAt(0);
        if (body.length() < 2) return '\\';
        char c = body.charAt(1);
        switch (c) {
            case 'n': return '\n';
            case 't': return '\t';
            case 'r': return '\r';
            case 'a': return 7;
            case 'b': return '\b';
            case 'f': return '\f';
            case 'v': return 11;
            case 'x': return Long.parseLong(body.substring(2), 16);
            case 'u', 'U': return Long.parseLong(body.substring(2), 16);
            default:
                if (c >= '0' && c <= '7') return Long.parseLong(body.substring(1), 8);
                return c;
        }
    }

    // ------------------------------------------------------------------ p-code helpers

    private static PcodeOp opOf(Tok t) { return t.src == null ? null : t.src.getPcodeOp(); }

    private static Address addrOf(PcodeOp op) {
        return op == null || op.getSeqnum() == null ? null : op.getSeqnum().getTarget();
    }

    /** Type of the value a p-code operation produces, as the decompiler typed it. */
    private CType typeOfOutput(PcodeOp op) {
        Varnode out = op.getOutput();
        if (out == null) return null;
        int bits = out.getSize() * 8;
        HighVariable high = out.getHigh();
        if (high != null && high.getDataType() != null) {
            CType t = CType.of(high.getDataType(), pointerBits);
            if (t.bits == bits && (t.isScalarInt() || t.isFloat())) return t;
        }
        return CType.integer(bits, false);
    }
}
