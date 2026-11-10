/*
 * TaintQueryParser - Parses query strings into TaintQuery objects
 *
 * Supports:
 *   - Full PATTERN syntax
 *   - Quick patterns (just the code pattern without PATTERN wrapper)
 *   - Built-in pattern templates
 *
 * Anything the parser does not understand is a ParseException: an unknown
 * statement used to become a wildcard that silently matched nothing.
 */
package decompfuncutils;

import java.util.*;
import java.util.regex.*;

public class TaintQueryParser {

    // Built-in query templates
    public static final Map<String, String> BUILTIN_PATTERNS = new LinkedHashMap<>();

    // Function families shared by several templates.
    private static final String ALLOCATORS =
        "\"malloc\", \"calloc\", \"realloc\", \"reallocarray\", \"strdup\", \"strndup\", \"valloc\", \"aligned_alloc\"";
    private static final String SIZE_ALLOCATORS =
        "\"malloc\", \"alloca\", \"valloc\", \"pvalloc\", \"xmalloc\", \"g_malloc\", \"operator.new\", \"operator.new[]\"";
    private static final String BUFFER_BUILDERS =
        "\"sprintf\", \"snprintf\", \"vsprintf\", \"vsnprintf\", \"strcpy\", \"strncpy\", \"stpcpy\", \"strcat\", "
        + "\"strncat\", \"strlcpy\", \"strlcat\", \"memcpy\", \"memmove\", \"wsprintfA\", \"lstrcpyA\", \"lstrcatA\"";
    private static final String COMMAND_SINKS =
        "\"system\", \"popen\", \"execl\", \"execlp\", \"execle\", \"execv\", \"execvp\", \"execve\", \"execvpe\", "
        + "\"WinExec\", \"_popen\", \"_wsystem\"";

    static {
        // Sink presets use tainted_ext(): data must come from a real input source
        // (getenv/read/recv/..., directly, through a builder buffer, or through a
        // wrapper's return value). Use tainted() in a custom query to also treat
        // every function parameter as attacker controlled.

        // Buffer overflow patterns
        BUILTIN_PATTERNS.put("strcpy_overflow",
            "PATTERN strcpy_overflow {\n" +
            "    $copy($dst, $src);\n" +
            "} WHERE function_in($copy, \"strcpy\", \"strcat\", \"stpcpy\") AND tainted_ext($src)");

        BUILTIN_PATTERNS.put("sprintf_overflow",
            "PATTERN sprintf_overflow {\n" +
            "    $fn($dst, $fmt, ...);\n" +
            "} WHERE function_in($fn, \"sprintf\", \"vsprintf\") AND tainted_ext($fmt)");

        BUILTIN_PATTERNS.put("memcpy_overflow",
            "PATTERN memcpy_overflow {\n" +
            "    memcpy($dst, $src, $len);\n" +
            "} WHERE tainted_ext($len)");

        // Stricter than memcpy_overflow: the input-derived length is also never
        // compared with a bound (or clamped with a min()) before the copy, and
        // is not simply the length of a string.
        BUILTIN_PATTERNS.put("unbounded_copy_length",
            "PATTERN unbounded_copy_length {\n" +
            "    $copy($dst, $src, $len);\n" +
            "} WHERE function_in($copy, \"memcpy\", \"memmove\", \"strncpy\", \"strncat\", \"bcopy\")"
            + " AND tainted_ext($len) AND NOT bounded($len)"
            + " AND NOT returned_by($len, \"strlen\", \"strnlen\", \"wcslen\")");

        BUILTIN_PATTERNS.put("gets_usage",
            "PATTERN gets_usage {\n" +
            "    gets($buf);\n" +
            "}");

        // Format string patterns (v*printf / dprintf share the argument layout)
        BUILTIN_PATTERNS.put("format_string",
            "PATTERN format_string {\n" +
            "    $fn($fmt, ...);\n" +
            "} WHERE function_in($fn, \"printf\", \"vprintf\") AND tainted_ext($fmt) AND NOT is_constant($fmt)");

        BUILTIN_PATTERNS.put("syslog_format",
            "PATTERN syslog_format {\n" +
            "    $fn($pri, $fmt, ...);\n" +
            "} WHERE function_in($fn, \"syslog\", \"vsyslog\") AND tainted_ext($fmt)");

        // Command injection. The command may be the input itself or a buffer
        // that sprintf/strcpy/strcat/... filled with input earlier on the path.
        BUILTIN_PATTERNS.put("command_injection",
            "PATTERN command_injection {\n" +
            "    system($cmd);\n" +
            "} WHERE tainted_ext($cmd)");

        BUILTIN_PATTERNS.put("popen_injection",
            "PATTERN popen_injection {\n" +
            "    popen($cmd, $mode);\n" +
            "} WHERE tainted_ext($cmd)");

        BUILTIN_PATTERNS.put("exec_injection",
            "PATTERN exec_injection {\n" +
            "    $exec($path, ...);\n" +
            "} WHERE function_in($exec, \"execl\", \"execlp\", \"execle\", \"execv\", \"execvp\", \"execve\", \"execvpe\")"
            + " AND tainted_ext($path)");

        // Windows process creation. WinExec(cmd, show); ShellExecute(hwnd, verb,
        // file, params, ...); CreateProcess(app, cmdline, ...).
        BUILTIN_PATTERNS.put("winexec_injection",
            "PATTERN winexec_injection {\n" +
            "    $exec($cmd, ...);\n" +
            "} WHERE function_in($exec, \"WinExec\", \"_wpopen\", \"_wsystem\") AND tainted_ext($cmd)");

        BUILTIN_PATTERNS.put("shellexecute_injection",
            "PATTERN shellexecute_injection {\n" +
            "    $exec(_, _, $file, $params, ...);\n" +
            "} WHERE function_in($exec, \"ShellExecuteA\", \"ShellExecuteW\")"
            + " AND (tainted_ext($file) OR tainted_ext($params))");

        BUILTIN_PATTERNS.put("createprocess_injection",
            "PATTERN createprocess_injection {\n" +
            "    $exec($app, $cmdline, ...);\n" +
            "} WHERE function_in($exec, \"CreateProcessA\", \"CreateProcessW\")"
            + " AND (tainted_ext($app) OR tainted_ext($cmdline))");

        // The classic shape of real command injections: build the command in a
        // buffer, then run it. Reports the builder call and the sink.
        BUILTIN_PATTERNS.put("command_injection_buffer",
            "PATTERN command_injection_buffer {\n" +
            "    $build($buf, ...);\n" +
            "    ...;\n" +
            "    $sink($buf, ...);\n" +
            "} WHERE function_in($build, " + BUFFER_BUILDERS + ")"
            + " AND function_in($sink, " + COMMAND_SINKS + ") AND tainted_ext($buf)");

        BUILTIN_PATTERNS.put("format_string_buffer",
            "PATTERN format_string_buffer {\n" +
            "    $build($buf, ...);\n" +
            "    ...;\n" +
            "    $sink($buf, ...);\n" +
            "} WHERE function_in($build, " + BUFFER_BUILDERS + ")"
            + " AND function_in($sink, \"printf\", \"vprintf\") AND tainted_ext($buf)");

        // Use-after-free (with negative check - no reassignment between free and use)
        BUILTIN_PATTERNS.put("use_after_free",
            "PATTERN use_after_free {\n" +
            "    free($ptr);\n" +
            "    ... not:$ptr=_;\n" +
            "    *$ptr;\n" +
            "}");

        // Use-after-free simple
        BUILTIN_PATTERNS.put("use_after_free_simple",
            "PATTERN use_after_free_simple {\n" +
            "    free($ptr);\n" +
            "    ...;\n" +
            "    *$ptr;\n" +
            "}");

        // Double free - with negative check (no reassignment between frees)
        BUILTIN_PATTERNS.put("double_free",
            "PATTERN double_free {\n" +
            "    free($ptr);\n" +
            "    ... not:$ptr=_;\n" +
            "    free($ptr);\n" +
            "}");

        // Double free simple (without negative check)
        BUILTIN_PATTERNS.put("double_free_simple",
            "PATTERN double_free_simple {\n" +
            "    free($ptr);\n" +
            "    ...;\n" +
            "    free($ptr);\n" +
            "}");

        // Only modeled memory-access APIs qualify; arbitrary calls may merely
        // compare/log a pointer or accept ownership without dereferencing it.
        BUILTIN_PATTERNS.put("use_after_free_as_arg",
            "PATTERN use_after_free_as_arg {\n" +
            "    free($ptr);\n" +
            "    ... not:$ptr=_;\n" +
            "    $usefn($ptr);\n" +
            "} WHERE function_in($usefn, \"strlen\", \"puts\", \"strcpy\", \"memcpy\", \"memset\") AND NOT is_constant($ptr)");

        // Source-buffer argument of known copy/concatenation APIs.
        BUILTIN_PATTERNS.put("use_after_free_as_arg2",
            "PATTERN use_after_free_as_arg2 {\n" +
            "    free($ptr);\n" +
            "    ... not:$ptr=_;\n" +
            "    $usefn(_, $ptr);\n" +
            "} WHERE function_in($usefn, \"memcpy\", \"memmove\", \"strcpy\", \"strcat\") AND NOT is_constant($ptr)");

        // Repeated calls must be known heap deallocators, not arbitrary APIs.
        BUILTIN_PATTERNS.put("double_free_like",
            "PATTERN double_free_like {\n" +
            "    $freefn($ptr);\n" +
            "    ... not:$ptr=_;\n" +
            "    $freefn($ptr);\n" +
            "} WHERE function_in($freefn, \"free\", \"g_free\", \"cfree\") AND NOT is_constant($ptr)");

        // Integer overflow: size computed in one statement, allocated in another.
        BUILTIN_PATTERNS.put("int_overflow_malloc",
            "PATTERN int_overflow_malloc {\n" +
            "    $size = $a * $b;\n" +
            "    malloc($size);\n" +
            "} WHERE (tainted_ext($a) OR tainted_ext($b)) AND NOT overflow_checked($a, $b)");

        // Allocation-size overflow: the product (or sum) is the allocation size,
        // an operand comes from input and nothing bounds it. calloc() is not
        // matched because it checks the multiplication itself.
        BUILTIN_PATTERNS.put("alloc_mul_overflow",
            "PATTERN alloc_mul_overflow {\n" +
            "    $alloc($a * $b);\n" +
            "} WHERE function_in($alloc, " + SIZE_ALLOCATORS + ")"
            + " AND (tainted_ext($a) OR tainted_ext($b)) AND NOT overflow_checked($a, $b)");

        BUILTIN_PATTERNS.put("realloc_mul_overflow",
            "PATTERN realloc_mul_overflow {\n" +
            "    realloc(_, $a * $b);\n" +
            "} WHERE (tainted_ext($a) OR tainted_ext($b)) AND NOT overflow_checked($a, $b)");

        // strlen()+1 style sizes are excluded: a string length cannot wrap.
        BUILTIN_PATTERNS.put("alloc_add_overflow",
            "PATTERN alloc_add_overflow {\n" +
            "    $alloc($n + $k);\n" +
            "} WHERE function_in($alloc, " + SIZE_ALLOCATORS + ")"
            + " AND is_constant($k) AND tainted_ext($n) AND NOT overflow_checked($n)"
            + " AND NOT returned_by($n, \"strlen\", \"strnlen\", \"wcslen\")");

        // Allocation size and copy length are unrelated: the length is input,
        // is never bounded, and is neither derived from nor compared with the
        // allocation size.
        BUILTIN_PATTERNS.put("alloc_copy_mismatch",
            "PATTERN alloc_copy_mismatch {\n" +
            "    $p = $alloc($n);\n" +
            "    ... not:$p=_;\n" +
            "    $copy($p, _, $m);\n" +
            "} WHERE function_in($alloc, " + SIZE_ALLOCATORS + ")"
            + " AND function_in($copy, \"memcpy\", \"memmove\", \"strncpy\", \"strncat\")"
            + " AND tainted_ext($m) AND NOT related($m, $n) AND NOT bounded($m)");

        BUILTIN_PATTERNS.put("alloc_read_mismatch",
            "PATTERN alloc_read_mismatch {\n" +
            "    $p = $alloc($n);\n" +
            "    ... not:$p=_;\n" +
            "    $rd(_, $p, $m, ...);\n" +
            "} WHERE function_in($alloc, " + SIZE_ALLOCATORS + ")"
            + " AND function_in($rd, \"read\", \"recv\", \"recvfrom\", \"pread\")"
            + " AND tainted_ext($m) AND NOT related($m, $n) AND NOT bounded($m)");

        // Integer-truncation → heap-overflow.
        //
        // NOTE (field note 2026-04-17): these two DSL patterns are kept for
        // completeness but do NOT reliably fire on real binaries. The cast
        // almost never decompiles as a stand-alone statement — it is folded
        // into `malloc((int)x)` / `malloc(x & 0xffffffff)`, so there is no
        // ClangStatement whose stmtAddr maps to a SUBPIECE / INT_AND with
        // the right shape, and the three-statement sequence below never
        // matches. For real audits use the dedicated MCP tool
        // `ghidra_find_integer_truncation`, which walks the p-code def-use
        // chain of every alloc/copy size argument directly and cross-
        // references shared sources at different widths.
        BUILTIN_PATTERNS.put("int_trunc_heap_overflow",
            "PATTERN int_trunc_heap_overflow {\n" +
            "    $small = (int)$big;\n" +
            "    $buf = malloc($small);\n" +
            "    memcpy($buf, $src, $big);\n" +
            "} WHERE tainted($big)");

        // Variant: same bug expressed via bitmask truncation. Same caveat as
        // above — prefer `ghidra_find_integer_truncation`.
        BUILTIN_PATTERNS.put("int_trunc_heap_overflow_mask",
            "PATTERN int_trunc_heap_overflow_mask {\n" +
            "    $small = $big & 0xffffffff;\n" +
            "    $buf = malloc($small);\n" +
            "    memcpy($buf, $src, $big);\n" +
            "} WHERE tainted($big)");

        // Tainted SIGNED length: only an upper bound (or nothing) is checked, so
        // a negative value becomes a huge size_t.
        BUILTIN_PATTERNS.put("signed_length_copy",
            "PATTERN signed_length_copy {\n" +
            "    $fn(_, _, $len, ...);\n" +
            "} WHERE function_in($fn, \"memcpy\", \"memmove\", \"memset\", \"strncpy\", \"strncat\", \"read\", \"recv\","
            + " \"pread\", \"write\", \"send\")"
            + " AND signed($len) AND tainted_ext($len) AND NOT nonneg_checked($len)"
            + " AND NOT returned_by($len, \"strlen\", \"strnlen\", \"wcslen\")");

        BUILTIN_PATTERNS.put("signed_length_alloc",
            "PATTERN signed_length_alloc {\n" +
            "    $alloc($len);\n" +
            "} WHERE function_in($alloc, " + SIZE_ALLOCATORS + ")"
            + " AND signed($len) AND tainted_ext($len) AND NOT nonneg_checked($len)"
            + " AND NOT returned_by($len, \"strlen\", \"strnlen\", \"wcslen\")");

        // Allocation result used without ever being compared (NULL dereference).
        // unchecked() follows the value itself, so the check is found wherever
        // the decompiler prints it.
        BUILTIN_PATTERNS.put("unchecked_alloc_deref",
            "PATTERN unchecked_alloc_deref {\n" +
            "    $p = $alloc(...);\n" +
            "    ... not:$p=_;\n" +
            "    *$p;\n" +
            "} WHERE function_in($alloc, " + ALLOCATORS + ") AND unchecked($p)");

        BUILTIN_PATTERNS.put("unchecked_alloc_use",
            "PATTERN unchecked_alloc_use {\n" +
            "    $p = $alloc(...);\n" +
            "    ... not:$p=_;\n" +
            "    $use($p, ...);\n" +
            "} WHERE function_in($alloc, " + ALLOCATORS + ")"
            + " AND function_in($use, \"memcpy\", \"memmove\", \"memset\", \"strcpy\", \"strncpy\", \"strcat\","
            + " \"sprintf\", \"snprintf\", \"fgets\", \"fread\", \"gets\") AND unchecked($p)");

        // Legacy names for the unchecked-allocation query.
        BUILTIN_PATTERNS.put("null_deref_after_malloc", BUILTIN_PATTERNS.get("unchecked_alloc_deref"));
        BUILTIN_PATTERNS.put("null_deref_unchecked", BUILTIN_PATTERNS.get("unchecked_alloc_deref"));

        // p = realloc(p, n): on failure the only pointer to the block is lost
        // (leak) and p becomes NULL.
        BUILTIN_PATTERNS.put("realloc_misuse",
            "PATTERN realloc_misuse {\n" +
            "    $p = realloc($p, $n);\n" +
            "}");

        // Time-of-check to time-of-use on a path name.
        BUILTIN_PATTERNS.put("toctou_file_access",
            "PATTERN toctou_file_access {\n" +
            "    $check($path, ...);\n" +
            "    ... not:$path=_;\n" +
            "    $use($path, ...);\n" +
            "} WHERE function_in($check, \"access\", \"stat\", \"lstat\", \"stat64\", \"lstat64\", \"euidaccess\", \"eaccess\")"
            + " AND function_in($use, \"open\", \"open64\", \"fopen\", \"fopen64\", \"creat\", \"unlink\", \"remove\","
            + " \"chmod\", \"chown\", \"rename\", \"mkdir\", \"rmdir\", \"truncate\", \"opendir\", \"execv\", \"execve\")");

        // read()/recv() can return -1; using the result as a length without any
        // check turns the error into a huge size.
        BUILTIN_PATTERNS.put("unchecked_read_length",
            "PATTERN unchecked_read_length {\n" +
            "    $n = $rd(...);\n" +
            "    ... not:$n=_;\n" +
            "    $use(_, _, $len, ...);\n" +
            "} WHERE function_in($rd, \"read\", \"recv\", \"recvfrom\", \"pread\", \"readlink\")"
            + " AND function_in($use, \"memcpy\", \"memmove\", \"strncpy\", \"memset\", \"write\", \"send\")"
            + " AND same($n, $len) AND unchecked($n)");

        // Constant length larger than the fixed-size stack buffer it fills.
        BUILTIN_PATTERNS.put("stack_buffer_const_overflow",
            "PATTERN stack_buffer_const_overflow {\n" +
            "    char $buf[$size];\n" +
            "    $fn($buf, _, $len, ...);\n" +
            "} WHERE function_in($fn, \"memcpy\", \"memmove\", \"memset\", \"strncpy\") AND const_gt($len, $size)");

        BUILTIN_PATTERNS.put("stack_buffer_const_read",
            "PATTERN stack_buffer_const_read {\n" +
            "    char $buf[$size];\n" +
            "    $fn(_, $buf, $len, ...);\n" +
            "} WHERE function_in($fn, \"read\", \"recv\", \"recvfrom\", \"pread\") AND const_gt($len, $size)");

        // SQL injection (common embedded DB functions)
        BUILTIN_PATTERNS.put("sql_injection",
            "PATTERN sql_injection {\n" +
            "    $fn($db, $sql, ...);\n" +
            "} WHERE function_in($fn, \"sqlite3_exec\", \"mysql_query\", \"PQexec\") AND tainted_ext($sql)");

        // Path traversal
        BUILTIN_PATTERNS.put("path_traversal",
            "PATTERN path_traversal {\n" +
            "    fopen($path, $mode);\n" +
            "} WHERE tainted_ext($path)");

        // Hardcoded credentials (look for strcmp with strings)
        BUILTIN_PATTERNS.put("hardcoded_creds",
            "PATTERN hardcoded_creds {\n" +
            "    strcmp($input, $password);\n" +
            "} WHERE is_constant($password)");

        // Broad sweep: any call whose first argument is a function parameter.
        BUILTIN_PATTERNS.put("tainted_param_to_sink",
            "PATTERN tainted_param_to_sink {\n" +
            "    $sink($arg, ...);\n" +
            "} WHERE is_param($arg) AND tainted($arg)");

        // std::string::find() result used as a position without an npos check.
        // (Earlier versions hard-coded a substr address from one binary.)
        BUILTIN_PATTERNS.put("find_no_npos_check",
            "PATTERN find_no_npos_check {\n" +
            "    $a = find(...);\n" +
            "    ... not:$a=_;\n" +
            "    $use(..., $pos, ...);\n" +
            "} WHERE function_in($use, \"substr\", \"erase\", \"replace\", \"insert\", \"at\")"
            + " AND related($a, $pos) AND unchecked($a)");
        BUILTIN_PATTERNS.put("find_to_substr_unchecked", BUILTIN_PATTERNS.get("find_no_npos_check"));

        // Use-after-free with tight distance bound (more precise)
        BUILTIN_PATTERNS.put("use_after_free_tight",
            "PATTERN use_after_free_tight {\n" +
            "    free($ptr);\n" +
            "    ...{0,20} not:$ptr=_;\n" +
            "    *$ptr;\n" +
            "}");
    }

    static {
        BUILTIN_PATTERNS.put("tainted_copy_length", BUILTIN_PATTERNS.get("memcpy_overflow"));
        BUILTIN_PATTERNS.put("tainted_format", BUILTIN_PATTERNS.get("format_string"));
        BUILTIN_PATTERNS.put("memmove_overflow",
            "PATTERN memmove_overflow { memmove($dst, $src, $len); } WHERE tainted_ext($len)");
        BUILTIN_PATTERNS.put("fprintf_format",
            "PATTERN fprintf_format { $fn($stream, $fmt, ...); } WHERE "
            + "function_in($fn, \"fprintf\", \"vfprintf\", \"dprintf\", \"vdprintf\") AND tainted_ext($fmt)");
        BUILTIN_PATTERNS.put("snprintf_format",
            "PATTERN snprintf_format { $fn($dst, $size, $fmt, ...); } WHERE "
            + "function_in($fn, \"snprintf\", \"vsnprintf\") AND tainted_ext($fmt)");
        for (String name : List.of("use_after_free", "double_free", "use_after_free_tight")) {
            BUILTIN_PATTERNS.put(name, BUILTIN_PATTERNS.get(name) + " WHERE NOT is_constant($ptr)");
        }
    }

    /**
     * Parse a query string
     */
    public TaintQuery parse(String queryText) throws ParseException {
        // Strip comments first
        queryText = stripComments(queryText).trim();

        if (queryText.isEmpty()) {
            throw new ParseException("Empty query after removing comments");
        }

        // Check if it's a builtin pattern name
        if (BUILTIN_PATTERNS.containsKey(queryText)) {
            queryText = BUILTIN_PATTERNS.get(queryText);
        }

        // Check for PATTERN keyword
        if (queryText.toUpperCase().startsWith("PATTERN")) {
            return parseFullPattern(queryText);
        }

        // Check for weggli-style inline: {free($ptr); not:$ptr=_; free($ptr);}
        if (queryText.startsWith("{")) {
            int close = findMatchingBrace(queryText, 0);
            if (close == queryText.length() - 1) {
                return parseWeggliStyle(queryText);
            }
            if (close > 0 && queryText.substring(close + 1).trim().toUpperCase().startsWith("WHERE")) {
                return parseFullPattern("PATTERN weggli_pattern " + queryText);
            }
            throw new ParseException("Unbalanced braces or unexpected text after '}' in pattern");
        }

        // Quick pattern - just function call or expression
        return parseQuickPattern(queryText);
    }

    /**
     * Strip line comments and block comments from query text
     */
    private String stripComments(String text) {
        StringBuilder result = new StringBuilder();
        String[] lines = text.split("\n");

        boolean inBlockComment = false;
        for (String line : lines) {
            if (inBlockComment) {
                int endIdx = line.indexOf("*/");
                if (endIdx != -1) {
                    inBlockComment = false;
                    line = line.substring(endIdx + 2);
                } else {
                    continue;  // Skip entire line
                }
            }

            // Remove // comments
            int lineCommentIdx = line.indexOf("//");
            if (lineCommentIdx != -1) {
                line = line.substring(0, lineCommentIdx);
            }

            // Handle /* */ on same line
            while (line.contains("/*")) {
                int startIdx = line.indexOf("/*");
                int endIdx = line.indexOf("*/", startIdx + 2);
                if (endIdx != -1) {
                    line = line.substring(0, startIdx) + line.substring(endIdx + 2);
                } else {
                    line = line.substring(0, startIdx);
                    inBlockComment = true;
                    break;
                }
            }

            if (!line.trim().isEmpty()) {
                result.append(line).append("\n");
            }
        }

        return result.toString();
    }

    /**
     * Parse weggli-style inline pattern: {stmt1; stmt2; ...}
     */
    private TaintQuery parseWeggliStyle(String text) throws ParseException {
        // Remove outer braces
        String body = text.substring(1, text.length() - 1).trim();

        // Check for WHERE clause
        String whereClause = null;
        int whereIdx = body.toUpperCase().lastIndexOf(" WHERE ");
        if (whereIdx != -1) {
            whereClause = body.substring(whereIdx + 7).trim();
            body = body.substring(0, whereIdx).trim();
        }

        List<TaintQuery.PatternElement> elements = parsePatternBody(body);

        TaintQuery.Constraint constraint = null;
        if (whereClause != null && !whereClause.isEmpty()) {
            constraint = parseConstraint(whereClause);
        }

        return build("weggli_pattern", body, elements, constraint);
    }

    /**
     * Parse full PATTERN syntax
     */
    private TaintQuery parseFullPattern(String text) throws ParseException {
        // Extract name
        Pattern namePattern = Pattern.compile("PATTERN\\s+(\\w+)\\s*\\{", Pattern.CASE_INSENSITIVE);
        Matcher nameMatcher = namePattern.matcher(text);
        if (!nameMatcher.find()) {
            throw new ParseException("Invalid PATTERN syntax - expected 'PATTERN name {'");
        }
        String name = nameMatcher.group(1);

        // Find the pattern body (between { and })
        int braceStart = text.indexOf('{');
        int braceEnd = findMatchingBrace(text, braceStart);
        if (braceEnd == -1) {
            throw new ParseException("Unmatched braces in pattern");
        }

        String patternBody = text.substring(braceStart + 1, braceEnd).trim();

        // Check for WHERE clause
        String whereClause = null;
        String tail = text.substring(braceEnd + 1).trim();
        if (!tail.isEmpty()) {
            if (!tail.toUpperCase().startsWith("WHERE")) {
                throw new ParseException("Unexpected text after pattern body: " + tail);
            }
            whereClause = tail.substring(5).trim();
            if (whereClause.isEmpty()) {
                throw new ParseException("WHERE needs a constraint");
            }
        }

        // Parse pattern elements
        List<TaintQuery.PatternElement> elements = parsePatternBody(patternBody);

        // Parse constraints
        TaintQuery.Constraint constraint = null;
        if (whereClause != null) {
            constraint = parseConstraint(whereClause);
        }

        return build(name, patternBody, elements, constraint);
    }

    private TaintQuery build(String name, String body, List<TaintQuery.PatternElement> elements,
                             TaintQuery.Constraint constraint) throws ParseException {
        if (elements.isEmpty()) {
            throw new ParseException("Pattern body is empty");
        }
        Set<String> boundVars = new HashSet<>();
        collectBoundVariables(elements, boundVars);
        return new TaintQuery.Builder()
            .name(name)
            .rawPattern(body)
            .elements(elements)
            .constraint(constraint)
            .variables(boundVars)
            .build();
    }

    /**
     * Parse quick pattern (just a function call or expression)
     */
    private TaintQuery parseQuickPattern(String text) throws ParseException {
        int where = findOperator(text, "WHERE");
        if (where >= 0) {
            return parseFullPattern("PATTERN quick_pattern { " + text.substring(0, where).trim()
                + "; } " + text.substring(where));
        }
        return build("quick_pattern", text, parsePatternBody(text), null);
    }

    /**
     * Parse the body of a pattern into elements
     */
    private List<TaintQuery.PatternElement> parsePatternBody(String body) throws ParseException {
        List<TaintQuery.PatternElement> elements = new ArrayList<>();

        // Split by semicolons (respecting nested structures)
        List<String> statements = splitStatements(body);

        for (String stmt : statements) {
            stmt = stmt.trim();
            if (stmt.isEmpty()) continue;
            elements.add(parseStatement(stmt));
        }

        return elements;
    }

    /**
     * Parse a single statement
     */
    private TaintQuery.PatternElement parseStatement(String stmt) throws ParseException {
        stmt = stmt.trim();

        // Wildcard multi with negative patterns (... not:$ptr=_)
        // Also supports distance constraint: ...{0,5} not:$ptr=_
        // Also supports guard/branch barrier: ...{0,5} guard:($a == 0xffffffff)
        //   and: ... not:($a == 0xffffffff)
        if (stmt.startsWith("...")) {
            return parseGap(stmt);
        }

        // Wildcard single (_): exactly one statement
        if (stmt.equals("_")) {
            return new TaintQuery.Wildcard();
        }

        // Assignment ($var = expr, type $var = expr, *$ptr = expr)
        int assign = findTopLevelAssignment(stmt);
        if (assign >= 0) {
            return parseAssignment(stmt.substring(0, assign).trim(), stmt.substring(assign + 1).trim());
        }

        // Branch condition ($p == 0, $n < $max)
        int[] cmp = findTopLevelComparison(stmt);
        if (cmp != null) {
            TaintQuery.Condition cond = new TaintQuery.Condition();
            cond.left = parseExpression(stmt.substring(0, cmp[0]).trim(), false);
            cond.op = stmt.substring(cmp[0], cmp[0] + cmp[1]);
            cond.right = parseExpression(stmt.substring(cmp[0] + cmp[1]).trim(), false);
            return cond;
        }

        // Variable declaration (type $var, type *$var, type $var[size])
        Pattern declPattern = Pattern.compile("^(\\w+)\\s*(\\*)?\\s*\\$(\\w+)(\\s*\\[([^\\]]*)\\])?\\s*$");
        Matcher declMatcher = declPattern.matcher(stmt);
        if (declMatcher.matches()) {
            TaintQuery.VariableDecl decl = new TaintQuery.VariableDecl();
            decl.typeName = declMatcher.group(1);
            decl.isPointer = declMatcher.group(2) != null;
            decl.varName = "$" + declMatcher.group(3);
            if (declMatcher.group(4) != null) {
                decl.isArray = true;
                String size = declMatcher.group(5).trim();
                if (size.isEmpty() || size.equals("_")) {
                    decl.arraySize = "_";
                } else if (size.matches("\\$\\w+")) {
                    decl.arraySize = "_";
                    decl.sizeVar = size;
                } else {
                    try {
                        decl.arraySize = Long.toString(Long.decode(size));
                    } catch (NumberFormatException e) {
                        throw new ParseException("Array size must be a number, _ or $var: " + stmt);
                    }
                }
            }
            if (decl.typeName.equals("_") || decl.typeName.equals("any")) {
                decl.typeName = null;
            }
            return decl;
        }

        // Expression statements: a call, or a dereference of a variable
        TaintQuery.Expr expr = parseExpression(stmt, false);
        if (expr instanceof TaintQuery.CallExpr callExpr) {
            return toFunctionCall(callExpr);
        }
        if (expr instanceof TaintQuery.DerefExpr deref && deref.pointer instanceof TaintQuery.VarExpr ptr) {
            TaintQuery.Dereference element = new TaintQuery.Dereference();
            element.ptrVar = ptr.name;
            return element;
        }
        throw new ParseException("Unsupported pattern statement: '" + stmt + "'. Expected a call f($a, ...), "
            + "an assignment $x = ..., a dereference *$p, a condition $a == 0, a declaration "
            + "char $buf[_], a gap '...' or a single-statement wildcard '_'.");
    }

    private TaintQuery.FunctionCall toFunctionCall(TaintQuery.CallExpr callExpr) {
        TaintQuery.FunctionCall call = new TaintQuery.FunctionCall();
        call.funcName = callExpr.funcName;
        call.argExprs = callExpr.args;
        call.args = new ArrayList<>();
        for (TaintQuery.Expr arg : callExpr.args) call.args.add(arg.toString());
        return call;
    }

    /** {@code ...}, {@code ...{min,max}}, with optional {@code not:} / {@code guard:} clauses. */
    private TaintQuery.PatternElement parseGap(String stmt) throws ParseException {
        TaintQuery.WildcardMulti wm = new TaintQuery.WildcardMulti();

        String remaining = stmt.substring(3).trim();

        // Parse optional distance constraint: {min,max} or {max}
        Pattern distPattern = Pattern.compile("^\\{\\s*(\\d+)\\s*(?:,\\s*(\\d*))?\\s*\\}(.*)$", Pattern.DOTALL);
        Matcher distMatcher = distPattern.matcher(remaining);
        if (distMatcher.matches()) {
            String first = distMatcher.group(1);
            String second = distMatcher.group(2);

            if (second != null) {
                // {min,max} or {min,} (unbounded max)
                wm.minDistance = Integer.parseInt(first);
                if (!second.isEmpty()) {
                    wm.maxDistance = Integer.parseInt(second);
                }
                // else maxDistance stays -1 (unbounded)
            } else {
                // {max} - shorthand for {0,max}
                wm.minDistance = 0;
                wm.maxDistance = Integer.parseInt(first);
            }
            remaining = distMatcher.group(3).trim();
        }

        // Parse not: and guard: clauses
        while (remaining.toLowerCase().startsWith("not:") ||
               remaining.toLowerCase().startsWith("guard:")) {

            boolean isGuard = remaining.toLowerCase().startsWith("guard:");
            remaining = remaining.substring(isGuard ? 6 : 4).trim();

            TaintQuery.NegativePattern neg = new TaintQuery.NegativePattern();

            // Check for conditional comparison pattern: ($var == 0xconst) or ($var == const)
            Pattern condPattern = Pattern.compile(
                "^\\(\\s*(\\$\\w+)\\s*(?:==|!=|<=|>=|<|>|cmp)\\s*(?:0x([0-9a-fA-F]+)|(\\d+)|_)\\s*\\)(.*)$",
                Pattern.DOTALL);
            Matcher condMatcher = condPattern.matcher(remaining);
            if (condMatcher.matches()) {
                neg.guardVarName = condMatcher.group(1);
                neg.isGuardCheck = isGuard;

                String hexVal = condMatcher.group(2);
                String decVal = condMatcher.group(3);
                if (hexVal != null) {
                    neg.guardConstant = Long.parseUnsignedLong(hexVal, 16);
                } else if (decVal != null) {
                    neg.guardConstant = Long.parseLong(decVal);
                }
                // else guardConstant stays null (matches any comparison)

                wm.negatives.add(neg);
                remaining = condMatcher.group(4).trim();
                continue;
            }
            if (isGuard) {
                throw new ParseException("guard: expects a comparison such as guard:($a == 0): " + stmt);
            }

            // Check for $var=_ pattern (no assignment to var)
            Pattern assignPattern = Pattern.compile("^(\\$\\w+)\\s*=\\s*_(?!\\w)(.*)$", Pattern.DOTALL);
            Matcher assignMatcher = assignPattern.matcher(remaining);
            if (assignMatcher.matches()) {
                neg.varName = assignMatcher.group(1);
                wm.negatives.add(neg);
                remaining = assignMatcher.group(2).trim();
                continue;
            }

            // Function call pattern: not:free($ptr), not:operator.delete($ptr), not:$fn($p, ...)
            Matcher nameMatcher = Pattern.compile("^(\\$?[\\w.:]+)\\s*\\(").matcher(remaining);
            if (nameMatcher.find()) {
                int open = nameMatcher.end() - 1;
                int close = findMatchingParen(remaining, open);
                if (close < 0) {
                    throw new ParseException("Unbalanced parentheses in gap clause: " + stmt);
                }
                neg.pattern = remaining.substring(0, close + 1);
                TaintQuery.Expr expr = parseExpression(neg.pattern, false);
                if (!(expr instanceof TaintQuery.CallExpr callExpr)) {
                    throw new ParseException("not: expects a call pattern: " + neg.pattern);
                }
                neg.call = toFunctionCall(callExpr);
                wm.negatives.add(neg);
                remaining = remaining.substring(close + 1).trim();
                continue;
            }

            throw new ParseException("Unsupported gap clause near '" + remaining + "'. Expected not:$var=_, "
                + "not:func(args), not:($var == const) or guard:($var == const).");
        }

        if (!remaining.isEmpty()) {
            throw new ParseException("Unexpected text in gap statement: '" + remaining + "'");
        }
        return wm;
    }

    /**
     * Parse an assignment statement
     */
    private TaintQuery.PatternElement parseAssignment(String lhs, String rhs) throws ParseException {
        if (rhs.isEmpty()) {
            throw new ParseException("Assignment has no right-hand side: " + lhs + " =");
        }
        // Check if LHS is a declaration (type $var = ...)
        Pattern declAssign = Pattern.compile("^(\\w+)\\s*(\\*)?\\s*\\$(\\w+)$");
        Matcher declMatcher = declAssign.matcher(lhs);

        TaintQuery.Assignment assign = new TaintQuery.Assignment();

        if (declMatcher.matches()) {
            // It's a declaration with assignment
            assign.lhs = "$" + declMatcher.group(3);
        } else if (lhs.matches("\\$\\w+")) {
            assign.lhs = lhs;
        } else if (lhs.matches("\\*\\s*\\$\\w+")) {
            // Store through a pointer
            assign.lhs = "*" + lhs.substring(1).trim();
        } else if (lhs.equals("_")) {
            assign.lhs = "_";
        } else {
            throw new ParseException("Unsupported assignment target '" + lhs
                + "'. Use $var, *$ptr or _.");
        }

        assign.rhs = rhs;
        // Legacy narrowing-cast form "(int)$big" keeps its truncation semantics.
        if (!rhs.matches("^\\(\\s*[\\w\\s]+?\\s*\\)\\s*\\$\\w+\\s*$")) {
            assign.rhsExpr = parseExpression(rhs, false);
        } else if (assign.lhs.startsWith("*")) {
            throw new ParseException("A narrowing cast cannot be stored through a pointer pattern: " + rhs);
        }
        return assign;
    }

    /** Index of a top-level '=' that is an assignment (not ==, !=, <=, >=), or -1. */
    private int findTopLevelAssignment(String text) {
        int depth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(' || c == '[') depth++;
            else if (c == ')' || c == ']') depth--;
            else if (c == '=' && depth == 0) {
                char prev = i > 0 ? text.charAt(i - 1) : ' ';
                char next = i + 1 < text.length() ? text.charAt(i + 1) : ' ';
                if (next == '=') { i++; continue; }
                if (prev == '!' || prev == '<' || prev == '>' || prev == '=') continue;
                return i;
            }
        }
        return -1;
    }

    /** {position, length} of a top-level comparison operator, or null. */
    private int[] findTopLevelComparison(String text) {
        int depth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(' || c == '[') depth++;
            else if (c == ')' || c == ']') depth--;
            if (depth != 0) continue;
            char next = i + 1 < text.length() ? text.charAt(i + 1) : ' ';
            if ((c == '=' || c == '!') && next == '=') return new int[]{i, 2};
            if (c == '<' || c == '>') {
                if (next == c) { i++; continue; }          // shift operator
                if (c == '>' && i > 0 && text.charAt(i - 1) == '-') continue;
                return new int[]{i, next == '=' ? 2 : 1};
            }
        }
        return null;
    }

    private int findMatchingParen(String text, int openPos) {
        int depth = 0;
        for (int i = openPos; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    // ------------------------------------------------------------------
    // Expression patterns
    // ------------------------------------------------------------------

    /** Parse a value pattern such as {@code $a * $b}, {@code malloc(strlen($s))} or {@code 0x10}. */
    public TaintQuery.Expr parseExpression(String text, boolean allowRest) throws ParseException {
        ExprParser parser = new ExprParser(text);
        TaintQuery.Expr expr = parser.parseBinary(0);
        parser.skipSpace();
        if (parser.pos < text.length()) {
            throw new ParseException("Unexpected '" + text.substring(parser.pos) + "' in expression '" + text + "'");
        }
        if (!allowRest && expr instanceof TaintQuery.RestExpr) {
            throw new ParseException("'...' is only valid as a call argument or as a gap statement");
        }
        return expr;
    }

    private static final String[][] BINARY_LEVELS = {
        {"|"}, {"^"}, {"&"}, {"<<", ">>"}, {"+", "-"}, {"*", "/", "%"}
    };

    private static final class ExprParser {
        final String src;
        int pos;

        ExprParser(String src) { this.src = src; }

        void skipSpace() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
        }

        ParseException error(String message) {
            return new ParseException(message + " in expression '" + src + "'");
        }

        TaintQuery.Expr parseBinary(int level) throws ParseException {
            if (level == BINARY_LEVELS.length) return parseUnary();
            TaintQuery.Expr left = parseBinary(level + 1);
            while (true) {
                skipSpace();
                String op = null;
                for (String candidate : BINARY_LEVELS[level]) {
                    if (!src.startsWith(candidate, pos)) continue;
                    // Do not read "&&" / "||" as bit operators.
                    char after = pos + candidate.length() < src.length() ? src.charAt(pos + candidate.length()) : ' ';
                    if ((candidate.equals("&") || candidate.equals("|")) && after == candidate.charAt(0)) continue;
                    op = candidate;
                    break;
                }
                if (op == null) return left;
                if (left instanceof TaintQuery.RestExpr) throw error("'...' cannot be an operand");
                pos += op.length();
                TaintQuery.Expr right = parseBinary(level + 1);
                if (right instanceof TaintQuery.RestExpr) throw error("'...' cannot be an operand");
                left = new TaintQuery.BinaryExpr(op, left, right);
            }
        }

        TaintQuery.Expr parseUnary() throws ParseException {
            skipSpace();
            if (pos >= src.length()) throw error("Missing operand");
            char c = src.charAt(pos);
            if (c == '*') {
                pos++;
                return new TaintQuery.DerefExpr(parseUnary());
            }
            if (c == '(') {
                // "(type)operand" is read as a transparent cast, as printed by the decompiler.
                Matcher cast = Pattern.compile("\\(\\s*[A-Za-z_][\\w ]*\\**\\s*\\)\\s*(?=[$(\\w*'-])")
                    .matcher(src).region(pos, src.length());
                if (cast.lookingAt() && !src.substring(pos, cast.end()).matches("\\(\\s*_\\s*\\)\\s*")) {
                    pos = cast.end();
                    return parseUnary();
                }
                pos++;
                TaintQuery.Expr inner = parseBinary(0);
                skipSpace();
                if (pos >= src.length() || src.charAt(pos) != ')') throw error("Missing ')'");
                pos++;
                return inner;
            }
            return parsePrimary();
        }

        TaintQuery.Expr parsePrimary() throws ParseException {
            skipSpace();
            if (src.startsWith("...", pos)) {
                pos += 3;
                return new TaintQuery.RestExpr();
            }
            char c = src.charAt(pos);
            if (c == '\'') {
                if (pos + 2 < src.length() && src.charAt(pos + 2) == '\'') {
                    long value = src.charAt(pos + 1);
                    pos += 3;
                    return new TaintQuery.LiteralExpr(value);
                }
                throw error("Unsupported character literal");
            }
            if (c == '"') {
                throw error("String literals are not supported as value patterns; use _ or is_constant($var)");
            }
            Matcher number = Pattern.compile("-?(0[xX][0-9a-fA-F]+|\\d+)(?![\\w.])").matcher(src).region(pos, src.length());
            if (number.lookingAt()) {
                pos = number.end();
                String digits = number.group();
                try {
                    return new TaintQuery.LiteralExpr(Long.decode(digits));
                } catch (NumberFormatException tooLarge) {
                    try {
                        if (digits.startsWith("0x") || digits.startsWith("0X")) {
                            return new TaintQuery.LiteralExpr(Long.parseUnsignedLong(digits.substring(2), 16));
                        }
                    } catch (NumberFormatException ignored) {
                        // fall through
                    }
                    throw error("Invalid number '" + digits + "'");
                }
            }
            Matcher ident = Pattern.compile("\\$?[A-Za-z_][\\w]*((::|\\.)[A-Za-z_~][\\w]*)*(\\[\\])?")
                .matcher(src).region(pos, src.length());
            if (!ident.lookingAt()) {
                throw error("Unexpected '" + src.substring(pos) + "'");
            }
            String name = ident.group();
            pos = ident.end();
            skipSpace();
            boolean call = pos < src.length() && src.charAt(pos) == '(';
            if (!call) {
                if (name.equals("_")) return new TaintQuery.AnyExpr();
                if (name.matches("\\$\\w+")) return new TaintQuery.VarExpr(name);
                throw error("'" + name + "' is not a pattern variable; use $" + name
                    + " to bind a value, _ for anything, or " + name + "(...) for a call");
            }
            pos++;  // '('
            List<TaintQuery.Expr> args = new ArrayList<>();
            skipSpace();
            if (pos < src.length() && src.charAt(pos) == ')') {
                pos++;
                return new TaintQuery.CallExpr(name, args);
            }
            while (true) {
                args.add(parseBinary(0));
                skipSpace();
                if (pos >= src.length()) throw error("Missing ')'");
                char d = src.charAt(pos++);
                if (d == ')') break;
                if (d != ',') throw error("Expected ',' or ')' but found '" + d + "'");
            }
            return new TaintQuery.CallExpr(name, args);
        }
    }

    /**
     * Parse constraint expression
     */
    private TaintQuery.Constraint parseConstraint(String text) throws ParseException {
        text = text.trim();
        if (text.isEmpty()) {
            throw new ParseException("Empty constraint");
        }

        // Handle OR (lowest precedence)
        int orIdx = findOperator(text, "OR");
        if (orIdx != -1) {
            TaintQuery.OrConstraint or = new TaintQuery.OrConstraint();
            or.left = parseConstraint(text.substring(0, orIdx).trim());
            or.right = parseConstraint(text.substring(orIdx + 2).trim());
            return or;
        }

        // Handle AND
        int andIdx = findOperator(text, "AND");
        if (andIdx != -1) {
            TaintQuery.AndConstraint and = new TaintQuery.AndConstraint();
            and.left = parseConstraint(text.substring(0, andIdx).trim());
            and.right = parseConstraint(text.substring(andIdx + 3).trim());
            return and;
        }

        // Handle NOT
        if (text.toUpperCase().startsWith("NOT ") || text.toUpperCase().startsWith("NOT(")) {
            TaintQuery.NotConstraint not = new TaintQuery.NotConstraint();
            not.inner = parseConstraint(text.substring(3).trim());
            return not;
        }

        // Handle parentheses
        if (text.startsWith("(") && findMatchingParen(text, 0) == text.length() - 1) {
            return parseConstraint(text.substring(1, text.length() - 1));
        }

        // Parse individual constraint functions
        return parseConstraintFunction(text);
    }

    /**
     * Parse a single constraint function: name(arg, ...). Arguments are
     * $variables, "quoted names" or integers, depending on the constraint.
     */
    private TaintQuery.Constraint parseConstraintFunction(String text) throws ParseException {
        text = text.trim();

        Matcher shape = Pattern.compile("^(\\w+)\\s*\\((.*)\\)$", Pattern.DOTALL).matcher(text);
        if (!shape.matches()) {
            throw new ParseException("Unknown constraint: " + text);
        }
        String name = shape.group(1);
        List<String> vars = new ArrayList<>();
        List<String> names = new ArrayList<>();
        List<Long> numbers = new ArrayList<>();
        List<Character> kinds = new ArrayList<>();
        for (String raw : splitConstraintArguments(shape.group(2))) {
            String arg = raw.trim();
            if (arg.matches("\\$\\w+")) {
                vars.add(arg);
                kinds.add('v');
            } else if (arg.length() >= 2 && arg.startsWith("\"") && arg.endsWith("\"")) {
                names.add(arg.substring(1, arg.length() - 1));
                kinds.add('s');
            } else if (arg.matches("-?(0[xX][0-9a-fA-F]+|\\d+)")) {
                try {
                    numbers.add(Long.decode(arg));
                } catch (NumberFormatException e) {
                    numbers.add(Long.parseUnsignedLong(arg.substring(2), 16));
                }
                kinds.add('n');
            } else {
                throw new ParseException("Bad argument '" + arg + "' in constraint: " + text);
            }
        }
        StringBuilder signature = new StringBuilder();
        for (char kind : kinds) signature.append(kind);
        String sig = signature.toString();

        switch (name) {
            case "function_is": {
                requireSignature(text, sig, "vs");
                TaintQuery.FunctionIsConstraint constraint = new TaintQuery.FunctionIsConstraint();
                constraint.varName = vars.get(0);
                constraint.functionName = names.get(0);
                return constraint;
            }
            case "tainted": {
                requireSignature(text, sig, "v", "vs");
                TaintQuery.TaintedConstraint tc = new TaintQuery.TaintedConstraint();
                tc.varName = vars.get(0);
                tc.sourceName = names.isEmpty() ? null : names.get(0);
                return tc;
            }
            case "tainted_ext": {
                requireSignature(text, sig, "v");
                TaintQuery.TaintedConstraint tc = new TaintQuery.TaintedConstraint();
                tc.varName = vars.get(0);
                tc.externalOnly = true;
                return tc;
            }
            case "flows_to": {
                requireSignature(text, sig, "vv");
                TaintQuery.FlowsToConstraint fc = new TaintQuery.FlowsToConstraint();
                fc.srcVar = vars.get(0);
                fc.dstVar = vars.get(1);
                return fc;
            }
            case "is_constant": {
                requireSignature(text, sig, "v");
                TaintQuery.IsConstantConstraint ic = new TaintQuery.IsConstantConstraint();
                ic.varName = vars.get(0);
                return ic;
            }
            case "is_param": {
                requireSignature(text, sig, "v");
                TaintQuery.IsParamConstraint ip = new TaintQuery.IsParamConstraint();
                ip.varName = vars.get(0);
                return ip;
            }
            case "is_local": {
                requireSignature(text, sig, "v");
                TaintQuery.IsLocalConstraint il = new TaintQuery.IsLocalConstraint();
                il.varName = vars.get(0);
                return il;
            }
            case "unchecked": case "bounded": case "nonneg_checked": case "signed":
                requireSignature(text, sig, "v");
                break;
            case "overflow_checked":
                requireSignature(text, sig, "v", "vv");
                break;
            case "same": case "related":
                requireSignature(text, sig, "vv");
                break;
            case "in_loop":
                requireSignature(text, sig, "", "v");
                break;
            case "const_eq": case "const_ne": case "const_lt":
            case "const_le": case "const_gt": case "const_ge":
                requireSignature(text, sig, "vv", "vn");
                break;
            case "function_in": case "returned_by":
                if (!sig.matches("vs+")) {
                    throw new ParseException(name + " expects a $variable followed by quoted function names: " + text);
                }
                break;
            default:
                throw new ParseException("Unknown constraint: " + text);
        }
        TaintQuery.CheckConstraint check = new TaintQuery.CheckConstraint();
        check.kind = name;
        check.vars = vars;
        check.names = names;
        check.number = numbers.isEmpty() ? null : numbers.get(0);
        return check;
    }

    private void requireSignature(String text, String actual, String... allowed) throws ParseException {
        for (String candidate : allowed) {
            if (candidate.equals(actual)) return;
        }
        throw new ParseException("Wrong arguments for constraint: " + text);
    }

    private List<String> splitConstraintArguments(String text) throws ParseException {
        List<String> parts = new ArrayList<>();
        if (text.trim().isEmpty()) return parts;
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (char c : text.toCharArray()) {
            if (c == '"') quoted = !quoted;
            if (c == ',' && !quoted) {
                parts.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        if (quoted) throw new ParseException("Unterminated string in constraint arguments: " + text);
        parts.add(current.toString());
        return parts;
    }

    /**
     * Find operator at the top level (not inside parentheses or strings)
     */
    private int findOperator(String text, String op) {
        int depth = 0;
        boolean quoted = false;
        String upperText = text.toUpperCase();
        String searchOp = " " + op + " ";

        for (int i = 0; i <= text.length() - searchOp.length(); i++) {
            char c = text.charAt(i);
            if (c == '"') quoted = !quoted;
            if (quoted) continue;
            if (c == '(') depth++;
            else if (c == ')') depth--;

            if (depth == 0 && upperText.startsWith(searchOp, i)) {
                return i + 1;  // Return position of operator (after leading space)
            }
        }
        return -1;
    }

    /**
     * Find matching closing brace
     */
    private int findMatchingBrace(String text, int openPos) {
        int depth = 1;
        for (int i = openPos + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    /**
     * Split statements by semicolons
     */
    private List<String> splitStatements(String body) {
        List<String> statements = new ArrayList<>();
        int depth = 0;
        StringBuilder current = new StringBuilder();

        for (char c : body.toCharArray()) {
            if (c == '(' || c == '{' || c == '[') depth++;
            else if (c == ')' || c == '}' || c == ']') depth--;
            else if (c == ';' && depth == 0) {
                statements.add(current.toString().trim());
                current = new StringBuilder();
                continue;
            }
            current.append(c);
        }

        if (current.length() > 0) {
            String last = current.toString().trim();
            if (!last.isEmpty()) {
                statements.add(last);
            }
        }

        return statements;
    }

    /**
     * Collect all bound variables from pattern elements
     */
    private void collectBoundVariables(List<TaintQuery.PatternElement> elements, Set<String> vars) {
        for (TaintQuery.PatternElement elem : elements) {
            if (elem instanceof TaintQuery.VariableDecl vd) {
                vars.add(vd.varName);
                if (vd.sizeVar != null) vars.add(vd.sizeVar);
            } else if (elem instanceof TaintQuery.FunctionCall fc) {
                if (fc.funcName.startsWith("$")) vars.add(fc.funcName);
                for (TaintQuery.Expr arg : fc.argExprs) arg.collectVariables(vars);
            } else if (elem instanceof TaintQuery.Assignment a) {
                Matcher m = Pattern.compile("\\$\\w+").matcher(a.lhs + " " + a.rhs);
                while (m.find()) vars.add(m.group());
            } else if (elem instanceof TaintQuery.Dereference d) {
                vars.add(d.ptrVar);
            } else if (elem instanceof TaintQuery.Condition c) {
                c.left.collectVariables(vars);
                c.right.collectVariables(vars);
            }
        }
    }

    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    /**
     * Get list of builtin pattern names
     */
    public static Set<String> getBuiltinPatternNames() {
        return BUILTIN_PATTERNS.keySet();
    }

    /** Default catalog omits exploratory templates that lack bug-specific evidence.
     * Legacy names remain parseable for saved queries. */
    public static Map<String, String> getRecommendedPatterns() {
        Map<String, String> patterns = new LinkedHashMap<>();
        for (String name : List.of("tainted_copy_length", "tainted_format", "strcpy_overflow",
                "sprintf_overflow", "memcpy_overflow", "memmove_overflow", "unbounded_copy_length", "gets_usage",
                "format_string", "fprintf_format", "snprintf_format", "syslog_format",
                "format_string_buffer",
                "command_injection", "popen_injection", "exec_injection", "command_injection_buffer",
                "winexec_injection", "shellexecute_injection", "createprocess_injection",
                "use_after_free", "double_free",
                "use_after_free_as_arg", "use_after_free_as_arg2", "double_free_like",
                "unchecked_alloc_deref", "unchecked_alloc_use", "realloc_misuse",
                "alloc_mul_overflow", "realloc_mul_overflow", "alloc_add_overflow",
                "alloc_copy_mismatch", "alloc_read_mismatch",
                "signed_length_copy", "signed_length_alloc", "unchecked_read_length",
                "stack_buffer_const_overflow", "stack_buffer_const_read",
                "toctou_file_access",
                "sql_injection")) {
            patterns.put(name, BUILTIN_PATTERNS.get(name));
        }
        return Collections.unmodifiableMap(patterns);
    }

    /**
     * Get builtin pattern by name
     */
    public static String getBuiltinPattern(String name) {
        return BUILTIN_PATTERNS.get(name);
    }
}
