/*
 * TaintQueryParser - Parses query strings into TaintQuery objects
 * 
 * Supports:
 *   - Full PATTERN syntax
 *   - Quick patterns (just the code pattern without PATTERN wrapper)
 *   - Built-in pattern templates
 */
package decompfuncutils;

import java.util.*;
import java.util.regex.*;

public class TaintQueryParser {
    
    // Built-in query templates
    public static final Map<String, String> BUILTIN_PATTERNS = new LinkedHashMap<>();
    static {
        // Buffer overflow patterns
        BUILTIN_PATTERNS.put("strcpy_overflow", 
            "PATTERN strcpy_overflow {\n" +
            "    strcpy($dst, $src);\n" +
            "} WHERE tainted($src)");
        
        BUILTIN_PATTERNS.put("sprintf_overflow",
            "PATTERN sprintf_overflow {\n" +
            "    sprintf($dst, $fmt, ...);\n" +
            "} WHERE tainted($fmt) OR tainted($dst)");
        
        BUILTIN_PATTERNS.put("memcpy_overflow",
            "PATTERN memcpy_overflow {\n" +
            "    memcpy($dst, $src, $len);\n" +
            "} WHERE tainted($len) OR tainted($src)");
        
        BUILTIN_PATTERNS.put("gets_usage",
            "PATTERN gets_usage {\n" +
            "    gets($buf);\n" +
            "}");
        
        // Format string patterns
        BUILTIN_PATTERNS.put("format_string",
            "PATTERN format_string {\n" +
            "    printf($fmt, ...);\n" +
            "} WHERE tainted($fmt) AND NOT is_constant($fmt)");
        
        BUILTIN_PATTERNS.put("syslog_format",
            "PATTERN syslog_format {\n" +
            "    syslog($pri, $fmt, ...);\n" +
            "} WHERE tainted($fmt)");
        
        // Command injection
        BUILTIN_PATTERNS.put("command_injection",
            "PATTERN command_injection {\n" +
            "    system($cmd);\n" +
            "} WHERE tainted($cmd)");
        
        BUILTIN_PATTERNS.put("popen_injection",
            "PATTERN popen_injection {\n" +
            "    popen($cmd, $mode);\n" +
            "} WHERE tainted($cmd)");
        
        BUILTIN_PATTERNS.put("exec_injection",
            "PATTERN exec_injection {\n" +
            "    execve($path, $argv, $envp);\n" +
            "} WHERE tainted($path) OR tainted($argv)");
        
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
        
        // Integer overflow
        BUILTIN_PATTERNS.put("int_overflow_malloc",
            "PATTERN int_overflow_malloc {\n" +
            "    $size = $a * $b;\n" +
            "    malloc($size);\n" +
            "} WHERE tainted($a) OR tainted($b)");
        
        // Null pointer dereference
        BUILTIN_PATTERNS.put("null_deref_after_malloc",
            "PATTERN null_deref_after_malloc {\n" +
            "    $ptr = malloc($size);\n" +
            "    *$ptr;\n" +
            "}");
        
        // SQL injection (common embedded DB functions)
        BUILTIN_PATTERNS.put("sql_injection",
            "PATTERN sql_injection {\n" +
            "    sqlite3_exec($db, $sql, ...);\n" +
            "} WHERE tainted($sql)");
        
        // Path traversal
        BUILTIN_PATTERNS.put("path_traversal",
            "PATTERN path_traversal {\n" +
            "    fopen($path, $mode);\n" +
            "} WHERE tainted($path)");
        
        // Hardcoded credentials (look for strcmp with strings)
        BUILTIN_PATTERNS.put("hardcoded_creds",
            "PATTERN hardcoded_creds {\n" +
            "    strcmp($input, $password);\n" +
            "} WHERE is_constant($password)");
        
        // Uninitialized variable use
        BUILTIN_PATTERNS.put("tainted_param_to_sink",
            "PATTERN tainted_param_to_sink {\n" +
            "    $sink($arg, ...);\n" +
            "} WHERE is_param($arg) AND tainted($arg)");
        
        // === New patterns using distance constraints and guard checks ===
        
        // Find npos check: find() result used in arithmetic without npos validation
        // Uses distance constraint to keep matches tight, and not:($a == 0xffffffff)
        // to filter out paths that DO have a guard check (those are safe)
        BUILTIN_PATTERNS.put("find_no_npos_check",
            "PATTERN find_no_npos_check {\n" +
            "    $a = std::__cxx11::string::find();\n" +
            "    ...{0,5} not:$a=_ not:($a == 0xffffffff);\n" +
            "    FUN_000216e4(_, _, $a + _);\n" +
            "}");
        
        // Broader variant: find() to any substr without npos check
        BUILTIN_PATTERNS.put("find_to_substr_unchecked",
            "PATTERN find_to_substr_unchecked {\n" +
            "    $a = std::__cxx11::string::find();\n" +
            "    ...{0,8} not:$a=_ not:($a == 0xffffffff);\n" +
            "    FUN_000215c4(_, _, $a + _);\n" +
            "}");
        
        // Use-after-free with tight distance bound (more precise)
        BUILTIN_PATTERNS.put("use_after_free_tight",
            "PATTERN use_after_free_tight {\n" +
            "    free($ptr);\n" +
            "    ...{0,20} not:$ptr=_;\n" +
            "    *$ptr;\n" +
            "}");
        
        // Null pointer dereference without null check guard
        BUILTIN_PATTERNS.put("null_deref_unchecked",
            "PATTERN null_deref_unchecked {\n" +
            "    $ptr = malloc($size);\n" +
            "    ...{0,10} not:($ptr == 0x0);\n" +
            "    *$ptr;\n" +
            "}");
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
        if (queryText.startsWith("{") && queryText.endsWith("}")) {
            return parseWeggliStyle(queryText);
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
        
        Set<String> boundVars = new HashSet<>();
        collectBoundVariables(elements, boundVars);
        
        return new TaintQuery.Builder()
            .name("weggli_pattern")
            .rawPattern(body)
            .elements(elements)
            .constraint(constraint)
            .variables(boundVars)
            .build();
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
        int whereIdx = text.toUpperCase().indexOf("WHERE", braceEnd);
        if (whereIdx != -1) {
            whereClause = text.substring(whereIdx + 5).trim();
        }
        
        // Parse pattern elements
        List<TaintQuery.PatternElement> elements = parsePatternBody(patternBody);
        
        // Parse constraints
        TaintQuery.Constraint constraint = null;
        if (whereClause != null && !whereClause.isEmpty()) {
            constraint = parseConstraint(whereClause);
        }
        
        // Collect bound variables
        Set<String> boundVars = new HashSet<>();
        collectBoundVariables(elements, boundVars);
        
        return new TaintQuery.Builder()
            .name(name)
            .rawPattern(patternBody)
            .elements(elements)
            .constraint(constraint)
            .variables(boundVars)
            .build();
    }
    
    /**
     * Parse quick pattern (just a function call or expression)
     */
    private TaintQuery parseQuickPattern(String text) throws ParseException {
        List<TaintQuery.PatternElement> elements = parsePatternBody(text);
        Set<String> boundVars = new HashSet<>();
        collectBoundVariables(elements, boundVars);
        
        return new TaintQuery.Builder()
            .name("quick_pattern")
            .rawPattern(text)
            .elements(elements)
            .variables(boundVars)
            .build();
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
            
            TaintQuery.PatternElement elem = parseStatement(stmt);
            if (elem != null) {
                elements.add(elem);
            }
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
            TaintQuery.WildcardMulti wm = new TaintQuery.WildcardMulti();
            
            String remaining = stmt.substring(3).trim();
            
            // Parse optional distance constraint: {min,max} or {max}
            Pattern distPattern = Pattern.compile("^\\{\\s*(\\d+)\\s*(?:,\\s*(\\d*))?\\s*\\}(.*)$");
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
                    "^\\(\\s*(\\$\\w+)\\s*(?:==|!=|cmp)\\s*(?:0x([0-9a-fA-F]+)|(\\d+)|_)\\s*\\)(.*)$");
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
                    if (remaining.startsWith(";")) {
                        remaining = remaining.substring(1).trim();
                    }
                    continue;
                }
                
                // Check for $var=_ pattern (no assignment to var)
                Pattern assignPattern = Pattern.compile("^(\\$\\w+)\\s*=\\s*_(.*)$");
                Matcher assignMatcher = assignPattern.matcher(remaining);
                if (assignMatcher.matches()) {
                    neg.varName = assignMatcher.group(1);
                    wm.negatives.add(neg);
                    remaining = assignMatcher.group(2).trim();
                    if (remaining.startsWith(";")) {
                        remaining = remaining.substring(1).trim();
                    }
                    continue;
                }
                
                // Check for function call pattern not:free($ptr)
                Pattern funcPattern = Pattern.compile("^(\\w+\\s*\\([^)]*\\))(.*)$");
                Matcher funcMatcher = funcPattern.matcher(remaining);
                if (funcMatcher.matches()) {
                    neg.pattern = funcMatcher.group(1);
                    wm.negatives.add(neg);
                    remaining = funcMatcher.group(2).trim();
                    if (remaining.startsWith(";")) {
                        remaining = remaining.substring(1).trim();
                    }
                    continue;
                }
                
                break;
            }
            
            return wm;
        }
        
        // Wildcard single (_)
        if (stmt.equals("_")) {
            return new TaintQuery.Wildcard();
        }
        
        // Legacy ... without not:
        if (stmt.equals("...")) {
            return new TaintQuery.WildcardMulti();
        }
        
        // Dereference (*$ptr or *$ptr = ...)
        if (stmt.startsWith("*$") && !stmt.contains("=")) {
            TaintQuery.Dereference deref = new TaintQuery.Dereference();
            // Extract variable name
            Pattern p = Pattern.compile("\\*\\$(\\w+)");
            Matcher m = p.matcher(stmt);
            if (m.find()) {
                deref.ptrVar = "$" + m.group(1);
                return deref;
            }
        }
        
        // Assignment ($var = expr or type $var = expr)
        if (stmt.contains("=") && !stmt.contains("==")) {
            return parseAssignment(stmt);
        }
        
        // Variable declaration (type $var or type $var[size])
        Pattern declPattern = Pattern.compile("^(\\w+)\\s*(\\*)?\\s*\\$(\\w+)(\\s*\\[([^\\]]+)\\])?\\s*$");
        Matcher declMatcher = declPattern.matcher(stmt);
        if (declMatcher.matches()) {
            TaintQuery.VariableDecl decl = new TaintQuery.VariableDecl();
            decl.typeName = declMatcher.group(1);
            decl.isPointer = declMatcher.group(2) != null;
            decl.varName = "$" + declMatcher.group(3);
            if (declMatcher.group(4) != null) {
                decl.isArray = true;
                decl.arraySize = declMatcher.group(5);
            }
            return decl;
        }
        
        // Function call (funcname($arg1, $arg2, ...))
        Pattern callPattern = Pattern.compile("^(\\$?\\w+)\\s*\\((.*)\\)\\s*$");
        Matcher callMatcher = callPattern.matcher(stmt);
        if (callMatcher.matches()) {
            TaintQuery.FunctionCall call = new TaintQuery.FunctionCall();
            call.funcName = callMatcher.group(1);
            call.args = parseArguments(callMatcher.group(2));
            return call;
        }
        
        // Unknown - treat as wildcard
        return new TaintQuery.Wildcard();
    }
    
    /**
     * Parse an assignment statement
     */
    private TaintQuery.PatternElement parseAssignment(String stmt) throws ParseException {
        int eqIdx = stmt.indexOf('=');
        String lhs = stmt.substring(0, eqIdx).trim();
        String rhs = stmt.substring(eqIdx + 1).trim();
        
        // Check if LHS is a declaration (type $var = ...)
        Pattern declAssign = Pattern.compile("^(\\w+)\\s*(\\*)?\\s*\\$(\\w+)$");
        Matcher declMatcher = declAssign.matcher(lhs);
        
        TaintQuery.Assignment assign = new TaintQuery.Assignment();
        
        if (declMatcher.matches()) {
            // It's a declaration with assignment
            assign.lhs = "$" + declMatcher.group(3);
        } else if (lhs.startsWith("$")) {
            assign.lhs = lhs;
        } else if (lhs.startsWith("*$")) {
            // Dereference assignment
            assign.lhs = lhs;
        } else {
            assign.lhs = "_";
        }
        
        // Parse RHS - could be function call, variable, or expression
        if (rhs.contains("(")) {
            // Function call on RHS - extract function name and mark as RHS
            Pattern callPattern = Pattern.compile("^(\\$?\\w+)\\s*\\((.*)\\)\\s*$");
            Matcher callMatcher = callPattern.matcher(rhs);
            if (callMatcher.matches()) {
                assign.rhs = rhs;  // Keep the full call
            } else {
                assign.rhs = rhs;
            }
        } else if (rhs.startsWith("$")) {
            assign.rhs = rhs;
        } else {
            assign.rhs = "_";
        }
        
        return assign;
    }
    
    /**
     * Parse function arguments
     */
    private List<String> parseArguments(String argsStr) {
        List<String> args = new ArrayList<>();
        if (argsStr.trim().isEmpty()) return args;
        
        int depth = 0;
        StringBuilder current = new StringBuilder();
        
        for (char c : argsStr.toCharArray()) {
            if (c == '(' || c == '[') depth++;
            else if (c == ')' || c == ']') depth--;
            else if (c == ',' && depth == 0) {
                args.add(current.toString().trim());
                current = new StringBuilder();
                continue;
            }
            current.append(c);
        }
        
        if (current.length() > 0) {
            args.add(current.toString().trim());
        }
        
        return args;
    }
    
    /**
     * Parse constraint expression
     */
    private TaintQuery.Constraint parseConstraint(String text) throws ParseException {
        text = text.trim();
        
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
        if (text.toUpperCase().startsWith("NOT ")) {
            TaintQuery.NotConstraint not = new TaintQuery.NotConstraint();
            not.inner = parseConstraint(text.substring(4).trim());
            return not;
        }
        
        // Handle parentheses
        if (text.startsWith("(") && text.endsWith(")")) {
            return parseConstraint(text.substring(1, text.length() - 1));
        }
        
        // Parse individual constraint functions
        return parseConstraintFunction(text);
    }
    
    /**
     * Parse a single constraint function
     */
    private TaintQuery.Constraint parseConstraintFunction(String text) throws ParseException {
        text = text.trim();
        
        // tainted($var) or tainted($var, "source")
        Pattern taintedPattern = Pattern.compile("tainted\\s*\\(\\s*(\\$\\w+)(?:\\s*,\\s*\"([^\"]+)\")?\\s*\\)");
        Matcher taintedMatcher = taintedPattern.matcher(text);
        if (taintedMatcher.matches()) {
            TaintQuery.TaintedConstraint tc = new TaintQuery.TaintedConstraint();
            tc.varName = taintedMatcher.group(1);
            tc.sourceName = taintedMatcher.group(2);
            return tc;
        }
        
        // flows_to($src, $dst)
        Pattern flowsPattern = Pattern.compile("flows_to\\s*\\(\\s*(\\$\\w+)\\s*,\\s*(\\$\\w+)\\s*\\)");
        Matcher flowsMatcher = flowsPattern.matcher(text);
        if (flowsMatcher.matches()) {
            TaintQuery.FlowsToConstraint fc = new TaintQuery.FlowsToConstraint();
            fc.srcVar = flowsMatcher.group(1);
            fc.dstVar = flowsMatcher.group(2);
            return fc;
        }
        
        // is_constant($var)
        Pattern constPattern = Pattern.compile("is_constant\\s*\\(\\s*(\\$\\w+)\\s*\\)");
        Matcher constMatcher = constPattern.matcher(text);
        if (constMatcher.matches()) {
            TaintQuery.IsConstantConstraint ic = new TaintQuery.IsConstantConstraint();
            ic.varName = constMatcher.group(1);
            return ic;
        }
        
        // is_param($var)
        Pattern paramPattern = Pattern.compile("is_param\\s*\\(\\s*(\\$\\w+)\\s*\\)");
        Matcher paramMatcher = paramPattern.matcher(text);
        if (paramMatcher.matches()) {
            TaintQuery.IsParamConstraint ip = new TaintQuery.IsParamConstraint();
            ip.varName = paramMatcher.group(1);
            return ip;
        }
        
        // is_local($var)
        Pattern localPattern = Pattern.compile("is_local\\s*\\(\\s*(\\$\\w+)\\s*\\)");
        Matcher localMatcher = localPattern.matcher(text);
        if (localMatcher.matches()) {
            TaintQuery.IsLocalConstraint il = new TaintQuery.IsLocalConstraint();
            il.varName = localMatcher.group(1);
            return il;
        }
        
        throw new ParseException("Unknown constraint: " + text);
    }
    
    /**
     * Find operator at the top level (not inside parentheses)
     */
    private int findOperator(String text, String op) {
        int depth = 0;
        String upperText = text.toUpperCase();
        String searchOp = " " + op + " ";
        
        for (int i = 0; i <= text.length() - searchOp.length(); i++) {
            char c = text.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') depth--;
            
            if (depth == 0 && upperText.substring(i).startsWith(searchOp)) {
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
            } else if (elem instanceof TaintQuery.FunctionCall fc) {
                if (fc.funcName.startsWith("$")) vars.add(fc.funcName);
                for (String arg : fc.args) {
                    if (arg.startsWith("$")) vars.add(arg);
                }
            } else if (elem instanceof TaintQuery.Assignment a) {
                if (a.lhs.startsWith("$")) vars.add(a.lhs);
                if (a.rhs.startsWith("$")) vars.add(a.rhs);
            } else if (elem instanceof TaintQuery.Dereference d) {
                vars.add(d.ptrVar);
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
    
    /**
     * Get builtin pattern by name
     */
    public static String getBuiltinPattern(String name) {
        return BUILTIN_PATTERNS.get(name);
    }
}