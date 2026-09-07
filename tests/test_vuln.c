/*
 * test_vuln.c — deterministic patterns for headless taint-query / emulator tests.
 * Cross-compiled to an x86-64 Linux ELF object; libc funcs declared extern so no
 * system headers are needed. Cases are written to exercise data flow the engine
 * actually models: structural call patterns, direct dereferences, and taint that
 * propagates through call RETURN VALUES (e.g. getenv).
 */
extern void *malloc(unsigned long);
extern void free(void *);
extern int printf(const char *, ...);
extern void *memcpy(void *, const void *, unsigned long);
extern char *getenv(const char *);

/* 1) Use-after-free: free($p); ... *$p  (direct deref) */
char uaf(void) {
    char *p = (char *)malloc(64);
    free(p);
    return *p;                  /* direct use after free */
}

/* 2) Double free: free($p); ... free($p) */
void df(void) {
    char *p = (char *)malloc(64);
    free(p);
    free(p);
}

/* 3) Tainted format string: $fmt comes from getenv() return value */
void fmt(void) {
    char *s = getenv("X");      /* s tainted by getenv return */
    printf(s);                  /* printf($fmt) WHERE tainted($fmt) */
}

/* 4) Tainted length into memcpy: $len from getenv() return value */
void cp(char *dst, char *src) {
    unsigned long len = (unsigned long)getenv("N");  /* len tainted by getenv */
    memcpy(dst, src, len);      /* memcpy($dst,$src,$len) WHERE tainted($len) */
}

/* 5) Safe memcpy (constant length) — must NOT match the tainted-len query */
void safe_cp(char *dst, char *src) {
    memcpy(dst, src, 16);
}

/* 6) Pure arithmetic for emulation: (a+3)*2 - 1 */
int add3(int a) {
    int x = a + 3;
    int y = x * 2;
    return y - 1;
}

/* 7) Calls an external then returns a+1 — for emulation skipCalls test */
int with_call(int a) {
    printf("x");                /* external call; skipCalls steps over it */
    return a + 1;
}

/* Accuracy regressions: unsafe cases paired with lookalikes. */
extern int puts(const char *);
extern int sprintf(char *, const char *, ...);
extern int snprintf(char *, unsigned long, const char *, ...);
extern int __printf_chk(int, const char *, ...);
extern long strtol(const char *, char **, int);
extern int memcpy_s(void *, unsigned long, const void *, unsigned long);

void numeric_cp(char *dst, char *src) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    memcpy(dst, src, n);
}
void fixed_input_copy(char *dst) { memcpy(dst, getenv("X"), 4); }
void safe_format(void) { printf("%s", getenv("X")); }
void checked_format(void) { __printf_chk(1, getenv("X")); }
void safe_checked_format(void) { __printf_chk(1, "%s", getenv("X")); }
void bounded_bad_format(char *dst) { snprintf(dst, 64, getenv("X")); }
void safe_sprintf_destination(void) { sprintf(getenv("OUT"), "%s", "ok"); }
char *source_wrapper(void) { return getenv("X"); }
char *unrelated_wrapper(void) { puts(getenv("X")); return "%s"; }
void wrapped_format(void) { printf(source_wrapper()); }
void safe_wrapped_format(void) { printf(unrelated_wrapper(), "ok"); }
void repeated_use(void) { char *p = getenv("X"); puts(p); puts(p); }
void freed_argument(void) { char *p = malloc(64); free(p); puts(p); }
void branch_free(int cond) {
    char *p = malloc(64);
    if (cond) { free(p); puts("left"); }
    else { puts("right"); free(p); }
}
void reallocated_free(void) {
    char *p = malloc(64); free(p); p = malloc(32); free(p);
}
void null_free(void) { free((void *)0); free((void *)0); }
void safe_crt_copy(char *dst, char *src) {
    memcpy_s(dst, 64, src, (unsigned long)strtol(getenv("N"), (char **)0, 10));
}
extern long read(int, void *, unsigned long);
void read_format(void) { char buf[64]; read(0, buf, 63); buf[63] = 0; printf(buf); }
void read_after_format(void) { char buf[64] = "%s"; printf(buf, "ok"); read(0, buf, 63); }
void read_other_buffer(void) { char buf[64]; char fmt[8] = "%s"; read(0, buf, 63); printf(fmt, buf); }
