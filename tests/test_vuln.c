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
