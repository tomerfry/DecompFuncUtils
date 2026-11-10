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

/* ===== Query-engine regressions and vulnerability-pattern fixtures =====
 * Parameter-free unsafe/safe pairs: every pattern has a lookalike that must
 * NOT match. Functions above this line are used by older checks; keep them. */
extern int system(const char *);
extern void *popen(const char *, const char *);
extern char *strcpy(char *, const char *);
extern char *strcat(char *, const char *);
extern unsigned long strlen(const char *);
extern void *realloc(void *, unsigned long);
extern char *strdup(const char *);
extern int access(const char *, int);
extern int open(const char *, int, ...);
extern int execl(const char *, const char *, ...);
extern int atoi(const char *);
extern int vprintf(const char *, void *);
extern unsigned WinExec(const char *, unsigned);

/* --- ordering: A; ...; B; ...; C must not accept C placed before B --- */
void order_abc(void) { char *p = getenv("A"); puts(p); strlen(p); atoi(p); }
void order_acb(void) { char *p = getenv("A"); puts(p); atoi(p); strlen(p); }

/* --- nested calls and calls used as conditions --- */
void nested_call(void) { char b[64]; puts(strcpy(b, getenv("X"))); }
void nested_alloc(void) { char *s = getenv("X"); char *p = malloc(strlen(s)); if (p) free(p); }
void plain_alloc(void) { char *p = malloc(16); if (p) free(p); }
int cond_call(void) { if (system(getenv("C")) != 0) return 1; return 0; }
int loop_cond_call(void) { int n = 0; while (system(getenv("C")) == 0) n++; return n; }

/* --- parameters as sources vs real input sources --- */
void param_copy(char *dst, char *src) { strcpy(dst, src); }
void env_copy(void) { char b[64]; strcpy(b, getenv("X")); puts(b); }

/* --- unchecked allocation results --- */
char alloc_unchecked(void) { char *p = malloc(32); p[0] = 'a'; char c = p[0]; free(p); return c; }
char alloc_unchecked_field(void) { char *p = malloc(32); p[5] = 'a'; char c = p[5]; free(p); return c; }
char alloc_checked(void) {
    char *p = malloc(32);
    if (p == 0) return 0;
    p[0] = 'a'; char c = p[0]; free(p); return c;
}
char alloc_checked_nested(void) {
    char c = 0; char *p = malloc(32);
    if (p) { p[0] = 'a'; c = p[0]; free(p); }
    return c;
}
void alloc_unchecked_arg(void) { char *p = strdup(getenv("X")); memcpy(p, "ab", 2); free(p); }
void alloc_checked_arg(void) { char *p = strdup(getenv("X")); if (!p) return; memcpy(p, "ab", 2); free(p); }

/* --- command / format injection through a builder buffer --- */
void cmd_build_unsafe(void) { char cmd[128]; sprintf(cmd, "ls %s", getenv("DIR")); system(cmd); }
void cmd_build_safe(void) { char cmd[128]; sprintf(cmd, "ls %s", "/tmp"); system(cmd); }
void cmd_build_snprintf(void) { char cmd[128]; snprintf(cmd, 128, "ls %s", getenv("DIR")); popen(cmd, "r"); }
void cmd_build_strcat(void) { char cmd[128]; strcpy(cmd, "ls "); strcat(cmd, getenv("DIR")); system(cmd); }
void cmd_build_late(void) { char cmd[128]; strcpy(cmd, "ls"); system(cmd); strcat(cmd, getenv("DIR")); puts(cmd); }
void cmd_build_other(void) {
    char cmd[128]; char note[128];
    strcpy(cmd, "ls"); sprintf(note, "%s", getenv("DIR")); system(cmd); puts(note);
}
void cmd_build_rewritten(void) {
    char cmd[128];
    sprintf(cmd, "ls %s", getenv("DIR")); puts(cmd); strcpy(cmd, "ls"); system(cmd);
}
void cmd_build_chain(void) {
    char a[64]; char cmd[128];
    strcpy(a, getenv("DIR")); sprintf(cmd, "ls %s", a); system(cmd);
}
void cmd_read_unsafe(void) {
    char in[64]; char cmd[128];
    read(0, in, 63); in[63] = 0; snprintf(cmd, 128, "ping %s", in); system(cmd);
}
void fmt_build_unsafe(void) { char b[128]; strcpy(b, getenv("F")); printf(b); }
void fmt_build_safe(void) { char b[128]; strcpy(b, getenv("F")); printf("%s", b); }
void exec_unsafe(void) { execl(getenv("P"), "x", (char *)0); }
void exec_safe(void) { execl("/bin/ls", "ls", getenv("P"), (char *)0); }
void vfmt_unsafe(void) { vprintf(getenv("F"), (void *)0); }
void vfmt_safe(void) { vprintf("%s", (void *)getenv("F")); }
void winexec_unsafe(void) { WinExec(getenv("C"), 0); }
void winexec_safe(void) { WinExec("calc.exe", (unsigned)atoi(getenv("C"))); }

/* --- allocation-size integer overflow --- */
void alloc_mul_unsafe(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    unsigned long m = (unsigned long)strtol(getenv("M"), (char **)0, 10);
    char *p = malloc(n * m); if (p) free(p);
}
void alloc_mul_checked(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    unsigned long m = (unsigned long)strtol(getenv("M"), (char **)0, 10);
    if (m != 0 && n > 0xffffffffUL / m) return;
    char *p = malloc(n * m); if (p) free(p);
}
void alloc_mul_bounded(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    if (n > 1000) return;
    char *p = malloc(n * 24); if (p) free(p);
}
void alloc_mul_const_unsafe(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc(n * 24); if (p) free(p);
}
void alloc_add_unsafe(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc(n + 16); if (p) free(p);
}
void alloc_add_checked(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    if (n >= 4096) return;
    char *p = malloc(n + 16); if (p) free(p);
}
void alloc_add_strlen(void) { char *p = malloc(strlen(getenv("S")) + 1); if (p) free(p); }

/* --- allocation size vs copy length --- */
void alloc_copy_mismatch(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    unsigned long m = (unsigned long)strtol(getenv("M"), (char **)0, 10);
    char *p = malloc(n); if (!p) return;
    memcpy(p, getenv("S"), m); free(p);
}
void alloc_copy_same(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc(n); if (!p) return;
    memcpy(p, getenv("S"), n); free(p);
}
void alloc_copy_derived(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc(n + 1); if (!p) return;
    memcpy(p, getenv("S"), n); free(p);
}
void alloc_copy_compared(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    unsigned long m = (unsigned long)strtol(getenv("M"), (char **)0, 10);
    char *p = malloc(n); if (!p) return;
    if (m <= n) memcpy(p, getenv("S"), m);
    free(p);
}

/* --- tainted signed length --- */
void signed_len_unsafe(void) {
    char dst[64]; int n = atoi(getenv("N"));
    if (n > 64) return;
    memcpy(dst, getenv("S"), n); puts(dst);
}
void signed_len_safe(void) {
    char dst[64]; int n = atoi(getenv("N"));
    if (n < 0) return;
    if (n > 64) return;
    memcpy(dst, getenv("S"), n); puts(dst);
}
void signed_len_unsigned(void) {
    char dst[64]; unsigned n = (unsigned)atoi(getenv("N"));
    if (n > 64) return;
    memcpy(dst, getenv("S"), n); puts(dst);
}
void signed_alloc_unsafe(void) { int n = atoi(getenv("N")); char *p = malloc(n); if (p) free(p); }
void signed_alloc_safe(void) { int n = atoi(getenv("N")); if (n <= 0) return; char *p = malloc(n); if (p) free(p); }

/* --- realloc misuse --- */
void realloc_unsafe(void) { char *p = malloc(16); p = realloc(p, 64); if (p) free(p); }
void realloc_safe(void) {
    char *p = malloc(16); char *q = realloc(p, 64);
    if (!q) { free(p); return; }
    p = q; free(p);
}

/* --- TOCTOU --- */
void toctou_unsafe(void) { char *path = getenv("P"); if (access(path, 0) == 0) open(path, 0); }
void toctou_other(void) { char *a = getenv("P"); char *b = getenv("Q"); if (access(a, 0) == 0) open(b, 0); }
void toctou_reversed(void) { char *path = getenv("P"); open(path, 0); access(path, 0); }

/* --- unchecked read() result used as a length --- */
void read_len_unchecked(void) { char in[64]; char out[64]; long n = read(0, in, 64); memcpy(out, in, n); puts(out); }
void read_len_checked(void) {
    char in[64]; char out[64]; long n = read(0, in, 64);
    if (n <= 0) return;
    memcpy(out, in, n); puts(out);
}
void read_len_ignored(void) { char in[64]; char out[64]; read(0, in, 64); memcpy(out, in, 64); puts(out); }

/* --- gap negatives must look at the arguments of the forbidden call --- */
void neg_call_other(void) { char *p = getenv("A"); char *q = getenv("B"); puts(p); atoi(q); strlen(p); }

/* --- operators in argument patterns --- */
void bitops_alloc(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc((n & 0xff) | 0x100); if (p) free(p);
}
void shift_alloc(void) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    char *p = malloc(n << 3); if (p) free(p);
}

/* --- taint must survive a long computation --- */
void long_chain(char *dst) {
    unsigned long n = (unsigned long)strtol(getenv("N"), (char **)0, 10);
    n = (n ^ 0x55) + 3; n = (n >> 1) * 5; n = (n ^ 0x33) + 7; n = (n >> 1) * 9;
    n = (n ^ 0x0f) + 11; n = (n >> 1) * 13; n = (n ^ 0x71) + 17; n = (n >> 1) * 19;
    n = (n ^ 0x1d) + 23; n = (n >> 1) * 29; n = (n ^ 0x2b) + 31; n = (n >> 1) * 37;
    n = (n ^ 0x47) + 41; n = (n >> 1) * 43; n = (n ^ 0x59) + 47; n = (n >> 1) * 53;
    memcpy(dst, "0123456789abcdef", n);
}

/* --- constant length vs fixed-size stack buffer --- */
void stack_const_overflow(void) { char b[16]; memcpy(b, getenv("S"), 32); puts(b); }
void stack_const_ok(void) { char b[16]; memcpy(b, getenv("S"), 16); puts(b); }
void stack_read_overflow(void) { char b[16]; read(0, b, 64); puts(b); }
void stack_read_ok(void) { char b[16]; read(0, b, 15); b[15] = 0; puts(b); }

/* --- lookalikes that needed extra care --- */
struct pkt { unsigned long len; char data[8]; };
void alloc_copy_field(void) {           /* same field read twice: sizes agree */
    struct pkt *k = (struct pkt *)getenv("P");
    char *p = malloc(k->len); if (!p) return;
    memcpy(p, k->data, k->len); free(p);
}
void signed_len_strlen(void) {          /* a string length is not negative */
    char d[64]; char *s = getenv("S"); int n = strlen(s);
    memcpy(d, s, n); puts(d);
}
void copy_min_len(void) {               /* length clamped with a min() */
    char d[64]; char in[128]; unsigned long n = (unsigned long)read(0, in, 128); unsigned long m = 64;
    if (n < m) m = n;
    memcpy(d, in, m); puts(d);
}
void copy_strlen(void) {                /* strlen() called twice on the same string */
    char *s = getenv("S"); char *d = malloc(strlen(s) + 1); if (!d) return;
    memcpy(d, s, strlen(s) + 1); puts(d); free(d);
}
void list_free_offset(void) {           /* two list-freeing loops over one variable */
    char *p = getenv("L");
    while (p) { void *blk = p - 16; p = *(char **)(p - 8); free(blk); }
    p = getenv("M");
    while (p) { void *blk = p - 16; p = *(char **)(p - 8); free(blk); }
}
struct node { struct node *next; };
void list_free(void) {                  /* correct: next is read before the free */
    struct node *p = (struct node *)getenv("L");
    while (p) { struct node *next = p->next; free(p); p = next; }
}
void loop_uaf(void) {                   /* freed in one iteration, written in a later one */
    char *p = malloc(8); int i;
    for (i = 0; i < 4; i++) { if (i == 2) p[0] = 'x'; if (i == 1) free(p); }
}

/* --- loops --- */
void loop_append(void) { char b[64]; char *s = getenv("X"); int i; b[0] = 0; for (i = 0; s[i]; i++) strcat(b, "x"); puts(b); }
