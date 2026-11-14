/*
 * Fixture for ghidra_angr_emulate (tests/scripts/AngrEmulateHeadlessTest.java).
 *
 * Built as a shared object so the libc calls go through real PLT/GOT imports, without debug
 * info so Ghidra knows no signatures - the situation the tool is normally used in. Rebuild with
 * tests/angr/build.ps1 (clang + lld); the built ELF is committed.
 *
 * Every function here is called by name from the test, so keep names and behaviour stable.
 */

extern int strcmp(const char *, const char *);
extern unsigned long strlen(const char *);
extern void *malloc(unsigned long);
extern int printf(const char *, ...);
extern int puts(const char *);

/* Not a libc function: nothing knows what it does, so the tool has to stub it. */
extern int mystery_device_read(int reg);

int g_counter = 7;
static const char SECRET[] = "hunter2";

struct point {
    int x;
    int y;
    const char *label;
};

/* Plain integer arithmetic; a negative result checks 32-bit return handling. */
int add3(int a, int b, int c) {
    return a + b + c;
}

/* Calls another function of this program, for stubbing and for 'find'. */
int twice_add(int a) {
    return add3(a, a, 1) * 2;
}

/* Eight integer arguments: the last two travel on the stack in the SysV x86-64 ABI. */
long many_args(long a, long b, long c, long d, long e, long f, long g, long h) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

/* A libc call whose arguments give the secret away in the call trace. */
int check_password(const char *pw) {
    return strcmp(pw, SECRET) == 0;
}

/* Writes through an out-parameter and returns the length written. */
int fill_greeting(char *out, unsigned long cap, const char *name) {
    static const char prefix[] = "hello, ";
    unsigned long n = 0;
    for (unsigned long i = 0; prefix[i] && n + 1 < cap; i++) {
        out[n++] = prefix[i];
    }
    for (unsigned long i = 0; name[i] && n + 1 < cap; i++) {
        out[n++] = name[i];
    }
    if (n + 1 < cap) {
        out[n++] = '!';
    }
    if (cap) {
        out[n] = 0;
    }
    return (int)n;
}

/* Reads a struct that itself holds a pointer. */
int point_score(const struct point *p) {
    return p->x * 10 + p->y + (int)strlen(p->label);
}

/* Dereferences whatever it is given; NULL must be reported, not silently read as zero. */
int deref(int *p) {
    return *p + 1;
}

/* Reads and writes a global. */
int bump_counter(int by) {
    g_counter += by;
    return g_counter;
}

/* Branches on an external the tool cannot model. */
int needs_device(void) {
    if (mystery_device_read(3) == 0x1234) {
        return 1;
    }
    return 0;
}

/* Output through libc. */
int say_hello(const char *name) {
    printf("hello %s\n", name);
    return puts("done");
}

/* Returns heap memory. */
char *dup_upper(const char *s) {
    unsigned long n = strlen(s);
    char *out = (char *)malloc(n + 1);
    for (unsigned long i = 0; i < n; i++) {
        char c = s[i];
        out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    out[n] = 0;
    return out;
}

/* Few 4-byte inputs pass: 'D' 'F' then two bytes that xor to 0x5a and sum to 0x9c. */
int magic_check(const unsigned char *buf) {
    if (buf[0] != 'D') {
        return 0;
    }
    if (buf[1] != 'F') {
        return 0;
    }
    if ((buf[2] ^ buf[3]) != 0x5a) {
        return 0;
    }
    if ((unsigned char)(buf[2] + buf[3]) != 0x9c) {
        return 0;
    }
    return 1;
}

/* Three distinguishable outcomes for path enumeration. */
int classify(int v) {
    if (v < 0) {
        return -1;
    }
    if (v > 100) {
        return 2;
    }
    return 1;
}

/* Never returns; exercises the step and time limits. */
int spin(int x) {
    volatile int v = x;
    for (;;) {
        v++;
    }
    return v;
}
