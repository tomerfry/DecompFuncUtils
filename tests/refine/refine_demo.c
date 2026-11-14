/*
 * refine_demo.c -- fixture for the refinement engine (tests/scripts/RefineEngineHeadlessTest.java).
 *
 * Built optimized (see build.ps1) so the decompiler sees what a compiler leaves behind:
 * reciprocal multiplication instead of division, shifts instead of multiplication, branchless
 * selects, rotated loops, open-coded libc loops and inlined helper bodies. Every function has one
 * obvious source-level meaning the engine is expected to recover.
 *
 * No libc headers: the object is linked -nostdlib.
 */
#define NOINLINE __attribute__((noinline))

/* ---- division / modulo by constants (reciprocal multiplication) ---- */
NOINLINE unsigned udiv10(unsigned x) { return x / 10; }
NOINLINE unsigned umod10(unsigned x) { return x % 10; }
NOINLINE int sdiv7(int x) { return x / 7; }
NOINLINE int smod100(int x) { return x % 100; }
NOINLINE unsigned long udiv1000(unsigned long x) { return x / 1000; }
NOINLINE int sdiv8(int x) { return x / 8; }
NOINLINE unsigned digit_sum(unsigned x) {
    unsigned s = 0;
    while (x) { s += x % 10; x /= 10; }
    return s;
}

/* ---- strength reduction ---- */
NOINLINE unsigned mul8(unsigned x) { return x * 8; }
NOINLINE int mul9(int x) { return x * 9; }
NOINLINE int mul_mix(int x, int y) { return x * 5 + y * 16; }

/* ---- branchless idioms ---- */
NOINLINE int abs_val(int x) { return x < 0 ? -x : x; }
NOINLINE int min_s(int a, int b) { return a < b ? a : b; }
NOINLINE unsigned max_u(unsigned a, unsigned b) { return a > b ? a : b; }
NOINLINE unsigned rotl13(unsigned x) { return (x << 13) | (x >> 19); }
NOINLINE int is_digit(int c) { return c >= '0' && c <= '9'; }
NOINLINE int sign_of(int x) { return (x > 0) - (x < 0); }

/* ---- open-coded library loops ---- */
NOINLINE unsigned long my_strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}
NOINLINE void my_zero(char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) p[i] = 0;
}
NOINLINE void my_copy(char *d, const char *s, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
}
NOINLINE void init_header(char *b) {
    b[0] = 'D'; b[1] = 'F'; b[2] = 'U'; b[3] = '1';
    b[4] = 0; b[5] = 0; b[6] = 0; b[7] = 0;
    b[8] = 0; b[9] = 0; b[10] = 0; b[11] = 0;
}

/* ---- helpers that exist standalone AND get inlined into their callers ---- */
int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
unsigned mix(unsigned h, unsigned k) {
    h ^= k;
    h *= 0x01000193u;
    return (h << 13) | (h >> 19);
}
NOINLINE int scale_clamped(int a) { return clamp(a * 3, 0, 255) + 1; }
NOINLINE unsigned hash3(unsigned a, unsigned b, unsigned c) {
    unsigned h = 0x811c9dc5u;
    h = mix(h, a);
    h = mix(h, b);
    h = mix(h, c);
    return h;
}
NOINLINE unsigned hash_bytes(const unsigned char *p, unsigned long n) {
    unsigned h = 0x811c9dc5u;
    for (unsigned long i = 0; i < n; i++) h = mix(h, p[i]);
    return h;
}

/* ---- opaque predicate: x*(x+1) is always even ---- */
NOINLINE int opaque(int x, int y) {
    volatile int keep = y;
    if (((x * (x + 1)) & 1) == 0) return keep + 1;
    return keep * 77 + x;
}

/* ---- a pure function called with constants: the result can be computed by emulation ---- */
NOINLINE unsigned decode_key(unsigned k) {
    unsigned r = k;
    for (int i = 0; i < 5; i++) r = (r ^ 0x5a5a5a5au) * 33u + (unsigned)i;
    return r;
}
NOINLINE unsigned use_decode(unsigned x) { return decode_key(0x1234) ^ x; }

/* ---- mixed: used for end-to-end differential checks ---- */
NOINLINE int poly(int x, int y) {
    int q = x / 10;
    int r = x % 10;
    int m = y < q ? y : q;
    return m * 8 + r;
}
