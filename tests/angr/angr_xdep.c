/*
 * The library half of the cross-module fixture for the angr debugger (see angr_xmain.c for the
 * half that imports it). Built by build.ps1 into libangrxdep.so.
 *
 * Both halves are shared objects, so Ghidra loads each at the same image base. Emulating them
 * together means moving this one, which is only right if every absolute pointer in it moves
 * too - hence the function-pointer table and the call through the library's own PLT below.
 */

/* An import nothing defines: stays unknown, in the library as it would in the importer. */
extern int cfg_tier(void);

/* Exported data, read by the importer through its GOT. */
int xdep_level = 3;

typedef int (*op_fn)(int);

static int add_one(int v) { return v + 1; }
static int add_two(int v) { return v + 2; }

/* Absolute pointers in data: relative relocations, which have to follow the library. */
static op_fn ops[2] = { add_one, add_two };

/* The destination of the cross-module tests. */
__attribute__((noinline)) int xdep_secret(int v)
{
    return v ^ 0x5a;
}

int xdep_apply(int which, int v)
{
    return ops[which & 1](v);
}

/*
 * Reaches xdep_secret() only when cfg_tier() == 4, the importer's callback maps key to 21 and
 * key + 2 == 9. The callback is code in the importing module, so execution crosses back.
 */
int xdep_check(int key, int (*cb)(int))
{
    if (cfg_tier() != 4) {
        return -1;
    }
    if (cb(key) != 21) {
        return -2;
    }
    if (xdep_apply(1, key) != 9) {
        return -3;
    }
    return xdep_secret(key);
}

/* Exported, but nothing in the importer calls it. */
int xdep_unused(int v)
{
    return v - 1;
}
