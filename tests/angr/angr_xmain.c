/*
 * The importing half of the cross-module fixture for the angr debugger. Built by build.ps1 into
 * libangrxmain.so, linked against libangrxdep.so (angr_xdep.c).
 *
 * xroute() gets to xdep_secret(), which lives in the other module, through one unknown import
 * of its own, a variable it imports from the library, a call into the library, an unknown
 * import of the library's, and a callback from the library back into this module.
 */

extern int xdep_check(int key, int (*cb)(int));
extern int xdep_apply(int which, int v);
extern int xdep_level;

/* An import nothing defines: stays unknown. */
extern int cfg_mode(void);

static int triple(int v)
{
    return v * 3;
}

int xroute(int key)
{
    if (cfg_mode() != 2) {
        return -10;
    }
    if (xdep_level != 3) {
        return -11;
    }
    return xdep_check(key, triple);
}

/* A plain call into the library: add_one() through its relocated table. */
int xlocal(int v)
{
    return xdep_apply(0, v);
}

/* Never gets anywhere near the library. */
int xnever(int v)
{
    return v + 1;
}
