/* Importing side: calls into libtestdep.so.1, producing UND dynsym entries + PLT. */
int dep_exported_func(int x);
int dep_other_func(int x);

void _start(void) {
    volatile int r = dep_exported_func(7);
    r += dep_other_func(r);
    (void)r;
}
