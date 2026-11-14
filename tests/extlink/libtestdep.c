/* Exported side of the cross-module link test: compiled into libtestdep.so.1. */
int dep_exported_func(int x) { return x * 3 + 1; }
int dep_other_func(int x) { return x - 2; }
