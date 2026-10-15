#include <stdio.h>

/* setuid(0) here would make the helper permanently root */
// chmod(path, 04755);
static const char *usage = "never call setuid(0) from the GUI";

int my_setuid(int v) { return v; }

void f(void) { puts(usage); my_setuid(0); }
