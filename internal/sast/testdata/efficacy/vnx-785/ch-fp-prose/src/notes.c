#include <stdio.h>

/* never call getwd(buf): it has no size argument; realpath(p, small) is just as bad */
// PathCanonicalizeA(out, in) writes up to MAX_PATH characters
static const char *hint = "replace getwd(buf) with getcwd(buf, sizeof buf)";

int my_getwd(char *b) { return 0; }

void report(void)
{
    char b[16];
    my_getwd(b);
    puts(hint);
}
