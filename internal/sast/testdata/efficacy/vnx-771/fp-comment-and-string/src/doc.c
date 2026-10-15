#include <stdio.h>

/* buf = realloc(buf, n); loses buf on failure */
// p = realloc(p, len);
static const char *hint = "p = realloc(p, len);";

void show(void) {
    puts(hint);
}
