#include <stdio.h>

void report(char *buf, size_t n, int code, int a, const char *where)
{
~>    fprintf(stderr, "error %d at %s\n", code);
~>    snprintf(buf, n, "%d-%d", a);
    (void)where;
}
