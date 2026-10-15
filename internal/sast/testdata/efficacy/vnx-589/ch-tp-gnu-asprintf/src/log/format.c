#include <stdio.h>
#include <stdlib.h>

char *format_line(const char *name, int n)
{
    char *out = NULL;
~>    if (asprintf(&out, "%s=%d", name, n) < 0)
        return NULL;
    return out;
}
