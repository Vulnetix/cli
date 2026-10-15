#include <stdio.h>
#include <string.h>

int parse_pair(const char *s, int *out)
{
    int rc, n;
    if (s == NULL)
~>        return rc;
    n = (int)strlen(s);
    *out = n;
    return 0;
}

const char *pick(int which)
{
    const char *a, *b;
    if (which)
        a = "first";
~>    return a;
}
