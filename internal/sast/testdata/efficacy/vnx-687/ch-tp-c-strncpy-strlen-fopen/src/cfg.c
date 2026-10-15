#include <stdio.h>
#include <string.h>

FILE *cfg(char *dst, const char *src, const char *p)
{
~>    strncpy(dst, src, strlen(src));
~>    return fopen(p, "rw");
}
