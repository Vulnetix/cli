#include <stdlib.h>
#include <string.h>
char *dup(const char *s)
{
    char *p = malloc(strlen(s) + 1);
    if (!p) return NULL;
    memcpy(p, s, strlen(s) + 1);
    return p;
}
