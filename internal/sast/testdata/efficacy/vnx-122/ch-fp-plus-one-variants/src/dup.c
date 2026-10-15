#include <stdlib.h>
#include <string.h>

char *dup_a(const char *s)
{
    char *p = malloc(1 + strlen(s));
    strcpy(p, s);
    return p;
}

char *dup_b(const char *s)
{
    size_t n = strlen( s )+1;
    char *p = malloc(n);
    memcpy(p, s, n);
    return p;
}
