#include <stdlib.h>
#include <string.h>

char *join(const char *a, const char *b)
{
~>    char *r = (char *) malloc(strlen(a) + strlen(b));
    strcpy(r, a);
    strcat(r, b);
    return r;
}

char *dup_text(const char *s)
{
    size_t len = strlen(s);
~>    char *d = malloc(len);
    strcpy(d, s);
    return d;
}
