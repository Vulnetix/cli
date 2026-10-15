#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name)
{
    char *out = malloc(strlen(name) + 1);
    strcpy(out, name);
    return out;
}

char *join(const char *a, const char *b)
{
    size_t n = strlen(a) + strlen(b) + 1;
    char *r = malloc(n);
    snprintf(r, n, "%s%s", a, b);
    return r;
}

void raw(const char *src, size_t n)
{
    unsigned char *bytes = malloc(strlen(src));
    memcpy(bytes, src, strlen(src));
}
