#include <stdlib.h>
#include <string.h>

void *copy_blob(const void *src, size_t len)
{
    void *p = malloc(len);
    memcpy(p, src, len);
    return p;
}

char *copy_str(const char *s)
{
    size_t n = strlen(s);
    char *p = malloc(n);
    memcpy(p, s, n);
    return p;
}
