#include <stdlib.h>
#include <string.h>

char *copy(const char *s)
{
    return strdup(s);
}

char *label(const char *s)
{
    size_t len = strlen(s);
    char *b = malloc(len + 1);
    memcpy(b, s, len + 1);
    return b;
}

size_t width(const char *s)
{
    size_t w = strlen(s);
    return w;
}
