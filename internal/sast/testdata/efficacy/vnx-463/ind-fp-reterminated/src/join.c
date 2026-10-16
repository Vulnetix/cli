#include <string.h>

void join(char *dst, const char *name)
{
    size_t n = strlen(dst);
    dst[n] = '/';
    strcpy(dst + n + 1, name);
}

void add_char(char *s, char c)
{
    size_t len = strlen(s);
    s[len] = c;
    s[len + 1] = '\0';
}
