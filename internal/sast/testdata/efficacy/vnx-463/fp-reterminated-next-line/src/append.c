#include <string.h>

void append_char(char *s, char c)
{
    size_t n = strlen(s);
    s[n] = c;
    s[n + 1] = '\0';
}

void add_slash(char *p)
{
    p[strlen(p)] = '/';
    p[strlen(p) + 1] = 0;
}
