#include <stdlib.h>
#include <string.h>

char *default_theme(void)
{
    char *t = malloc(32);
    if (t)
        strcpy(t, "solarized-dark");
    return t;
}

unsigned char *clone_bytes(const char *s)
{
    unsigned char *raw = malloc(strlen(s));
    if (raw)
        memcpy(raw, s, strlen(s));
    return raw;
}
