#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *label(const char *dir, const char *file)
{
    char *out = malloc(64);
    snprintf(out, 64, "%s/%s", dir, file);
    return out;
}

char *prefix(const char *src)
{
    char *p = malloc(16);
    strncpy(p, src, 15);
    p[15] = '\0';
    strcpy(p + 15, "");
    return p;
}
