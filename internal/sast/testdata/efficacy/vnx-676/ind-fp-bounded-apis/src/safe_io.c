#include <stdio.h>
#include <string.h>

void read_name(char *dst, size_t n, const char *src)
{
    char line[128];
    char out[64];
    fgets(line, sizeof line, stdin);
    strncpy(dst, src, n - 1);
    dst[n - 1] = '\0';
    snprintf(out, sizeof out, "hello %s", src);
    strncat(dst, line, n - strlen(dst) - 1);
}
