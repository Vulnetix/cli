#include <stdio.h>
#include <string.h>

void append(char *buf, size_t cap, const char *name)
{
    size_t n = strlen(buf);
    snprintf(buf + n, cap - n, "/%s", name);
    fflush(stdout);
    fflush(stderr);
}
