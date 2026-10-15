#include <stdlib.h>
#include <string.h>

char *dup_block(const char *src, size_t n)
{
    char *buf = malloc(n + 1);
~>    memcpy(buf, src, n);
    buf[n] = '\0';
    return buf;
}
