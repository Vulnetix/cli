#include <alloca.h>
#include <stdlib.h>
#include <string.h>

#define STACK_LIMIT 1024
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

void *scratch_for(size_t n)
{
    if (n > STACK_LIMIT)
        return NULL;
    void *p = alloca(n);
    memset(p, 0, n);
    return NULL;
}

void encode(const char *src, size_t len)
{
    char *buf = len < 256 ? alloca(len) : malloc(len);
    memcpy(buf, src, len);
    if (len >= 256)
        free(buf);
}

void clamp_copy(const char *src, size_t len)
{
    char *tmp = alloca(MIN(len, 128));
    memcpy(tmp, src, MIN(len, 128));
}
