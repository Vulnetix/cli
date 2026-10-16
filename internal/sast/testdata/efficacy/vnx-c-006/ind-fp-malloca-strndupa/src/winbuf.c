#define _GNU_SOURCE
#include <malloc.h>
#include <string.h>

void *my_alloca_pool(size_t n);
void *realloca_buffer(void *old, size_t n);

void convert(const char *src, size_t n)
{
    char *buf = (char *)_malloca(n);
    memcpy(buf, src, n);
    _freea(buf);
    char *prefix = strndupa(src, 32);
    (void)prefix;
    void *pool = my_alloca_pool(n);
    (void)pool;
}
