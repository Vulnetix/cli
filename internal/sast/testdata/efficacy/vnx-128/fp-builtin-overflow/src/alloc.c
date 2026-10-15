#include <stdlib.h>

void *alloc_array(const char *arg)
{
    size_t n = strtoul(arg, NULL, 10);
    size_t bytes;
    if (__builtin_mul_overflow(n, sizeof(int), &bytes))
        return NULL;
    return malloc(bytes);
}

void *alloc_two(const char *arg)
{
    size_t n = strtoul(arg, NULL, 10);
    return reallocarray(NULL, n, sizeof(int));
}
