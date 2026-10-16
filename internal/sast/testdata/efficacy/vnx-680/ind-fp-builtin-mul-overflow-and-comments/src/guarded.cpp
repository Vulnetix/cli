#include <cstdlib>
#include <cstdio>

// p = malloc(atoi(argv[1]) * sizeof(int));   old unsafe version
void *alloc_n(int argc, char **argv)
{
    const char *help = "do not call malloc(atoi(s) * 8) directly";
    size_t n = strtoul(argv[1], NULL, 10), bytes;
    if (__builtin_mul_overflow(n, sizeof(double), &bytes))
        return NULL;
    /* new char[n * 4] was removed */
    return malloc(bytes);
}
