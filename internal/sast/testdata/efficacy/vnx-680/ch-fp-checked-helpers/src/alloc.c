#include <stdlib.h>
#include <stdio.h>

void *grow(void *p, FILE *fp)
{
    size_t n, bytes;
    fread(&n, sizeof n, 1, fp);
    p = reallocarray(p, n, sizeof(long));
    if (__builtin_mul_overflow(n, sizeof(long), &bytes))
        return NULL;
    void *q = malloc(bytes);
    void *z = calloc(n, sizeof(long));
    free(z);
    free(q);
    return p;
}
