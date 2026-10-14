#include <stdio.h>
#include <stdlib.h>

struct vec {
    double *items;
    size_t len;
};

int vec_load(struct vec *v, FILE *f)
{
    unsigned int extra;

    if (fread(&extra, sizeof extra, 1, f) != 1)
        return -1;
~>    v->items = realloc(v->items, (v->len + extra) * sizeof(double));
    return v->items ? 0 : -1;
}

char *plane(const char *spec)
{
    unsigned long rows = strtoul(spec, NULL, 10);
~>    return calloc(rows * rows, 1);
}

void *aligned(const char *spec)
{
    size_t blocks = strtoull(spec, NULL, 0);
~>    return aligned_alloc(64, blocks * 64);
}
