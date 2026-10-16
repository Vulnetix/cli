#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct vec { double *items; size_t len; };

int vec_load(struct vec *v, FILE *f)
{
    uint32_t extra;
    if (fread(&extra, sizeof extra, 1, f) != 1)
        return -1;
~>    double *grown = realloc(v->items, (v->len + extra) * sizeof(double));
    if (grown == NULL)
        return -1;
    v->items = grown;
    if (fread(v->items + v->len, sizeof(double), extra, f) != extra)
        return -1;
    v->len += extra;
    return 0;
}
