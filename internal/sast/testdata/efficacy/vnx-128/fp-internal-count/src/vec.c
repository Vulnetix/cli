#include <stdlib.h>

struct vec { size_t len, cap; int *data; };

void vec_grow(struct vec *v, size_t extra)
{
    size_t cap = v->cap * 2;
    v->data = realloc(v->data, cap * sizeof(int));
    float *f = malloc(sizeof(float) * 300);
    char *g = malloc(MAX_ITEMS * sizeof(char *));
}
