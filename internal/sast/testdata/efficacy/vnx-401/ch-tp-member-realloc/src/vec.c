#include <stdlib.h>

int vec_push(struct vec *v, int value)
{
    if (v->len == v->cap) {
        v->cap *= 2;
~>        v->data = realloc(v->data, v->cap * sizeof(int));
        if (!v->data)
            return -1;
    }
    v->data[v->len++] = value;
    return 0;
}
