#include <stdlib.h>

typedef struct {
    int *items;
    size_t len;
    size_t cap;
} intvec;

int intvec_push(intvec *v, int x)
{
    if (v->len == v->cap) {
        size_t cap = v->cap ? v->cap * 2 : 16;
        int *tmp = realloc(v->items, cap * sizeof(*tmp));
        if (tmp == NULL)
            return -1;
        v->items = tmp;
        v->cap = cap;
    }
    v->items[v->len++] = x;
    return 0;
}
