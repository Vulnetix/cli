#include <stdlib.h>
#include <string.h>

int grow(char **out, size_t *cap) {
    char *buf = *out;
    *cap *= 2;
~>    buf = realloc(buf, *cap);
    if (buf == NULL) {
        return -1;
    }
    *out = buf;
    return 0;
}

struct vec { int *items; size_t n; };

void push(struct vec *v, int x) {
~>    v->items = realloc(v->items, (v->n + 1) * sizeof(int));
    v->items[v->n++] = x;
}
