#include <stdlib.h>
#define MAX_ITEMS 128

struct vec { size_t len; size_t cap; int *data; };

int vec_grow(struct vec *v) {
    size_t cap = v->cap ? v->cap * 2 : 16;
    int *d = realloc(v->data, cap * sizeof(int));
    if (!d) return -1;
    v->data = d;
    v->cap = cap;
    int *fixed = malloc(MAX_ITEMS * sizeof(int));
    char *line = malloc(sizeof(char) * 256);
    free(fixed);
    free(line);
    return 0;
}

void *dup_of(const char *s) {
    size_t n = strlen(s);
    return malloc(n * sizeof(char));
}
