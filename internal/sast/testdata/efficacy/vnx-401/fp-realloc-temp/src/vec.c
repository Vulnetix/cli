#include <stdlib.h>

int vec_grow(struct vec *v, size_t cap)
{
    void *tmp = realloc(v->items, cap * sizeof(*v->items));
    if (tmp == NULL)
        return -1;
    v->items = tmp;
    return 0;
}

char *read_line(char *line, size_t maxlen)
{
    char *oldval = line;
    line = realloc(line, maxlen);
    if (line == NULL) {
        free(oldval);
        return NULL;
    }
    return line;
}
