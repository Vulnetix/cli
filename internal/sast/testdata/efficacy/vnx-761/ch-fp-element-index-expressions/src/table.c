#include <stdlib.h>

struct table {
    char **items;
    size_t n;
};

void table_clear(struct table *t)
{
    for (size_t i = 0; i + 1 < t->n; i++) {
        free(t->items[i + 1]);
        free(t->items[i]);
    }
    free(t->items[t->n - 1]);
    free(t->items);
}

void drop(char **names, int k)
{
    free(names[k + 1]);
    free(names[2 * k]);
}
