#include <stdlib.h>

int *grow(int *items, size_t count) {
    items = realloc(items, (count + 1) * sizeof(int));
~>    items[count] = 0;
    return items;
}

void zero(size_t n) {
    char *p = malloc(n);
~>    *p = 0;
}
