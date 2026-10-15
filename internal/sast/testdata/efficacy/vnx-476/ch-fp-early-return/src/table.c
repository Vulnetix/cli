#include <stdlib.h>

struct table {
    int *slots;
    int size;
};

int table_init(struct table *t, int size)
{
    t->slots = calloc((size_t)size, sizeof(int));
    if (t->slots == NULL)
    {
        return -1;
    }
    t->slots[0] = 1;
    t->size = size;
    return 0;
}
