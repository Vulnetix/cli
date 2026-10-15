#include <stdlib.h>

void list_free(struct item **items, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(items[i]->data);
        free(items[i]);
    }
    free(items);
}
