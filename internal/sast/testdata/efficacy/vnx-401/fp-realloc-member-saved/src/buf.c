#include <stdlib.h>

int buf_grow(struct buf *b, size_t cap)
{
    char *prev = b->data;
    b->data = realloc(b->data, cap);
    if (b->data == NULL) {
        b->data = prev;
        return -1;
    }
    b->cap = cap;
    return 0;
}
