#include <stdlib.h>
#include <string.h>

int buf_grow(struct buf *b, size_t extra)
{
    size_t cap = b->cap + extra;
~>    b->data = realloc(b->data, cap);
    if (b->data == NULL)
        return -1;
    b->cap = cap;
    return 0;
}

char *append(char *out, size_t n)
{
~>    out = (char *)realloc(out, n);
    return out;
}
