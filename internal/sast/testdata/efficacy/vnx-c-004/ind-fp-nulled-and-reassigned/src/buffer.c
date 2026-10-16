#include <stdlib.h>
#include <string.h>

struct buf {
    char *data;
    size_t len;
};

void buf_clear(struct buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    if (b->data != NULL)
        memset(b->data, 0, b->len);
}

int buf_resize(struct buf *b, size_t n)
{
    free(b->data);
    b->data = malloc(n);
    if (b->data == NULL)
        return -1;
    memset(b->data, 0, n);
    b->len = n;
    return 0;
}
