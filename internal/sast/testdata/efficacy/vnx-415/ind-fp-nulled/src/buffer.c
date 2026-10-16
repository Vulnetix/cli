#include <stdlib.h>

void buffer_clear(struct buffer *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    free(b->data);
}

void buffer_regrow(char *p, size_t n)
{
    free(p);
    p = malloc(n);
    if (p == NULL)
        return;
    free(p);
}
