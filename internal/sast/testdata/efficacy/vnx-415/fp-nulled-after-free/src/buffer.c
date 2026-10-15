#include <stdlib.h>

void buffer_reset(struct buffer *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    free(b->data);
}

void scratch(void)
{
    char *p = malloc(16);
    free(p);
    p = malloc(32);
    use(p);
    free(p);
}

void again(char *q)
{
    free(q);
    q = NULL;
    free(q);
}
