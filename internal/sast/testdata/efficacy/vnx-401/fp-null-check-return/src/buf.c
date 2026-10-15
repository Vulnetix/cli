#include <stdlib.h>

int make_buffer(struct ctx *c, size_t n)
{
    char *b = malloc(n);
    if (b == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    c->buf = b;
    return 0;
}
