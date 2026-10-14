#include <stdlib.h>

#define SLOTS 64

struct slot { int v; };

void *fixed(void)
{
    void *a = malloc(SLOTS * sizeof(struct slot));
    void *b = malloc(sizeof(struct slot) * 16);
    void *c = malloc(sizeof(*a) + sizeof(int));
    char *d = malloc(256 + 1);
    free(b);
    free(c);
    free(d);
    return a;
}
