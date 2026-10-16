#include <stdlib.h>
#include <string.h>

struct holder { char *name; char buf[32]; };

void clean(struct holder *h, char *arr, size_t n)
{
    char *p = malloc(n);
    free(p);
    free(&p[0]);
    free(h->name);
    free(arr);
}

void wrapper(void *s)
{
    sdsfree(s);
}
