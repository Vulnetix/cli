#include <stdlib.h>

int *make_table(size_t n)
{
    int *t = calloc(n, sizeof *t);
    if (!t) {
        perror("calloc");
        return NULL;
    }
    t[0] = 1;
    return t;
}
