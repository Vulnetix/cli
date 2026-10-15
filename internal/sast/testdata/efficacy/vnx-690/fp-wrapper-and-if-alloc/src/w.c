#include <stdlib.h>
#include <string.h>

void *xmalloc(size_t n);

void a(size_t n) {
    char *p = xmalloc(n);
    p[0] = 0;
    char *q = zmalloc(n);
    memset(q, 0, n);
}

int b(size_t n) {
    char *p;
    if ((p = malloc(n)) == NULL)
        return -1;
    p[0] = 0;
    return 0;
}

void c(size_t n) {
    char *p = malloc(n);
    free(p);
}
