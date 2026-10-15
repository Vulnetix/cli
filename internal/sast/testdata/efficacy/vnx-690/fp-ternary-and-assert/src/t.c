#include <assert.h>
#include <stdlib.h>
#include <string.h>

void f(size_t n) {
    char *p = malloc(n);
    assert(p);
    p[0] = 0;
}

void g(size_t n) {
    char *p = malloc(n);
    if (p) memset(p, 0, n);
}
