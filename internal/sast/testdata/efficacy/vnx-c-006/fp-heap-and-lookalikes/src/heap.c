#include <malloc.h>
#include <stdlib.h>

struct arena { void *(*alloca_fn)(size_t); };

void heap(size_t n, struct arena *a)
{
    char *p = malloc(n);
    char *q = _malloca(n);
    char *r = a->alloca_fn(n);
    char *s = my_alloca(n);
    size_t alloca_size = n;
    char *t = strndupa(p, 16);
    use(p, q, r, s, t, alloca_size);
    _freea(q);
}

void sized(size_t n, const char *buf)
{
    char tmp[n];
    copy(tmp, buf, n);
}
