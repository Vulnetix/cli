#include <stdlib.h>
#include <string.h>

struct ctx {
    int field;
};

static int cmp_records(const void *a, const void *b, void *arg)
{
    const struct ctx *c = arg;
    return memcmp(a, b, (size_t)c->field);
}

void sort_records(void *recs, size_t n, size_t sz, struct ctx *c)
{
~>    qsort_r(recs, n, sz,
            cmp_records, c);
}

const char *last_slash(const char *p, size_t n)
{
~>    return memrchr(p, '/', n);
}
