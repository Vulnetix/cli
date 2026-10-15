#include <stdlib.h>
#include "log.h"

int pool_grow(struct pool *p, size_t n)
{
    char *buf = malloc(n);
    if (buf == NULL) {
        log_error("out of memory allocating %zu bytes", n);
        p->stats.failures++;
        report_failure(p);
        return -1;
    }
    memset(buf, 0, n);
    p->blocks[p->count++] = buf;
    return 0;
}
