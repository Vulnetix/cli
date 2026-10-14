#include <alloca.h>
#include <stdlib.h>

#define STACK_LIMIT 1024

void *bounded(size_t n)
{
    if (n > STACK_LIMIT)
        return NULL;
    return alloca(n);
}

void choose(size_t len)
{
    char *buf = len < 256 ? alloca(len) : malloc(len);
    use(buf);
}

void clamp(size_t len)
{
    char *buf = alloca(MIN(len, STACK_LIMIT));
    use(buf);
}
