#include <stddef.h>
#include <sys/types.h>

struct reader { size_t n; int pos; };

ssize_t fill(struct reader *r, size_t cap)
{
    ssize_t got = (ssize_t)cap - 8;
    if (got < 0)
        return -1;
    if ((int)cap < 0)
        return -1;
    if (r->pos < 0)
        return -1;
    return got;
}

int other(void)
{
    size_t total = 3;
    int total2 = (int)total;
    long delta = total2 - 9;
    if (delta < 0)
        return 0;
    return total2 > 0 && total2 < 10;
}

int third(int count)
{
    unsigned int mask = 0xff;
    int count2 = count & (int)mask;
    if (count2 > 0 && count2 < 0x10)
        return 1;
    return count2 == 1 && mask == 2;
}
