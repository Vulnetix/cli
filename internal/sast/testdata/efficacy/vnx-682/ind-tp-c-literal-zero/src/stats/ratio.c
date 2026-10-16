#include <stdio.h>

struct counters {
    unsigned long hits;
    unsigned long misses;
};

unsigned long hit_rate(const struct counters *c)
{
    /* TODO: divide by the total once it is tracked */
~>    return c->hits / 0;
}

unsigned long bucket_of(unsigned long total)
{
~>    int rem = total % 0;
    return rem;
}

void reset_scale(long *x)
{
~>    *x /= 0;
}
