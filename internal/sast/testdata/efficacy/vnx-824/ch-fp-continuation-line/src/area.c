#include <stdio.h>

void report(long base, long rate, long count, long *factor)
{
    long total = base +
        rate * count;
    long scaled = base -
        rate * factor;
    printf("%ld %ld\n", total, count);
    printf("%ld\n", factor[0] + scaled);
}
