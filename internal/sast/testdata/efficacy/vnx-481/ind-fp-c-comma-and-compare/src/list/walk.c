#include "list.h"

int count(struct item *q)
{
    struct item *p;
    int n = 0;

    while (p = q, q = next(q), p)
        n++;
    if (n <= 0 || n >= LIMIT)
        return -1;
    return n;
}
