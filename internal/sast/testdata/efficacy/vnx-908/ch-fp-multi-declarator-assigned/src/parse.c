#include <string.h>

int span(const char *s)
{
    int lo, hi;
    lo = 0;
    hi = (int)strlen(s);
    return hi - lo;
}

void swap(int *x, int *y)
{
    int t, u;
    t = *x;
    u = *y;
    *x = u;
    *y = t;
}

struct range { int lo, hi; };
