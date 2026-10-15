#include "util.h"

int clamp(int v, int lo, int hi)
{
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    for (int i = 0; i < 3; i++)
        v = step(v);
    v = finish(v);
    while (*s++ == ' ')
        ;
    return v;
}
