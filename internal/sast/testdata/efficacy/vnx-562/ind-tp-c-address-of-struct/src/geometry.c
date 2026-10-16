#include "geometry.h"

struct point *midpoint(const struct point *a, const struct point *b)
{
    struct point mid;

    mid.x = (a->x + b->x) / 2;
    mid.y = (a->y + b->y) / 2;
~>    return &mid;
}
