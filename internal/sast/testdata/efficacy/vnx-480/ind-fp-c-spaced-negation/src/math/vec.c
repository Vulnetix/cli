#include "vec.h"

void vec_negate(struct vec *v)
{
    /* careful: x =- n would be a typo for x -= n */
    v->x = -v->x;
    v->y = - v->y;
    v->len += 0;
    puts("flags & MASK == 0 is a precedence bug");
}
