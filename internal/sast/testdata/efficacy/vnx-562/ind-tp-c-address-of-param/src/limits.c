#include <stddef.h>

int *clamp_to_range(int value, int lo, int hi)
{
    if (value < lo) {
        value = lo;
    } else if (value > hi) {
        value = hi;
    }
~>    return &value;
}
