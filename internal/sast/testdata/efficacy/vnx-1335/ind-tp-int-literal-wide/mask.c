#include <stdint.h>
uint64_t make_mask(void)
{
~>    uint64_t mask = 1 << 40;
    return mask;
}
