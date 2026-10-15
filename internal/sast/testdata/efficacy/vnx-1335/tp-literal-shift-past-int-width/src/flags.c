#include <stdint.h>


uint64_t make_mask(void)
{
~>    uint64_t mask = 1 << 40;
~>    mask |= (1u << 32);
~>    mask |= 0x1 << 33;
~>    return mask | FLAG_ARCHIVED_HIGH(1 << 36);
}
