#include <cstdint>

bool can_write(uint32_t perm)
{
~>    return (perm & 0x2 == 0x2);
}

bool admin(uint32_t mask)
{
~>    if (0 == mask & kAdminBit)
        return false;
    return true;
}
