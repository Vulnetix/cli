#include <cstdint>

bool can_write(uint32_t mode)
{
~>    return mode & 0200 == 0200;
}

bool is_dir(uint32_t mode)
{
~>    if (mode & S_IFMT != S_IFDIR)
        return false;
    return true;
}
