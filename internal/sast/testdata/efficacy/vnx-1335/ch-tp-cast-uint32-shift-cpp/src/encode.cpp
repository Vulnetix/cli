#include <cstdint>

uint64_t pack(uint32_t hi, uint32_t lo)
{
~>    return static_cast<uint32_t>(hi) << 32 | lo;
}
