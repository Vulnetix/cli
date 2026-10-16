#include <cstdint>

namespace q {
inline void pause_hint()
{
~>    asm("pause");
}
inline uint64_t swap64(uint64_t v)
{
~>    __asm__("bswap %0" : "+r"(v));
    return v;
}
}
