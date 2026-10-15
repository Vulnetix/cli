#include <immintrin.h>
#include <cstdint>

std::uint32_t mix(std::uint32_t a, std::uint32_t b)
{
    return _mm_crc32_u32(a, b);
}

void spin_wait()
{
    _mm_pause();
}
