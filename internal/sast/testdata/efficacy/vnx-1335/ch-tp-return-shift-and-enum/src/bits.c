#include <stdint.h>

enum feature_flags {
    FEATURE_A = 1 << 0,
    FEATURE_B = 1 << 1,
~>    FEATURE_WIDE = 1 << 33,
};

static inline uint32_t high_word(uint32_t packed)
{
~>    return packed >> 32;
}

static uint64_t join(uint32_t hi, uint32_t lo)
{
~>    return hi << 32 | lo;
}
