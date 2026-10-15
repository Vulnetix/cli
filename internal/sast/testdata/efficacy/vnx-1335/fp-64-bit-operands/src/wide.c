#include <stdint.h>

uint64_t wide(uint32_t hi, uint32_t lo, long long t)
{
    uint64_t v = ((uint64_t)hi << 32) | lo;
    int64_t s = (int64_t)hi << 32;
    unsigned long long w = t;
    long seconds = t;
    w = w << 40;
    seconds = seconds >> 32;
    return v ^ (uint64_t)s ^ w;
}
