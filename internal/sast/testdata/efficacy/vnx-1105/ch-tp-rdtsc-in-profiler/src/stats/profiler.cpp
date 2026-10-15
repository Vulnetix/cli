#include <cstdint>
#include "profiler.h"

namespace stats {

static inline std::uint64_t ticks()
{
    std::uint32_t lo, hi;
~>    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<std::uint64_t>(hi) << 32) | lo;
}

void Profiler::begin(const char *name)
{
    start_ = ticks();
    name_ = name;
}

}  // namespace stats
