#include <cstdint>

struct Pair {
    int32_t lo;
    int32_t hi;
};

static int64_t widen(void)
{
    Pair val = {1, 2};
    return val.lo;
}

int32_t high_half(void)
{
    int32_t val = 7;
~>    Pair *p = (Pair *)&val;
    return p->hi;
}
