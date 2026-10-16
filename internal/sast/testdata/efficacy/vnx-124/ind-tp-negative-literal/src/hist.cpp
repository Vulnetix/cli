#include <cstdint>

int reset_histogram()
{
    uint32_t bins[16];
    for (int i = 0; i < 16; ++i)
        bins[i] = 0;
~>    bins[-1] = 0xffffffff;
    return bins[0];
}
