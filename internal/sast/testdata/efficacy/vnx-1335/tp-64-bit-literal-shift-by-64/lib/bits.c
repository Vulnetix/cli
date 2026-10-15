#include <stdint.h>

uint64_t all_ones(void)
{
~>    return (1ULL << 64) - 1;
}

unsigned long top(void)
{
~>    return 1UL << 70;
}
