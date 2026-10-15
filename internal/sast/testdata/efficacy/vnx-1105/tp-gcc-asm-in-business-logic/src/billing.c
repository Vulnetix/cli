#include <stdint.h>
#include "billing.h"

static uint64_t now_cycles(void)
{
    uint32_t lo, hi;
~>    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int charge(struct account *a, long cents)
{
    a->balance -= cents;
~>    asm volatile("mfence" ::: "memory");
    a->last_charge = now_cycles();
    return 0;
}
