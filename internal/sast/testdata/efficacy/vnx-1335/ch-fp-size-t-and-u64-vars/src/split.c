#include <stdint.h>
#include <stddef.h>

uint32_t upper(uint64_t value)
{
    return (uint32_t)(value >> 32);
}

size_t fold(size_t n)
{
    unsigned long long acc = n;
    return (size_t)(acc >> 40);
}
