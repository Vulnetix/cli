#include <stddef.h>

static long table[64];

long lookup(size_t i)
{
~>    return table[i * sizeof(long)];
}
