#include <stddef.h>

long checksum(const unsigned char *data, size_t n)
{
    long total;
    size_t i;

    for (i = 0; i < n; i++)
~>        total += data[i];
    return total;
}
