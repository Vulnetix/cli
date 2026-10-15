#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

int *alloc_ints(uint32_t wire)
{
    uint32_t n = ntohl(wire);
    if (n > SIZE_MAX / sizeof(int))
        return NULL;
    return malloc(n * sizeof(int));
}
