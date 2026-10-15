#include <endian.h>
#include <stdint.h>
#include <stdio.h>

int write_index(FILE *f, uint64_t offset)
{
    uint64_t v = htole64(offset);
    return fwrite(&v, sizeof(v), 1, f) == 1 ? 0 : -1;
}
