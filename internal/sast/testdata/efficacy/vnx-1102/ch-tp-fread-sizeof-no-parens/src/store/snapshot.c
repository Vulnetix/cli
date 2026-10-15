#include <stdio.h>
#include <stdint.h>

int load_snapshot(FILE *f, uint64_t *out_count)
{
    uint32_t magic;
    uint64_t count;

~>    if (fread(&magic, sizeof magic, 1, f) != 1)
        return -1;
    if (magic != 0x534e4150u)
        return -2;
~>    if (fread(&count, sizeof count, 1, f) != 1)
        return -1;
    *out_count = count;
    return 0;
}
