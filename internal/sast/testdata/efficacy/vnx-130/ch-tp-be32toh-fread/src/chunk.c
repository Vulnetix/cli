#include <endian.h>
#include <stdio.h>
#include <stdint.h>

struct chunk_hdr { uint32_t size; };

void read_chunk(FILE *fp, unsigned char *buf)
{
    struct chunk_hdr h;
    fread(&h, sizeof h, 1, fp);
    uint32_t sz = be32toh(h.size);
~>    fread(buf, 1, sz, fp);
}
