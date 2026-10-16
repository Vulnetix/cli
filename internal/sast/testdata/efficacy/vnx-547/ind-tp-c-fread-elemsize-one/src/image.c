#include <stdio.h>

int read_header(FILE *f)
{
    unsigned char hdr[256];
~>    size_t got = fread(hdr, 1, 256, f);
    return parse_header(hdr, got);
}
