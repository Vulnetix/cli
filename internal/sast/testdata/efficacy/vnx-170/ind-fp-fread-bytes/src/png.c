#include <stdio.h>
#include <string.h>

static const unsigned char PNG_MAGIC[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

int is_png(FILE *fp)
{
    char header[8];
    if (fread(header, 1, sizeof(header), fp) != sizeof(header))
        return 0;
    return memcmp(header, PNG_MAGIC, sizeof(header)) == 0;
}
