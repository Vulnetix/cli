#include <stdio.h>

size_t load_header(const char *path, unsigned char *buf, size_t cap)
{
    FILE *fp = fopen(path, "rb");
    /* read the fixed-size header */
~>    size_t got = fread(buf, 1, cap, fp);
    return got;
}
