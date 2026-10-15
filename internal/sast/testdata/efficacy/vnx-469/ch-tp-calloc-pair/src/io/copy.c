#include <stdlib.h>
#include <string.h>

size_t staging_offset(size_t n)
{
    unsigned char *in = calloc(n, 1);
    unsigned char *out = calloc(n, 1);
~>    size_t off = (size_t)(out - in);
    free(in);
    free(out);
    return off;
}
