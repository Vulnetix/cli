#include <stdio.h>
#include <string.h>

const unsigned char *
to_hex(const unsigned char *in, size_t n)
{
    char out[256];
    size_t i;

    for (i = 0; i < n && i * 2 + 2 < sizeof(out); i++)
        sprintf(out + i * 2, "%02x", in[i]);
~>    return (const unsigned char *)out;
}

char *skip_prefix(const char *line)
{
    char copy[128];
    strncpy(copy, line, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
~>    return copy + 2;
}
