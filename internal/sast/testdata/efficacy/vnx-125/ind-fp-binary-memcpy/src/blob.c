#include <stdio.h>
#include <string.h>

int load_key(FILE *fp, unsigned char *out)
{
    unsigned char raw[32];
    size_t got = fread(raw, 1, sizeof(raw), fp);
    if (got != sizeof(raw))
        return -1;
    memcpy(out, raw, sizeof(raw));
    return 0;
}
