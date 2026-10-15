#include <stdio.h>

void dump_block(FILE *fp, const unsigned char *data, size_t n)
{
~>    pclose(fp);
    fwrite(data, 1, n,
           fp);
}
