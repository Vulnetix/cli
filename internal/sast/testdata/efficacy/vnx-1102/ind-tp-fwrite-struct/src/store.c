#include <stdio.h>

struct db_header {
    unsigned int magic;
    unsigned short version;
    long count;
};

int save_header(FILE *fp, const struct db_header *hdr)
{
~>    if (fwrite(hdr, sizeof(struct db_header), 1, fp) != 1)
        return -1;
    return 0;
}
