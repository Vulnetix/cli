#include <stdio.h>
#include <stdint.h>

struct db_header {
    uint32_t magic;
    uint16_t version;
    uint64_t record_count;
};

int save_header(FILE *fp, const struct db_header *hdr, long offset)
{
~>    if (fwrite(hdr, sizeof(struct db_header), 1, fp) != 1)
        return -1;
~>    fwrite(&offset, sizeof(long), 1, fp);
    return 0;
}
