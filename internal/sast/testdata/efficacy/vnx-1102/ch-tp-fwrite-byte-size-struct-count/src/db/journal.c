#include <stdio.h>
#include <stdint.h>

struct journal_rec {
    uint64_t lsn;
    uint32_t len;
    int32_t kind;
};

int journal_append(FILE *fp, const struct journal_rec *in)
{
    struct journal_rec rec = *in;
~>    return fwrite(&rec, 1, sizeof(rec), fp) == sizeof(rec) ? 0 : -1;
}

int journal_next(FILE *fp, struct journal_rec *out)
{
    struct journal_rec rec;
~>    if (fread(&rec, 1, sizeof rec, fp) != sizeof rec)
        return -1;
    *out = rec;
    return 0;
}
