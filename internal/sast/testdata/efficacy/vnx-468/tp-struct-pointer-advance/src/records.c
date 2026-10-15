#include <stdint.h>

struct record {
    uint32_t id;
    uint32_t len;
};

void skip_header(struct record *rec, uint32_t *words)
{
~>    rec += sizeof(struct record);
~>    words = words + sizeof(uint32_t);
    consume(rec, words);
}

void rewind_one(struct record *cur)
{
~>    cur = cur - sizeof(struct record);
    consume(cur, 0);
}
