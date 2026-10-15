#include <stddef.h>
#include <stdint.h>

struct rec {
    int id;
    double score;
};

struct rec *rec_at(void *base, size_t i)
{
    return (struct rec *)((char *)base + i * sizeof(struct rec));
}

uint32_t word_at(const uint8_t *bytes, size_t i)
{
    const uint8_t *b = bytes + i * sizeof(uint32_t);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8);
}
