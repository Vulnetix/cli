#include <stdint.h>
#include <string.h>

void write_words(unsigned char *out, const uint32_t *words, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        memcpy(out + i * sizeof(uint32_t), &words[i], sizeof(uint32_t));
    }
}

uint32_t word_at(const void *base, size_t i)
{
    uint32_t w;
    memcpy(&w, (const char *)base + i * sizeof(uint32_t), sizeof w);
    return w;
}

void *payload(void *msg)
{
    return (uint8_t *)msg + sizeof(struct header);
}

char *after_header(char *p)
{
    p += sizeof(struct header);
    return p;
}

int *next(int *p)
{
    return p + 1;
}

uint8_t *bytes(uint8_t *buf, size_t i)
{
    return buf + i * sizeof(uint16_t);
}
