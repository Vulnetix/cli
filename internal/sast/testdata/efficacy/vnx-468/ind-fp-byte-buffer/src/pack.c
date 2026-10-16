#include <stdint.h>
#include <string.h>

void pack_words(unsigned char *out, const uint32_t *words, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        memcpy(out + i * sizeof(uint32_t), &words[i], sizeof(uint32_t));
    }
}
