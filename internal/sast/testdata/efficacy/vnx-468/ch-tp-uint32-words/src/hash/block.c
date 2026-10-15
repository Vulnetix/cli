#include <stdint.h>
#include <stddef.h>

uint32_t load_word(const uint32_t *words, size_t n)
{
~>    const uint32_t *w = words + n * sizeof(uint32_t);
    return *w;
}
