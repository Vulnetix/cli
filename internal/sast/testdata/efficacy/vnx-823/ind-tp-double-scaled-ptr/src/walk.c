#include <stdint.h>
#include <stddef.h>

uint32_t sum_words(uint32_t *table, size_t n)
{
    uint32_t *words = table;
    uint32_t total = 0;
~>    uint32_t *end = words + sizeof(table);
    while (words < end) {
        total += *words++;
    }
    return total;
}
