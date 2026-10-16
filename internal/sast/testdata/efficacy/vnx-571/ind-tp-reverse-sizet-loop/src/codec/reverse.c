#include <stddef.h>
#include <stdint.h>

void reverse_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t j = 0;
~>    for (size_t i = n - 1; i >= 0; i--) {
        dst[j++] = src[i];
    }
}
