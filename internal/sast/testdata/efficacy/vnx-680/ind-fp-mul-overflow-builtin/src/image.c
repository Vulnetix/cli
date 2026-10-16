#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t *load_pixels(FILE *f)
{
    uint32_t w, h;
    size_t bytes;
    fread(&w, sizeof w, 1, f);
    fread(&h, sizeof h, 1, f);
    if (__builtin_mul_overflow((size_t)w, (size_t)h, &bytes)) {
        return NULL;
    }
    if (__builtin_mul_overflow(bytes, 4, &bytes)) {
        return NULL;
    }
    return malloc(bytes);
}
