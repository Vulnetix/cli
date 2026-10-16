#include <stdlib.h>
#include <stddef.h>

double *alloc_matrix(const char *rows_s, const char *cols_s)
{
    size_t rows = strtoul(rows_s, NULL, 10);
    size_t cols = strtoul(cols_s, NULL, 10);
    size_t cells, bytes;
    if (__builtin_mul_overflow(rows, cols, &cells))
        return NULL;
    if (__builtin_mul_overflow(cells, sizeof(double), &bytes))
        return NULL;
    return malloc(bytes);
}
