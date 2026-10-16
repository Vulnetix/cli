#include <stddef.h>

void deltas(const int *a, const int *b, int *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = a[i] - b[i];
    }
}
