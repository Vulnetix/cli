#include <stddef.h>

double mean(const double *v, size_t n)
{
    double sum;
    size_t i;

    for (i = 0; i < n; i++) {
~>        sum += v[i];
    }
    return n ? sum / n : 0.0;
}
