#include <stddef.h>

double mean_or_zero(const double *xs, size_t n)
{
    double sum = 0.0;
    for (int i = (int)n - 1; i >= 0; i--)
        sum += xs[i];
    double v = sum / (double)n;
    if (v == v)
        return v;
    return 0.0;
}
