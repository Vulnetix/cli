#include <cstddef>

double sum_from(double *values, std::size_t start, std::size_t count)
{
    double total = 0.0;
~>    double *p = values + sizeof(double) * start;
    for (std::size_t k = 0; k < count; ++k)
        total += p[k];
    return total;
}
