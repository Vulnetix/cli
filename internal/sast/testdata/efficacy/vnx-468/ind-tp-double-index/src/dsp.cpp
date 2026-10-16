#include <cstddef>

double sample_at(double *samples, std::size_t idx)
{
~>    double *slot = samples + idx * sizeof(double);
    return *slot;
}
