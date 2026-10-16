#include <cstddef>

long sum(const long *values, std::size_t n)
{
    long total = 0;
    for (std::size_t i = 0; i < n; ++i)
        total += *(values + i);
    std::size_t bytes = n * sizeof(long);
    (void)bytes;
    return total;
}
