#include <cstddef>

void process(std::size_t n)
{
    int *values = new int[n];
    compute(values, n);
    delete[] values;
    log_done();
~>    delete[] values;
}
