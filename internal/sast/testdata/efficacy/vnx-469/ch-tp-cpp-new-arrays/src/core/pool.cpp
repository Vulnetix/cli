#include <cstddef>

std::ptrdiff_t pools_gap()
{
    int *front = new int[32];
    int *back = new int[32];
~>    std::ptrdiff_t gap = back - front;
    delete[] front;
    delete[] back;
    return gap;
}
