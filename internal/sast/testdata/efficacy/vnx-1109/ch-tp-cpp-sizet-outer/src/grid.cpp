#include <cstddef>

long checksum(const int *cells, std::size_t rows, std::size_t cols)
{
    long acc = 0;
    for (std::size_t r = 0; r < rows; ++r) {
        acc ^= cells[r];
~>        for(r = 0; r < cols; ++r) {
            acc += cells[r * cols];
        }
    }
    return acc;
}
