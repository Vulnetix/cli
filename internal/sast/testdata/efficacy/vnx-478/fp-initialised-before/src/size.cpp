#include <cstddef>

size_t byte_size(int wtype, size_t size, size_t width)
{
    size_t num_bytes = 0;
    switch (wtype) {
        case 1:
            num_bytes = (size * width + 7) >> 3;
            break;
        case 2:
            num_bytes = size * width;
            break;
    }
    return num_bytes + 8;
}
