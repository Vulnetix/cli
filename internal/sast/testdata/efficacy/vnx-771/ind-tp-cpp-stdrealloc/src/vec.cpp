#include <cstdlib>

void grow(int *&items, std::size_t n)
{
~>    items = static_cast<int *>(std::realloc(items, n * sizeof(int)));
}
