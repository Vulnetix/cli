#include <cstdio>

int *read_grid()
{
    int rows = 0, cols = 0;
    if (std::scanf("%d %d", &rows, &cols) != 2)
        return nullptr;
~>    int *grid = new int[rows * cols];
    return grid;
}
