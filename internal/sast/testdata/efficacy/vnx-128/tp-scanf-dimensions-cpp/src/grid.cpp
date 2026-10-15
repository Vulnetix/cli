#include <cstdio>

int *read_grid()
{
    int rows, cols;
    scanf("%d %d", &rows, &cols);
~>    int *grid = new int[rows * cols];
    return grid;
}
