#include <stdio.h>
#include <stdlib.h>

int *read_grid(void)
{
    int rows = 0, cols = 0;
    size_t cells;
    if (scanf("%d %d", &rows, &cols) != 2)
        return NULL;
    if (__builtin_mul_overflow((size_t)rows, (size_t)cols, &cells))
        return NULL;
    int *grid = malloc(cells * sizeof(int));
    return grid;
}
