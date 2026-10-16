#include <stdio.h>
#include <stdlib.h>

double *alloc_grid(const char *header_line)
{
    int rows = 0;
    if (sscanf(header_line, "rows=%d", &rows) != 1) {
        return NULL;
    }
    if (rows <= 0) {
        return NULL;
    }
~>    double *grid = malloc(rows * sizeof(double));
    return grid;
}
