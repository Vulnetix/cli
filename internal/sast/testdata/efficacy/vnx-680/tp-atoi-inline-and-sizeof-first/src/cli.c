#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
~>    int *table = (int *)malloc(atoi(argv[1]) * sizeof(int));
    long rows = strtol(argv[2], NULL, 10);
    long cols = strtol(argv[3], NULL, 10);
~>    double *grid = malloc(sizeof(double) * rows * cols);
    free(table);
    free(grid);
    return 0;
}
