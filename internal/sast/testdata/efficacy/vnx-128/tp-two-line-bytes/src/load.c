#include <stdio.h>
#include <stdlib.h>

void *load(FILE *fp)
{
    unsigned int count;
    fread(&count, sizeof(count), 1, fp);
    size_t bytes = count * sizeof(double);
~>    double *vals = malloc(bytes);
    fread(vals, sizeof(double), count, fp);
    return vals;
}
