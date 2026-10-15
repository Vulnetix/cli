#include <stdio.h>
#include <stdlib.h>

int *load(FILE *f, int *p)
{
    unsigned int n;
    fread(&n, sizeof n, 1, f);
~>    p = realloc(p, n * sizeof *p);
    return p;
}
