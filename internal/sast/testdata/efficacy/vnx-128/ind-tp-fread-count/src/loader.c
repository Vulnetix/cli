#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

float *load_vector(FILE *fp)
{
    uint32_t n;
    if (fread(&n, sizeof(n), 1, fp) != 1)
        return NULL;
~>    float *v = malloc(n * sizeof(float));
    if (!v)
        return NULL;
    fread(v, sizeof(float), n, fp);
    return v;
}
