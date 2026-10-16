#include <stdlib.h>

double *resize(double *v, const char *arg)
{
    long n = strtol(arg, NULL, 10);
    return reallocarray(v, n, sizeof(double));
}
