#include <stdio.h>

void dump_samples(const char *path, const double *samples, size_t n)
{
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return;
~>    fwrite(samples, sizeof(double), n, fp);
    fclose(fp);
}
