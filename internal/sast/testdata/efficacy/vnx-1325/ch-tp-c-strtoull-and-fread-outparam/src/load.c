#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char **argv)
{
    unsigned long long count = strtoull(argv[1], NULL, 10);
~>    double *samples = calloc(count, sizeof(double));
    if (!samples)
        return 1;
    free(samples);
    return 0;
}

void *load_blob(FILE *f)
{
    uint32_t blob_len;
    fread(&blob_len, sizeof(blob_len), 1, f);
~>    void *blob = malloc(blob_len);
    if (blob)
        fread(blob, 1, blob_len, f);
    return blob;
}
