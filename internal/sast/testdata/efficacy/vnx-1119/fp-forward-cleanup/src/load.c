#include <stdio.h>
#include <stdlib.h>

int load(const char *path, char **out)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    if (!f)
        goto err;
    buf = malloc(4096);
    if (!buf)
        goto cleanup;
    if (fread(buf, 1, 4096, f) == 0)
        goto cleanup;
    *out = buf;
    fclose(f);
    return 0;
cleanup:
    free(buf);
    fclose(f);
err:
    return -1;
}
