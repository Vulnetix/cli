#include <stdio.h>
#include <stdlib.h>

int load(const char *path)
{
    char *buf = malloc(4096);
    FILE *f = fopen(path, "r");
    if (!f)
        goto out;
    if (fread(buf, 1, 4096, f) == 0) {
~>        free(buf);
~>        fclose(f);
        goto out_close;
    }
    fclose(f);
    free(buf);
    return 0;
out_close:
    fclose(f);
out:
    free(buf);
    return -1;
}
