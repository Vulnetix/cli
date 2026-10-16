#include <stdio.h>
#include <stdlib.h>
int load(FILE *f)
{
    char *buf = malloc(4096);
    if (fread(buf, 1, 4096, f) == 0) {
~>        free(buf);
        goto out;
    }
    parse(buf);
out:
    free(buf);
    return 0;
}
