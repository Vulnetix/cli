#include <stdio.h>
#include <stdlib.h>

int load(const char *path)
{
    FILE *in = fopen(path, "rb");
    if (unlikely(in == NULL))
        goto fail;
    char *buf = malloc(4096);
    if (buf == NULL) { fclose(in); goto fail; }
    fread(buf, 1, 4096, in);
    fclose(in);
    char *home = getenv("HOME");
    size_t n = home ? strlen(home) : 0;
    free(buf);
    return (int)n;
fail:
    return -1;
}
