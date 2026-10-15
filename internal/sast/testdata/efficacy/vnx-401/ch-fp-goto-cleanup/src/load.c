#include <stdlib.h>

int load_file(const char *path, struct blob *out)
{
    int rc = -1;
    char *buf = malloc(4096);
    if (buf == NULL)
        return -1;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        goto out;
    if (fread(buf, 1, 4096, fp) == 0)
        goto close;
    out->data = buf;
    buf = NULL;
    rc = 0;
close:
    fclose(fp);
out:
    free(buf);
    return rc;
}
