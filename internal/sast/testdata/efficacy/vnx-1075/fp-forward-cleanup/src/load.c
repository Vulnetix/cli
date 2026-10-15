#include <stdio.h>
#include <stdlib.h>

int load(const char *path, char **out) {
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    if (!f)
        goto err;
    buf = malloc(4096);
    if (!buf)
        goto err_close;
    if (fread(buf, 1, 4096, f) == 0)
        goto err_free;
    fclose(f);
    *out = buf;
    return 0;
err_free:
    free(buf);
err_close:
    fclose(f);
err:
    return -1;
}

int pick(int c) {
    switch (c) {
    case 1:
        return 10;
    default:
        break;
    }
    return 0;
}
