#include <stdlib.h>

int load(const char *path)
{
    char *data = read_all(path);
    char *meta = NULL;
    if (data == NULL)
        goto fail;
    meta = parse(data);
    if (meta == NULL) {
        free(data);
        data = NULL;
        goto fail;
    }
    if (bad(meta)) {
        free(meta);
        goto fail;
    }
    return commit(data, meta);
fail:
    free(data);
    return -1;
}
