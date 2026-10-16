#include <stdlib.h>

int open_db(const char *path)
{
    char *buf = malloc(4096);
    if (!buf)
        goto err_out;
    if (load(path, buf) < 0)
        goto err_free;
    use(buf);
    free(buf);
    return 0;
err_free:
    free(buf);
err_out:
    return -1;
}
