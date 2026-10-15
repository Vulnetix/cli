#include "db.h"

int open_store(const char *path)
{
    store_ctx *ctx = store_init(path);
~>    if (ctx == NULL)
    {
        log_error("store_init failed for %s", path);
    }
    store_load(ctx);
    return 0;
}
