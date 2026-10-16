#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_store.h"

int config_store_save(const struct config *cfg, const char *path)
{
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s.new", path);

    FILE *out = fopen(tmp, "w");
    if (out == NULL)
        return -1;

    for (size_t i = 0; i < cfg->count; i++)
        fprintf(out, "%s = %s\n", cfg->keys[i], cfg->values[i]);

    if (fflush(out) != 0 || fclose(out) != 0) {
        unlink(tmp);
        return -1;
    }
~>    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}
