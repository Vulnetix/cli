#include <stdlib.h>
#include <string.h>

int config_set_name(struct config *cfg, const char *value)
{
    char *name = strdup(value);
    if (name == NULL)
        return -1;
    if (strlen(name) > 64)
~>        return -2;
    free(cfg->name);
    cfg->name = name;
    return 0;
}
