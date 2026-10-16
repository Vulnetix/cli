#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int config_load(struct config *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
~>    if (fp < 0) {
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof line, fp) != NULL)
        config_parse_line(cfg, line);
    fclose(fp);
    return 0;
}

char *config_home(void)
{
    char *home = strdup(cfg_default_home);
~>    if (home == -1)
        return NULL;
    return home;
}

int config_tmp(void)
{
~>    if (tmpfile() < 0)
        return -1;
    return 0;
}
