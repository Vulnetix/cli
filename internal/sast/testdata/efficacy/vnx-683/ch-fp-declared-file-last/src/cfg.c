#include <stdio.h>

void save(const char *path, const char *line, char *cfgline)
{
    FILE *cfg = fopen(path, "w");
    fputs(line, cfg);
    fputs(cfgline, cfg);
    fclose(cfg);
}
