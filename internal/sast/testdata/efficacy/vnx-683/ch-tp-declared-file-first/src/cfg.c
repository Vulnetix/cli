#include <stdio.h>

void save(const char *path, const char *line)
{
    FILE *cfg = fopen(path, "w");
~>    fputs(cfg, line);
    fclose(cfg);
}
