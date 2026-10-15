#include <stdio.h>
#include <stdlib.h>

struct conf {
    int port;
};

void load(const char *path)
{
    struct conf cfg;
    char line[256];
    FILE *f = fopen(path, "r");
    while (fgets(line, sizeof line, f))
        sscanf(line, "%d", &cfg.port);
    fclose(f);
~>    free((void *) &cfg);
~>    free(line);
}
