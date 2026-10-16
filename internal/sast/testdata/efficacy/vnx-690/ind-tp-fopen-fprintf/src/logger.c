#include <stdio.h>

void log_start(const char *path)
{
    FILE *fp = fopen(path, "a");
~>    fprintf(fp, "started\n");
    fclose(fp);
}
