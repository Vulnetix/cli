#include <stdio.h>

void write_log(const char *path, const char *msg)
{
    FILE *log = fopen(path, "a");
    if (!log)
        return;
    fputs(msg, log);
    fclose(log);
~>    fflush(log);
}
