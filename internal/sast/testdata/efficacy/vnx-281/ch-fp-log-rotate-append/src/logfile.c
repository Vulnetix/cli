#include <stdio.h>

static FILE *logf;

void log_open(const char *logpath)
{
    logf = fopen(logpath, "a");
}

void log_rotate(const char *logpath, const char *archived)
{
    if (logf)
        fclose(logf);
    rename(logpath, archived);
    logf = fopen(logpath, "a");
}
