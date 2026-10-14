#include <stdio.h>

static void warn(const char *msg)
{
    fputs(msg, stderr);
}

static void err(int code, const char *msg)
{
    fputs(msg, stderr);
    exit(code);
}

void check(const char *path)
{
    warn(path);
    err(1, path);
}
