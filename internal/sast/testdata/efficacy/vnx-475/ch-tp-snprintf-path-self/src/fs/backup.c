#include <stdio.h>

void backup_name(char *path, size_t n)
{
~>    snprintf(path, n, "%s.bak", path);
}

void join(char *out, const char *name)
{
~>    sprintf(out,
            "%s/%s", out, name);
}
