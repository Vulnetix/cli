#include <string.h>
#include <stdio.h>

void build_path(const char *dir, const char *name)
{
    char path[256];

~>    strcat(path, dir);
    strcat(path, "/");
    strcat(path, name);
    puts(path);
}
