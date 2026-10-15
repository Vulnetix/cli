#include <stdio.h>

void build(const char *dir)
{
    char name[32];
    char path[256];
    snprintf(name, sizeof(name), "%s", "cfg");
~>    snprintf(path, sizeof(name), "%s/%s", dir, name);
}
