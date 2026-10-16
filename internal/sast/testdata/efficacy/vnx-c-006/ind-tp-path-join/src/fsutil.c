#include <alloca.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int path_exists(const char *root, const char *name)
{
    struct stat st;
~>    char *path = alloca(strlen(root) + strlen(name) + 2);
    sprintf(path, "%s/%s", root, name);
    return stat(path, &st) == 0;
}
